//! Route resolver: for a request described by the caller, which route sozune
//! serves it with, why each other candidate loses, and what happens next.
//!
//! Nothing here re-implements a routing rule. Sōzu's own `Router` is fed the
//! frontends `build_http_frontends` sends to the workers, in `routing_order`,
//! and answers the lookup itself. The middleware stage fills a middleware
//! route table the way a reload does and builds the route's real chain; the
//! steps that decide from the request alone (IP allow-list, match conditions)
//! are run on a synthetic copy of it. Only what depends on live state (rate
//! limit buckets, in-flight slots, a forward-auth server) is reported as
//! applying rather than decided.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::body::Body;
use serde::{Deserialize, Serialize};
use sozu_command_lib::proto::command::{RedirectPolicy, SocketAddress};
use sozu_lib::protocol::kawa_h1::parser::Method;
use sozu_lib::router::{
    DomainRule, MethodRule, MethodRuleResult, PathRule, PathRuleResult, Router,
};

use crate::middleware::chain::{Flow, Middleware, RequestCtx};
use crate::middleware::ip_allow_list::TrustedProxies;
use crate::middleware::request_match::RequestMatchMiddleware;
use crate::middleware::{self, MiddlewareRouteTable, PluginRegistry};
use crate::model::{Entrypoint, PathRuleType, Protocol};
use crate::proxy::health::UnhealthyMap;
use crate::proxy::sozu::{
    ACME_CHALLENGE_CLUSTER, FrontListener, build_acme_frontend, build_http_frontends,
    fill_middleware_table, routing_order,
};
use crate::util::fuzzy::closest_match;

/// The request to resolve, as described by the caller.
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    /// Absolute URL: scheme (`http` or `https`), host, path and query.
    pub url: String,
    /// `GET` when absent.
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The address the client connects from. Rules on the client address are
    /// not evaluated without it.
    #[serde(default)]
    pub client_ip: Option<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded to a backend.
    Proxied,
    /// Answered with a redirect.
    Redirected,
    /// A route matched, but the request is answered with an error before
    /// reaching a backend.
    Rejected,
    /// Served by the ACME HTTP-01 challenge responder.
    AcmeChallenge,
    /// No route matches.
    NoRoute,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub outcome: Outcome,
    /// The status sozune answers with itself; `None` when a backend answers.
    pub status: Option<u16>,
    pub summary: String,
    pub route: Option<RouteSummary>,
    pub candidates: Vec<Candidate>,
    pub pipeline: Vec<Step>,
    pub backends: Vec<BackendState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteSummary {
    pub id: String,
    pub name: String,
    pub source: Option<String>,
    pub priority: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub name: String,
    pub priority: i32,
    pub verdict: Verdict,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Would match, but a route tried before it matches first.
    Shadowed,
    /// Its host matches, its path or method does not.
    Rejected,
    /// Refused by Sōzu: never live.
    Refused,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub verdict: StepVerdict,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepVerdict {
    Pass,
    Blocked,
    /// Applies, but its decision depends on live state.
    Applies,
    NotEvaluated,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackendState {
    pub address: String,
    pub healthy: bool,
    pub reason: Option<String>,
}

/// What the resolver reads: the same state the proxy routes from.
pub struct ResolveInputs<'a> {
    /// Every stored route: what the middleware server builds its table from.
    pub storage: &'a BTreeMap<String, Entrypoint>,
    /// The routes the last reload installed in Sōzu: what Sōzu routes on.
    pub live: &'a BTreeMap<String, Entrypoint>,
    pub unhealthy: &'a UnhealthyMap,
    pub acme_enabled: bool,
    pub trusted_proxies: &'a TrustedProxies,
    /// The WASM plugins the proxy loaded: a route's chain holds them at their
    /// place, and leaves out the ones it names but the proxy does not have.
    pub plugins: &'a PluginRegistry,
}

/// The request reduced to what routing looks at.
struct Target {
    listener: FrontListener,
    host: String,
    /// Path and query, as Sōzu matches it.
    path_and_query: String,
    /// Path alone, as the middleware server matches it.
    path: String,
    method: String,
}

impl Target {
    fn parse(request: &ResolveRequest) -> Result<Self, String> {
        let url = url::Url::parse(&request.url)
            .map_err(|e| format!("`{}` is not an absolute URL: {e}", request.url))?;
        let listener = match url.scheme() {
            "http" => FrontListener::Http,
            "https" => FrontListener::Https,
            other => return Err(format!("unsupported scheme `{other}`, use http or https")),
        };
        let host = url
            .host_str()
            .ok_or_else(|| format!("`{}` has no host", request.url))?
            .to_ascii_lowercase();
        let path = url.path().to_string();
        let path_and_query = match url.query() {
            Some(query) => format!("{path}?{query}"),
            None => path.clone(),
        };
        let method = request
            .method
            .as_deref()
            .unwrap_or("GET")
            .to_ascii_uppercase();
        Ok(Self {
            listener,
            host,
            path_and_query,
            path,
            method,
        })
    }
}

/// What Sōzu's router decided, copied out of it: the router itself holds `Rc`s
/// and cannot live across an await.
struct SozuDecision {
    /// Cluster of the frontend that matched.
    cluster_id: Option<String>,
    redirect: RedirectPolicy,
    required_auth: bool,
    /// Routes Sōzu refused, with its reason.
    refused: BTreeMap<String, String>,
}

pub async fn resolve(
    inputs: &ResolveInputs<'_>,
    request: &ResolveRequest,
) -> Result<Resolution, String> {
    let target = Target::parse(request)?;
    // Built once up front so an invalid method or header is a 400 whatever
    // route the request would take.
    synthetic_request(&target, request)?;
    let decision = route_with_sozu(inputs, &target);
    let candidates = explain_candidates(inputs, &target, &decision);

    let Some(cluster_id) = decision.cluster_id.clone() else {
        return Ok(no_route(inputs, &target, candidates));
    };

    if cluster_id == ACME_CHALLENGE_CLUSTER {
        return Ok(Resolution {
            outcome: Outcome::AcmeChallenge,
            status: None,
            summary: "served by the ACME HTTP-01 challenge responder".to_string(),
            route: None,
            candidates,
            pipeline: Vec::new(),
            backends: Vec::new(),
        });
    }

    let Some(entrypoint) = inputs.live.get(&cluster_id) else {
        return Err(format!("Sōzu matched `{cluster_id}`, which is not live"));
    };

    let mut resolution = Resolution {
        outcome: Outcome::Proxied,
        status: None,
        summary: format!("proxied by route `{}`", entrypoint.name),
        route: Some(route_summary(entrypoint)),
        candidates,
        pipeline: Vec::new(),
        backends: Vec::new(),
    };

    if let Some(answer) = frontend_answer(&decision, entrypoint, &target, request) {
        resolution.outcome = answer.0;
        resolution.status = Some(answer.1);
        resolution.summary = answer.2;
        return Ok(resolution);
    }
    // Credentials are present but never checked here: the resolver must not
    // tell a read-only user which password works.
    let credentials_unchecked = decision.required_auth;
    if credentials_unchecked {
        resolution.pipeline.push(step(
            "basic-auth",
            StepVerdict::NotEvaluated,
            Some("credentials are not checked here: wrong ones get a 401"),
        ));
    }

    let served_by = if middleware::needs_middleware(&entrypoint.config) {
        match run_middleware(inputs, &target, request, &mut resolution.pipeline).await? {
            MiddlewareResult::Continue(id) => id,
            MiddlewareResult::Stopped { status, summary } => {
                resolution.outcome = Outcome::Rejected;
                resolution.status = Some(status);
                resolution.summary = summary;
                return Ok(resolution);
            }
        }
    } else {
        cluster_id
    };

    // The route Sōzu picked is described as installed, which can lag behind
    // storage until the next reload. One the middleware picked instead comes
    // from its table, built from storage.
    let served = if served_by == entrypoint.id {
        entrypoint
    } else {
        match inputs
            .storage
            .get(&served_by)
            .or_else(|| inputs.live.get(&served_by))
        {
            Some(served) => served,
            None => {
                return Err(format!(
                    "the middleware picked `{served_by}`, which is not stored"
                ));
            }
        }
    };
    if served.id != entrypoint.id {
        resolution.summary = format!(
            "matched route `{}` in Sōzu, then served by `{}` in the middleware",
            entrypoint.name, served.name
        );
        resolution.route = Some(route_summary(served));
    }
    if credentials_unchecked {
        resolution.summary = format!("{} if the credentials are valid", resolution.summary);
    }
    resolution.backends = backend_states(served, inputs.unhealthy);
    if resolution.backends.is_empty() {
        // Sōzu answers 503 for a cluster with nothing behind it; the
        // middleware server answers 502 when its route has no backend.
        let status = if middleware::needs_middleware(&served.config) {
            502
        } else {
            503
        };
        resolution.outcome = Outcome::Rejected;
        resolution.status = Some(status);
        resolution.summary = format!("route `{}` has no backend", served.name);
    } else if resolution.backends.iter().all(|b| !b.healthy) {
        resolution.summary = format!(
            "{}, but every backend is failing its health check",
            resolution.summary
        );
    }
    Ok(resolution)
}

fn route_summary(entrypoint: &Entrypoint) -> RouteSummary {
    RouteSummary {
        id: entrypoint.id.clone(),
        name: entrypoint.name.clone(),
        source: entrypoint.source.clone(),
        priority: entrypoint.config.priority,
    }
}

/// Builds the router the target's listener holds from the routes the last
/// reload installed, and asks it. Routes go in as a reload sends them: by `routing_order`, ACME challenge frontends first on
/// the HTTP listener, and a route Sōzu refuses any frontend of is taken out
/// whole, as the reload rolls it back.
fn route_with_sozu(inputs: &ResolveInputs<'_>, target: &Target) -> SozuDecision {
    let mut router = Router::new();
    let mut refused = BTreeMap::new();
    let any_address = SocketAddress::new_v4(0, 0, 0, 0, 0);

    for (cluster_id, entrypoint) in routing_order(inputs.live) {
        if entrypoint.protocol != Protocol::Http {
            continue;
        }
        if target.listener == FrontListener::Http && inputs.acme_enabled {
            for hostname in &entrypoint.config.hostnames {
                // Refused when another route already sent it: same as a reload.
                if let Ok(front) = build_acme_frontend(hostname, 0).to_frontend() {
                    let _ = router.add_http_front(&front);
                }
            }
        }

        let mut added = Vec::new();
        for (listener, front) in build_http_frontends(cluster_id, entrypoint, 0, any_address) {
            if listener != target.listener {
                continue;
            }
            let outcome = front
                .to_frontend()
                .map_err(|e| e.to_string())
                .and_then(|front| match router.add_http_front(&front) {
                    Ok(()) => Ok(front),
                    Err(e) => Err(e.to_string()),
                });
            match outcome {
                Ok(front) => added.push(front),
                Err(reason) => {
                    for front in &added {
                        let _ = router.remove_http_front(front);
                    }
                    refused.insert(cluster_id.clone(), reason);
                    break;
                }
            }
        }
    }

    let method = Method::new(target.method.as_bytes());
    match router.lookup(&target.host, &target.path_and_query, &method) {
        Ok(result) => SozuDecision {
            cluster_id: result.cluster_id.map(|id| id.to_string()),
            redirect: result.redirect,
            required_auth: result.required_auth,
            refused,
        },
        Err(_) => SozuDecision {
            cluster_id: None,
            redirect: RedirectPolicy::Forward,
            required_auth: false,
            refused,
        },
    }
}

/// Every other route whose hostname matches, and why it does not serve the
/// request.
fn explain_candidates(
    inputs: &ResolveInputs<'_>,
    target: &Target,
    decision: &SozuDecision,
) -> Vec<Candidate> {
    let winner = decision
        .cluster_id
        .as_deref()
        .and_then(|id| inputs.live.get(id));
    let method = Method::new(target.method.as_bytes());
    let any_address = SocketAddress::new_v4(0, 0, 0, 0, 0);
    let mut candidates = Vec::new();

    for (cluster_id, entrypoint) in routing_order(inputs.storage) {
        if entrypoint.protocol != Protocol::Http
            || decision.cluster_id.as_deref() == Some(cluster_id.as_str())
            || !hostnames_match(&entrypoint.config.hostnames, &target.host)
        {
            continue;
        }
        let candidate = |verdict, reason| Candidate {
            id: entrypoint.id.clone(),
            name: entrypoint.name.clone(),
            priority: entrypoint.config.priority,
            verdict,
            reason,
        };

        if let Some(reason) = decision.refused.get(cluster_id) {
            candidates.push(candidate(
                Verdict::Refused,
                format!("refused by Sōzu, so never live: {reason}"),
            ));
            continue;
        }
        if inputs.live.get(cluster_id) != Some(entrypoint) {
            candidates.push(candidate(
                Verdict::Refused,
                "stored, but not live in Sōzu: refused on the last reload, or not applied yet"
                    .to_string(),
            ));
            continue;
        }
        if target.listener == FrontListener::Https && !entrypoint.config.tls {
            candidates.push(candidate(
                Verdict::Rejected,
                "not served over HTTPS: tls is off for this route".to_string(),
            ));
            continue;
        }

        let fronts: Vec<_> = build_http_frontends(cluster_id, entrypoint, 0, any_address)
            .into_iter()
            .filter(|(listener, _)| *listener == target.listener)
            .map(|(_, front)| front)
            .filter(|front| host_matches(&front.hostname, &target.host))
            .collect();
        let path_ok = |front: &sozu_command_lib::proto::command::RequestHttpFrontend| {
            PathRule::from_config(front.path.clone()).is_some_and(|rule| {
                rule.matches(target.path_and_query.as_bytes()) != PathRuleResult::None
            })
        };
        let method_ok = |front: &sozu_command_lib::proto::command::RequestHttpFrontend| {
            MethodRule::new(front.method.clone()).matches(&method) != MethodRuleResult::None
        };

        if fronts.iter().any(|f| path_ok(f) && method_ok(f)) {
            let reason = match winner {
                Some(winner) => shadowed_reason(winner, entrypoint),
                None => "the ACME challenge path is served first".to_string(),
            };
            candidates.push(candidate(Verdict::Shadowed, reason));
        } else if fronts.iter().any(path_ok) {
            candidates.push(candidate(
                Verdict::Rejected,
                format!(
                    "method: {} is not one of {}",
                    target.method,
                    entrypoint.config.methods.join(", ")
                ),
            ));
        } else {
            candidates.push(candidate(
                Verdict::Rejected,
                format!(
                    "path: {} does not match `{}`",
                    describe_path(entrypoint),
                    target.path_and_query
                ),
            ));
        }
    }
    candidates
}

fn shadowed_reason(winner: &Entrypoint, loser: &Entrypoint) -> String {
    if winner.config.priority > loser.config.priority {
        format!(
            "matches too, but `{}` has a higher priority ({} > {})",
            winner.name, winner.config.priority, loser.config.priority
        )
    } else {
        format!(
            "matches too, but `{}` has the same priority ({}) and comes first by id; \
             set a priority to choose",
            winner.name, winner.config.priority
        )
    }
}

fn describe_path(entrypoint: &Entrypoint) -> String {
    match &entrypoint.config.path {
        None => "any path".to_string(),
        Some(path) => match path.rule_type {
            PathRuleType::Prefix => format!("prefix `{}`", path.value),
            PathRuleType::Exact => format!("exactly `{}`", path.value),
            PathRuleType::Regex => format!("regex `{}`", path.value),
        },
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    pattern
        .parse::<DomainRule>()
        .is_ok_and(|rule| rule.matches(host.as_bytes()))
}

fn hostnames_match(hostnames: &[String], host: &str) -> bool {
    hostnames.iter().any(|pattern| host_matches(pattern, host))
}

/// Answers Sōzu gives at the frontend, before anything is forwarded: a
/// redirect, or a 401 for basic auth. `None` when the request goes on.
fn frontend_answer(
    decision: &SozuDecision,
    entrypoint: &Entrypoint,
    target: &Target,
    request: &ResolveRequest,
) -> Option<(Outcome, u16, String)> {
    let redirect = |status: u16| {
        Some((
            Outcome::Redirected,
            status,
            format!("redirected ({status}) by route `{}`", entrypoint.name),
        ))
    };
    match decision.redirect {
        RedirectPolicy::Permanent => return redirect(301),
        RedirectPolicy::Found => return redirect(302),
        RedirectPolicy::PermanentRedirect => return redirect(308),
        RedirectPolicy::Unauthorized => {
            return Some((
                Outcome::Rejected,
                401,
                format!("route `{}` answers 401 to every request", entrypoint.name),
            ));
        }
        RedirectPolicy::Forward => {}
    }
    if entrypoint.config.https_redirect && target.listener == FrontListener::Http {
        return Some((
            Outcome::Redirected,
            301,
            format!("redirected to HTTPS by route `{}`", entrypoint.name),
        ));
    }
    let has_credentials = request
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("authorization"));
    if decision.required_auth && !has_credentials {
        return Some((
            Outcome::Rejected,
            401,
            format!(
                "route `{}` requires basic auth credentials (add an Authorization header; \
                 they are not checked here)",
                entrypoint.name
            ),
        ));
    }
    None
}

enum MiddlewareResult {
    /// The cluster the middleware serves the request with.
    Continue(String),
    Stopped {
        status: u16,
        summary: String,
    },
}

const NEEDS_CLIENT_IP: &str = "depends on the client address: pass `client_ip`";

/// Middlewares that decide from the request alone, and can be run here.
const EVALUATED: [&str; 2] = ["ip-allow-list", "request-match"];

/// Finds the route the middleware server would pick, and walks its chain.
async fn run_middleware(
    inputs: &ResolveInputs<'_>,
    target: &Target,
    request: &ResolveRequest,
    pipeline: &mut Vec<Step>,
) -> Result<MiddlewareResult, String> {
    let mut table = MiddlewareRouteTable::default();
    fill_middleware_table(
        &mut table,
        inputs.storage,
        inputs.plugins,
        inputs.trusted_proxies,
    );
    let Some(route) = table.get_route(&target.host, &target.path) else {
        return Ok(MiddlewareResult::Stopped {
            status: 502,
            summary: format!(
                "Sōzu sends the request to the middleware, which finds no route for \
                 `{}` `{}`",
                target.host, target.path
            ),
        });
    };
    let Some(entrypoint) = inputs.storage.get(&route.cluster_id) else {
        return Ok(MiddlewareResult::Continue(route.cluster_id.clone()));
    };

    let (mut ctx, mut synthetic) = synthetic_request(target, request)?;
    let mut stopped = None;
    for mw in &route.middlewares {
        let name = mw.name();
        if stopped.is_some() {
            pipeline.push(step(name, StepVerdict::NotEvaluated, Some("not reached")));
            continue;
        }
        if !EVALUATED.contains(&name) {
            pipeline.push(step(name, StepVerdict::Applies, applies_detail(name)));
            continue;
        }
        let config = &entrypoint.config;
        let client_unknown = request.client_ip.is_none();
        if client_unknown && name == "ip-allow-list" {
            pipeline.push(step(name, StepVerdict::NotEvaluated, Some(NEEDS_CLIENT_IP)));
            continue;
        }
        // The client-address condition cannot be decided, but header and query
        // conditions still can: a request failing them is a 404 whatever its
        // address.
        let partial =
            client_unknown && name == "request-match" && !config.match_client_ip.is_empty();
        let flow = if partial {
            if config.match_headers.is_empty() && config.match_query.is_empty() {
                pipeline.push(step(name, StepVerdict::NotEvaluated, Some(NEEDS_CLIENT_IP)));
                continue;
            }
            RequestMatchMiddleware::new(
                config.match_headers.clone(),
                config.match_query.clone(),
                None,
                inputs.trusted_proxies.clone(),
            )
            .on_request(&mut ctx, &mut synthetic)
            .await
        } else {
            mw.on_request(&mut ctx, &mut synthetic).await
        };
        match flow {
            Flow::Continue if partial => pipeline.push(step(
                name,
                StepVerdict::NotEvaluated,
                Some("headers and query match; the client address needs `client_ip`"),
            )),
            Flow::Continue => pipeline.push(step(name, StepVerdict::Pass, None)),
            Flow::ShortCircuit(response) => {
                let status = response.status().as_u16();
                pipeline.push(step(
                    name,
                    StepVerdict::Blocked,
                    Some(format!("answers {status}").as_str()),
                ));
                stopped = Some(MiddlewareResult::Stopped {
                    status,
                    summary: format!(
                        "route `{}` matched, but `{name}` answers {status}",
                        entrypoint.name
                    ),
                });
            }
        }
    }
    if let Some(timeout) = entrypoint.config.backend_timeout {
        pipeline.push(step(
            "backend-timeout",
            StepVerdict::Applies,
            Some(&format!("{timeout} ms")),
        ));
    }
    if let Some(retry) = entrypoint.config.retry.as_ref().filter(|r| r.attempts > 1) {
        pipeline.push(step(
            "retry",
            StepVerdict::Applies,
            Some(&format!("{} attempts", retry.attempts)),
        ));
    }
    if entrypoint.config.circuit_breaker.is_some() {
        pipeline.push(step("circuit-breaker", StepVerdict::Applies, None));
    }
    Ok(stopped.unwrap_or_else(|| MiddlewareResult::Continue(route.cluster_id.clone())))
}

fn step(name: &str, verdict: StepVerdict, detail: Option<&str>) -> Step {
    Step {
        name: name.to_string(),
        verdict,
        detail: detail.map(str::to_string),
    }
}

fn applies_detail(name: &str) -> Option<&'static str> {
    match name {
        "forward-auth" => Some("asks the auth server, not called here"),
        "rate-limit" => Some("depends on the client's recent requests"),
        "in-flight-req" => Some("depends on the client's requests in progress"),
        "compress" => Some("applies to the response"),
        // A WASM plugin, named after its declaration.
        _ => Some("plugin, not run here"),
    }
}

/// The request as the middleware server receives it: from Sōzu on loopback,
/// with the client's address appended to `X-Forwarded-For` the way Sōzu does.
fn synthetic_request(
    target: &Target,
    request: &ResolveRequest,
) -> Result<(RequestCtx, axum::http::Request<Body>), String> {
    let mut builder = axum::http::Request::builder()
        .method(target.method.as_str())
        .uri(target.path_and_query.as_str())
        .header("host", target.host.as_str());
    let mut forwarded_for = None;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("x-forwarded-for") {
            forwarded_for = Some(value.clone());
        } else {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    if let Some(client) = request.client_ip {
        forwarded_for = Some(match forwarded_for {
            Some(existing) => format!("{existing}, {client}"),
            None => client.to_string(),
        });
    }
    if let Some(value) = forwarded_for {
        builder = builder.header("x-forwarded-for", value);
    }
    // An invalid method or header would otherwise be dropped, and the
    // middlewares would judge a different request than the one described.
    let synthetic = builder
        .body(Body::empty())
        .map_err(|e| format!("the request cannot be built: {e}"))?;
    let ctx = RequestCtx {
        host: target.host.clone(),
        client_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        is_tls: target.listener == FrontListener::Https,
        method: synthetic.method().clone(),
        path: target.path.clone(),
        client_encoding: None,
        pending_response_headers: Vec::new(),
        in_flight_guards: Vec::new(),
    };
    Ok((ctx, synthetic))
}

fn backend_states(entrypoint: &Entrypoint, unhealthy: &UnhealthyMap) -> Vec<BackendState> {
    entrypoint
        .backends
        .iter()
        .map(|backend| {
            let address = backend.to_string();
            let reason = unhealthy.get(&address).map(|r| r.message.clone());
            BackendState {
                healthy: reason.is_none(),
                address,
                reason,
            }
        })
        .collect()
}

fn no_route(inputs: &ResolveInputs<'_>, target: &Target, candidates: Vec<Candidate>) -> Resolution {
    let known: BTreeSet<&str> = inputs
        .storage
        .values()
        .filter(|ep| ep.protocol == Protocol::Http)
        .flat_map(|ep| ep.config.hostnames.iter().map(String::as_str))
        .collect();
    let known: Vec<&str> = known.into_iter().collect();
    let summary = if candidates.is_empty() {
        match closest_match(&target.host, &known, 3) {
            Some(suggestion) => format!(
                "no route for host `{}`; did you mean `{suggestion}`?",
                target.host
            ),
            None => format!("no route for host `{}`", target.host),
        }
    } else {
        format!(
            "routes exist for host `{}`, but none matches this path and method",
            target.host
        )
    };
    Resolution {
        outcome: Outcome::NoRoute,
        status: Some(404),
        summary,
        route: None,
        candidates,
        pipeline: Vec::new(),
        backends: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A route as the providers store it, with only what a test sets.
    fn route(id: &str, hosts: &[&str], config: serde_json::Value) -> Entrypoint {
        let mut base = serde_json::json!({
            "hostnames": hosts,
            "path": null,
            "tls": false,
            "strip_prefix": false,
            "https_redirect": false,
            "priority": 0,
            "auth": null,
            "headers": []
        });
        for (key, value) in config.as_object().unwrap() {
            base[key] = value.clone();
        }
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": id,
            "backends": [{ "address": "10.0.0.1", "port": 80, "weight": 100 }],
            "protocol": "Http",
            "config": base
        }))
        .unwrap()
    }

    fn prefix(value: &str) -> serde_json::Value {
        serde_json::json!({ "rule_type": "Prefix", "value": value })
    }

    fn storage(routes: Vec<Entrypoint>) -> BTreeMap<String, Entrypoint> {
        routes.into_iter().map(|r| (r.id.clone(), r)).collect()
    }

    async fn resolve_in(routes: Vec<Entrypoint>, request: serde_json::Value) -> Resolution {
        let storage = storage(routes);
        let unhealthy = UnhealthyMap::new();
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &storage,
            live: &storage,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest = serde_json::from_value(request).unwrap();
        resolve(&inputs, &request).await.unwrap()
    }

    fn get(url: &str) -> serde_json::Value {
        serde_json::json!({ "url": url })
    }

    fn served_by(resolution: &Resolution) -> Option<&str> {
        resolution.route.as_ref().map(|r| r.id.as_str())
    }

    #[tokio::test]
    async fn the_higher_priority_route_wins_and_the_other_is_shadowed() {
        let resolution = resolve_in(
            vec![
                route("web", &["app.example.com"], serde_json::json!({})),
                route(
                    "api",
                    &["app.example.com"],
                    serde_json::json!({ "path": prefix("/api"), "priority": 10 }),
                ),
            ],
            get("http://app.example.com/api/users"),
        )
        .await;

        assert_eq!(resolution.outcome, Outcome::Proxied);
        assert_eq!(served_by(&resolution), Some("api"));
        assert_eq!(resolution.candidates.len(), 1);
        assert_eq!(resolution.candidates[0].verdict, Verdict::Shadowed);
        assert!(resolution.candidates[0].reason.contains("higher priority"));
    }

    /// Sōzu tries routes of equal priority by id, first match wins: a `/`
    /// route sorting first captures `/api/...` from an `/api` route of the
    /// same priority. The answer must say so rather than pretend one was
    /// preferred on purpose.
    #[tokio::test]
    async fn at_equal_priority_the_first_id_wins_even_over_a_longer_path() {
        let resolution = resolve_in(
            vec![
                route("a-web", &["app.example.com"], serde_json::json!({})),
                route(
                    "b-api",
                    &["app.example.com"],
                    serde_json::json!({ "path": prefix("/api") }),
                ),
            ],
            get("http://app.example.com/api/users"),
        )
        .await;

        assert_eq!(served_by(&resolution), Some("a-web"));
        assert_eq!(resolution.candidates[0].verdict, Verdict::Shadowed);
        assert!(resolution.candidates[0].reason.contains("same priority"));
    }

    /// Two routes claiming the same host, path and method: Sōzu refuses the
    /// second frontend, so it never goes live.
    #[tokio::test]
    async fn a_duplicate_route_is_refused() {
        let resolution = resolve_in(
            vec![
                route("b-web", &["app.example.com"], serde_json::json!({})),
                route("a-web", &["app.example.com"], serde_json::json!({})),
            ],
            get("http://app.example.com/"),
        )
        .await;

        assert_eq!(served_by(&resolution), Some("a-web"));
        assert_eq!(resolution.candidates[0].id, "b-web");
        assert_eq!(resolution.candidates[0].verdict, Verdict::Refused);
    }

    #[tokio::test]
    async fn a_route_on_another_path_is_rejected_by_its_path() {
        let resolution = resolve_in(
            vec![
                route("web", &["app.example.com"], serde_json::json!({})),
                route(
                    "admin",
                    &["app.example.com"],
                    serde_json::json!({ "path": prefix("/admin"), "priority": 5 }),
                ),
            ],
            get("http://app.example.com/shop"),
        )
        .await;

        assert_eq!(served_by(&resolution), Some("web"));
        assert_eq!(resolution.candidates[0].verdict, Verdict::Rejected);
        assert!(resolution.candidates[0].reason.starts_with("path:"));
    }

    #[tokio::test]
    async fn an_unknown_host_suggests_the_closest_one() {
        let resolution = resolve_in(
            vec![route("web", &["example.com"], serde_json::json!({}))],
            get("http://exmple.com/"),
        )
        .await;

        assert_eq!(resolution.outcome, Outcome::NoRoute);
        assert_eq!(resolution.status, Some(404));
        assert!(resolution.summary.contains("did you mean `example.com`"));
    }

    #[tokio::test]
    async fn a_route_without_tls_is_not_served_over_https() {
        let resolution = resolve_in(
            vec![route("web", &["app.example.com"], serde_json::json!({}))],
            get("https://app.example.com/"),
        )
        .await;

        assert_eq!(resolution.outcome, Outcome::NoRoute);
        assert!(resolution.candidates[0].reason.contains("HTTPS"));
    }

    #[tokio::test]
    async fn a_wildcard_host_serves_one_label() {
        let routes = || vec![route("wild", &["*.example.com"], serde_json::json!({}))];

        let one_label = resolve_in(routes(), get("http://shop.example.com/")).await;
        let two_labels = resolve_in(routes(), get("http://a.shop.example.com/")).await;

        assert_eq!(served_by(&one_label), Some("wild"));
        assert_eq!(two_labels.outcome, Outcome::NoRoute);
    }

    #[tokio::test]
    async fn an_https_redirect_answers_before_the_backend() {
        let resolution = resolve_in(
            vec![route(
                "web",
                &["app.example.com"],
                serde_json::json!({ "tls": true, "https_redirect": true }),
            )],
            get("http://app.example.com/"),
        )
        .await;

        assert_eq!(resolution.outcome, Outcome::Redirected);
        assert_eq!(resolution.status, Some(301));
    }

    /// A header condition is checked after Sōzu picked the route: a request
    /// without it gets a 404 from that route, not another route's answer.
    #[tokio::test]
    async fn a_failed_header_condition_answers_404_without_trying_another_route() {
        let routes = || {
            vec![
                route("web", &["app.example.com"], serde_json::json!({})),
                route(
                    "tenant",
                    &["app.example.com"],
                    serde_json::json!({
                        "priority": 10,
                        "match_headers": [{ "key": "X-Tenant", "value": "acme" }]
                    }),
                ),
            ]
        };

        let with_header = resolve_in(
            routes(),
            serde_json::json!({ "url": "http://app.example.com/", "headers": { "X-Tenant": "acme" } }),
        )
        .await;
        let without = resolve_in(routes(), get("http://app.example.com/")).await;

        assert_eq!(with_header.outcome, Outcome::Proxied);
        assert_eq!(served_by(&with_header), Some("tenant"));
        assert_eq!(without.outcome, Outcome::Rejected);
        assert_eq!(without.status, Some(404));
        assert_eq!(served_by(&without), Some("tenant"));
        assert!(
            without
                .pipeline
                .iter()
                .any(|s| s.name == "request-match" && s.verdict == StepVerdict::Blocked)
        );
    }

    #[tokio::test]
    async fn an_ip_allow_list_is_evaluated_only_with_a_client_address() {
        let routes = || {
            vec![route(
                "internal",
                &["app.example.com"],
                serde_json::json!({ "ip_allow_list": ["10.0.0.0/8"] }),
            )]
        };
        let with_ip =
            |ip: &str| serde_json::json!({ "url": "http://app.example.com/", "client_ip": ip });

        let inside = resolve_in(routes(), with_ip("10.1.2.3")).await;
        let outside = resolve_in(routes(), with_ip("203.0.113.7")).await;
        let unknown = resolve_in(routes(), get("http://app.example.com/")).await;

        assert_eq!(inside.outcome, Outcome::Proxied);
        assert_eq!(outside.status, Some(403));
        assert_eq!(unknown.outcome, Outcome::Proxied);
        assert_eq!(unknown.pipeline[0].verdict, StepVerdict::NotEvaluated);
    }

    /// A forged `X-Forwarded-For` must not get past the allow-list here any
    /// more than it does in the proxy: the address Sōzu appends is the one
    /// that counts.
    #[tokio::test]
    async fn a_forged_forwarded_for_does_not_pass_the_allow_list() {
        let resolution = resolve_in(
            vec![route(
                "internal",
                &["app.example.com"],
                serde_json::json!({ "ip_allow_list": ["10.0.0.0/8"] }),
            )],
            serde_json::json!({
                "url": "http://app.example.com/",
                "headers": { "X-Forwarded-For": "10.0.0.1" },
                "client_ip": "203.0.113.7"
            }),
        )
        .await;

        assert_eq!(resolution.status, Some(403));
    }

    /// Without `client_ip`, a route matching on client address *and* a
    /// header still has its header checked: a request missing the header is
    /// a 404 whatever its address.
    #[tokio::test]
    async fn header_conditions_are_checked_even_without_a_client_address() {
        let routes = || {
            vec![route(
                "tenant",
                &["app.example.com"],
                serde_json::json!({
                    "match_headers": [{ "key": "X-Tenant", "value": "acme" }],
                    "match_client_ip": ["10.0.0.0/8"]
                }),
            )]
        };

        let without_header = resolve_in(routes(), get("http://app.example.com/")).await;
        let with_header = resolve_in(
            routes(),
            serde_json::json!({ "url": "http://app.example.com/", "headers": { "X-Tenant": "acme" } }),
        )
        .await;

        assert_eq!(without_header.status, Some(404));
        assert_eq!(with_header.outcome, Outcome::Proxied);
        assert_eq!(with_header.pipeline[0].verdict, StepVerdict::NotEvaluated);
    }

    /// The proxy skips a plugin it never loaded; the resolver must not
    /// report it as running.
    #[tokio::test]
    async fn a_plugin_the_proxy_did_not_load_is_not_in_the_pipeline() {
        let resolution = resolve_in(
            vec![route(
                "web",
                &["app.example.com"],
                serde_json::json!({ "plugins": ["missing"], "compress": true }),
            )],
            get("http://app.example.com/"),
        )
        .await;

        let names: Vec<&str> = resolution
            .pipeline
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, vec!["compress"]);
    }

    /// Basic-auth credentials are never checked here, or a read-only user
    /// could test passwords with it: with credentials the answer says so, and
    /// without them it is the 401 Sōzu gives.
    #[tokio::test]
    async fn basic_auth_credentials_are_reported_as_unchecked() {
        let routes = || {
            vec![route(
                "private",
                &["app.example.com"],
                serde_json::json!({ "auth": { "basic": [{
                    "username": "alice",
                    "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
                }] } }),
            )]
        };

        let anonymous = resolve_in(routes(), get("http://app.example.com/")).await;
        let with_credentials = resolve_in(
            routes(),
            serde_json::json!({ "url": "http://app.example.com/", "headers": { "Authorization": "Basic d3Jvbmc6d3Jvbmc=" } }),
        )
        .await;

        assert_eq!(anonymous.status, Some(401));
        assert_eq!(with_credentials.pipeline[0].name, "basic-auth");
        assert_eq!(
            with_credentials.pipeline[0].verdict,
            StepVerdict::NotEvaluated
        );
        assert!(
            with_credentials
                .summary
                .ends_with("if the credentials are valid")
        );
    }

    /// A route stored but missing from what the last reload installed is not
    /// served, whatever its priority: the answer must not name it.
    #[tokio::test]
    async fn a_stored_route_that_is_not_live_is_not_announced() {
        let storage = storage(vec![
            route("web", &["app.example.com"], serde_json::json!({})),
            route(
                "api",
                &["app.example.com"],
                serde_json::json!({ "path": prefix("/api"), "priority": 10 }),
            ),
        ]);
        let mut live = storage.clone();
        live.remove("api");
        let unhealthy = UnhealthyMap::new();
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &storage,
            live: &live,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest =
            serde_json::from_value(get("http://app.example.com/api/users")).unwrap();

        let resolution = resolve(&inputs, &request).await.unwrap();

        assert_eq!(served_by(&resolution), Some("web"));
        assert_eq!(resolution.candidates[0].id, "api");
        assert_eq!(resolution.candidates[0].verdict, Verdict::Refused);
    }

    /// Until the next reload, Sōzu serves the route as it was installed: a
    /// change still waiting in storage must not be described as live.
    #[tokio::test]
    async fn the_selected_route_is_described_as_installed() {
        let live = storage(vec![route(
            "web",
            &["app.example.com"],
            serde_json::json!({}),
        )]);
        let mut stored = live.clone();
        stored.get_mut("web").unwrap().backends[0].port = 9999;
        let unhealthy = UnhealthyMap::new();
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &stored,
            live: &live,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest =
            serde_json::from_value(get("http://app.example.com/")).unwrap();

        let resolution = resolve(&inputs, &request).await.unwrap();

        assert_eq!(resolution.backends[0].address, "10.0.0.1:80");
    }

    /// A header the proxy could never receive must not be dropped and the
    /// rest judged without it.
    #[tokio::test]
    async fn an_invalid_header_is_an_error() {
        let storage = storage(vec![route(
            "web",
            &["app.example.com"],
            serde_json::json!({}),
        )]);
        let unhealthy = UnhealthyMap::new();
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &storage,
            live: &storage,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest = serde_json::from_value(serde_json::json!({
            "url": "http://app.example.com/",
            "headers": { "bad header": "x" }
        }))
        .unwrap();

        assert!(resolve(&inputs, &request).await.is_err());
    }

    /// A route with no backend is answered by whoever holds it: Sōzu with a
    /// 503, the middleware server with a 502.
    #[tokio::test]
    async fn a_route_without_backends_gets_the_status_of_whoever_answers() {
        let empty = |config: serde_json::Value| {
            let mut ep = route("web", &["app.example.com"], config);
            ep.backends.clear();
            ep
        };

        let direct = resolve_in(
            vec![empty(serde_json::json!({}))],
            get("http://app.example.com/"),
        )
        .await;
        let through_middleware = resolve_in(
            vec![empty(serde_json::json!({ "compress": true }))],
            get("http://app.example.com/"),
        )
        .await;

        assert_eq!(direct.status, Some(503));
        assert_eq!(through_middleware.status, Some(502));
    }

    #[tokio::test]
    async fn an_unhealthy_backend_is_reported() {
        let storage = storage(vec![route(
            "web",
            &["app.example.com"],
            serde_json::json!({}),
        )]);
        let mut unhealthy = UnhealthyMap::new();
        unhealthy.insert(
            "10.0.0.1:80".to_string(),
            crate::proxy::health::UnhealthyReason {
                kind: crate::proxy::health::UnhealthyKind::ConnectionRefused,
                message: "connection refused".to_string(),
                since: 0,
                last_checked: 0,
            },
        );
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &storage,
            live: &storage,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest =
            serde_json::from_value(get("http://app.example.com/")).unwrap();

        let resolution = resolve(&inputs, &request).await.unwrap();

        assert!(!resolution.backends[0].healthy);
        assert_eq!(
            resolution.backends[0].reason.as_deref(),
            Some("connection refused")
        );
    }

    #[tokio::test]
    async fn an_invalid_url_is_an_error() {
        let storage = BTreeMap::new();
        let unhealthy = UnhealthyMap::new();
        let trusted = TrustedProxies::default();
        let inputs = ResolveInputs {
            storage: &storage,
            live: &storage,
            unhealthy: &unhealthy,
            acme_enabled: false,
            trusted_proxies: &trusted,
            plugins: &PluginRegistry::new(),
        };
        let request: ResolveRequest =
            serde_json::from_value(get("app.example.com/no-scheme")).unwrap();

        assert!(resolve(&inputs, &request).await.is_err());
    }
}
