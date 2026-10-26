//! Post-parse lint pass over `Entrypoint`s. Catches semantically-questionable
//! but syntactically-valid configurations that would otherwise route silently.
//!
//! - per-entrypoint checks: `lint_entrypoint`
//! - cross-cutting checks (collisions, global state): `lint_collection`,
//!   `lint_acme_without_tls`, `lint_unknown_resolvers`

use std::collections::HashMap;

use crate::config::{AcmeConfig, ProxyTimeouts};
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{Entrypoint, Protocol};
use crate::proxy::sozu::{header_predicate, listener_http_port, routes_on_query};

/// Run per-entrypoint lints. Called immediately after parsing one candidate.
/// `prefix` is `sozune.<protocol>.<service>.`, so labels name the full key.
pub fn lint_entrypoint(ep: &Entrypoint, prefix: &str, diagnostics: &mut Vec<Diagnostic>) {
    if ep.config.https_redirect && !ep.config.tls {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W016HttpsRedirectWithoutTls,
                "https_redirect=true but tls=false; clients will be redirected to a port that has no TLS listener for this hostname",
            )
            .with_label(format!("{prefix}httpsRedirect"))
            .with_hint("either set tls=true (and configure a certificate or ACME) or remove httpsRedirect"),
        );
    }

    if let Some(rl) = &ep.config.rate_limit
        && rl.burst < rl.average
    {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W017RateLimitBurstBelowAverage,
                format!(
                    "rate_limit.burst ({}) is lower than rate_limit.average ({}); the burst window is effectively disabled",
                    rl.burst, rl.average
                ),
            )
            .with_label(format!("{prefix}ratelimit.burst"))
            .with_hint("burst should be >= average; a typical setup is burst = 2x average for short spikes"),
        );
    }
}

/// A route's header conditions Sōzu routes on, as lowercase name and value.
type HeaderConditions = Vec<(String, String)>;

/// Where routes may meet: host, path and listener, an HTTP one by its port
/// (`Some`), the HTTPS one (`None`).
type RouteKey = (String, String, Option<u16>);

/// What tells a route from another on the same host and path: its priority,
/// and the header and query conditions Sōzu routes on.
struct RouteConditions {
    priority: i32,
    /// Whether it routes on methods, tried before a route on any method.
    on_methods: bool,
    headers: HeaderConditions,
    query: Vec<(String, String)>,
}

/// Run lints that need to look at the full set of routed entrypoints (e.g.
/// host+path collisions across services).
///
/// Routes on one host and path collide when a request can match both and
/// only one serves it. A route with header conditions does not collide with
/// one without: Sōzu tries it first, and the other serves the requests it
/// leaves. Two routes with header conditions collide unless one header
/// requires different values on each, which no request can carry at once.
/// Query conditions Sōzu routes on keep a route without any from colliding
/// with one with them, unless its priority is higher. Two routes with query
/// conditions collide: a request can repeat a parameter with each value.
pub fn lint_collection(entrypoints: &[(&str, &Entrypoint)]) -> Vec<(String, Diagnostic)> {
    let mut out = Vec::new();
    // Keyed by host, path and listener: routes on Gateway HTTP listeners of
    // different ports never meet there, though they can on HTTPS.
    let mut routes: HashMap<RouteKey, Vec<(&str, RouteConditions)>> = HashMap::new();

    for (cand_id, ep) in entrypoints {
        if !matches!(ep.protocol, Protocol::Http) {
            continue;
        }
        let path = ep
            .config
            .path
            .as_ref()
            .map(|p| p.value.clone())
            .unwrap_or_else(|| "/".into());
        // Only the conditions Sōzu routes on choose between routes; the others
        // answer 404 from the route Sōzu picked.
        let headers: HeaderConditions = ep
            .config
            .match_headers
            .iter()
            .filter(|c| header_predicate(c).is_some())
            // A regex can match the value another condition asks for: it
            // tells routes apart no better than the header's presence.
            .map(|c| {
                let value = if c.regex {
                    String::new()
                } else {
                    c.value.clone()
                };
                (c.key.to_ascii_lowercase(), value)
            })
            .collect();
        let query: Vec<(String, String)> = if routes_on_query(&ep.config) {
            ep.config
                .match_query
                .iter()
                .map(|c| (c.key.clone(), c.value.clone()))
                .collect()
        } else {
            Vec::new()
        };
        // The listeners it is served on.
        let mut listeners = Vec::new();
        if !ep.config.https_only {
            listeners.push(Some(listener_http_port(ep, 0)));
        }
        if ep.config.tls {
            listeners.push(None);
        }
        for host in &ep.config.hostnames {
            for listener in &listeners {
                routes
                    .entry((host.clone(), path.clone(), *listener))
                    .or_default()
                    .push((
                        cand_id,
                        RouteConditions {
                            priority: ep.config.priority,
                            on_methods: !ep.config.methods.is_empty(),
                            headers: headers.clone(),
                            query: query.clone(),
                        },
                    ));
            }
        }
    }

    // Each route's partners on every listener, merged: one diagnostic per
    // route, host and path. Ordered, so it reads the same at every run.
    let mut collisions: std::collections::BTreeMap<(String, String, String), (bool, Vec<String>)> =
        std::collections::BTreeMap::new();
    for ((host, path, _), declared) in &routes {
        for (cand_id, conditions) in declared {
            let others = declared
                .iter()
                .filter(|(other, other_conditions)| {
                    other != cand_id && conditions_overlap(conditions, other_conditions)
                })
                .map(|(other, _)| other.to_string());
            let entry = collisions
                .entry((cand_id.to_string(), host.clone(), path.clone()))
                .or_insert_with(|| {
                    (
                        conditions.headers.is_empty() && conditions.query.is_empty(),
                        Vec::new(),
                    )
                });
            entry.1.extend(others);
        }
    }
    for ((cand_id, host, path), (unconditional, mut others)) in collisions {
        if others.is_empty() {
            continue;
        }
        others.sort();
        others.dedup();
        let others_str = others.join(", ");
        let message = if unconditional {
            format!(
                "route ({host}{path}) is also defined by: {others_str}; only the highest-priority candidate is reachable"
            )
        } else {
            format!(
                "route ({host}{path}) is also defined by: {others_str}, with conditions a request can meet for both; the highest-priority candidate serves it"
            )
        };
        out.push((
            cand_id,
            Diagnostic::new(DiagnosticCode::W018RouteCollision, message)
            .with_label("host+path")
            .with_value(format!("{host}{path}"))
            .with_hint("set distinct hostnames or paths, or use `priority` to make the precedence explicit"),
        ));
    }

    out
}

/// Whether one request can match both routes and only one serves it.
fn conditions_overlap(a: &RouteConditions, b: &RouteConditions) -> bool {
    if !can_overlap(&a.headers, &b.headers) {
        return false;
    }
    // A route without query conditions is tried after one with them, unless
    // its priority is higher, or at equal priority it routes on methods and
    // the other does not, or has more header conditions. Two routes with query conditions always overlap: Sōzu
    // takes any occurrence of a parameter, and a request can repeat one with
    // each value (`?v=2&v=3`).
    if a.query.is_empty() != b.query.is_empty() {
        let (with, without) = if a.query.is_empty() { (b, a) } else { (a, b) };
        let rank = |r: &RouteConditions| (r.priority, r.on_methods, r.headers.len());
        return rank(without) > rank(with);
    }
    true
}

/// Whether one request can match both sets of header conditions, given that
/// Sōzu serves a route with conditions before any route without.
fn can_overlap(a: &[(String, String)], b: &[(String, String)]) -> bool {
    if a.is_empty() != b.is_empty() {
        return false;
    }
    !a.iter().any(|(key, value)| {
        !value.is_empty()
            && b.iter().any(|(other_key, other_value)| {
                other_key == key && !other_value.is_empty() && other_value != value
            })
    })
}

/// Returns a diagnostic if ACME is enabled but no entrypoint actually requests TLS.
pub fn lint_acme_without_tls(
    acme_enabled: bool,
    entrypoints: &[&Entrypoint],
) -> Option<Diagnostic> {
    if !acme_enabled {
        return None;
    }
    let any_tls = entrypoints
        .iter()
        .any(|ep| matches!(ep.protocol, Protocol::Http) && ep.config.tls);
    if any_tls {
        return None;
    }
    Some(
        Diagnostic::new(
            DiagnosticCode::W015AcmeWithoutTls,
            "ACME is enabled in the configuration but no entrypoint declares tls=true; no certificates will ever be requested",
        )
        .with_hint("either disable ACME (acme.enabled=false) or set tls=true on at least one HTTP entrypoint"),
    )
}

/// Flag each TLS route whose `acme.resolver` names a resolver that
/// `acme.resolvers` does not declare. Only checked with ACME enabled: without
/// it, no certificate is ever ordered and the label has no effect. Neither does
/// it on a route whose hostnames are all covered by `file_names`, the names of
/// the certificates loaded from files: ACME orders nothing for them.
pub fn lint_unknown_resolvers(
    acme: Option<&AcmeConfig>,
    file_names: &[String],
    entrypoints: &[(&str, &Entrypoint)],
) -> Vec<(String, Diagnostic)> {
    let Some(acme) = acme.filter(|a| a.enabled) else {
        return Vec::new();
    };
    let mut declared: Vec<&str> = acme.resolvers.keys().map(String::as_str).collect();
    declared.sort_unstable();
    let hint = if declared.is_empty() {
        "declare it under acme.resolvers in config.yaml, or remove the label to use HTTP-01 on challenge_port".to_string()
    } else {
        format!(
            "use one of the declared resolvers ({}), or declare it under acme.resolvers",
            declared.join(", ")
        )
    };

    entrypoints
        .iter()
        .filter(|(_, ep)| ep.config.tls)
        .filter(|(_, ep)| {
            !ep.config
                .hostnames
                .iter()
                .all(|host| crate::manual_certs::covered(file_names, host))
        })
        .filter_map(|(id, ep)| {
            let name = &ep.config.acme.as_ref()?.resolver;
            if acme.resolvers.contains_key(name) {
                return None;
            }
            Some((
                id.to_string(),
                Diagnostic::new(
                    DiagnosticCode::W029UnknownAcmeResolver,
                    format!(
                        "acme.resolver `{name}` is not declared under acme.resolvers; a certificate ordered through it fails"
                    ),
                )
                .with_label("acme.resolver")
                .with_value(name.clone())
                .with_hint(hint.clone()),
            ))
        })
        .collect()
}

/// Flag an HTTP route whose `backendTimeout` the listener cannot honour. The
/// HTTP and HTTPS listeners close a backend connection silent for
/// `proxy.timeouts.backend_idle` and a client connection silent for
/// `client_idle`, whatever the route sets: a request that waits longer for
/// its response is cut with a `504` before `backendTimeout` is reached.
pub fn lint_backend_timeouts(
    timeouts: &ProxyTimeouts,
    entrypoints: &[(&str, &Entrypoint)],
) -> Vec<(String, Diagnostic)> {
    use sozu_command_lib::config::{DEFAULT_BACK_TIMEOUT, DEFAULT_FRONT_TIMEOUT};
    let backend_idle = timeouts.backend_idle.unwrap_or(DEFAULT_BACK_TIMEOUT);
    let client_idle = timeouts.client_idle.unwrap_or(DEFAULT_FRONT_TIMEOUT);
    let (limit, field) = if backend_idle <= client_idle {
        (backend_idle, "backend_idle")
    } else {
        (client_idle, "client_idle")
    };

    entrypoints
        .iter()
        .filter(|(_, ep)| ep.protocol == Protocol::Http)
        .filter_map(|(id, ep)| {
            let ms = ep.config.backend_timeout?;
            if ms != 0 && ms <= u64::from(limit) * 1000 {
                return None;
            }
            let asked = if ms == 0 {
                "0 (no timeout)".to_string()
            } else {
                format!("{ms}ms")
            };
            Some((
                id.to_string(),
                Diagnostic::new(
                    DiagnosticCode::W030BackendTimeoutBeyondListener,
                    format!(
                        "backendTimeout is {asked}, but proxy.timeouts.{field} cuts a request left waiting {limit}s for its response first"
                    ),
                )
                .with_label("backendTimeout")
                .with_value(ms.to_string())
                .with_hint(
                    "raise proxy.timeouts.backend_idle and client_idle in config.yaml past the longest wait, or keep backendTimeout below them",
                ),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolverConfig;
    use crate::model::{
        Backend, EntrypointAcmeConfig, EntrypointConfig, LoadBalancer, MatchCondition, PathConfig,
        PathRuleType, RateLimitConfig,
    };

    fn ep(host: &str, path: Option<&str>, tls: bool, https_redirect: bool) -> Entrypoint {
        Entrypoint {
            id: "x".into(),
            backends: vec![Backend::new("10.0.0.1", 80)],
            name: "svc".into(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.into()],
                path: path.map(|p| PathConfig {
                    rule_type: PathRuleType::Prefix,
                    value: p.into(),
                }),
                tls,
                strip_prefix: false,
                add_prefix: None,
                https_redirect,
                https_redirect_port: None,
                https_only: false,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                rewrite_host: None,
                rewrite_path: None,
                rewrite: None,
                rewrite_port: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                request_timeout: None,
                health_check: None,
                load_balancer: LoadBalancer::default(),
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                sni: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: std::collections::BTreeMap::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                invalid_backends: false,
                ip_allow_list: Vec::new(),
            },
            source: None,
            candidates: Vec::new(),
        }
    }

    #[test]
    fn https_redirect_without_tls_emits_w016() {
        let ep = ep("example.com", None, false, true);
        let mut diags = Vec::new();
        lint_entrypoint(&ep, "sozune.http.svc.", &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W016HttpsRedirectWithoutTls);
    }

    #[test]
    fn https_redirect_with_tls_is_silent() {
        let ep = ep("example.com", None, true, true);
        let mut diags = Vec::new();
        lint_entrypoint(&ep, "sozune.http.svc.", &mut diags);
        assert!(diags.is_empty());
    }

    #[test]
    fn rate_limit_burst_below_average_emits_w017() {
        let mut ep = ep("example.com", None, false, false);
        ep.config.rate_limit = Some(RateLimitConfig {
            average: 100,
            burst: 50,
        });
        let mut diags = Vec::new();
        lint_entrypoint(&ep, "sozune.http.svc.", &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].code,
            DiagnosticCode::W017RateLimitBurstBelowAverage
        );
    }

    #[test]
    fn rate_limit_burst_equal_or_above_is_silent() {
        let mut ep = ep("example.com", None, false, false);
        ep.config.rate_limit = Some(RateLimitConfig {
            average: 100,
            burst: 100,
        });
        let mut diags = Vec::new();
        lint_entrypoint(&ep, "sozune.http.svc.", &mut diags);
        assert!(diags.is_empty());
    }

    #[test]
    fn collision_on_same_host_path_emits_w018_for_each_candidate() {
        let a = ep("example.com", Some("/api"), false, false);
        let b = ep("example.com", Some("/api"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|(_, d)| d.code == DiagnosticCode::W018RouteCollision)
        );
        let owners: Vec<&str> = out.iter().map(|(c, _)| c.as_str()).collect();
        assert!(owners.contains(&"cand-a"));
        assert!(owners.contains(&"cand-b"));
    }

    #[test]
    fn distinct_paths_do_not_collide() {
        let a = ep("example.com", Some("/api"), false, false);
        let b = ep("example.com", Some("/web"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert!(out.is_empty());
    }

    #[test]
    fn distinct_header_conditions_do_not_collide() {
        let a = ep("example.com", Some("/api"), false, false);
        let mut b = ep("example.com", Some("/api"), false, false);
        b.config.match_headers = vec![MatchCondition {
            key: "X-Canary".into(),
            value: String::new(),
            regex: false,
        }];
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        assert!(lint_collection(&pairs).is_empty());

        let mut c = b.clone();
        c.config.match_headers[0].key = "x-canary".into();
        let pairs = vec![("cand-b", &b), ("cand-c", &c)];
        assert_eq!(lint_collection(&pairs).len(), 2);
    }

    /// Query conditions Sōzu routes on tell routes apart, unless a route
    /// without any outranks the one with them.
    #[test]
    fn query_conditions_tell_routes_apart() {
        let a = ep("example.com", Some("/api"), false, false);
        let mut b = ep("example.com", Some("/api"), false, false);
        b.config.match_query = vec![MatchCondition {
            key: "v".into(),
            value: "2".into(),
            regex: false,
        }];
        assert!(lint_collection(&[("cand-a", &a), ("cand-b", &b)]).is_empty());

        // `?v=2&v=3` matches both.
        let mut c = b.clone();
        c.config.match_query[0].value = "3".into();
        assert_eq!(lint_collection(&[("cand-b", &b), ("cand-c", &c)]).len(), 2);

        let mut high = a.clone();
        high.config.priority = 10;
        assert_eq!(
            lint_collection(&[("cand-high", &high), ("cand-b", &b)]).len(),
            2
        );

        // More header conditions put a route without query conditions first.
        let header = |key: &str| MatchCondition {
            key: key.into(),
            value: String::new(),
            regex: false,
        };
        let mut two_headers = a.clone();
        two_headers.config.match_headers = vec![header("X-A"), header("X-B")];
        let mut header_and_query = b.clone();
        header_and_query.config.match_headers = vec![header("X-A")];
        assert_eq!(
            lint_collection(&[
                ("cand-headers", &two_headers),
                ("cand-query", &header_and_query)
            ])
            .len(),
            2
        );

        // So does a method: `GET /api` comes before `/api?v=2`.
        let mut get = a.clone();
        get.config.methods = vec!["GET".into()];
        assert_eq!(
            lint_collection(&[("cand-get", &get), ("cand-b", &b)]).len(),
            2
        );
    }

    /// Routes on Gateway listeners of different ports never meet.
    #[test]
    fn routes_on_different_listener_ports_do_not_collide() {
        let a = ep("example.com", Some("/api"), false, false);
        let mut b = ep("example.com", Some("/api"), false, false);
        b.config.entrypoint = Some("gateway:http:8080".into());
        assert!(lint_collection(&[("cand-a", &a), ("cand-b", &b)]).is_empty());
    }

    /// Routes on different HTTP ports still meet on the HTTPS listener they
    /// share, once reported.
    #[test]
    fn tls_routes_meet_on_https_whatever_their_http_port() {
        let mut a = ep("example.com", Some("/api"), false, false);
        a.config.tls = true;
        let mut b = a.clone();
        b.config.entrypoint = Some("gateway:http:8080".into());
        assert_eq!(lint_collection(&[("cand-a", &a), ("cand-b", &b)]).len(), 2);
        // On the same HTTP listener too: still one each.
        assert_eq!(
            lint_collection(&[("cand-a", &a), ("cand-c", &a.clone())]).len(),
            2
        );
    }

    /// Partners met on HTTP and on HTTPS are named together.
    #[test]
    fn partners_on_every_listener_are_named_together() {
        let mut a = ep("example.com", Some("/api"), false, false);
        a.config.tls = true;
        let plain = ep("example.com", Some("/api"), false, false);
        let mut elsewhere = a.clone();
        elsewhere.config.entrypoint = Some("gateway:http:8080".into());
        let out = lint_collection(&[
            ("cand-a", &a),
            ("cand-plain", &plain),
            ("cand-else", &elsewhere),
        ]);
        let for_a: Vec<_> = out.iter().filter(|(id, _)| id == "cand-a").collect();
        assert_eq!(for_a.len(), 1);
        assert!(
            for_a[0].1.message.contains("cand-else, cand-plain"),
            "{}",
            for_a[0].1.message
        );
    }

    /// A request can carry `X-Env: prod` and match both a route on that
    /// value and one on the header's presence; it cannot carry two values.
    #[test]
    fn header_conditions_collide_when_one_request_can_match_both() {
        let with = |value: &str| {
            let mut e = ep("example.com", Some("/api"), false, false);
            e.config.match_headers = vec![MatchCondition {
                key: "X-Env".into(),
                value: value.into(),
                regex: false,
            }];
            e
        };
        let (any, prod, staging) = (with(""), with("prod"), with("staging"));

        let out = lint_collection(&[("any", &any), ("prod", &prod), ("staging", &staging)]);
        let mut owners: Vec<&str> = out.iter().map(|(c, _)| c.as_str()).collect();
        owners.sort();
        assert_eq!(owners, ["any", "prod", "staging"]);
        let prod_message = &out.iter().find(|(c, _)| c == "prod").unwrap().1.message;
        assert!(
            prod_message
                .contains("also defined by: any, with conditions a request can meet for both")
        );

        assert!(lint_collection(&[("prod", &prod), ("staging", &staging)]).is_empty());
    }

    /// Sōzu cannot route on a cookie, so it does not choose between the
    /// routes: the one it picks answers 404 when the cookie is missing.
    #[test]
    fn a_cookie_condition_does_not_separate_routes() {
        let plain = ep("example.com", Some("/api"), false, false);
        let mut beta = ep("example.com", Some("/api"), false, false);
        beta.config.match_headers = vec![MatchCondition {
            key: "Cookie".into(),
            value: "beta=1".into(),
            regex: false,
        }];

        assert_eq!(
            lint_collection(&[("plain", &plain), ("beta", &beta)]).len(),
            2
        );
    }

    #[test]
    fn distinct_hosts_do_not_collide() {
        let a = ep("a.example.com", Some("/api"), false, false);
        let b = ep("b.example.com", Some("/api"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert!(out.is_empty());
    }

    #[test]
    fn acme_without_any_tls_emits_w015() {
        let a = ep("example.com", None, false, false);
        let r = lint_acme_without_tls(true, &[&a]);
        assert!(r.is_some());
        assert_eq!(r.unwrap().code, DiagnosticCode::W015AcmeWithoutTls);
    }

    #[test]
    fn acme_disabled_is_silent() {
        let a = ep("example.com", None, false, false);
        assert!(lint_acme_without_tls(false, &[&a]).is_none());
    }

    #[test]
    fn acme_with_one_tls_endpoint_is_silent() {
        let a = ep("example.com", None, false, false);
        let b = ep("secure.example.com", None, true, false);
        assert!(lint_acme_without_tls(true, &[&a, &b]).is_none());
    }
    fn acme_with(resolvers: &[&str], enabled: bool) -> AcmeConfig {
        AcmeConfig {
            enabled,
            email: String::new(),
            certs_dir: String::from("/tmp"),
            staging: true,
            challenge_port: 80,
            tls_alpn_port: 3038,
            resolvers: resolvers
                .iter()
                .map(|name| (name.to_string(), ResolverConfig::Http01 { ca_server: None }))
                .collect(),
        }
    }

    fn with_resolver(mut ep: Entrypoint, resolver: &str) -> Entrypoint {
        ep.config.acme = Some(EntrypointAcmeConfig {
            resolver: resolver.into(),
        });
        ep
    }

    #[test]
    fn unknown_resolver_emits_w029_with_the_declared_ones() {
        let a = with_resolver(ep("example.com", None, true, false), "letsencrpyt");
        let acme = acme_with(&["letsencrypt", "cloudflare"], true);

        let out = lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "cand-a");
        assert_eq!(out[0].1.code, DiagnosticCode::W029UnknownAcmeResolver);
        let hint = out[0].1.hint.as_deref().unwrap();
        assert!(hint.contains("cloudflare, letsencrypt"), "{hint}");
    }

    #[test]
    fn declared_resolver_is_silent() {
        let a = with_resolver(ep("example.com", None, true, false), "letsencrypt");
        let acme = acme_with(&["letsencrypt"], true);
        assert!(lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]).is_empty());
    }

    #[test]
    fn unknown_resolver_is_ignored_without_acme_or_tls() {
        let tls = with_resolver(ep("example.com", None, true, false), "missing");
        let plain = with_resolver(ep("example.com", None, false, false), "missing");

        assert!(lint_unknown_resolvers(None, &[], &[("cand-a", &tls)]).is_empty());
        let disabled = acme_with(&[], false);
        assert!(lint_unknown_resolvers(Some(&disabled), &[], &[("cand-a", &tls)]).is_empty());
        let enabled = acme_with(&[], true);
        assert!(lint_unknown_resolvers(Some(&enabled), &[], &[("cand-a", &plain)]).is_empty());
    }

    #[test]
    fn route_served_by_a_file_certificate_is_silent() {
        let a = with_resolver(ep("app.example.com", None, true, false), "missing");
        let acme = acme_with(&[], true);
        let file_names = vec!["*.example.com".to_string()];

        assert!(lint_unknown_resolvers(Some(&acme), &file_names, &[("cand-a", &a)]).is_empty());
        let other = with_resolver(ep("app.example.org", None, true, false), "missing");
        assert_eq!(
            lint_unknown_resolvers(Some(&acme), &file_names, &[("cand-b", &other)]).len(),
            1
        );
    }

    #[test]
    fn route_without_resolver_is_silent() {
        let a = ep("example.com", None, true, false);
        let acme = acme_with(&[], true);
        assert!(lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]).is_empty());
    }

    fn with_backend_timeout(ms: u64) -> Entrypoint {
        let mut e = ep("example.com", None, false, false);
        e.config.backend_timeout = Some(ms);
        e
    }

    fn timeouts(backend_idle: Option<u32>, client_idle: Option<u32>) -> ProxyTimeouts {
        ProxyTimeouts {
            backend_idle,
            client_idle,
            ..Default::default()
        }
    }

    #[test]
    fn backend_timeout_within_the_listener_is_silent() {
        let a = with_backend_timeout(20_000);
        assert!(lint_backend_timeouts(&timeouts(None, None), &[("cand-a", &a)]).is_empty());
        let unset = ep("example.com", None, false, false);
        assert!(lint_backend_timeouts(&timeouts(None, None), &[("cand-a", &unset)]).is_empty());
    }

    #[test]
    fn backend_timeout_beyond_backend_idle_is_flagged() {
        let a = with_backend_timeout(60_000);
        let out = lint_backend_timeouts(&timeouts(None, None), &[("cand-a", &a)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "cand-a");
        assert_eq!(
            out[0].1.code,
            DiagnosticCode::W030BackendTimeoutBeyondListener
        );
        assert!(
            out[0].1.message.contains("backend_idle"),
            "{}",
            out[0].1.message
        );
        assert!(out[0].1.message.contains("30s"), "{}", out[0].1.message);
    }

    #[test]
    fn no_backend_timeout_is_flagged_too() {
        let a = with_backend_timeout(0);
        let out = lint_backend_timeouts(&timeouts(Some(3600), Some(3600)), &[("cand-a", &a)]);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].1.message.contains("no timeout"),
            "{}",
            out[0].1.message
        );
    }

    #[test]
    fn the_shorter_listener_timeout_is_named() {
        let a = with_backend_timeout(90_000);
        let out = lint_backend_timeouts(&timeouts(Some(120), None), &[("cand-a", &a)]);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].1.message.contains("client_idle"),
            "{}",
            out[0].1.message
        );
        assert!(
            lint_backend_timeouts(&timeouts(Some(120), Some(120)), &[("cand-a", &a)]).is_empty()
        );
    }
}
