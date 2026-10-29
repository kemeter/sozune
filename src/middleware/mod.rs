pub mod chain;
pub mod circuit_breaker;
mod compress;
mod cors;
mod diag;
mod fixed_answer;
mod forward_auth;
pub mod in_flight_req;
pub mod ip_allow_list;
pub mod passive_health;
mod proxy;
pub mod rate_limit;
mod redirect;
pub(crate) mod request_match;
pub mod tunnels;
mod wasm;

use std::sync::{Arc, Mutex, RwLock};

use axum::{Router, routing::any};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{error, info, warn};

use crate::model::{
    Backend, Entrypoint, EntrypointConfig, HeaderConfig, HeaderDirection, LoadBalancer,
    MatchCondition,
};
use crate::proxy::sozu::{header_predicate, routes_on_query};
use chain::Middleware;
use compress::CompressMiddleware;
use fixed_answer::FixedAnswerMiddleware;
use forward_auth::ForwardAuthMiddleware;
use in_flight_req::{InFlightLimiter, InFlightReqMiddleware};
use ip_allow_list::{IpAllowList, IpAllowListMiddleware, TrustedProxies};
use rate_limit::{RateLimitMiddleware, RateLimiter};
use redirect::RedirectMiddleware;
use request_match::RequestMatchMiddleware;
use sozu_lib::router::DomainRule;

/// Build the shared HTTP client used by forward-auth middlewares. Same config
/// as before: short timeout, no redirect following.
pub fn build_forward_auth_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(forward_auth::TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds with default config")
}

/// Shared state for the middleware server
#[derive(Clone)]
pub struct MiddlewareAppState {
    pub route_table: Arc<RwLock<MiddlewareRouteTable>>,
    pub http_client: Client<hyper_util::client::legacy::connect::HttpConnector, axum::body::Body>,
    /// Live request-latency histogram. The proxy handler records each
    /// completed request here; the API `/metrics` endpoint reads the same Arc.
    pub request_metrics: crate::proxy::request_metrics::RequestMetricsStore,
    /// The backends left out after failing requests in a row.
    pub passive_health: Arc<passive_health::PassiveHealth>,
}

pub type MiddlewareState = Arc<RwLock<MiddlewareRouteTable>>;

/// Route table mapping hostname → middleware config + real backends
/// How a route's path was declared, kept whole.
///
/// `PathConfig` carries a rule type as well as a value, and only `Prefix`
/// covers what sits below it. Keeping just the string treated `Exact` as a
/// prefix and turned `Regex` into a literal prefix that normally matches
/// nothing — so the middleware server could answer 404, or hand the request to
/// a different route, for a frontend Sozu had matched correctly.
#[derive(Debug)]
pub enum PathMatch {
    Prefix(String),
    Exact(String),
    /// `None` when the pattern would not compile: it then matches nothing,
    /// which keeps a broken route dark rather than letting it swallow the
    /// hostname.
    Regex(Option<regex::Regex>, String),
}

impl PathMatch {
    fn from_config(path: &crate::model::PathConfig) -> Self {
        match path.rule_type {
            crate::model::PathRuleType::Prefix => PathMatch::Prefix(path.value.clone()),
            crate::model::PathRuleType::Exact => PathMatch::Exact(path.value.clone()),
            crate::model::PathRuleType::Regex => {
                let compiled = regex::Regex::new(&path.value).ok();
                if compiled.is_none() {
                    warn!(
                        "path regex `{}` does not compile; the route will match nothing",
                        path.value
                    );
                }
                PathMatch::Regex(compiled, path.value.clone())
            }
        }
    }

    fn matches(&self, request_path: &str) -> bool {
        match self {
            PathMatch::Prefix(prefix) => prefix_matches(prefix, request_path),
            PathMatch::Exact(value) => request_path == value,
            PathMatch::Regex(compiled, _) => {
                compiled.as_ref().is_some_and(|r| r.is_match(request_path))
            }
        }
    }

    /// How specific this match is, for picking between two that both apply.
    /// An exact match beats any prefix; among prefixes the longest wins.
    fn specificity(&self) -> usize {
        match self {
            PathMatch::Exact(value) => usize::MAX - value.len(),
            PathMatch::Prefix(value) => value.len(),
            PathMatch::Regex(_, value) => value.len(),
        }
    }

    #[cfg(test)]
    fn exact(value: &str) -> Self {
        PathMatch::Exact(value.to_string())
    }

    #[cfg(test)]
    fn regex(value: &str) -> Self {
        PathMatch::Regex(regex::Regex::new(value).ok(), value.to_string())
    }

    #[cfg(test)]
    fn prefix(value: &str) -> Self {
        PathMatch::Prefix(value.to_string())
    }
}

/// Request header carrying the id of the route Sōzu picked, set by the
/// frontend of every route that goes through the middleware. Sōzu drops any
/// value the client sent, and the middleware drops it before the backend.
pub const ROUTE_HEADER: &str = "sozune-route";

/// The scheme of the listener a request came in on, which the frontends of a
/// route whose redirect the middleware answers set (see
/// [`answers_redirect`]).
pub const SCHEME_HEADER: &str = "sozune-scheme";

/// The routes one hostname carries, each with the path it was declared with.
/// `None` is a route with no path: the catch-all for that hostname.
type HostRoutes = Vec<(Option<PathMatch>, Arc<MiddlewareRoute>)>;

#[derive(Debug, Default)]
pub struct MiddlewareRouteTable {
    /// Keyed by hostname, but a hostname can carry several routes: Sozu routes
    /// on host *and* path, so one entry per hostname would drop all but the
    /// last one stored.
    pub(super) routes: std::collections::HashMap<String, HostRoutes>,
    /// Wildcard and regex hostnames, in the order Sozu tries them, each with
    /// the key its routes are stored under. The request carries the host it
    /// was sent to, not the pattern that matched it, so these are matched with
    /// Sozu's own `DomainRule`.
    patterns: Vec<(DomainRule, String)>,
    /// Every route by the id of its entrypoint, for requests carrying
    /// [`ROUTE_HEADER`].
    by_cluster: std::collections::HashMap<String, Arc<MiddlewareRoute>>,
}

/// Middleware configuration for a single entrypoint.
///
/// The middleware stack is an ordered list run before (and after) the backend.
/// `backend_timeout` is not a middleware — it's a property of the backend
/// forward itself — so it stays a plain field.
pub struct MiddlewareRoute {
    /// The entrypoint (Sōzu cluster) this route was built from.
    pub cluster_id: String,
    pub backends: Vec<(String, u16)>,
    /// Picks among `backends` in proportion to their weights.
    pub balancer: WeightedRoundRobin,
    /// How a request's backend is picked: by `balancer` in turn, at random,
    /// or by load. Hashing on a flow key has no meaning for HTTP: those pick
    /// in turn.
    pub algorithm: LoadBalancer,
    /// Requests waiting for an answer from each backend of `backends`, from
    /// [`backend_load`]: shared by every route to that address, and kept
    /// across a rebuild of the table while a request still waits.
    pub in_flight: Vec<Arc<std::sync::atomic::AtomicUsize>>,
    /// Indexes into `backends` of the backups: weight 0 next to backends that
    /// have a weight. Tried when the picked backend gives no response.
    pub backups: Vec<usize>,
    pub backend_timeout: Option<u64>,
    /// Milliseconds the whole request may take, from its arrival.
    pub request_timeout: Option<u64>,
    /// Total forward attempts (first try + retries) on a connection-level
    /// failure or timeout. `1` (or `0`) means no retry — the default.
    pub retry_attempts: u32,
    /// Per-route circuit breaker, shared across requests so its state persists.
    /// `None` when the route doesn't configure one.
    pub circuit_breaker: Option<Arc<circuit_breaker::CircuitBreaker>>,
    pub middlewares: Vec<Arc<dyn Middleware>>,
    /// The `Host` the backend gets instead of the client's, the client's
    /// going in `X-Forwarded-Host`.
    pub rewrite_host: Option<String>,
    /// Where each request is copied to, its answer ignored.
    pub mirrors: Vec<MirrorTarget>,
    /// The header edits of each backend, by its index in `backends`.
    pub backend_headers: Vec<Vec<HeaderConfig>>,
    /// The route's response header edits, which the middleware makes rather
    /// than Sōzu when a backend has edits of its own: see
    /// [`edits_responses`].
    pub response_headers: Vec<HeaderConfig>,
    /// Picks, by their weights, whether a request is forwarded (`0`) or
    /// answered `500` (`1`) or `503` (`2`): see [`crate::model::FailingShares`].
    pub failing_shares: Option<WeightedRoundRobin>,
    /// The route's CORS policy, which marks every response to an origin it
    /// allows, whatever gave it: the backend, a middleware or an error.
    pub cors: Option<Arc<cors::CorsMiddleware>>,
}

/// One of a route's mirrors: its backends, how to pick one, and which
/// requests to copy.
pub struct MirrorTarget {
    pub backends: Vec<(String, u16)>,
    pub balancer: WeightedRoundRobin,
    fraction: Option<crate::model::MirrorFraction>,
}

/// How many copies to mirrors may be under way at once, all routes together:
/// a slow mirror would otherwise hold a connection and a body for every
/// request. Past it, a copy is dropped: the request it copies goes on all the
/// same. One limit for the process, so a reload rebuilding the routes does not
/// give them a fresh one while earlier copies still run.
pub const MIRROR_MAX_IN_FLIGHT: usize = 1024;

/// The count of requests waiting for `backend`'s answer, one per address
/// whatever the route: the routes rebuilt on a reload get the count their
/// predecessors still update.
pub fn backend_load(backend: &(String, u16)) -> Arc<std::sync::atomic::AtomicUsize> {
    type Loads =
        std::collections::HashMap<(String, u16), std::sync::Weak<std::sync::atomic::AtomicUsize>>;
    static LOADS: std::sync::OnceLock<Mutex<Loads>> = std::sync::OnceLock::new();
    let mut loads = LOADS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(load) = loads.get(backend).and_then(std::sync::Weak::upgrade) {
        return load;
    }
    // Forget the addresses no route holds any more.
    loads.retain(|_, load| load.strong_count() > 0);
    let load = Arc::default();
    loads.insert(backend.clone(), Arc::downgrade(&load));
    load
}

/// The permits of [`MIRROR_MAX_IN_FLIGHT`].
pub fn mirror_permits() -> Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    Arc::clone(PERMITS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MIRROR_MAX_IN_FLIGHT))))
}

impl MirrorTarget {
    fn new(mirror: &crate::model::Mirror) -> Self {
        let weights: Vec<u32> = mirror.backends.iter().map(|b| b.weight).collect();
        Self {
            backends: mirror
                .backends
                .iter()
                .map(|b| (b.address.clone(), b.port))
                .collect(),
            balancer: WeightedRoundRobin::new(&weights),
            fraction: mirror.fraction,
        }
    }

    /// Whether to copy the next request: drawn at random, with a chance of
    /// `numerator` in `denominator`. Without a state, so a route rebuilt on a
    /// reload keeps copying its share from its first request.
    pub fn copies_next(&self) -> bool {
        let Some(fraction) = self.fraction else {
            return true;
        };
        let denominator = u64::from(fraction.denominator.max(1));
        random_u64() % denominator < u64::from(fraction.numerator)
    }

    /// The backend the next copy goes to.
    pub fn pick(&self) -> Option<&(String, u16)> {
        self.balancer.next().and_then(|i| self.backends.get(i))
    }
}

impl std::fmt::Debug for MiddlewareRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareRoute")
            .field("cluster_id", &self.cluster_id)
            .field("backends", &self.backends)
            .field("backend_timeout", &self.backend_timeout)
            .field(
                "middlewares",
                &self
                    .middlewares
                    .iter()
                    .map(|m| m.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Whether Sozu reads `hostname` as a pattern (wildcard or regex) rather than
/// a literal name.
fn is_host_pattern(hostname: &str) -> bool {
    hostname.contains('*') || hostname.contains('/')
}

/// Whether `request_path` falls under `prefix`, on a segment boundary.
///
/// `/api` covers `/api` and `/api/users`, but not `/apifoo` — a prefix that
/// matched mid-segment would capture paths it was never given.
fn prefix_matches(prefix: &str, request_path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    match request_path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// Index of the candidate that should serve `request_path`: the longest prefix
/// that matches, with a pathless route as the catch-all.
///
/// Sozu already routed the request on host *and* path before handing it over,
/// so this only has to reproduce that choice among the routes sharing a
/// hostname. Resolving on the hostname alone let whichever entrypoint was
/// stored last serve every path under it.
fn best_match<T>(candidates: &[(Option<PathMatch>, T)], request_path: &str) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, (path, _))| match path {
            Some(matcher) => matcher.matches(request_path),
            None => true,
        })
        .max_by_key(|(_, (path, _))| path.as_ref().map(PathMatch::specificity).unwrap_or(0))
        .map(|(index, _)| index)
}

impl MiddlewareRouteTable {
    pub fn update_routes_for_entrypoint(
        &mut self,
        hostnames: &[String],
        path: Option<&crate::model::PathConfig>,
        route: Arc<MiddlewareRoute>,
    ) {
        self.by_cluster
            .insert(route.cluster_id.clone(), Arc::clone(&route));
        for hostname in hostnames {
            if is_host_pattern(hostname) && !self.patterns.iter().any(|(_, key)| key == hostname) {
                match hostname.parse::<DomainRule>() {
                    Ok(rule) => self.patterns.push((rule, hostname.clone())),
                    Err(()) => warn!(
                        "hostname pattern `{}` cannot be parsed; requests to it will find no route",
                        hostname
                    ),
                }
            }
            // Built per hostname: a compiled regex cannot be cloned, and the
            // same path under two hostnames is two independent matchers.
            self.routes
                .entry(hostname.clone())
                .or_default()
                .push((path.map(PathMatch::from_config), Arc::clone(&route)));
        }
    }

    pub fn clear(&mut self) {
        self.routes.clear();
        self.patterns.clear();
        self.by_cluster.clear();
    }

    /// The route of the entrypoint `cluster_id`, as named by [`ROUTE_HEADER`].
    pub fn route_for_cluster(&self, cluster_id: &str) -> Option<Arc<MiddlewareRoute>> {
        self.by_cluster.get(cluster_id).cloned()
    }

    /// The route serving `host` and `request_path`: among the routes declared
    /// for that exact hostname first, then among those of each wildcard or
    /// regex hostname it matches, in the order Sozu tries them.
    pub fn get_route(&self, host: &str, request_path: &str) -> Option<Arc<MiddlewareRoute>> {
        // Strip port from host header if present (e.g. "example.com:8080" -> "example.com")
        let hostname = host.split(':').next().unwrap_or(host);
        let exact = self.routes.get(hostname).into_iter();
        let patterns = self
            .patterns
            .iter()
            .filter(|(rule, _)| rule.matches(hostname.as_bytes()))
            .filter_map(|(_, key)| self.routes.get(key));
        exact.chain(patterns).find_map(|candidates| {
            best_match(candidates, request_path).map(|index| Arc::clone(&candidates[index].1))
        })
    }

    pub fn known_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.routes.keys().cloned().collect();
        hosts.sort();
        hosts
    }
}

impl MiddlewareRoute {
    /// The header edits of the backend at `index`, if one was picked.
    pub fn edits_for(&self, index: Option<usize>) -> &[HeaderConfig] {
        index
            .and_then(|index| self.backend_headers.get(index))
            .map_or(&[], Vec::as_slice)
    }

    /// Makes the response edits of the route, then those of the backend that
    /// gave `response`, if one did (see [`ServedBy`]).
    pub fn edit_response(&self, response: &mut axum::response::Response) {
        let served_by = response.extensions().get::<ServedBy>().map(|s| s.0);
        let headers = response.headers_mut();
        edit_headers(headers, &self.response_headers, HeaderDirection::Response);
        edit_headers(
            headers,
            self.edits_for(served_by),
            HeaderDirection::Response,
        );
    }

    /// The backends one request tries, in order, until one answers. See
    /// [`BackendAttempts`]. `attempts` is the route's retry budget; a
    /// WebSocket upgrade, which is never retried, passes 1. `health` tells
    /// the backends left out after failing.
    pub fn attempts<'a>(
        &'a self,
        attempts: u32,
        health: &'a passive_health::PassiveHealth,
    ) -> BackendAttempts<'a> {
        BackendAttempts {
            route: self,
            health,
            attempts: attempts.max(1) as usize,
            tried: Vec::new(),
            fallback: None,
        }
    }

    fn is_backup(&self, index: usize) -> bool {
        self.backups.contains(&index)
    }

    /// The backend a request goes to, among those `eligible` takes, by the
    /// route's algorithm. Weights count whatever the algorithm.
    pub fn pick(&self, eligible: impl Fn(usize) -> bool) -> Option<usize> {
        let weights = &self.balancer.weights;
        let eligible = |index: usize| weights.get(index).is_some_and(|&w| w > 0) && eligible(index);
        if matches!(
            self.algorithm,
            LoadBalancer::RoundRobin | LoadBalancer::Hrw | LoadBalancer::Maglev
        ) {
            return self.balancer.next_where(eligible);
        }
        let candidates: Vec<usize> = (0..self.backends.len()).filter(|&i| eligible(i)).collect();
        match self.algorithm {
            LoadBalancer::Random => self.weighted_random(&candidates),
            LoadBalancer::LeastConnections => {
                // Ties drawn by weight: on a quiet route every backend often
                // has nothing waiting, and the weights must still share it.
                let best = candidates.iter().copied().reduce(|best, index| {
                    if self.less_loaded(index, best) {
                        index
                    } else {
                        best
                    }
                })?;
                let least: Vec<usize> = candidates
                    .iter()
                    .copied()
                    .filter(|&index| !self.less_loaded(best, index))
                    .collect();
                self.weighted_random(&least)
            }
            LoadBalancer::PowerOfTwo => {
                let a = self.weighted_random(&candidates)?;
                let others: Vec<usize> = candidates.iter().copied().filter(|&i| i != a).collect();
                let Some(b) = self.weighted_random(&others) else {
                    return Some(a);
                };
                Some(if self.less_loaded(b, a) { b } else { a })
            }
            LoadBalancer::RoundRobin | LoadBalancer::Hrw | LoadBalancer::Maglev => None,
        }
    }

    /// One of `candidates` at random, in proportion to its weight.
    fn weighted_random(&self, candidates: &[usize]) -> Option<usize> {
        let weights = &self.balancer.weights;
        let total: u64 = candidates.iter().map(|&i| weights[i] as u64).sum();
        if total == 0 {
            return None;
        }
        let mut draw = random_u64() % total;
        candidates.iter().copied().find(|&index| {
            let weight = weights[index] as u64;
            if draw < weight {
                true
            } else {
                draw -= weight;
                false
            }
        })
    }

    /// Whether `a` has fewer requests waiting for its answer than `b`, for
    /// its weight.
    fn less_loaded(&self, a: usize, b: usize) -> bool {
        let load = |index: usize| {
            self.in_flight
                .get(index)
                .map_or(0, |n| n.load(std::sync::atomic::Ordering::Relaxed)) as u128
        };
        let weight = |index: usize| self.balancer.weights[index].max(1) as u128;
        load(a) * weight(b) < load(b) * weight(a)
    }

    /// Count a request waiting for the answer of the backend at `index`,
    /// until the returned guard is dropped.
    pub fn waiting_on(&self, index: usize) -> Option<Waiting> {
        let load = self.in_flight.get(index)?;
        load.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(Waiting(Arc::clone(load)))
    }
}

/// A request waiting for a backend's answer, counted for the balancers that
/// pick by load.
pub struct Waiting(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A cheap pseudo-random number, for the balancers that pick at random: an
/// xorshift over a state seeded from the clock.
fn random_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let next = |mut x: u64| {
        if x == 0 {
            x = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0x9E37_79B9_7F4A_7C15, |d| d.as_nanos() as u64)
                | 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    // Advanced atomically, so concurrent requests never share a draw.
    let previous = STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| Some(next(x)))
        .unwrap_or_default();
    next(previous)
}

/// The backends one request tries, in order, until one answers:
///
/// 1. the balancer's pick, by weight;
/// 2. up to `attempts - 1` retries, each on the heaviest backend the request
///    has not tried; once it has tried them all, the balancer picks again;
/// 3. when the route has backups and every attempt failed, each backend the
///    request has not tried, heaviest first, then each backup in turn.
///
/// A backup is tried only once every other backend has been. Backends are
/// picked one at a time, as attempts fail, so a request that does not retry
/// moves the balancer once. A backend left out after failing (see
/// [`passive_health`]) comes after the others, unless every one is.
pub struct BackendAttempts<'a> {
    route: &'a MiddlewareRoute,
    health: &'a passive_health::PassiveHealth,
    attempts: usize,
    tried: Vec<usize>,
    fallback: Option<std::collections::VecDeque<usize>>,
}

impl BackendAttempts<'_> {
    /// The index in the route's `backends` of the backend last returned.
    pub fn last_index(&self) -> Option<usize> {
        self.tried.last().copied()
    }

    /// The backends that are not backups and that this request has not
    /// tried: those not left out first, heaviest first, then in declaration
    /// order.
    fn untried_primaries(&self) -> Vec<usize> {
        let route = self.route;
        let mut untried: Vec<usize> = (0..route.backends.len())
            .filter(|index| !route.is_backup(*index) && !self.tried.contains(index))
            .collect();
        untried.sort_by_key(|&index| {
            (
                self.is_down(index),
                std::cmp::Reverse(route.balancer.weights[index]),
            )
        });
        untried
    }

    fn is_down(&self, index: usize) -> bool {
        self.route
            .backends
            .get(index)
            .is_some_and(|backend| self.health.is_down(backend))
    }

    /// The balancer's pick among the backends not left out, by their
    /// weights; a backup not left out when every other backend is; the
    /// balancer's pick among all of them when every backend is.
    fn balanced(&self) -> Option<usize> {
        let route = self.route;
        route
            .pick(|index| !self.is_down(index))
            .or_else(|| {
                route
                    .backups
                    .iter()
                    .copied()
                    .find(|&index| !self.is_down(index))
            })
            .or_else(|| route.pick(|_| true))
    }
}

impl<'a> Iterator for BackendAttempts<'a> {
    type Item = &'a (String, u16);

    fn next(&mut self) -> Option<Self::Item> {
        let route = self.route;
        let index = if self.tried.is_empty() {
            self.balanced()
        } else if self.tried.len() < self.attempts {
            // An untried backend not left out; when each untried one is, a
            // backup not left out before them. Once every backend was tried,
            // the balancer picks again.
            let primaries = self.untried_primaries();
            let up = |index: &usize| !self.is_down(*index);
            match primaries.iter().copied().find(up) {
                Some(index) => Some(index),
                None if !primaries.is_empty() => route
                    .backups
                    .iter()
                    .copied()
                    .filter(|index| !self.tried.contains(index))
                    .find(up)
                    .or_else(|| primaries.first().copied()),
                None => self.balanced(),
            }
        } else {
            if self.fallback.is_none() {
                let fallback = if route.backups.is_empty() {
                    Default::default()
                } else {
                    // Those left out last, backups included.
                    let (up, down): (Vec<usize>, Vec<usize>) = self
                        .untried_primaries()
                        .into_iter()
                        .chain(
                            route
                                .backups
                                .iter()
                                .copied()
                                .filter(|index| !self.tried.contains(index)),
                        )
                        .partition(|&index| !self.is_down(index));
                    up.into_iter().chain(down).collect()
                };
                self.fallback = Some(fallback);
            }
            self.fallback.as_mut().and_then(|queue| queue.pop_front())
        }?;
        self.tried.push(index);
        route.backends.get(index)
    }
}

/// Smooth weighted round robin, as Sōzu runs it: a backend of weight `w`
/// serves `w` requests out of every `Σw`, and the picks interleave (weights
/// `5, 1, 1` give `a a b a c a a`). Equal weights give a plain rotation.
///
/// A backend of weight 0 is never picked, unless every backend has weight 0:
/// then they share the traffic equally.
#[derive(Debug)]
pub struct WeightedRoundRobin {
    weights: Vec<i64>,
    current: Mutex<Vec<i64>>,
}

impl WeightedRoundRobin {
    pub fn new(weights: &[u32]) -> Self {
        // Capped as Sōzu caps them, so a route splits its traffic the same
        // way with or without the middleware.
        let mut weights: Vec<i64> = weights
            .iter()
            .map(|&w| i64::from(w.min(i32::MAX as u32)))
            .collect();
        if weights.iter().all(|&w| w == 0) {
            weights.iter_mut().for_each(|w| *w = 1);
        }
        Self {
            current: Mutex::new(vec![0; weights.len()]),
            weights,
        }
    }

    pub fn next(&self) -> Option<usize> {
        self.next_where(|_| true)
    }

    /// [`Self::next`] among the backends `eligible` takes. One it leaves out
    /// does not take part in the turn, so the others keep their ratios.
    pub fn next_where(&self, eligible: impl Fn(usize) -> bool) -> Option<usize> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut picked: Option<usize> = None;
        let mut total = 0;
        for (index, &weight) in self.weights.iter().enumerate() {
            if weight == 0 || !eligible(index) {
                continue;
            }
            current[index] += weight;
            total += weight;
            if picked.is_none_or(|p| current[index] > current[p]) {
                picked = Some(index);
            }
        }
        if let Some(index) = picked {
            current[index] -= total;
        }
        picked
    }
}

/// Indexes of the backups among `weights`: the weight-0 backends, when another
/// backend has a weight.
fn backup_indexes(weights: &[u32]) -> Vec<usize> {
    if weights.iter().all(|&w| w == 0) {
        return Vec::new();
    }
    weights
        .iter()
        .enumerate()
        .filter(|(_, w)| **w == 0)
        .map(|(index, _)| index)
        .collect()
}

/// Compiled WASM plugins keyed by their declared name. Each plugin is compiled
/// once at startup and shared across every route that references it. The value
/// is the concrete [`wasm::WasmMiddleware`] (not a `dyn Middleware`) so a route
/// can cheaply derive a copy with its own config via
/// [`wasm::WasmMiddleware::with_route_config`].
pub type PluginRegistry = std::collections::HashMap<String, Arc<wasm::WasmMiddleware>>;

/// Compile every declared plugin into a shareable middleware. A plugin that
/// fails to load (missing file, bad wasm) is logged and skipped, so one broken
/// plugin doesn't take down routing.
pub fn build_plugin_registry(
    declared: &std::collections::HashMap<String, crate::config::PluginConfig>,
    handle: &tokio::runtime::Handle,
) -> PluginRegistry {
    let mut registry = PluginRegistry::new();

    // The outbound client for plugins is built lazily on first network plugin,
    // wired with a DNS-rebinding guard that exempts every operator-declared host
    // (across all plugins) and hardens everything else (i.e. tenant hosts added
    // per route). Forward-auth keeps its own `fetch_client`, unchanged.
    let outbound_client = std::cell::OnceCell::new();
    let operator_hosts: Vec<String> = declared
        .values()
        .flat_map(|c| c.allowed_hosts.iter())
        .map(|h| wasm::bare_host(h))
        .collect();

    for (name, cfg) in declared {
        let wasm_bytes = match std::fs::read(&cfg.path) {
            Ok(w) => w,
            Err(e) => {
                error!("Cannot read WASM plugin '{}' at {}: {}", name, cfg.path, e);
                continue;
            }
        };
        let limits = http_wasm_host::Limits::default();

        // A plugin opts into the outbound-HTTP extension when it declares
        // operator `allowed_hosts` OR `outbound_host_keys` (per-route tenant
        // hosts); otherwise it gets the standard sandbox with no network.
        let needs_network = !cfg.allowed_hosts.is_empty() || !cfg.outbound_host_keys.is_empty();
        let built = if needs_network {
            let client =
                outbound_client.get_or_init(|| wasm::build_outbound_client(operator_hosts.clone()));
            wasm::WasmMiddleware::from_bytes_with_network(
                &wasm_bytes,
                cfg.config.clone(),
                limits,
                client.clone(),
                handle.clone(),
                cfg.allowed_hosts.clone(),
                cfg.outbound_host_keys.clone(),
            )
        } else {
            wasm::WasmMiddleware::from_bytes(&wasm_bytes, cfg.config.clone(), limits)
        };

        match built {
            Ok(mw) => {
                let policy =
                    wasm::PluginPolicy::new(&cfg.skip_paths, &cfg.skip_methods, cfg.fail_open);
                info!(
                    "Loaded WASM plugin '{}' from {} (fail_open={}, skip_paths={}, skip_methods={})",
                    name,
                    cfg.path,
                    cfg.fail_open,
                    cfg.skip_paths.len(),
                    cfg.skip_methods.len(),
                );
                registry.insert(name.clone(), Arc::new(mw.with_policy(policy)));
            }
            Err(e) => error!("Failed to load WASM plugin '{}': {}", name, e),
        }
    }
    registry
}

/// The header conditions Sōzu cannot route on, left for the middleware to
/// enforce. Sōzu takes every other one as a frontend predicate.
pub fn middleware_header_conditions(config: &EntrypointConfig) -> Vec<MatchCondition> {
    config
        .match_headers
        .iter()
        .filter(|condition| header_predicate(condition).is_none())
        .cloned()
        .collect()
}

/// The query conditions left for the middleware to enforce, `None` when
/// there are none: Sōzu routes on them when it can (see `routes_on_query`).
pub fn middleware_query_conditions(config: &EntrypointConfig) -> Option<Vec<MatchCondition>> {
    (!config.match_query.is_empty() && !routes_on_query(config)).then(|| config.match_query.clone())
}

/// Whether `error`, or one it wraps, is a timeout.
pub(crate) fn timed_out(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(err) = current {
        if err
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        current = err.source();
    }
    false
}

/// The index of the backend that gave a response, for its header edits.
#[derive(Clone, Copy)]
pub struct ServedBy(pub usize);

/// Whether the middleware, rather than Sōzu, makes the response header edits
/// of `entrypoint`'s route: those of a backend with edits of its own come
/// after the route's, and Sōzu's would come last.
pub fn edits_responses(entrypoint: &Entrypoint) -> bool {
    // A route Sōzu answers itself keeps them at Sōzu.
    !entrypoint.answers_without_backend()
        && entrypoint.backends.iter().any(|b| !b.headers.is_empty())
}

/// Makes the `edits` going `direction` on `headers`, as Sōzu makes a route's:
/// a set replaces the header, an append adds a value next to it, and an empty
/// value removes it.
pub(crate) fn edit_headers(
    headers: &mut axum::http::HeaderMap,
    edits: &[HeaderConfig],
    direction: HeaderDirection,
) {
    use axum::http::{HeaderName, HeaderValue};
    for edit in edits {
        if edit.direction != direction && edit.direction != HeaderDirection::Both {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(edit.name.as_bytes()) else {
            continue;
        };
        if !edit.append || edit.value.is_empty() {
            headers.remove(&name);
        }
        if let Ok(value) = HeaderValue::from_str(&edit.value)
            && !edit.value.is_empty()
        {
            headers.append(name, value);
        }
    }
}

/// Check if an entrypoint needs middleware processing
pub fn needs_middleware(entrypoint: &Entrypoint) -> bool {
    let config = &entrypoint.config;
    config.answer.is_some()
        || url_rewrite_host(config).is_some()
        || config.backend_timeout.is_some()
        || config.request_timeout.is_some()
        || config.rate_limit.is_some()
        || config.in_flight_req.is_some()
        || config.compress
        || config.forward_auth.is_some()
        || !config.plugins.is_empty()
        || !middleware_header_conditions(config).is_empty()
        || middleware_query_conditions(config).is_some()
        || !config.match_client_ip.is_empty()
        || !config.ip_allow_list.is_empty()
        // Retry is enforced in the middleware proxy handler, so a route that
        // only configures retry still has to go through it.
        || config.retry.as_ref().is_some_and(|r| r.attempts > 1)
        // The circuit breaker is enforced in the middleware proxy handler.
        || config.circuit_breaker.is_some()
        // So is the copy of each request to a mirror.
        || !config.mirrors.is_empty()
        // And the share of requests answered with an error.
        || config.failing_shares.is_some()
        // And the header edits of a backend of its own.
        || edits_responses(entrypoint)
        // And a redirect Sōzu has no status for.
        || answers_redirect(config)
        // And a CORS policy.
        || config.cors.is_some()
}

/// Whether the middleware answers the route's redirect instead of Sōzu: see
/// [`EntrypointConfig::middleware_redirect_status`].
pub fn answers_redirect(config: &EntrypointConfig) -> bool {
    config.middleware_redirect_status().is_some()
}

/// Build middleware route from entrypoint config.
///
/// The stack is assembled in order: **IP allow-list first** (a denied client
/// never reaches anything else), then request-match (reject requests that
/// don't meet header/query conditions), forward-auth, then rate-limit (all
/// before the backend), then compression (on the response).
/// `forward_auth_client` is the shared client from
/// [`build_forward_auth_client`]. `trusted_proxies` comes from the global
/// `ProxyConfig` and gates how `X-Forwarded-For` is interpreted by the
/// allow-list — see [`ip_allow_list`] for the trust model.
pub fn build_middleware_route(
    cluster_id: &str,
    config: &EntrypointConfig,
    backends: &[Backend],
    forward_auth_client: &reqwest::Client,
    plugins: &PluginRegistry,
    trusted_proxies: &TrustedProxies,
) -> Arc<MiddlewareRoute> {
    let mut middlewares: Vec<Arc<dyn Middleware>> = Vec::new();

    // IP allow-list runs *first*: a request from a denied client never reaches
    // request-match, auth, rate-limit, or the backend.
    if !config.ip_allow_list.is_empty() {
        let list = IpAllowList::new(&config.ip_allow_list);
        if list.is_empty() {
            // Every entry was invalid. Skip the middleware so the route stays
            // reachable instead of being silently black-holed; the per-entry
            // warnings are already logged by `IpAllowList::new`.
            warn!(
                "ip_allow_list for entrypoint with hosts {:?} has no valid entries; \
                 middleware not installed (route stays open)",
                config.hostnames
            );
        } else {
            middlewares.push(Arc::new(IpAllowListMiddleware::new(
                list,
                trusted_proxies.clone(),
            )));
        }
    }

    // Header/query/client-IP match conditions run first: a request that doesn't
    // match the route's conditions is rejected (404) before auth, rate-limit, or
    // backend. The client-IP matcher is a *routing* construct (404), not an
    // access filter (403) — that's the `ip_allow_list` middleware above.
    let client_ip = if config.match_client_ip.is_empty() {
        None
    } else {
        let list = IpAllowList::new(&config.match_client_ip);
        if list.is_empty() {
            // Every entry was invalid. Drop the constraint rather than 404 every
            // request; per-entry warnings are already logged by `IpAllowList::new`.
            warn!(
                "match_client_ip for entrypoint with hosts {:?} has no valid entries; \
                 client-IP routing constraint dropped (route stays reachable)",
                config.hostnames
            );
            None
        } else {
            Some(list)
        }
    };
    let match_headers = middleware_header_conditions(config);
    let match_query = middleware_query_conditions(config).unwrap_or_default();
    if !match_headers.is_empty() || !match_query.is_empty() || client_ip.is_some() {
        middlewares.push(Arc::new(RequestMatchMiddleware::new(
            match_headers,
            match_query,
            client_ip,
            trusted_proxies.clone(),
        )));
    }

    // CORS answers the preflight requests it allows before anything else
    // does: they carry no credentials for auth to check.
    let cors = config
        .cors
        .as_ref()
        .map(|cors| Arc::new(cors::CorsMiddleware::new(cors)));
    if let Some(cors) = cors.as_ref() {
        middlewares.push(Arc::clone(cors) as Arc<dyn Middleware>);
    }

    // A route with no valid backend answers the requests it matches, and
    // nothing else runs.
    if let Some(answer) = config.answer {
        middlewares.push(Arc::new(FixedAnswerMiddleware(answer)));
    }

    // So does a route that redirects them with a status Sōzu has not.
    if answers_redirect(config) {
        let (path_rule, rewrite) = crate::proxy::sozu::path_and_rewrite(cluster_id, config);
        if let Some(redirect) = RedirectMiddleware::new(config, &path_rule, rewrite) {
            middlewares.push(Arc::new(redirect));
        }
    }

    if let Some(cfg) = config.forward_auth.as_ref() {
        middlewares.push(Arc::new(ForwardAuthMiddleware::new(
            cfg.clone(),
            forward_auth_client.clone(),
        )));
    }

    if let Some(rl) = config.rate_limit.as_ref() {
        middlewares.push(Arc::new(RateLimitMiddleware::new(
            RateLimiter::new(rl.average, rl.burst),
            trusted_proxies.clone(),
        )));
    }

    if let Some(max) = config.in_flight_req {
        middlewares.push(Arc::new(InFlightReqMiddleware::new(
            InFlightLimiter::new(max),
            trusted_proxies.clone(),
        )));
    }

    // WASM plugins run after the native request-phase middlewares, in the order
    // the entrypoint lists them. An unknown name is logged and skipped. When the
    // route carries per-plugin config (`plugins.<name>.*` labels), the plugin is
    // re-derived with that config merged over its global default; otherwise the
    // shared global instance is used directly.
    for name in &config.plugins {
        match plugins.get(name) {
            Some(mw) => match config.plugin_config.get(name) {
                Some(overlay) => middlewares.push(Arc::new(mw.with_route_config(overlay))),
                None => middlewares.push(Arc::clone(mw) as Arc<dyn Middleware>),
            },
            None => warn!("entrypoint references unknown plugin '{}', skipping", name),
        }
    }

    if config.compress {
        middlewares.push(Arc::new(CompressMiddleware));
    }

    let circuit_breaker = config
        .circuit_breaker
        .map(|cfg| Arc::new(circuit_breaker::CircuitBreaker::new(cfg)));

    let weights: Vec<u32> = backends.iter().map(|b| b.weight).collect();
    Arc::new(MiddlewareRoute {
        cluster_id: cluster_id.to_string(),
        backends: backends
            .iter()
            .map(|b| (b.address.clone(), b.port))
            .collect(),
        balancer: WeightedRoundRobin::new(&weights),
        algorithm: config.load_balancer,
        in_flight: backends
            .iter()
            .map(|b| backend_load(&(b.address.clone(), b.port)))
            .collect(),
        backups: backup_indexes(&weights),
        backend_headers: backends.iter().map(|b| b.headers.clone()).collect(),
        response_headers: if config.redirect.is_none_or(|r| !r.answers_without_backend())
            && backends.iter().any(|b| !b.headers.is_empty())
        {
            config
                .headers
                .iter()
                .filter(|h| h.direction != HeaderDirection::Request)
                .cloned()
                .collect()
        } else {
            Vec::new()
        },
        backend_timeout: config.backend_timeout,
        request_timeout: config.request_timeout,
        retry_attempts: config.retry.as_ref().map_or(1, |r| r.attempts.max(1)),
        circuit_breaker,
        middlewares,
        rewrite_host: url_rewrite_host(config).map(str::to_string),
        mirrors: config.mirrors.iter().map(MirrorTarget::new).collect(),
        failing_shares: config
            .failing_shares
            .map(|s| WeightedRoundRobin::new(&[s.forwarded, s.invalid, s.unavailable])),
        cors,
    })
}

/// The host a route's URL rewrite gives the request. The middleware applies
/// it: Sōzu's own host rewrite sends the backend two `Host` headers, which
/// many servers refuse.
pub fn url_rewrite_host(config: &EntrypointConfig) -> Option<&str> {
    config.rewrite.as_ref()?.hostname.as_deref()
}

/// Start the middleware reverse proxy server
pub async fn serve(
    port: u16,
    route_table: MiddlewareState,
    request_metrics: crate::proxy::request_metrics::RequestMetricsStore,
) -> anyhow::Result<()> {
    let app_state = MiddlewareAppState {
        route_table,
        http_client: Client::builder(TokioExecutor::new()).build_http(),
        request_metrics,
        passive_health: Arc::default(),
    };

    let app = Router::new()
        .fallback(any(proxy::handle_proxy))
        .with_state(app_state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("Middleware server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod route_key_tests {
    use super::*;

    #[test]
    fn a_mirror_copies_its_fraction_of_the_requests() {
        let copies = |fraction: Option<crate::model::MirrorFraction>, requests: usize| {
            let mirror = MirrorTarget::new(&crate::model::Mirror {
                backends: Vec::new(),
                fraction,
            });
            (0..requests).filter(|_| mirror.copies_next()).count()
        };
        let fraction = |numerator, denominator| {
            Some(crate::model::MirrorFraction {
                numerator,
                denominator,
            })
        };
        assert_eq!(copies(None, 10), 10);
        assert_eq!(copies(fraction(0, 100), 1000), 0);
        assert_eq!(copies(fraction(100, 100), 1000), 1000);
        // A numerator past the denominator copies every request.
        assert_eq!(copies(fraction(5, 2), 1000), 1000);
        // About the share asked for, drawn at random.
        let copied = copies(fraction(20, 100), 10_000);
        assert!((1_500..=2_500).contains(&copied), "{copied}");
        let copied = copies(fraction(1, 3), 9_000);
        assert!((2_500..=3_500).contains(&copied), "{copied}");
    }

    /// A route over backends `b0`, `b1`… with these weights.
    #[test]
    fn edit_headers_sets_appends_and_removes() {
        let edit = |name: &str, value: &str, append: bool| HeaderConfig {
            name: name.into(),
            value: value.into(),
            direction: HeaderDirection::Request,
            append,
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-set", "old".parse().unwrap());
        headers.insert("x-add", "old".parse().unwrap());
        headers.insert("x-gone", "old".parse().unwrap());
        let edits = [
            edit("X-Set", "new", false),
            edit("X-Add", "new", true),
            edit("X-Gone", "", false),
            HeaderConfig {
                direction: HeaderDirection::Response,
                ..edit("X-Response", "no", false)
            },
        ];
        edit_headers(&mut headers, &edits, HeaderDirection::Request);
        assert_eq!(headers.get_all("x-set").iter().collect::<Vec<_>>(), ["new"]);
        assert_eq!(
            headers.get_all("x-add").iter().collect::<Vec<_>>(),
            ["old", "new"]
        );
        assert!(!headers.contains_key("x-gone"));
        assert!(!headers.contains_key("x-response"));
    }

    /// The route's response edits come first, then those of the backend that
    /// answered.
    #[test]
    fn edit_response_makes_the_route_edits_then_the_backend_ones() {
        let set = |value: &str| HeaderConfig {
            name: "X-Edit".into(),
            value: value.into(),
            direction: HeaderDirection::Response,
            append: false,
        };
        let mut route = weighted_route(&[1, 1]);
        route.response_headers = vec![set("route")];
        route.backend_headers = vec![vec![set("backend")], Vec::new()];

        let mut served = axum::response::Response::new(axum::body::Body::empty());
        served.extensions_mut().insert(ServedBy(0));
        route.edit_response(&mut served);
        assert_eq!(served.headers()["x-edit"], "backend");

        let mut local = axum::response::Response::new(axum::body::Body::empty());
        route.edit_response(&mut local);
        assert_eq!(local.headers()["x-edit"], "route");
    }

    fn weighted_route(weights: &[u32]) -> MiddlewareRoute {
        MiddlewareRoute {
            cluster_id: "web".to_string(),
            backends: (0..weights.len()).map(|i| (format!("b{i}"), 80)).collect(),
            balancer: WeightedRoundRobin::new(weights),
            algorithm: LoadBalancer::RoundRobin,
            in_flight: weights.iter().map(|_| Default::default()).collect(),
            backups: backup_indexes(weights),
            backend_timeout: None,
            request_timeout: None,
            retry_attempts: 1,
            circuit_breaker: None,
            middlewares: Vec::new(),
            rewrite_host: None,
            mirrors: Vec::new(),
            failing_shares: None,
            cors: None,
            backend_headers: Vec::new(),
            response_headers: Vec::new(),
        }
    }

    fn with_algorithm(weights: &[u32], algorithm: LoadBalancer) -> MiddlewareRoute {
        MiddlewareRoute {
            algorithm,
            ..weighted_route(weights)
        }
    }

    fn load(route: &MiddlewareRoute, loads: &[usize]) {
        for (n, &load) in route.in_flight.iter().zip(loads) {
            n.store(load, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// `random` picks in proportion to the weights, among eligible backends.
    #[test]
    fn random_picks_by_weight() {
        let route = with_algorithm(&[3, 1, 5], LoadBalancer::Random);
        let mut counts = [0; 3];
        for _ in 0..4000 {
            counts[route.pick(|index| index != 2).unwrap()] += 1;
        }
        assert_eq!(counts[2], 0);
        assert!((2700..3300).contains(&counts[0]), "{counts:?}");
    }

    /// `least_connections` picks the backend with the fewest requests
    /// waiting for its answer, for its weight.
    #[test]
    fn least_connections_picks_the_least_loaded() {
        let route = with_algorithm(&[1, 1], LoadBalancer::LeastConnections);
        load(&route, &[2, 0]);
        assert_eq!(route.pick(|_| true), Some(1));
        // Twice the weight takes twice the load.
        let route = with_algorithm(&[2, 1], LoadBalancer::LeastConnections);
        load(&route, &[1, 1]);
        assert_eq!(route.pick(|_| true), Some(0));
        load(&route, &[3, 1]);
        assert_eq!(route.pick(|_| true), Some(1));
        assert_eq!(route.pick(|index| index == 0), Some(0));
    }

    /// `power_of_two` keeps the less loaded of two picks.
    #[test]
    fn power_of_two_avoids_the_loaded_backend() {
        let route = with_algorithm(&[1, 1], LoadBalancer::PowerOfTwo);
        load(&route, &[10, 0]);
        let loaded = (0..1000)
            .filter(|_| route.pick(|_| true) == Some(0))
            .count();
        // The two picks are distinct backends: the idle one always wins.
        assert_eq!(loaded, 0);
    }

    /// Equal loads leave the weights to share the traffic: on a quiet route
    /// nothing is ever waiting.
    #[test]
    fn least_connections_ties_go_by_weight() {
        let route = with_algorithm(&[9, 1], LoadBalancer::LeastConnections);
        let first = (0..2000)
            .filter(|_| route.pick(|_| true) == Some(0))
            .count();
        assert!((1700..1900).contains(&first), "{first}");
    }

    /// A request waiting for a backend counts until its guard goes.
    #[test]
    fn waiting_counts_until_dropped() {
        let route = with_algorithm(&[1, 1], LoadBalancer::LeastConnections);
        let waiting = route.waiting_on(0);
        assert_eq!(route.pick(|_| true), Some(1));
        drop(waiting);
        assert_eq!(
            route.in_flight[0].load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// A route rebuilt on a reload sees the requests still waiting on the
    /// one it replaces.
    #[test]
    fn load_survives_a_rebuild() {
        let backend = ("load-survives-a-rebuild".to_string(), 80);
        let old = backend_load(&backend);
        old.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let new = backend_load(&backend);
        assert_eq!(new.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop((old, new));
        // Nothing holds it any more: a later route starts from zero.
        assert_eq!(
            backend_load(&backend).load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// The backends a request tries when every one of them fails.
    fn tried(route: &MiddlewareRoute, attempts: u32) -> Vec<String> {
        tried_with(route, attempts, &passive_health::PassiveHealth::default())
    }

    fn tried_with(
        route: &MiddlewareRoute,
        attempts: u32,
        health: &passive_health::PassiveHealth,
    ) -> Vec<String> {
        route
            .attempts(attempts, health)
            .take(10)
            .map(|(host, _)| host.clone())
            .collect()
    }

    /// A backend left out after failing is not picked while another one can
    /// be; when every one is, they are tried all the same.
    #[test]
    fn a_backend_left_out_comes_after_the_others() {
        let health = passive_health::PassiveHealth::default();
        let down = |host: &str| {
            for _ in 0..passive_health::MAX_FAILURES {
                health.failed(&(host.to_string(), 80));
            }
        };
        down("b0");
        let route = weighted_route(&[100, 100]);
        for _ in 0..4 {
            assert_eq!(tried_with(&route, 1, &health), ["b1"]);
        }
        assert_eq!(tried_with(&route, 2, &health), ["b1", "b0"]);
        down("b1");
        assert_eq!(tried_with(&route, 1, &health).len(), 1);

        // The others keep their ratios.
        let health = passive_health::PassiveHealth::default();
        for _ in 0..passive_health::MAX_FAILURES {
            health.failed(&("b2".to_string(), 80));
        }
        let route = weighted_route(&[100, 100, 100]);
        let mut picks = std::collections::HashMap::new();
        for _ in 0..100 {
            *picks
                .entry(tried_with(&route, 1, &health)[0].clone())
                .or_insert(0) += 1;
        }
        assert_eq!(picks.get("b0"), Some(&50));
        assert_eq!(picks.get("b1"), Some(&50));

        // However much heavier the backend left out.
        let health = passive_health::PassiveHealth::default();
        for _ in 0..passive_health::MAX_FAILURES {
            health.failed(&("b0".to_string(), 80));
        }
        let route = weighted_route(&[100_000, 1]);
        assert_eq!(tried_with(&route, 1, &health), ["b1"]);

        // A backup when every other backend is left out.
        let route = weighted_route(&[100, 0]);
        assert_eq!(tried_with(&route, 1, &health), ["b1", "b0"]);

        // On a retry too, before the backend left out.
        let health = passive_health::PassiveHealth::default();
        for _ in 0..passive_health::MAX_FAILURES {
            health.failed(&("b1".to_string(), 80));
        }
        let route = weighted_route(&[100, 50, 0]);
        assert_eq!(tried_with(&route, 2, &health)[..2], ["b0", "b2"]);
    }

    #[test]
    fn without_retry_or_backup_a_request_tries_one_backend() {
        assert_eq!(tried(&weighted_route(&[100, 100]), 1), ["b0"]);
        assert!(tried(&weighted_route(&[]), 3).is_empty());
    }

    /// A heavy backend that is down must not take every retry.
    #[test]
    fn a_retry_goes_to_a_backend_not_tried_yet() {
        assert_eq!(tried(&weighted_route(&[100, 1]), 2), ["b0", "b1"]);
        assert_eq!(tried(&weighted_route(&[1, 100, 50]), 3), ["b1", "b2", "b0"]);
    }

    /// Once every backend was tried, the balancer picks again.
    #[test]
    fn retries_beyond_the_backends_go_back_to_the_balancer() {
        assert_eq!(
            tried(&weighted_route(&[100, 100]), 4),
            ["b0", "b1", "b1", "b0"]
        );
    }

    /// A backup serves only once every other backend failed, retry or not.
    #[test]
    fn backups_come_after_every_other_backend() {
        let route = weighted_route(&[100, 0, 50, 0]);
        assert_eq!(tried(&route, 1), ["b0", "b2", "b1", "b3"]);
        assert_eq!(tried(&route, 2), ["b2", "b0", "b1", "b3"]);
        assert_eq!(tried(&route, 3), ["b0", "b2", "b0", "b1", "b3"]);
    }

    /// With every weight at 0 there is no backup: they share the traffic.
    #[test]
    fn all_zero_weights_are_plain_backends() {
        assert_eq!(tried(&weighted_route(&[0, 0]), 1), ["b0"]);
        assert_eq!(tried(&weighted_route(&[0, 0]), 2), ["b0", "b1"]);
    }

    fn picks(weights: &[u32], count: usize) -> Vec<usize> {
        let balancer = WeightedRoundRobin::new(weights);
        (0..count).filter_map(|_| balancer.next()).collect()
    }

    /// Sōzu's smooth weighted round robin: shares follow the weights and the
    /// picks interleave instead of bunching.
    #[test]
    fn backends_take_requests_in_proportion_to_their_weight() {
        assert_eq!(picks(&[5, 1, 1], 7), [0, 0, 1, 0, 2, 0, 0]);
        assert_eq!(
            picks(&[90, 10], 100).iter().filter(|&&i| i == 1).count(),
            10
        );
        assert_eq!(picks(&[100, 100, 100], 6), [0, 1, 2, 0, 1, 2]);
        assert!(picks(&[], 3).is_empty());
    }

    /// Weights past `i32::MAX` are capped there, as Sōzu caps them.
    #[test]
    fn weights_are_capped_as_sozu_caps_them() {
        assert_eq!(picks(&[u32::MAX, u32::MAX / 2 + 1], 4), [0, 1, 0, 1]);
    }

    /// Large weights keep their exact ratio.
    #[test]
    fn large_weights_keep_their_ratio() {
        let light = picks(&[100_000, 1], 200_002)
            .iter()
            .filter(|&&i| i == 1)
            .count();
        assert_eq!(light, 2);
    }

    #[test]
    fn a_zero_weight_is_a_backup_unless_all_are_zero() {
        assert_eq!(picks(&[0, 100], 3), [1, 1, 1]);
        assert_eq!(backup_indexes(&[0, 100]), [0]);
        assert_eq!(picks(&[0, 0], 4), [0, 1, 0, 1]);
        assert!(backup_indexes(&[0, 0]).is_empty());
    }

    /// Sozu routes on host *and* path and hands the request to the middleware
    /// server, which used to resolve it by host alone. Two entrypoints on one
    /// hostname therefore collapsed into whichever was inserted last, decided
    /// by cluster-id order:
    ///
    /// ```text
    /// api: app.example.com /api  rateLimit=10
    /// web: app.example.com /     compress
    /// ```
    ///
    /// `GET /api/users` was matched by Sozu against the /api frontend, then
    /// sent to *web's* backends with web's middleware stack — the rate limit
    /// never ran. An ip_allow_list or forward_auth on the losing route was
    /// dropped the same way, silently.
    #[test]
    fn the_longest_matching_prefix_wins() {
        let candidates = vec![
            (Some(PathMatch::prefix("/api")), ()),
            (Some(PathMatch::prefix("/")), ()),
        ];

        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/index.html"), Some(1));
    }

    /// `PathConfig` carries a rule type, and only `Prefix` covers what sits
    /// below it. Keeping just the string treated an `Exact` route as a prefix,
    /// so `/api/users` matched a route declared to serve `/api` alone — and a
    /// `Regex` became a literal prefix that normally matches nothing, which is
    /// worse than what host-only resolution did for those routes.
    #[test]
    fn an_exact_path_does_not_swallow_what_is_below_it() {
        let exact = vec![(Some(PathMatch::exact("/api")), ())];

        assert_eq!(best_match(&exact, "/api"), Some(0));
        assert_eq!(best_match(&exact, "/api/users"), None);
    }

    /// A regex route matches what the regex says, not what its source text
    /// looks like as a prefix.
    #[test]
    fn a_regex_path_matches_by_pattern() {
        let regex = vec![(Some(PathMatch::regex("^/api/v[0-9]+/")), ())];

        assert_eq!(best_match(&regex, "/api/v2/users"), Some(0));
        assert_eq!(best_match(&regex, "/api/users"), None);
    }

    /// An unparseable regex must not silently become a catch-all: it matches
    /// nothing, so the route stays dark rather than swallowing the hostname.
    #[test]
    fn an_unparseable_regex_matches_nothing() {
        let broken = vec![(Some(PathMatch::regex("^/api/v[0-9")), ())];

        assert_eq!(best_match(&broken, "/api/v2/users"), None);
    }

    /// A route with no path serves everything under the hostname, so it is the
    /// catch-all and must lose to any prefix that matches.
    #[test]
    fn a_pathless_route_is_the_catch_all() {
        let candidates = vec![(Some(PathMatch::prefix("/api")), ()), (None, ())];

        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/other"), Some(1));
    }

    /// A prefix only matches on a segment boundary: /apifoo is not under /api,
    /// or a route would capture hostnames it was never given.
    #[test]
    fn a_prefix_matches_only_on_a_segment_boundary() {
        let candidates = vec![(Some(PathMatch::prefix("/api")), ())];

        assert_eq!(best_match(&candidates, "/api"), Some(0));
        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/apifoo"), None);
    }

    fn backend_named(name: &str) -> Arc<MiddlewareRoute> {
        Arc::new(MiddlewareRoute {
            cluster_id: name.to_string(),
            backends: vec![(name.to_string(), 80)],
            balancer: WeightedRoundRobin::new(&[100]),
            algorithm: LoadBalancer::RoundRobin,
            in_flight: vec![Default::default()],
            backups: Vec::new(),
            backend_timeout: None,
            request_timeout: None,
            retry_attempts: 1,
            circuit_breaker: None,
            middlewares: Vec::new(),
            rewrite_host: None,
            mirrors: Vec::new(),
            failing_shares: None,
            cors: None,
            backend_headers: Vec::new(),
            response_headers: Vec::new(),
        })
    }

    fn routed_to(table: &MiddlewareRouteTable, host: &str, path: &str) -> Option<String> {
        table
            .get_route(host, path)
            .map(|route| route.backends[0].0.clone())
    }

    /// The route named by the frontend wins over a host and path lookup,
    /// which cannot tell two routes on the same host and path apart.
    #[test]
    fn a_route_is_found_by_the_id_sozu_names() {
        let mut table = MiddlewareRouteTable::default();
        table.update_routes_for_entrypoint(
            &["app.example.com".to_string()],
            None,
            backend_named("a"),
        );
        table.update_routes_for_entrypoint(
            &["app.example.com".to_string()],
            None,
            backend_named("b"),
        );

        assert_eq!(table.route_for_cluster("b").unwrap().cluster_id, "b");
        assert!(table.route_for_cluster("c").is_none());

        table.clear();
        assert!(table.route_for_cluster("b").is_none());
    }

    /// Sozu matches a wildcard or regex hostname and forwards the request with
    /// the host it was sent to. Keyed on the pattern alone, the table found no
    /// route for that host and the middleware answered 502.
    #[test]
    fn a_pattern_hostname_resolves_the_host_it_matched() {
        let mut table = MiddlewareRouteTable::default();
        table.update_routes_for_entrypoint(
            &["*.example.com".to_string()],
            None,
            backend_named("wild"),
        );
        table.update_routes_for_entrypoint(
            &["/node[0-9]+/.example.org".to_string()],
            None,
            backend_named("regex"),
        );

        assert_eq!(
            routed_to(&table, "app.example.com", "/").as_deref(),
            Some("wild")
        );
        assert_eq!(
            routed_to(&table, "node7.example.org:8080", "/").as_deref(),
            Some("regex")
        );
        assert_eq!(routed_to(&table, "a.b.example.com", "/"), None);
        assert_eq!(routed_to(&table, "nodex.example.org", "/"), None);
    }

    /// A literal hostname is tried before any pattern, and when none of its
    /// paths match the request falls through to a pattern that covers it, as
    /// it does in Sozu.
    #[test]
    fn a_literal_hostname_comes_before_the_patterns_covering_it() {
        let mut table = MiddlewareRouteTable::default();
        table.update_routes_for_entrypoint(
            &["*.example.com".to_string()],
            None,
            backend_named("wild"),
        );
        table.update_routes_for_entrypoint(
            &["app.example.com".to_string()],
            Some(&crate::model::PathConfig {
                value: "/admin".to_string(),
                rule_type: crate::model::PathRuleType::Prefix,
            }),
            backend_named("admin"),
        );

        assert_eq!(
            routed_to(&table, "app.example.com", "/admin/users").as_deref(),
            Some("admin")
        );
        assert_eq!(
            routed_to(&table, "app.example.com", "/").as_deref(),
            Some("wild")
        );
    }

    /// Patterns are tried in the order they were added, which is the order
    /// Sozu checks its rules in.
    #[test]
    fn overlapping_patterns_resolve_in_insertion_order() {
        let mut table = MiddlewareRouteTable::default();
        table.update_routes_for_entrypoint(
            &["*.example.com".to_string()],
            None,
            backend_named("first"),
        );
        table.update_routes_for_entrypoint(
            &["/[a-z]+/.example.com".to_string()],
            None,
            backend_named("second"),
        );

        assert_eq!(
            routed_to(&table, "app.example.com", "/").as_deref(),
            Some("first")
        );
    }

    /// Nothing matches: the caller answers 404 rather than picking a route at
    /// random, which is what host-only keying amounted to.
    #[test]
    fn no_candidate_matches() {
        let candidates = vec![
            (Some(PathMatch::prefix("/api")), ()),
            (Some(PathMatch::prefix("/admin")), ()),
        ];

        assert_eq!(best_match(&candidates, "/"), None);
    }
}
