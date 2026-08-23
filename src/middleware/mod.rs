pub mod chain;
pub mod circuit_breaker;
mod compress;
mod diag;
mod forward_auth;
pub mod in_flight_req;
pub mod ip_allow_list;
mod proxy;
pub mod rate_limit;
mod request_match;
mod wasm;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::{Router, routing::any};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{error, info, warn};

use crate::model::{Backend, EntrypointConfig};
use chain::Middleware;
use compress::CompressMiddleware;
use forward_auth::ForwardAuthMiddleware;
use in_flight_req::{InFlightLimiter, InFlightReqMiddleware};
use ip_allow_list::{IpAllowList, IpAllowListMiddleware, TrustedProxies};
use rate_limit::{RateLimitMiddleware, RateLimiter};
use request_match::RequestMatchMiddleware;

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
}

pub type MiddlewareState = Arc<RwLock<MiddlewareRouteTable>>;

/// Route table mapping hostname → middleware config + real backends
/// The routes one hostname carries, each with the path prefix it was declared
/// with. `None` is a route with no path: the catch-all for that hostname.
type HostRoutes = Vec<(Option<String>, Arc<MiddlewareRoute>)>;

#[derive(Debug, Default)]
pub struct MiddlewareRouteTable {
    /// Keyed by hostname, but a hostname can carry several routes: Sozu routes
    /// on host *and* path, so one entry per hostname would drop all but the
    /// last one stored.
    pub(super) routes: std::collections::HashMap<String, HostRoutes>,
}

/// Middleware configuration for a single entrypoint.
///
/// The middleware stack is an ordered list run before (and after) the backend.
/// `backend_timeout` is not a middleware — it's a property of the backend
/// forward itself — so it stays a plain field.
pub struct MiddlewareRoute {
    pub backends: Vec<(String, u16)>,
    pub backend_counter: AtomicUsize,
    pub backend_timeout: Option<u64>,
    /// Total forward attempts (first try + retries) on a connection-level
    /// failure or timeout. `1` (or `0`) means no retry — the default.
    pub retry_attempts: u32,
    /// Per-route circuit breaker, shared across requests so its state persists.
    /// `None` when the route doesn't configure one.
    pub circuit_breaker: Option<Arc<circuit_breaker::CircuitBreaker>>,
    pub middlewares: Vec<Arc<dyn Middleware>>,
}

impl std::fmt::Debug for MiddlewareRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareRoute")
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
fn best_match(candidates: &[Option<String>], request_path: &str) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, path)| match path {
            Some(prefix) => prefix_matches(prefix, request_path),
            None => true,
        })
        .max_by_key(|(_, path)| path.as_deref().map(str::len).unwrap_or(0))
        .map(|(index, _)| index)
}

impl MiddlewareRouteTable {
    pub fn update_routes_for_entrypoint(
        &mut self,
        hostnames: &[String],
        path: Option<String>,
        route: Arc<MiddlewareRoute>,
    ) {
        for hostname in hostnames {
            self.routes
                .entry(hostname.clone())
                .or_default()
                .push((path.clone(), Arc::clone(&route)));
        }
    }

    pub fn clear(&mut self) {
        self.routes.clear();
    }

    pub fn get_route(&self, host: &str, request_path: &str) -> Option<Arc<MiddlewareRoute>> {
        // Strip port from host header if present (e.g. "example.com:8080" -> "example.com")
        let hostname = host.split(':').next().unwrap_or(host);
        let candidates = self.routes.get(hostname)?;

        let paths: Vec<Option<String>> = candidates.iter().map(|(p, _)| p.clone()).collect();
        best_match(&paths, request_path).map(|index| Arc::clone(&candidates[index].1))
    }

    pub fn known_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.routes.keys().cloned().collect();
        hosts.sort();
        hosts
    }
}

impl MiddlewareRoute {
    /// Pick the next backend using round-robin
    pub fn next_backend(&self) -> Option<&(String, u16)> {
        if self.backends.is_empty() {
            return None;
        }
        let index = self.backend_counter.fetch_add(1, Ordering::Relaxed) % self.backends.len();
        self.backends.get(index)
    }
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

/// Check if an entrypoint needs middleware processing
pub fn needs_middleware(config: &EntrypointConfig) -> bool {
    config.backend_timeout.is_some()
        || config.rate_limit.is_some()
        || config.in_flight_req.is_some()
        || config.compress
        || config.forward_auth.is_some()
        || !config.plugins.is_empty()
        || !config.match_headers.is_empty()
        || !config.match_query.is_empty()
        || !config.match_client_ip.is_empty()
        || !config.ip_allow_list.is_empty()
        // Retry is enforced in the middleware proxy handler, so a route that
        // only configures retry still has to go through it.
        || config.retry.as_ref().is_some_and(|r| r.attempts > 1)
        // The circuit breaker is enforced in the middleware proxy handler.
        || config.circuit_breaker.is_some()
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
    if !config.match_headers.is_empty() || !config.match_query.is_empty() || client_ip.is_some() {
        middlewares.push(Arc::new(RequestMatchMiddleware::new(
            config.match_headers.clone(),
            config.match_query.clone(),
            client_ip,
            trusted_proxies.clone(),
        )));
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
        middlewares.push(Arc::new(InFlightReqMiddleware::new(InFlightLimiter::new(
            max,
        ))));
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

    Arc::new(MiddlewareRoute {
        backends: backends
            .iter()
            .map(|b| (b.address.clone(), b.port))
            .collect(),
        backend_counter: AtomicUsize::new(0),
        backend_timeout: config.backend_timeout,
        retry_attempts: config.retry.as_ref().map_or(1, |r| r.attempts.max(1)),
        circuit_breaker,
        middlewares,
    })
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
        let candidates = vec![Some("/api".to_string()), Some("/".to_string())];

        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/index.html"), Some(1));
    }

    /// A route with no path serves everything under the hostname, so it is the
    /// catch-all and must lose to any prefix that matches.
    #[test]
    fn a_pathless_route_is_the_catch_all() {
        let candidates = vec![Some("/api".to_string()), None];

        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/other"), Some(1));
    }

    /// A prefix only matches on a segment boundary: /apifoo is not under /api,
    /// or a route would capture hostnames it was never given.
    #[test]
    fn a_prefix_matches_only_on_a_segment_boundary() {
        let candidates = vec![Some("/api".to_string())];

        assert_eq!(best_match(&candidates, "/api"), Some(0));
        assert_eq!(best_match(&candidates, "/api/users"), Some(0));
        assert_eq!(best_match(&candidates, "/apifoo"), None);
    }

    /// Nothing matches: the caller answers 404 rather than picking a route at
    /// random, which is what host-only keying amounted to.
    #[test]
    fn no_candidate_matches() {
        let candidates = vec![Some("/api".to_string()), Some("/admin".to_string())];

        assert_eq!(best_match(&candidates, "/"), None);
    }
}
