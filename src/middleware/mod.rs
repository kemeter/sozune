pub mod chain;
mod compress;
mod diag;
mod forward_auth;
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
#[derive(Debug, Default)]
pub struct MiddlewareRouteTable {
    pub(super) routes: std::collections::HashMap<String, Arc<MiddlewareRoute>>,
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

impl MiddlewareRouteTable {
    pub fn update_routes_for_entrypoint(
        &mut self,
        hostnames: &[String],
        route: Arc<MiddlewareRoute>,
    ) {
        for hostname in hostnames {
            self.routes.insert(hostname.clone(), Arc::clone(&route));
        }
    }

    pub fn clear(&mut self) {
        self.routes.clear();
    }

    pub fn get_route_by_host(&self, host: &str) -> Option<Arc<MiddlewareRoute>> {
        // Strip port from host header if present (e.g. "example.com:8080" -> "example.com")
        let hostname = host.split(':').next().unwrap_or(host);
        self.routes.get(hostname).cloned()
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
/// once at startup and shared across every route that references it.
pub type PluginRegistry = std::collections::HashMap<String, Arc<dyn Middleware>>;

/// Compile every declared plugin into a shareable middleware. A plugin that
/// fails to load (missing file, bad wasm) is logged and skipped, so one broken
/// plugin doesn't take down routing.
pub fn build_plugin_registry(
    declared: &std::collections::HashMap<String, crate::config::PluginConfig>,
    fetch_client: &reqwest::Client,
    handle: &tokio::runtime::Handle,
) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    for (name, cfg) in declared {
        let wasm = match std::fs::read(&cfg.path) {
            Ok(w) => w,
            Err(e) => {
                error!("Cannot read WASM plugin '{}' at {}: {}", name, cfg.path, e);
                continue;
            }
        };
        let config_bytes = serde_json::to_vec(&cfg.config).unwrap_or_default();
        let limits = http_wasm_host::Limits::default();

        // A plugin with declared allowed_hosts opts into the outbound-HTTP
        // extension; otherwise it gets the standard sandbox with no network.
        let built = if cfg.allowed_hosts.is_empty() {
            wasm::WasmMiddleware::from_bytes(&wasm, config_bytes, limits)
        } else {
            wasm::WasmMiddleware::from_bytes_with_network(
                &wasm,
                config_bytes,
                limits,
                fetch_client.clone(),
                handle.clone(),
                cfg.allowed_hosts.clone(),
            )
        };

        match built {
            Ok(mw) => {
                info!("Loaded WASM plugin '{}' from {}", name, cfg.path);
                registry.insert(name.clone(), Arc::new(mw));
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
        || config.compress
        || config.forward_auth.is_some()
        || !config.plugins.is_empty()
        || !config.match_headers.is_empty()
        || !config.match_query.is_empty()
        || !config.match_client_ip.is_empty()
        || !config.ip_allow_list.is_empty()
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
        middlewares.push(Arc::new(RateLimitMiddleware::new(RateLimiter::new(
            rl.average, rl.burst,
        ))));
    }

    // WASM plugins run after the native request-phase middlewares, in the order
    // the entrypoint lists them. An unknown name is logged and skipped.
    for name in &config.plugins {
        match plugins.get(name) {
            Some(mw) => middlewares.push(Arc::clone(mw)),
            None => warn!("entrypoint references unknown plugin '{}', skipping", name),
        }
    }

    if config.compress {
        middlewares.push(Arc::new(CompressMiddleware));
    }

    Arc::new(MiddlewareRoute {
        backends: backends
            .iter()
            .map(|b| (b.address.clone(), b.port))
            .collect(),
        backend_counter: AtomicUsize::new(0),
        backend_timeout: config.backend_timeout,
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
