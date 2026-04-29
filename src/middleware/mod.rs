mod compress;
mod diag;
mod proxy;
pub mod rate_limit;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::{Router, routing::any};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::info;

use crate::model::EntrypointConfig;
use rate_limit::RateLimiter;

/// Shared state for the middleware server
#[derive(Clone)]
pub struct MiddlewareAppState {
    pub route_table: Arc<RwLock<MiddlewareRouteTable>>,
    pub http_client: Client<hyper_util::client::legacy::connect::HttpConnector, axum::body::Body>,
}

pub type MiddlewareState = Arc<RwLock<MiddlewareRouteTable>>;

/// Route table mapping hostname → middleware config + real backends
#[derive(Debug, Default)]
pub struct MiddlewareRouteTable {
    pub(super) routes: std::collections::HashMap<String, Arc<MiddlewareRoute>>,
}

/// Middleware configuration for a single entrypoint
#[derive(Debug)]
pub struct MiddlewareRoute {
    pub backends: Vec<(String, u16)>,
    pub backend_counter: AtomicUsize,
    pub backend_timeout: Option<u64>,
    pub rate_limiter: Option<RateLimiter>,
    pub compress: bool,
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

/// Check if an entrypoint needs middleware processing
pub fn needs_middleware(config: &EntrypointConfig) -> bool {
    config.backend_timeout.is_some() || config.rate_limit.is_some() || config.compress
}

/// Build middleware route from entrypoint config
pub fn build_middleware_route(
    config: &EntrypointConfig,
    backends: &[String],
) -> Arc<MiddlewareRoute> {
    let rate_limiter = config
        .rate_limit
        .as_ref()
        .map(|rl| RateLimiter::new(rl.average, rl.burst));

    Arc::new(MiddlewareRoute {
        backends: backends.iter().map(|b| (b.clone(), config.port)).collect(),
        backend_counter: AtomicUsize::new(0),
        backend_timeout: config.backend_timeout,
        rate_limiter,
        compress: config.compress,
    })
}

/// Start the middleware reverse proxy server
pub async fn serve(port: u16, route_table: MiddlewareState) -> anyhow::Result<()> {
    let app_state = MiddlewareAppState {
        route_table,
        http_client: Client::builder(TokioExecutor::new()).build_http(),
    };

    let app = Router::new()
        .fallback(any(proxy::handle_proxy))
        .with_state(app_state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("Middleware server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
