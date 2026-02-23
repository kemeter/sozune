mod auth;
mod headers;
mod proxy;
mod strip_prefix;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::{Router, routing::any};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::info;

use crate::model::{BasicAuthUser, EntrypointConfig};

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
    pub(super) routes: HashMap<String, Arc<MiddlewareRoute>>,
}

/// Middleware configuration for a single entrypoint
#[derive(Debug)]
pub struct MiddlewareRoute {
    pub backends: Vec<(String, u16)>,
    pub backend_counter: AtomicUsize,
    pub auth: Option<Vec<BasicAuthUser>>,
    pub headers: HashMap<String, String>,
    pub strip_prefix: Option<String>,
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
    config.strip_prefix || config.auth.is_some() || !config.headers.is_empty()
}

/// Build middleware route from entrypoint config
pub fn build_middleware_route(
    config: &EntrypointConfig,
    backends: &[String],
) -> Arc<MiddlewareRoute> {
    let strip_prefix = if config.strip_prefix {
        config.path.as_ref().map(|p| p.value.clone())
    } else {
        None
    };

    Arc::new(MiddlewareRoute {
        backends: backends.iter().map(|b| (b.clone(), config.port)).collect(),
        backend_counter: AtomicUsize::new(0),
        auth: config.auth.as_ref().and_then(|a| a.basic.clone()),
        headers: config.headers.clone(),
        strip_prefix,
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
