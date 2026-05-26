use axum::body::Body;
use axum::http::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;

use super::compress::Encoding;

/// Shared per-request context passed to every middleware. Holds values that
/// middlewares need but don't carry on the request itself (client address,
/// resolved host, the negotiated response encoding picked from the request's
/// `Accept-Encoding` but applied on the response).
pub struct RequestCtx {
    pub host: String,
    pub client_addr: Option<SocketAddr>,
    pub is_tls: bool,
    /// Encoding negotiated from the request, consumed by the compression
    /// middleware on the response side. `None` if the client accepts nothing
    /// we support.
    pub client_encoding: Option<Encoding>,
    /// Response headers staged during the request phase (a WASM guest can set
    /// response headers from `handle_request`). Applied to the final response
    /// on the way out. `(lowercase_name, value)` pairs.
    pub pending_response_headers: Vec<(String, String)>,
}

/// Outcome of a middleware's request phase.
pub enum Flow {
    /// Proceed down the chain. The middleware may have mutated the request
    /// (e.g. forward-auth stamping headers).
    Continue,
    /// Stop here: return this response to the client. The backend and any
    /// later middlewares are skipped.
    ShortCircuit(Response<Body>),
}

/// A single middleware in the pipeline.
///
/// `on_request` runs before the backend (in chain order) and may mutate the
/// request or short-circuit. `on_response` runs after the backend (in reverse
/// order, onion-style) and transforms the response.
#[async_trait::async_trait]
pub trait Middleware: Send + Sync {
    /// Stable identifier used in logs and diagnostics.
    fn name(&self) -> &'static str;

    async fn on_request(&self, _ctx: &mut RequestCtx, _req: &mut Request<Body>) -> Flow {
        Flow::Continue
    }

    async fn on_response(&self, _ctx: &RequestCtx, resp: Response<Body>) -> Response<Body> {
        resp
    }
}

/// Run the request phase of every middleware in order. Returns `Err(response)`
/// the moment one short-circuits, so the caller can return it without touching
/// the backend.
pub async fn run_request_phase(
    middlewares: &[Arc<dyn Middleware>],
    ctx: &mut RequestCtx,
    req: &mut Request<Body>,
) -> Result<(), Response<Body>> {
    for mw in middlewares {
        match mw.on_request(ctx, req).await {
            Flow::Continue => {}
            Flow::ShortCircuit(resp) => return Err(resp),
        }
    }
    Ok(())
}

/// Run the response phase in reverse order (onion model).
pub async fn run_response_phase(
    middlewares: &[Arc<dyn Middleware>],
    ctx: &RequestCtx,
    mut resp: Response<Body>,
) -> Response<Body> {
    for mw in middlewares.iter().rev() {
        resp = mw.on_response(ctx, resp).await;
    }
    resp
}
