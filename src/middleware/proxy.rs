use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use tracing::{debug, error, warn};

use super::MiddlewareAppState;
use super::auth;
use super::headers;
use super::strip_prefix;

/// Main proxy handler: identifies the route by Host header,
/// applies middleware stack, and forwards to the real backend.
pub async fn handle_proxy(
    State(state): State<MiddlewareAppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let host = match req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
    {
        Some(h) => h.to_string(),
        None => {
            warn!("Request with missing or invalid Host header");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let route = {
        let table = match state.route_table.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Middleware route table lock poisoned: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        // Route lookup validates Host against configured hostnames
        table.get_route_by_host(&host)
    };

    let route = match route {
        Some(r) => r,
        None => {
            debug!("No middleware route for host '{}'", host);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // 1. Basic auth check
    if let Some(ref users) = route.auth {
        if let Err(response) = auth::check_basic_auth(&req, users) {
            return response.into_response();
        }
    }

    // 2. Pick a backend using round-robin
    let (backend_host, backend_port) = match route.next_backend() {
        Some(b) => b,
        None => {
            error!("No backends configured for host '{}'", host);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // 3. Build the forwarded URI with strip_prefix applied
    let original_path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let forwarded_path = if let Some(ref prefix) = route.strip_prefix {
        strip_prefix::strip(prefix, &original_path)
    } else {
        original_path.clone()
    };

    let target_uri = format!(
        "http://{}:{}{}{}",
        backend_host, backend_port, forwarded_path, query
    );

    debug!(
        "Proxying {} {} -> {}",
        req.method(),
        original_path,
        target_uri
    );

    // 4. Check for WebSocket upgrade
    let is_websocket = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    // 5. Build the forwarded request
    let (mut parts, body) = req.into_parts();

    // Inject custom headers
    headers::inject_headers(&mut parts.headers, &route.headers);

    // Update the URI
    parts.uri = match target_uri.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            error!("Failed to parse target URI '{}': {}", target_uri, e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let forwarded_req = Request::from_parts(parts, body);

    // 6. Send the request to the real backend
    let timeout_secs = if is_websocket {
        0 // No timeout for WebSocket
    } else {
        route.backend_timeout.unwrap_or(30)
    };

    let response_future = state.http_client.request(forwarded_req);

    let result = if timeout_secs == 0 {
        response_future.await.map_err(|e| e.to_string())
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            response_future,
        )
        .await
        {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => {
                error!("Backend request to {} timed out", target_uri);
                return StatusCode::GATEWAY_TIMEOUT.into_response();
            }
        }
    };

    match result {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body =
                Body::new(body.map_err(|e| {
                    axum::Error::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                }));
            Response::from_parts(parts, body).into_response()
        }
        Err(e) => {
            error!("Failed to forward request to {}: {}", target_uri, e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}
