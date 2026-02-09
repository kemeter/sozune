use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use tracing::{debug, error, warn};

use super::auth;
use super::headers;
use super::strip_prefix;
use super::MiddlewareAppState;

/// Main proxy handler: identifies the route by Host header,
/// applies middleware stack, and forwards to the real backend.
pub async fn handle_proxy(
    State(state): State<MiddlewareAppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let route = {
        let table = match state.route_table.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Middleware route table lock poisoned: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        table.get_route_by_host(&host)
    };

    let route = match route {
        Some(r) => r,
        None => {
            warn!("No middleware route found for host '{}'", host);
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
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();

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

    // 4. Build the forwarded request
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

    // 5. Send the request to the real backend using the shared client
    match state.http_client.request(forwarded_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body = Body::new(body.map_err(|e| {
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
