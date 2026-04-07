use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, warn};

use super::MiddlewareAppState;
use super::auth;
use super::headers;
use super::rate_limit::RateLimitResult;
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

    // 1. Rate limit check (before auth to save CPU on bcrypt)
    if let Some(ref limiter) = route.rate_limiter {
        let source_ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| host.clone());

        if matches!(limiter.check(&source_ip), RateLimitResult::Limited) {
            warn!("Rate limited request from {} to {}", source_ip, host);
            return (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").into_response();
        }
    }

    // 2. Basic auth check
    if let Some(ref users) = route.auth {
        if let Err(response) = auth::check_basic_auth(&req, users) {
            return response.into_response();
        }
    }

    // 3. Pick a backend using round-robin
    let (backend_host, backend_port) = match route.next_backend() {
        Some(b) => b.clone(),
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

    if is_websocket {
        return handle_websocket(req, &backend_host, backend_port, &forwarded_path, &query)
            .await;
    }

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
    let timeout_secs = route.backend_timeout.unwrap_or(30);

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

/// Handle WebSocket upgrade by establishing a TCP tunnel to the backend
async fn handle_websocket(
    req: Request<Body>,
    backend_host: &str,
    backend_port: u16,
    path: &str,
    query: &str,
) -> axum::response::Response {
    debug!("WebSocket upgrade request to {}:{}{}", backend_host, backend_port, path);

    // Connect to backend
    let backend_addr = format!("{}:{}", backend_host, backend_port);
    let mut backend_stream = match tokio::net::TcpStream::connect(&backend_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to backend {} for WebSocket: {}", backend_addr, e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Build the raw HTTP upgrade request to send to the backend
    let mut upgrade_request = format!(
        "GET {}{} HTTP/1.1\r\n",
        path, query
    );

    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            upgrade_request.push_str(&format!("{}: {}\r\n", key, v));
        }
    }
    upgrade_request.push_str("\r\n");

    // Send upgrade request to backend
    if let Err(e) = backend_stream.write_all(upgrade_request.as_bytes()).await {
        error!("Failed to send WebSocket upgrade to backend: {}", e);
        return StatusCode::BAD_GATEWAY.into_response();
    }

    // Read the backend's response header
    let mut response_buf = vec![0u8; 4096];
    let n = match backend_stream.read(&mut response_buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            error!("No response from backend for WebSocket upgrade");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // Check that backend accepted the upgrade (101 Switching Protocols)
    if !response_str.starts_with("HTTP/1.1 101") {
        error!("Backend rejected WebSocket upgrade: {}", response_str.lines().next().unwrap_or(""));
        return StatusCode::BAD_GATEWAY.into_response();
    }

    // Parse the response headers to forward to the client
    let mut response_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);

    for line in response_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            response_builder = response_builder.header(key, value);
        }
    }

    // Use hyper's upgrade mechanism to get the client's underlying connection
    let on_upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client_stream = hyper_util::rt::TokioIo::new(upgraded);
                let (mut client_read, mut client_write) = tokio::io::split(&mut client_stream);
                let (mut backend_read, mut backend_write) = tokio::io::split(&mut backend_stream);

                let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
                let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);

                tokio::select! {
                    result = client_to_backend => {
                        if let Err(e) = result {
                            debug!("WebSocket client->backend closed: {}", e);
                        }
                    }
                    result = backend_to_client => {
                        if let Err(e) = result {
                            debug!("WebSocket backend->client closed: {}", e);
                        }
                    }
                }
                debug!("WebSocket connection closed");
            }
            Err(e) => {
                error!("WebSocket upgrade failed: {}", e);
            }
        }
    });

    response_builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
