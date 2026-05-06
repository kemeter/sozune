use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use super::MiddlewareAppState;
use super::compress;
use super::diag;
use super::forward_auth::{self, AuthRequestSnapshot, ForwardAuthOutcome};
use super::rate_limit::RateLimitResult;

/// Main proxy handler: identifies the route by Host header,
/// applies middleware stack, and forwards to the real backend.
pub async fn handle_proxy(
    State(state): State<MiddlewareAppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let start = Instant::now();
    let client_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let source_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "-".to_string());

    let host = match req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
    {
        Some(h) => h.to_string(),
        None => {
            warn!("Request with missing or invalid Host header");
            return diag::bad_request(
                "missing-host-header",
                "the request did not include a usable Host header",
            )
            .into_response();
        }
    };

    let (route, known_hosts) = {
        let table = match state.route_table.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!(
                    "internal state corrupted (middleware routing), restart required: {}",
                    e
                );
                return diag::internal_error("middleware-routing-corrupted").into_response();
            }
        };
        (table.get_route_by_host(&host), table.known_hosts())
    };

    let route = match route {
        Some(r) => r,
        None => {
            info!(
                "no route for host '{}' (known: {})",
                host,
                known_hosts.len()
            );
            return diag::no_route_for_host(&host, &known_hosts).into_response();
        }
    };

    // 1. Forward auth (runs before rate limit, headers, compression)
    let mut auth_injected_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    if let Some(cfg) = route.forward_auth.as_ref() {
        let snapshot = AuthRequestSnapshot {
            method: req.method().clone(),
            uri: req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| req.uri().path().to_string()),
            host: host.clone(),
            headers: req.headers().clone(),
            is_tls: req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("https"))
                .unwrap_or(false),
        };
        match forward_auth::evaluate(&state.forward_auth_client, cfg, snapshot, client_addr).await {
            ForwardAuthOutcome::Allow { headers } => {
                auth_injected_headers = headers;
            }
            ForwardAuthOutcome::Deny(response) => {
                let status = response.status().as_u16();
                let duration = start.elapsed();
                info!(
                    "{} {} {} {} {} {}ms (forward-auth)",
                    source_ip,
                    method,
                    host,
                    path,
                    status,
                    duration.as_millis()
                );
                return response.into_response();
            }
        }
    }

    // 2. Rate limit check
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
            return diag::rate_limited(&host).into_response();
        }
    }

    // 3. Pick a backend using round-robin
    let (backend_host, backend_port) = match route.next_backend() {
        Some(b) => b.clone(),
        None => {
            error!("No backends configured for host '{}'", host);
            return diag::no_healthy_backend(&host, &route.backends).into_response();
        }
    };

    // 4. Build the forwarded URI
    let original_path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let forwarded_path = original_path.clone();

    let target_uri = format!(
        "http://{}:{}{}{}",
        backend_host, backend_port, forwarded_path, query
    );

    let client_encoding = compress::pick_encoding(req.headers());

    debug!(
        "Proxying {} {} -> {}",
        req.method(),
        original_path,
        target_uri
    );

    // 5. Check for WebSocket upgrade
    let is_websocket = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if is_websocket {
        return handle_websocket(req, &backend_host, backend_port, &forwarded_path, &query).await;
    }

    // 6. Build the forwarded request
    let (mut parts, body) = req.into_parts();

    // Stamp forward-auth response headers onto the request before forwarding.
    for (name, value) in auth_injected_headers {
        parts.headers.insert(name, value);
    }

    // Update the URI
    parts.uri = match target_uri.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            error!("Failed to parse target URI '{}': {}", target_uri, e);
            return diag::forwarding_failed("invalid-target-uri", &e.to_string()).into_response();
        }
    };

    let forwarded_req = Request::from_parts(parts, body);

    // 7. Send the request to the real backend
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
                return diag::backend_timeout(&target_uri, timeout_secs).into_response();
            }
        }
    };

    let response = match result {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();

            let encoding = client_encoding.filter(|_| {
                route.compress
                    && compress::is_compressible(&parts.headers)
                    && !compress::is_already_compressed(&parts.headers)
            });

            if let Some(encoding) = encoding {
                let body = Body::new(body.map_err(|e| axum::Error::new(std::io::Error::other(e))));
                match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
                    Ok(bytes) => match compress::compress(&bytes, encoding) {
                        Ok(compressed) => {
                            parts.headers.insert(
                                "content-encoding",
                                encoding.header_value().parse().unwrap(),
                            );
                            parts.headers.insert(
                                "content-length",
                                compressed.len().to_string().parse().unwrap(),
                            );
                            parts.headers.remove("transfer-encoding");
                            Response::from_parts(parts, Body::from(compressed)).into_response()
                        }
                        Err(e) => {
                            debug!("Compression failed, sending uncompressed: {}", e);
                            Response::from_parts(parts, Body::from(bytes)).into_response()
                        }
                    },
                    Err(e) => {
                        error!("Failed to read response body for compression: {}", e);
                        diag::forwarding_failed("response-body-read-failed", &e.to_string())
                            .into_response()
                    }
                }
            } else {
                let body = Body::new(body.map_err(|e| axum::Error::new(std::io::Error::other(e))));
                Response::from_parts(parts, body).into_response()
            }
        }
        Err(e) => {
            error!("Failed to forward request to {}: {}", target_uri, e);
            diag::backend_unreachable(&format!("backend at {target_uri}: {e}")).into_response()
        }
    };

    let duration = start.elapsed();
    info!(
        "{} {} {} {} {} {}ms",
        source_ip,
        method,
        host,
        path,
        response.status().as_u16(),
        duration.as_millis()
    );

    response
}

/// Handle WebSocket upgrade by establishing a TCP tunnel to the backend
async fn handle_websocket(
    req: Request<Body>,
    backend_host: &str,
    backend_port: u16,
    path: &str,
    query: &str,
) -> axum::response::Response {
    debug!(
        "WebSocket upgrade request to {}:{}{}",
        backend_host, backend_port, path
    );

    // Connect to backend
    let backend_addr = format!("{}:{}", backend_host, backend_port);
    let mut backend_stream = match tokio::net::TcpStream::connect(&backend_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to connect to backend {} for WebSocket: {}",
                backend_addr, e
            );
            return diag::backend_unreachable(&format!(
                "websocket: cannot connect to {backend_addr}: {e}"
            ))
            .into_response();
        }
    };

    // Build the raw HTTP upgrade request to send to the backend
    let mut upgrade_request = format!("GET {}{} HTTP/1.1\r\n", path, query);

    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            upgrade_request.push_str(&format!("{}: {}\r\n", key, v));
        }
    }
    upgrade_request.push_str("\r\n");

    // Send upgrade request to backend
    if let Err(e) = backend_stream.write_all(upgrade_request.as_bytes()).await {
        error!("Failed to send WebSocket upgrade to backend: {}", e);
        return diag::forwarding_failed("websocket-write-failed", &e.to_string()).into_response();
    }

    // Read the backend's response header
    let mut response_buf = vec![0u8; 4096];
    let n = match backend_stream.read(&mut response_buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            error!("No response from backend for WebSocket upgrade");
            return diag::backend_unreachable(
                "websocket: backend closed connection without responding",
            )
            .into_response();
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // Check that backend accepted the upgrade (101 Switching Protocols)
    if !response_str.starts_with("HTTP/1.1 101") {
        let first_line = response_str.lines().next().unwrap_or("").to_string();
        error!("Backend rejected WebSocket upgrade: {}", first_line);
        return diag::forwarding_failed(
            "websocket-upgrade-rejected",
            &format!("backend response: {first_line}"),
        )
        .into_response();
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
