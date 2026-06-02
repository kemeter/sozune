use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::MiddlewareAppState;
use super::chain::{self, RequestCtx};
use super::diag;

/// Monotonic milliseconds since the process started, for circuit-breaker
/// cooldown timing. Monotonic (not wall-clock) so clock changes don't confuse
/// the breaker.
fn monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Main proxy handler: identifies the route by Host header,
/// applies middleware stack, and forwards to the real backend.
pub async fn handle_proxy(
    State(state): State<MiddlewareAppState>,
    mut req: Request<Body>,
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

    // One span per proxied request. The incoming W3C `traceparent` (if any) is
    // attached as the parent so this request continues an upstream trace; the
    // span's `trace_id` is logged and propagated to the backend below. When
    // tracing is disabled the span is cheap and simply never exported.
    let span = tracing::info_span!(
        "proxy.request",
        otel.name = %format!("{method} {host}"),
        http.request.method = %method,
        server.address = %host,
        url.path = %path,
        http.response.status_code = tracing::field::Empty,
    );
    // `set_parent` only errors if the otel context can't be attached (no
    // active otel subscriber, i.e. tracing disabled) — harmless to ignore.
    let _ = span.set_parent(crate::tracing_otel::extract_parent(req.headers()));

    let fut = async move {
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

        // Build the per-request context shared across middlewares.
        let mut ctx = RequestCtx {
            host: host.clone(),
            client_addr,
            is_tls: req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("https"))
                .unwrap_or(false),
            client_encoding: None,
            pending_response_headers: Vec::new(),
        };

        // Request phase: run the middleware stack in order. A middleware may mutate
        // the request (e.g. forward-auth stamping headers) or short-circuit (e.g.
        // forward-auth deny, rate limit).
        if let Err(response) =
            chain::run_request_phase(&route.middlewares, &mut ctx, &mut req).await
        {
            let duration = start.elapsed();
            let status = response.status().as_u16();
            state.request_metrics.record(duration, status);
            access_log(
                &source_ip,
                &method,
                &host,
                &path,
                status,
                duration,
                "middleware",
            );
            return response.into_response();
        }

        // Circuit breaker: if the route's breaker is open, short-circuit with
        // 503 before touching the backend. `should_allow` also handles the
        // open→half-open transition after the cooldown.
        let cb_now = monotonic_ms();
        if let Some(cb) = route.circuit_breaker.as_ref()
            && !cb.should_allow(cb_now)
        {
            warn!("circuit breaker open for host '{}', short-circuiting", host);
            let resp = diag::circuit_open(&host).into_response();
            state
                .request_metrics
                .record(start.elapsed(), resp.status().as_u16());
            return resp;
        }

        // Pick a backend using round-robin.
        let (backend_host, backend_port) = match route.next_backend() {
            Some(b) => b.clone(),
            None => {
                error!("No backends configured for host '{}'", host);
                let resp = diag::no_healthy_backend(&host, &route.backends).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                return resp;
            }
        };

        // Build the forwarded URI.
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

        debug!(
            "Proxying {} {} -> {}",
            req.method(),
            original_path,
            target_uri
        );

        // Check for WebSocket upgrade.
        let is_websocket = req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

        if is_websocket {
            // WebSocket tunnels live for the whole connection (minutes to hours),
            // so their duration is not a request latency — deliberately excluded
            // from the request-duration histogram to avoid skewing the distribution.
            return handle_websocket(req, &backend_host, backend_port, &forwarded_path, &query)
                .await;
        }

        // Build the forwarded request.
        let (mut parts, body) = req.into_parts();

        // Propagate the trace downstream: write this span's context as the
        // outgoing `traceparent` so the backend joins the same trace. No-op when
        // tracing is disabled (the context is invalid/empty).
        crate::tracing_otel::inject_context(
            &tracing::Span::current().context(),
            &mut parts.headers,
        );

        parts.uri = match target_uri.parse::<Uri>() {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to parse target URI '{}': {}", target_uri, e);
                let resp =
                    diag::forwarding_failed("invalid-target-uri", &e.to_string()).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                return resp;
            }
        };

        let timeout_secs = route.backend_timeout.unwrap_or(30);

        // Buffer the request body up front so each retry can replay it. The
        // body has to be owned bytes — a streaming body can only be sent once.
        // With no retry (`attempts <= 1`) this is still a single send.
        let attempts = route.retry_attempts.max(1);
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to buffer request body for {}: {}", target_uri, e);
                let resp = diag::forwarding_failed("request-body", &e.to_string()).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                return resp;
            }
        };

        // Send to the backend, retrying connection-level failures and timeouts
        // (the backend produced no response). A response that arrives — even a
        // 5xx — is returned as-is and never retried, so a side effect is not
        // replayed.
        let mut last_err = String::new();
        let mut last_was_timeout = false;
        let mut backend_response = None;
        for attempt in 1..=attempts {
            let forwarded_req = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));
            let response_future = state.http_client.request(forwarded_req);

            // `Ok(resp)` on success, `Err((msg, is_timeout))` otherwise.
            let result = if timeout_secs == 0 {
                response_future.await.map_err(|e| (e.to_string(), false))
            } else {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(timeout_secs),
                    response_future,
                )
                .await
                {
                    Ok(result) => result.map_err(|e| (e.to_string(), false)),
                    Err(_) => Err((format!("timed out after {timeout_secs}s"), true)),
                }
            };

            match result {
                Ok(resp) => {
                    let (parts, body) = resp.into_parts();
                    let body =
                        Body::new(body.map_err(|e| axum::Error::new(std::io::Error::other(e))));
                    backend_response = Some(Response::from_parts(parts, body));
                    break;
                }
                Err((msg, is_timeout)) => {
                    last_err = msg;
                    last_was_timeout = is_timeout;
                    if attempt < attempts {
                        debug!(
                            "Backend {} attempt {}/{} failed ({}); retrying",
                            target_uri, attempt, attempts, last_err
                        );
                    }
                }
            }
        }

        let backend_response = match backend_response {
            Some(resp) => resp,
            None => {
                error!(
                    "Failed to forward request to {} after {} attempt(s): {}",
                    target_uri, attempts, last_err
                );
                // All attempts failed: count it as a backend failure for the
                // circuit breaker.
                if let Some(cb) = route.circuit_breaker.as_ref() {
                    cb.record(true, monotonic_ms());
                }
                // Preserve the distinct 504 for a timeout; 502 otherwise.
                let resp = if last_was_timeout {
                    diag::backend_timeout(&target_uri, timeout_secs).into_response()
                } else {
                    diag::backend_unreachable(&format!("backend at {target_uri}: {last_err}"))
                        .into_response()
                };
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                return resp;
            }
        };

        // Response phase: run the middleware stack in reverse (onion model). This is
        // where compression applies.
        let response = chain::run_response_phase(&route.middlewares, &ctx, backend_response).await;

        let duration = start.elapsed();
        let status = response.status().as_u16();
        state.request_metrics.record(duration, status);
        // Feed the circuit breaker: a 5xx is a backend fault, anything else is
        // a success for breaker purposes (4xx is the client's fault).
        if let Some(cb) = route.circuit_breaker.as_ref() {
            cb.record(status >= 500, monotonic_ms());
        }
        tracing::Span::current().record("http.response.status_code", status);
        access_log(
            &source_ip, &method, &host, &path, status, duration, "backend",
        );

        response.into_response()
    };

    fut.instrument(span).await
}

/// Emit one access-log line for a completed request.
///
/// The event carries **structured fields** (`client_ip`, `method`, `host`,
/// `path`, `status`, `duration_ms`, `phase`) on the `access` target. With the
/// text formatter these render as the familiar
/// `<ip> <method> <host> <path> <status> <ms>ms` line; with the JSON formatter
/// (`log.format: json`) each field becomes a top-level key, so log pipelines
/// can filter and aggregate without regex-parsing the message.
///
/// `phase` is `"backend"` for a normally-proxied response or `"middleware"`
/// when a middleware short-circuited the request (auth deny, rate limit, …).
///
/// `trace_id` is the current request span's OpenTelemetry trace id (32 hex
/// chars), or `"-"` when tracing is disabled / the trace id is invalid — so log
/// pipelines can join an access line to its trace.
fn access_log(
    client_ip: &str,
    method: &str,
    host: &str,
    path: &str,
    status: u16,
    duration: std::time::Duration,
    phase: &'static str,
) {
    let duration_ms = duration.as_millis();
    let trace_id = current_trace_id();
    info!(
        target: "access",
        client_ip,
        method,
        host,
        path,
        status,
        duration_ms,
        phase,
        trace_id = %trace_id,
        "{client_ip} {method} {host} {path} {status} {duration_ms}ms ({phase}) trace={trace_id}",
    );
}

/// Trace id of the current span as 32 lowercase hex chars, or `"-"` when there
/// is no valid (sampled) trace context — e.g. tracing disabled. Returns a
/// borrowed `"-"` on the hot path when tracing is off, so the disabled case
/// allocates nothing.
fn current_trace_id() -> std::borrow::Cow<'static, str> {
    use opentelemetry::trace::TraceContextExt;
    let cx = tracing::Span::current().context();
    let span_ref = cx.span();
    let sc = span_ref.span_context();
    if sc.is_valid() {
        std::borrow::Cow::Owned(sc.trace_id().to_string())
    } else {
        std::borrow::Cow::Borrowed("-")
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
