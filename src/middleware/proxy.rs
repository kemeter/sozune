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
use crate::model::HeaderDirection;

/// `host` as the host of a URI or a socket address: an IPv6 literal in
/// brackets, anything else as it is.
fn uri_host(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') && !host.starts_with('[') {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// How long a copy to a mirror may take, on a route without a backend
/// timeout.
const MIRROR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Monotonic milliseconds since the process started, for circuit-breaker
/// cooldown timing. Monotonic (not wall-clock) so clock changes don't confuse
/// the breaker.
fn monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Give the request `new_host` as its `Host`, the client's going in
/// `X-Forwarded-Host`.
fn rewrite_host(headers: &mut axum::http::HeaderMap, new_host: &str) {
    let Ok(value) = axum::http::HeaderValue::from_str(new_host) else {
        warn!("Ignoring the invalid rewritten host {:?}", new_host);
        return;
    };
    if let Some(original) = headers.remove(axum::http::header::HOST) {
        headers.insert("x-forwarded-host", original);
    }
    headers.insert(axum::http::header::HOST, value);
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

    // Taken off the request so the backend never sees it. Read as UTF-8: a
    // route id is not limited to ASCII, which `to_str` would require.
    let picked = req
        .headers_mut()
        .remove(super::ROUTE_HEADER)
        .and_then(|v| String::from_utf8(v.as_bytes().to_vec()).ok());

    // The route the request matched, whose response edits apply to whatever
    // answers it.
    let matched = std::sync::Arc::new(std::sync::OnceLock::new());
    let matched_route = matched.clone();
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
            // The route Sōzu picked, which the host and path alone cannot tell
            // apart from another route on them that differs by its method or
            // headers. Looked up by host and path when the header is missing.
            let route = picked
                .as_deref()
                .and_then(|id| table.route_for_cluster(id))
                .or_else(|| table.get_route(&host, &path));
            (route, table.known_hosts())
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
        let _ = matched_route.set(route.clone());

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
            method: req.method().clone(),
            path: path.clone(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        };

        // The whole request's deadline, from its arrival: the middleware
        // stack, the client's body, every attempt and the response body all
        // come within it.
        let request_deadline = route
            .request_timeout
            .filter(|ms| *ms > 0)
            .map(|ms| tokio::time::Instant::from_std(start) + std::time::Duration::from_millis(ms));

        // Whether a request reached a backend, and whether a deadline cut the
        // response body short: the breaker then hears of a failure.
        let forwarded = std::sync::atomic::AtomicBool::new(false);
        // Whether the breaker let the request through: a half-open one then
        // waits on its outcome.
        let admitted = std::sync::atomic::AtomicBool::new(false);
        let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Everything up to the response bounded by the request's deadline.
        let handled = async {
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

            // The share of requests that falls to a backend which cannot take
            // them is answered with its error.
            let failing = match route.failing_shares.as_ref().and_then(|s| s.next()) {
                Some(1) => Some(diag::invalid_backends(&host)),
                Some(2) => Some(diag::unavailable_backend(&host)),
                _ => None,
            };
            if let Some(resp) = failing {
                let duration = start.elapsed();
                let status = resp.status().as_u16();
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
                return resp.into_response();
            }

            // Circuit breaker: if the route's breaker is open, short-circuit with
            // 503 before touching the backend. `should_allow` also handles the
            // open→half-open transition after the cooldown.
            let cb_now = monotonic_ms();
            if let Some(cb) = route.circuit_breaker.as_ref()
                && !cb.should_allow(cb_now)
            {
                warn!("circuit breaker open for host '{}', short-circuiting", host);
                // Not admitted: no outcome owed.
                let resp = diag::circuit_open(&host).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                return resp;
            }
            admitted.store(
                route.circuit_breaker.is_some(),
                std::sync::atomic::Ordering::Relaxed,
            );

            let is_websocket = req
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

            // The backends this request tries, in order; a WebSocket upgrade is
            // never retried, but still fails over to the other backends.
            let attempts = if is_websocket {
                1
            } else {
                route.retry_attempts.max(1)
            };
            let mut plan = route.attempts(attempts, &state.passive_health);
            let (backend_host, backend_port) = match plan.next() {
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
                uri_host(&backend_host),
                backend_port,
                forwarded_path,
                query
            );

            debug!(
                "Proxying {} {} -> {}",
                req.method(),
                original_path,
                target_uri
            );

            if let Some(new_host) = route.rewrite_host.as_deref() {
                rewrite_host(req.headers_mut(), new_host);
            }

            if is_websocket {
                // WebSocket tunnels live for the whole connection (minutes to hours),
                // so their duration is not a request latency — deliberately excluded
                // from the request-duration histogram to avoid skewing the distribution.
                let first = plan.last_index();
                let mut candidates = vec![((backend_host.clone(), backend_port), first)];
                while let Some(backend) = plan.next() {
                    candidates.push((backend.clone(), plan.last_index()));
                }
                // The request's deadline bounds the handshakes, not the tunnel.
                let timeout = backend_timeout(route.backend_timeout);
                return handle_websocket(
                    req,
                    &candidates,
                    &forwarded_path,
                    &query,
                    timeout,
                    &state,
                    &route,
                )
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

            let primary_uri = match target_uri.parse::<Uri>() {
                Ok(uri) => uri,
                Err(e) => {
                    error!("Failed to parse target URI '{}': {}", target_uri, e);
                    let resp = diag::forwarding_failed("invalid-target-uri", &e.to_string())
                        .into_response();
                    state
                        .request_metrics
                        .record(start.elapsed(), resp.status().as_u16());
                    return resp;
                }
            };

            let timeout = backend_timeout(route.backend_timeout);

            // Buffer the request body up front so each retry can replay it. The
            // body has to be owned bytes — a streaming body can only be sent once.
            // With no retry (`attempts <= 1`) this is still a single send.
            let collected = body.collect().await;
            let body_bytes = match collected {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    error!("Failed to buffer request body for {}: {}", target_uri, e);
                    let resp =
                        diag::forwarding_failed("request-body", &e.to_string()).into_response();
                    state
                        .request_metrics
                        .record(start.elapsed(), resp.status().as_u16());
                    return resp;
                }
            };

            // A copy to each mirror, its answer ignored: the client's response
            // waits for none of them, and a mirror failing changes nothing.
            for mirror in &route.mirrors {
                if !mirror.copies_next() {
                    continue;
                }
                // Too many copies under way already: this one is dropped.
                let Ok(permit) = super::mirror_permits().try_acquire_owned() else {
                    debug!("Mirror busy, request not copied");
                    continue;
                };
                let Some((mirror_host, mirror_port)) = mirror.pick() else {
                    continue;
                };
                let Ok(mirror_uri) = format!(
                    "http://{}:{mirror_port}{forwarded_path}{query}",
                    uri_host(mirror_host)
                )
                .parse::<Uri>() else {
                    continue;
                };
                let mut copy = parts.clone();
                copy.uri = mirror_uri;
                let copy = Request::from_parts(copy, Body::from(body_bytes.clone()));
                let client = state.http_client.clone();
                let limit = timeout.unwrap_or(MIRROR_TIMEOUT);
                tokio::spawn(async move {
                    let _permit = permit;
                    let uri = copy.uri().to_string();
                    match tokio::time::timeout(limit, client.request(copy)).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => debug!("Mirror {} failed: {}", uri, e),
                        Err(_) => debug!("Mirror {} timed out", uri),
                    }
                });
            }

            // Send to the backend, retrying connection-level failures and timeouts
            // (the backend produced no response). A response that arrives — even a
            // 5xx — is returned as-is and never retried, so a side effect is not
            // replayed.
            //
            // The backends come from `plan`, one per failed attempt: retries go to
            // the backends this request has not tried, and a backup (weight 0)
            // only takes over once every other backend failed.
            let uri_of = |(host, port): &(String, u16)| {
                format!("http://{}:{port}{forwarded_path}{query}", uri_host(host))
                    .parse::<Uri>()
                    .ok()
            };
            let mut last_err = String::new();
            let mut last_was_timeout = false;
            let mut backend_response = None;
            let mut target_uri = target_uri;
            let mut tries = 0u32;
            let mut picked = plan.last_index();
            let mut uri = Some(((backend_host.clone(), backend_port), primary_uri));
            while let Some((backend, current)) = uri.take() {
                tries += 1;
                target_uri = current.to_string();
                parts.uri = current;
                // The picked backend's own header edits.
                let mut attempt_parts = parts.clone();
                super::edit_headers(
                    &mut attempt_parts.headers,
                    route.edits_for(picked),
                    HeaderDirection::Request,
                );
                let forwarded_req =
                    Request::from_parts(attempt_parts, Body::from(body_bytes.clone()));
                let attempt_start = tokio::time::Instant::now();
                // Counted for the balancers that pick by load, until the
                // backend answers or the attempt ends.
                let waiting = picked.and_then(|index| route.waiting_on(index));
                // Counted a failure if the request's deadline cancels it.
                let attempt = super::passive_health::Attempt::new(
                    state.passive_health.clone(),
                    backend.clone(),
                );
                forwarded.store(true, std::sync::atomic::Ordering::Relaxed);
                let response_future = state.http_client.request(forwarded_req);

                // The attempt ends at the backend timeout or the request's
                // deadline, whichever comes first.
                let attempt_deadline = timeout.map(|limit| attempt_start + limit);

                // `Ok(resp)` on success, `Err((msg, is_timeout))` otherwise.
                let result = if let Some(deadline) = attempt_deadline {
                    match tokio::time::timeout_at(deadline, response_future).await {
                        Ok(result) => result.map_err(|e| (e.to_string(), false)),
                        Err(_) => Err(("timed out".to_string(), true)),
                    }
                } else {
                    response_future.await.map_err(|e| (e.to_string(), false))
                };

                drop(waiting);
                match result {
                    Ok(resp) => {
                        // An answer, whatever its status: the backend is up.
                        attempt.succeeded();
                        let (parts, body) = resp.into_parts();
                        let body = body.map_err(|e| axum::Error::new(std::io::Error::other(e)));
                        // A backend timeout the route sets caps the whole response,
                        // its body included; the default one only the wait for it.
                        let body = match (route.backend_timeout, timeout) {
                            (Some(ms), Some(limit)) if ms > 0 => body_before(
                                Body::new(body),
                                attempt_start + limit,
                                timed_out.clone(),
                            ),
                            _ => Body::new(body),
                        };
                        backend_response = Some(Response::from_parts(parts, body));
                    }
                    Err((msg, is_timeout)) => {
                        attempt.failed();
                        last_err = msg;
                        last_was_timeout = is_timeout;
                        // Past the request's deadline, no other attempt.
                        let expired = request_deadline
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline);
                        uri = if expired {
                            None
                        } else {
                            plan.by_ref()
                                .find_map(|b| uri_of(b).map(|u| (b.clone(), u)))
                        };
                        picked = plan.last_index();
                        if uri.is_some() {
                            debug!(
                                "Backend {} attempt {} failed ({}); retrying",
                                target_uri, tries, last_err
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
                        target_uri, tries, last_err
                    );
                    // All attempts failed: count it as a backend failure for the
                    // circuit breaker.
                    if let Some(cb) = route.circuit_breaker.as_ref() {
                        cb.record(true, monotonic_ms());
                    }
                    // Preserve the distinct 504 for a timeout; 502 otherwise.
                    let resp = if last_was_timeout {
                        diag::backend_timeout(&target_uri, timeout).into_response()
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
            let response =
                chain::run_response_phase(&route.middlewares, &ctx, backend_response).await;

            let duration = start.elapsed();
            let status = response.status().as_u16();
            state.request_metrics.record(duration, status);
            tracing::Span::current().record("http.response.status_code", status);
            access_log(
                &source_ip, &method, &host, &path, status, duration, "backend",
            );

            // Feed the circuit breaker: a 5xx is a backend fault, anything else
            // is a success for breaker purposes (4xx is the client's fault).
            // When a deadline bounds the response body, once the body has gone
            // through, as it can still fail or be cut short; on the status
            // otherwise, so an endless stream does not hold the breaker.
            let mut response = response.into_response();
            // Set after the response phase, which a middleware may rebuild
            // the response in.
            if let Some(index) = picked {
                response.extensions_mut().insert(super::ServedBy(index));
            }
            let bounded =
                request_deadline.is_some() || route.backend_timeout.is_some_and(|ms| ms > 0);
            match route.circuit_breaker.clone() {
                Some(breaker) if bounded => {
                    let (parts, body) = response.into_parts();
                    let body = record_outcome(body, breaker, status >= 500, timed_out.clone());
                    Response::from_parts(parts, body)
                }
                Some(breaker) => {
                    breaker.record(status >= 500, monotonic_ms());
                    response
                }
                None => response,
            }
        };

        let Some(deadline) = request_deadline else {
            return handled.await;
        };
        match tokio::time::timeout_at(deadline, handled).await {
            Ok(response) => {
                // The body still to stream is bounded by the deadline too.
                let (parts, body) = response.into_parts();
                Response::from_parts(parts, body_before(body, deadline, timed_out.clone()))
            }
            Err(_) => {
                warn!("Request to '{}' past the route's request timeout", host);
                // A request the breaker let through owes it an outcome, or a
                // half-open one would wait forever: a backend failure once a
                // backend was asked, a success before (the client was slow).
                if let Some(cb) = route.circuit_breaker.as_ref()
                    && admitted.load(std::sync::atomic::Ordering::Relaxed)
                {
                    cb.record(
                        forwarded.load(std::sync::atomic::Ordering::Relaxed),
                        monotonic_ms(),
                    );
                }
                let resp = diag::backend_timeout(&host, None).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                resp
            }
        }
    };

    let mut response = fut.instrument(span).await;
    if let Some(route) = matched.get() {
        route.edit_response(&mut response);
    }
    response
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
/// Connects to `backend_addr`, sends the upgrade and reads the first bytes of
/// the answer into `buf`.
async fn websocket_handshake(
    backend_addr: &str,
    upgrade_request: &str,
    buf: &mut [u8],
) -> Result<(tokio::net::TcpStream, usize), (String, bool)> {
    let mut stream = tokio::net::TcpStream::connect(backend_addr)
        .await
        .map_err(|e| (format!("cannot connect to {backend_addr}: {e}"), false))?;
    stream
        .write_all(upgrade_request.as_bytes())
        .await
        .map_err(|e| {
            (
                format!("cannot send the upgrade to {backend_addr}: {e}"),
                false,
            )
        })?;
    match stream.read(buf).await {
        Ok(n) if n > 0 => Ok((stream, n)),
        _ => Err((
            format!("{backend_addr} closed the connection without responding"),
            false,
        )),
    }
}

/// Tunnels a WebSocket upgrade to the first of `backends` that accepts the
/// connection: the picked backend, then the backups.
async fn handle_websocket(
    req: Request<Body>,
    backends: &[((String, u16), Option<usize>)],
    path: &str,
    query: &str,
    timeout: Option<std::time::Duration>,
    state: &MiddlewareAppState,
    route: &std::sync::Arc<super::MiddlewareRoute>,
) -> axum::response::Response {
    debug!("WebSocket upgrade request to {:?}{}", backends, path);

    // Build the raw HTTP upgrade request to send to a backend, with its
    // header edits.
    let request_headers = req.headers().clone();
    let upgrade_request_for = |index: Option<usize>| {
        let mut headers = request_headers.clone();
        super::edit_headers(
            &mut headers,
            route.edits_for(index),
            HeaderDirection::Request,
        );
        let mut upgrade_request = format!("GET {}{} HTTP/1.1\r\n", path, query);
        for (key, value) in &headers {
            if let Ok(v) = value.to_str() {
                upgrade_request.push_str(&format!("{}: {}\r\n", key, v));
            }
        }
        upgrade_request.push_str("\r\n");
        upgrade_request
    };

    // Send the upgrade to each backend in turn until one answers it: a
    // backend that refuses the connection, or closes it without a response,
    // hands the upgrade to the next.
    let mut response_buf = vec![0u8; 4096];
    let mut answered = None;
    let mut last_failure = String::from("no backend");
    let mut last_timed_out = false;
    for ((backend_host, backend_port), index) in backends {
        let backend_addr = format!("{}:{}", uri_host(backend_host), backend_port);
        let attempt = super::passive_health::Attempt::new(
            state.passive_health.clone(),
            (backend_host.clone(), *backend_port),
        );
        // Counted as waiting until the backend answers, not for the tunnel.
        let waiting = index.and_then(|index| route.waiting_on(index));
        // Bounded by the route's backend timeout, so a backend that accepts
        // the connection and never answers does not hold the upgrade back
        // from the next one.
        let upgrade_request = upgrade_request_for(*index);
        let handshake = websocket_handshake(&backend_addr, &upgrade_request, &mut response_buf);
        let outcome = match timeout {
            Some(limit) => tokio::time::timeout(limit, handshake)
                .await
                .unwrap_or_else(|_| {
                    Err((
                        format!(
                            "{backend_addr} did not answer within {}ms",
                            limit.as_millis()
                        ),
                        true,
                    ))
                }),
            None => handshake.await,
        };
        drop(waiting);
        match outcome {
            Ok((stream, n)) => {
                attempt.succeeded();
                answered = Some((stream, n, (backend_host.clone(), *backend_port), *index));
                break;
            }
            Err((failure, is_timeout)) => {
                attempt.failed();
                error!("WebSocket upgrade failed: {}", failure);
                last_failure = failure;
                last_timed_out = is_timeout;
            }
        }
    }
    let Some((mut backend_stream, n, tunnel_backend, answered_index)) = answered else {
        // A 504 when the last backend tried timed out, as for a request.
        return if last_timed_out {
            diag::backend_timeout(&format!("websocket: {last_failure}"), timeout).into_response()
        } else {
            diag::backend_unreachable(&format!("websocket: {last_failure}")).into_response()
        };
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

    // Parse the response headers to forward to the client.
    let mut response_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);

    if let Some(headers) = response_builder.headers_mut() {
        for line in response_str.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(": ")
                && let (Ok(key), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(key.as_bytes()),
                    axum::http::HeaderValue::from_str(value),
                )
            {
                headers.append(key, value);
            }
        }
    }
    if let (Some(extensions), Some(index)) = (response_builder.extensions_mut(), answered_index) {
        extensions.insert(super::ServedBy(index));
    }

    // Use hyper's upgrade mechanism to get the client's underlying connection
    let on_upgrade = hyper::upgrade::on(req);
    // Closed when its backend leaves the route; refused when it already has.
    let Some(mut tunnel) = super::tunnels::tunnels().register(&route.cluster_id, tunnel_backend)
    else {
        return diag::backend_unreachable("websocket: the backend left the route").into_response();
    };

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
                    _ = tunnel.closed() => {
                        debug!("WebSocket closed: its backend left the route");
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

/// `body`, cut short with an error once `deadline` passes: the client then
/// sees the response end early rather than wait past the route's timeout.
/// `timed_out` is set when it does, before the body it wraps is dropped.
fn body_before(
    body: Body,
    deadline: tokio::time::Instant,
    timed_out: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Body {
    use futures_util::StreamExt;
    use http_body_util::{BodyStream, StreamBody};

    let frames = futures_util::stream::unfold(Some(BodyStream::new(body)), move |state| {
        let timed_out = timed_out.clone();
        async move {
            let mut frames = state?;
            match tokio::time::timeout_at(deadline, frames.next()).await {
                Ok(Some(frame)) => Some((frame, Some(frames))),
                Ok(None) => None,
                Err(_) => {
                    warn!("Backend response cut short: past the route's timeout");
                    timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                    Some((
                        Err(axum::Error::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "past the route's timeout",
                        ))),
                        None,
                    ))
                }
            }
        }
    });
    Body::new(StreamBody::new(frames))
}

/// `body`, telling `breaker` its outcome once: a failure at an error frame,
/// `failed` at its end, and when dropped unfinished (the client gone) a
/// failure if a deadline cut it short (`timed_out`), `failed` otherwise, so a
/// half-open breaker always hears back.
fn record_outcome(
    body: Body,
    breaker: std::sync::Arc<super::circuit_breaker::CircuitBreaker>,
    failed: bool,
    timed_out: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Body {
    use futures_util::StreamExt;
    use http_body_util::{BodyStream, StreamBody};

    let outcome = BreakerOutcome {
        breaker: Some(breaker),
        failed,
        timed_out,
    };
    let frames =
        futures_util::stream::unfold(Some((BodyStream::new(body), outcome)), |state| async move {
            let (mut frames, mut outcome) = state?;
            match frames.next().await {
                Some(frame) => {
                    if frame.is_err() {
                        outcome.record(true);
                    }
                    Some((frame, Some((frames, outcome))))
                }
                None => {
                    let failed = outcome.failed;
                    outcome.record(failed);
                    None
                }
            }
        });
    Body::new(StreamBody::new(frames))
}

/// The outcome a response body still owes its route's circuit breaker.
struct BreakerOutcome {
    breaker: Option<std::sync::Arc<super::circuit_breaker::CircuitBreaker>>,
    failed: bool,
    timed_out: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BreakerOutcome {
    fn record(&mut self, failed: bool) {
        if let Some(breaker) = self.breaker.take() {
            breaker.record(failed, monotonic_ms());
        }
    }
}

impl Drop for BreakerOutcome {
    fn drop(&mut self) {
        let failed = self.failed || self.timed_out.load(std::sync::atomic::Ordering::Relaxed);
        self.record(failed);
    }
}

/// How long to wait on a backend, from the label's millisecond value.
///
/// `None` means no timeout at all, which a route asks for with `0`. Everything
/// else is milliseconds: the parser documents the label that way, its
/// diagnostic hint says so, and `sozune explain W003` gives
/// `backendTimeout=30000  # 30s` as the example. Reading it as seconds turned
/// that example into eight hours.
fn backend_timeout(configured_ms: Option<u64>) -> Option<std::time::Duration> {
    const DEFAULT_MS: u64 = 30_000;

    match configured_ms.unwrap_or(DEFAULT_MS) {
        0 => None,
        ms => Some(std::time::Duration::from_millis(ms)),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// The label is documented in milliseconds — the parser says so, its
    /// diagnostic hint says so, and `sozune explain W003` gives
    /// `backendTimeout=30000  # 30s` as the example. The consumer read it as
    /// seconds, so following that example bought a timeout of 30000 seconds:
    /// eight hours and twenty minutes during which a hung backend pins a
    /// connection, a task and the buffered request body.
    #[test]
    fn the_documented_example_means_thirty_seconds() {
        assert_eq!(
            backend_timeout(Some(30_000)),
            Some(std::time::Duration::from_secs(30))
        );
    }

    /// The default has to keep meaning what it did: 30 seconds.
    #[test]
    fn the_default_is_thirty_seconds() {
        assert_eq!(
            backend_timeout(None),
            Some(std::time::Duration::from_secs(30))
        );
    }

    /// Zero is how a route says "wait as long as it takes". It is worth
    /// keeping, but it must stay explicit rather than being what a typo
    /// silently produces.
    #[test]
    fn zero_means_no_timeout() {
        assert_eq!(backend_timeout(Some(0)), None);
    }

    /// Sub-second values are the point of a millisecond unit.
    #[test]
    fn a_sub_second_timeout_survives_the_conversion() {
        assert_eq!(
            backend_timeout(Some(250)),
            Some(std::time::Duration::from_millis(250))
        );
    }
}

#[cfg(test)]
mod forwarding_tests {
    use super::*;

    #[test]
    fn an_ipv6_backend_is_bracketed() {
        assert_eq!(uri_host("fd00::1"), "[fd00::1]");
        assert_eq!(uri_host("[fd00::1]"), "[fd00::1]");
        assert_eq!(uri_host("10.0.0.1"), "10.0.0.1");
        assert!(
            format!("http://{}:8080/", uri_host("fd00::1"))
                .parse::<Uri>()
                .is_ok()
        );
    }

    fn breaker() -> std::sync::Arc<super::super::circuit_breaker::CircuitBreaker> {
        std::sync::Arc::new(super::super::circuit_breaker::CircuitBreaker::new(
            crate::model::CircuitBreakerConfig {
                threshold: 0.5,
                min_requests: 1,
                cooldown_secs: 60,
            },
        ))
    }

    fn flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    /// A body read to its end records the response's outcome.
    #[tokio::test]
    async fn a_finished_body_records_its_status() {
        let ok = breaker();
        let body = record_outcome(Body::from("done"), ok.clone(), false, flag());
        assert!(body.collect().await.is_ok());
        assert!(ok.should_allow(monotonic_ms()));

        let failed = breaker();
        let body = record_outcome(Body::from("oops"), failed.clone(), true, flag());
        assert!(body.collect().await.is_ok());
        assert!(!failed.should_allow(monotonic_ms()));
    }

    /// A body dropped unfinished still tells the breaker: a failure if a
    /// deadline cut it short.
    #[tokio::test]
    async fn a_dropped_body_still_records_its_outcome() {
        let timed_out = flag();
        let cb = breaker();
        let body = record_outcome(Body::from("unread"), cb.clone(), false, timed_out.clone());
        timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(body);
        assert!(!cb.should_allow(monotonic_ms()));
    }

    /// A deadline wrapping the recorder fails its outcome when it cuts the
    /// body short.
    #[tokio::test]
    async fn a_deadline_cutting_the_body_records_a_failure() {
        let timed_out = flag();
        let cb = breaker();
        let stalled = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let recorded = record_outcome(
            Body::from_stream(stalled),
            cb.clone(),
            false,
            timed_out.clone(),
        );
        let cut = body_before(
            recorded,
            tokio::time::Instant::now() + std::time::Duration::from_millis(50),
            timed_out,
        );
        assert!(cut.collect().await.is_err());
        assert!(!cb.should_allow(monotonic_ms()));
    }

    /// A body error frame is a backend failure, whatever the status said.
    #[tokio::test]
    async fn a_body_error_records_a_failure() {
        let cb = breaker();
        let failing = futures_util::stream::iter([Err::<axum::body::Bytes, _>(
            std::io::Error::other("backend reset"),
        )]);
        let body = record_outcome(Body::from_stream(failing), cb.clone(), false, flag());
        assert!(body.collect().await.is_err());
        assert!(!cb.should_allow(monotonic_ms()));
    }

    /// A body still streaming past the deadline ends with an error.
    #[tokio::test]
    async fn a_body_past_the_deadline_is_cut_short() {
        let slow = futures_util::stream::unfold(0u8, |n| async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            (n < 10).then(|| {
                (
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"x")),
                    n + 1,
                )
            })
        });
        let timed_out = flag();
        let body = body_before(
            Body::from_stream(slow),
            tokio::time::Instant::now() + std::time::Duration::from_millis(120),
            timed_out.clone(),
        );
        assert!(body.collect().await.is_err());
        assert!(timed_out.load(std::sync::atomic::Ordering::Relaxed));

        let fast = body_before(
            Body::from("done"),
            tokio::time::Instant::now() + std::time::Duration::from_millis(120),
            flag(),
        );
        assert_eq!(fast.collect().await.unwrap().to_bytes(), "done");
    }

    #[test]
    fn a_rewritten_host_replaces_the_client_one() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::HOST, "rewrite.example".parse().unwrap());
        rewrite_host(&mut headers, "one.example.org");
        let hosts: Vec<_> = headers.get_all(axum::http::header::HOST).iter().collect();
        assert_eq!(hosts, ["one.example.org"]);
        assert_eq!(headers["x-forwarded-host"], "rewrite.example");
    }
}
