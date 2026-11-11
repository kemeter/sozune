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

/// How much of a request body is kept to send it again: to a mirror, or on
/// a retry. A larger body is streamed to a single attempt instead, neither
/// retried nor copied, rather than held in memory.
const REPLAY_BODY_LIMIT: usize = 1024 * 1024;

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

    // Over HTTP/2 the host is the `:authority`, which Sōzu sends without a
    // `Host` header: it becomes one, as the rest expects.
    if !req.headers().contains_key(axum::http::header::HOST)
        && let Some(value) = req
            .uri()
            .authority()
            .and_then(|a| axum::http::HeaderValue::from_str(a.as_str()).ok())
    {
        req.headers_mut().insert(axum::http::header::HOST, value);
    }
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

    // Kept for the route's CORS policy, which marks whatever answers it.
    let origin = req.headers().get(axum::http::header::ORIGIN).cloned();
    // And for the page that replaces the route's errors, which can be told
    // the request it answers.
    let request_method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| path.clone(), |pq| pq.as_str().to_string());

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
        // The streamed body of the attempt under way: its client's turn
        // is not the backend's time.
        let current_upload: std::sync::Mutex<Option<BodySent>> = std::sync::Mutex::new(None);

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

            // The listener's scheme was for the middleware's redirects alone.
            req.headers_mut().remove(super::SCHEME_HEADER);

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
                access_log(
                    &source_ip,
                    &method,
                    &host,
                    &path,
                    resp.status().as_u16(),
                    start.elapsed(),
                    "middleware",
                );
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
                    access_log(
                        &source_ip,
                        &method,
                        &host,
                        &path,
                        resp.status().as_u16(),
                        start.elapsed(),
                        "middleware",
                    );
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
                    access_log(
                        &source_ip,
                        &method,
                        &host,
                        &path,
                        resp.status().as_u16(),
                        start.elapsed(),
                        "middleware",
                    );
                    return resp;
                }
            };

            let timeout = backend_timeout(route.backend_timeout);

            // The body is streamed to the backend. It is kept to be sent again
            // only when a mirror or a retry may need it, and up to
            // `REPLAY_BODY_LIMIT`: a larger one is streamed all the same, to a
            // single attempt.
            // Backups take over a failed attempt even without retries.
            // The backend's protocol, whatever the client spoke.
            let version = if route.h2c {
                axum::http::Version::HTTP_2
            } else {
                axum::http::Version::HTTP_11
            };
            let replays = attempts > 1 || !route.backups.is_empty();
            let request_body = if replays || hyper::body::Body::is_end_stream(&body) {
                // An empty body costs nothing to keep: any backend the plan
                // holds can be tried.
                replayable(body, &parts.headers, REPLAY_BODY_LIMIT).await
            } else {
                Ok(RequestBody::Streamed(Some(body)))
            };
            let mut request_body = match request_body {
                Ok(body) => body,
                Err(e) => {
                    error!("Failed to read request body for {}: {}", target_uri, e);
                    let resp =
                        diag::forwarding_failed("request-body", &e.to_string()).into_response();
                    state
                        .request_metrics
                        .record(start.elapsed(), resp.status().as_u16());
                    access_log(
                        &source_ip,
                        &method,
                        &host,
                        &path,
                        resp.status().as_u16(),
                        start.elapsed(),
                        "middleware",
                    );
                    return resp;
                }
            };

            // A copy to each mirror, its answer ignored: the client's response
            // waits for none of them, and a mirror failing changes nothing.
            // The mirrors this request is copied to: the body kept is
            // copied whole, a streamed one part by part as it goes.
            let copying: Vec<&super::MirrorTarget> =
                route.mirrors.iter().filter(|m| m.copies_next()).collect();
            let mut streamed_copies = match &mut request_body {
                RequestBody::Streamed(body) if !copying.is_empty() => match body.take() {
                    Some(whole) => {
                        let (primary, copies) = tee(whole, copying.len());
                        *body = Some(primary);
                        copies.into_iter().map(Some).collect()
                    }
                    None => Vec::new(),
                },
                _ => Vec::new(),
            };
            let replayed = request_body.bytes().cloned();
            for (index, mirror) in copying.into_iter().enumerate() {
                let copy_body = match &replayed {
                    Some(bytes) => Body::from(bytes.clone()),
                    None => match streamed_copies.get_mut(index).and_then(Option::take) {
                        Some(body) => body,
                        None => continue,
                    },
                };
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
                copy.version = version;
                // A copy streamed with the request is timed as an attempt is:
                // the client's turns left out.
                let (copy_body, copy_sent) = if replayed.is_some() {
                    (copy_body, None)
                } else {
                    let (body, sent) = watch_end(copy_body);
                    (body, Some(sent))
                };
                let copy = Request::from_parts(copy, copy_body);
                let mirror_state = state.clone();
                let mirror_route = route.clone();
                let mirror_backend = (mirror_host.clone(), *mirror_port);
                let limit = timeout.unwrap_or(MIRROR_TIMEOUT);
                tokio::spawn(async move {
                    let _permit = permit;
                    let uri = copy.uri().to_string();
                    let sent = send_to(&mirror_state, &mirror_route, &mirror_backend, copy);
                    let expiry = attempt_expiry(copy_sent, tokio::time::Instant::now(), limit);
                    tokio::select! {
                        result = sent => {
                            if let Err(e) = result {
                                debug!("Mirror {} failed: {}", uri, e);
                            }
                        }
                        () = expiry => debug!("Mirror {} timed out", uri),
                    }
                });
            }

            // Send to the backend, retrying connection-level failures and timeouts
            // (the backend produced no response). A response that arrives is
            // returned as-is, so a side effect is not replayed — unless the route
            // retries its status: then the next attempt takes over, and the last
            // one's response is returned whatever its status.
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
            // Whether the client's body, not a backend, failed the request.
            let mut client_fault = false;
            let mut picked = plan.last_index();
            let mut uri = Some(((backend_host.clone(), backend_port), primary_uri));
            while let Some((backend, current)) = uri.take() {
                if tries > 0
                    && let Some(backoff) = route.retry_backoff
                {
                    // The request's deadline cuts the wait short.
                    tokio::time::sleep(backoff).await;
                }
                tries += 1;
                target_uri = current.to_string();
                parts.uri = current;
                // The picked backend's own header edits.
                let mut attempt_parts = parts.clone();
                attempt_parts.version = version;
                super::edit_headers(
                    &mut attempt_parts.headers,
                    route.edits_for(picked),
                    HeaderDirection::Request,
                );
                let Some((attempt_body, body_sent)) = request_body.take() else {
                    break;
                };
                let forwarded_req = Request::from_parts(attempt_parts, attempt_body);
                let attempt_start = tokio::time::Instant::now();
                // Counted for the balancers that pick by load, until the
                // backend answers or the attempt ends.
                let waiting = picked.and_then(|index| route.waiting_on(index));
                // Counted a failure if the request's deadline cancels it.
                let attempt = super::passive_health::Attempt::new(
                    state.passive_health.clone(),
                    backend.clone(),
                )
                .excused_by(client_turn(body_sent.clone()));
                // Read when the request's deadline cancels the attempt.
                if let Ok(mut upload) = current_upload.lock() {
                    upload.clone_from(&body_sent);
                }
                forwarded.store(true, std::sync::atomic::Ordering::Relaxed);
                let response_future = send_to(&state, &route, &backend, forwarded_req);

                // The attempt ends at the backend timeout or the request's
                // deadline, whichever comes first. The backend timeout counts
                // from the end of the request body: a long upload is the
                // client's time, which the request's deadline bounds.

                // `Ok(resp)` on success, `Err((msg, is_timeout))` otherwise.
                let result = if let Some(limit) = timeout {
                    let expiry = attempt_expiry(body_sent.clone(), attempt_start, limit);
                    tokio::select! {
                        result = response_future => result.map_err(|e| (e, false)),
                        () = expiry => Err(("timed out".to_string(), true)),
                    }
                } else {
                    response_future.await.map_err(|e| (e, false))
                };

                drop(waiting);
                match result {
                    Ok(resp) => {
                        // An answer, whatever its status: the backend is up.
                        attempt.succeeded();
                        let retried = tries < attempts
                            && request_body.replays()
                            && route.retry_codes.contains(&resp.status().as_u16());
                        let next = if retried {
                            plan.by_ref()
                                .find_map(|b| uri_of(b).map(|u| (b.clone(), u)))
                        } else {
                            None
                        };
                        if next.is_some() {
                            debug!(
                                "Backend {} attempt {} answered {}; retrying",
                                target_uri,
                                tries,
                                resp.status().as_u16()
                            );
                            picked = plan.last_index();
                            uri = next;
                            continue;
                        }
                        let (parts, body) = resp.into_parts();
                        let body = body.map_err(|e| axum::Error::new(std::io::Error::other(e)));
                        // A backend timeout the route sets caps the whole response,
                        // its body included; the default one only the wait for it.
                        // The rest of the attempt's time, as of the answer: an
                        // upload still on its way no longer counts.
                        let limit =
                            timeout.filter(|_| route.backend_timeout.is_some_and(|ms| ms > 0));
                        let body = match limit {
                            Some(limit) => body_before(
                                Body::new(body),
                                attempt_deadline(body_sent.as_ref(), attempt_start, limit),
                                timed_out.clone(),
                            ),
                            None => Body::new(body),
                        };
                        backend_response = Some(Response::from_parts(parts, body));
                    }
                    Err((msg, is_timeout)) => {
                        if client_failed(body_sent.as_ref()) {
                            // The client's body broke the attempt.
                            client_fault = true;
                            attempt.excused();
                        } else {
                            attempt.failed();
                        }
                        last_err = msg;
                        last_was_timeout = is_timeout;
                        // Past the request's deadline, or with a body that
                        // cannot be sent again, no other attempt.
                        let expired = request_deadline
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline);
                        uri = if expired || !request_body.replays() {
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
                    // circuit breaker, unless the client's body did.
                    if let Some(cb) = route.circuit_breaker.as_ref() {
                        cb.record(!client_fault, monotonic_ms());
                    }
                    // Preserve the distinct 504 for a timeout; 502 otherwise.
                    let resp = if client_fault {
                        diag::forwarding_failed("request-body", &last_err).into_response()
                    } else if last_was_timeout {
                        diag::backend_timeout(&target_uri, timeout).into_response()
                    } else {
                        diag::backend_unreachable(&format!("backend at {target_uri}: {last_err}"))
                            .into_response()
                    };
                    state
                        .request_metrics
                        .record(start.elapsed(), resp.status().as_u16());
                    access_log(
                        &source_ip,
                        &method,
                        &host,
                        &path,
                        resp.status().as_u16(),
                        start.elapsed(),
                        "backend",
                    );
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
                    let waiting_on_client = current_upload
                        .lock()
                        .ok()
                        .and_then(|upload| upload.clone())
                        .is_some_and(|sent| matches!(*sent.borrow(), Upload::Client { .. }));
                    cb.record(
                        forwarded.load(std::sync::atomic::Ordering::Relaxed) && !waiting_on_client,
                        monotonic_ms(),
                    );
                }
                let resp = diag::backend_timeout(&host, None).into_response();
                state
                    .request_metrics
                    .record(start.elapsed(), resp.status().as_u16());
                access_log(
                    &source_ip,
                    &method,
                    &host,
                    &path,
                    resp.status().as_u16(),
                    start.elapsed(),
                    "backend",
                );
                resp
            }
        }
    };

    let mut response = fut.instrument(span).await;
    if let Some(route) = matched.get() {
        // The page goes in first, so that the edits and CORS mark it too.
        if let Some(errors) = route.errors.as_ref()
            && errors.replaces(response.status())
        {
            response = errors
                .replace(&request_method, &path_and_query, response)
                .await;
        }
        route.edit_response(&mut response);
        if let Some(cors) = route.cors.as_ref() {
            cors.mark_response(origin.as_ref(), &mut response);
        }
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

/// Send `req` to `backend` with the route's protocol: HTTP/1.1, or h2c
/// under the authority the request names.
async fn send_to(
    state: &MiddlewareAppState,
    route: &super::MiddlewareRoute,
    backend: &(String, u16),
    req: Request<Body>,
) -> Result<Response<hyper::body::Incoming>, String> {
    if route.h2c {
        let authority = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}:{}", uri_host(&backend.0), backend.1));
        state
            .h2c
            .send(backend, &authority, req)
            .await
            .map_err(|e| e.to_string())
    } else {
        state
            .http_client
            .request(req)
            .await
            .map_err(|e| e.to_string())
    }
}

/// `body` streamed on, each part also handed to `copies` bodies for the
/// mirrors. A mirror that falls behind is cut off rather than slow the
/// request or hold its parts: its copy ends with an error.
fn tee(body: Body, copies: usize) -> (Body, Vec<Body>) {
    use futures_util::StreamExt;
    use http_body_util::{BodyStream, StreamBody};

    /// How many parts a mirror may lag behind.
    const MIRROR_LAG: usize = 64;
    let (senders, bodies): (Vec<_>, Vec<_>) = (0..copies)
        .map(|_| {
            let (tx, rx) = tokio::sync::mpsc::channel::<
                Result<hyper::body::Frame<axum::body::Bytes>, axum::Error>,
            >(MIRROR_LAG + 1);
            let frames = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|frame| (frame, rx))
            });
            (Some(tx), Body::new(StreamBody::new(frames)))
        })
        .unzip();
    let frames = futures_util::stream::unfold(
        (BodyStream::new(body), Copies(senders)),
        |(mut frames, mut copies)| async move {
            let Some(frame) = frames.next().await else {
                // Sent whole: the copies end as the body does.
                copies.0.clear();
                return None;
            };
            for sender in copies.0.iter_mut() {
                let Some(tx) = sender else {
                    continue;
                };
                let copy = match &frame {
                    Ok(frame) => match (frame.data_ref(), frame.trailers_ref()) {
                        (Some(data), _) => Ok(hyper::body::Frame::data(data.clone())),
                        (_, Some(trailers)) => Ok(hyper::body::Frame::trailers(trailers.clone())),
                        _ => continue,
                    },
                    Err(_) => Err(axum::Error::new(std::io::Error::other(
                        "client body failed",
                    ))),
                };
                // The last slot is kept for the error that cuts it off:
                // a copy cut short must not look whole.
                if tx.capacity() > 1 && tx.try_send(copy).is_ok() {
                    continue;
                }
                if let Some(tx) = sender.take() {
                    let _ = tx.try_send(Err(axum::Error::new(std::io::Error::other(
                        "mirror fell behind",
                    ))));
                }
            }
            Some((frame, (frames, copies)))
        },
    );
    (Body::new(StreamBody::new(frames)), bodies)
}

/// The mirrors' ends of a [`tee`]: a body dropped before its end, by an
/// attempt that failed, ends their copies with an error, rather than with
/// what looks like the whole body.
struct Copies(Vec<Option<CopySender>>);

/// Where a [`tee`] hands a mirror its parts.
type CopySender =
    tokio::sync::mpsc::Sender<Result<hyper::body::Frame<axum::body::Bytes>, axum::Error>>;

impl Drop for Copies {
    fn drop(&mut self) {
        for tx in self.0.iter_mut().filter_map(Option::take) {
            let _ = tx.try_send(Err(axum::Error::new(std::io::Error::other(
                "the request body was not sent whole",
            ))));
        }
    }
}

/// A request body on its way to the backends: kept to be sent to each
/// attempt, or streamed to the first one alone.
enum RequestBody {
    Replayable(axum::body::Bytes),
    /// `None` once sent.
    Streamed(Option<Body>),
}

impl RequestBody {
    /// The body for the next attempt, with what tells when it has been sent
    /// for a streamed one; `None` when it was streamed already.
    fn take(&mut self) -> Option<(Body, Option<BodySent>)> {
        match self {
            Self::Replayable(bytes) => Some((Body::from(bytes.clone()), None)),
            Self::Streamed(body) => {
                let (body, sent) = watch_end(body.take()?);
                Some((body, Some(sent)))
            }
        }
    }

    /// Whether another attempt can be sent the body.
    fn replays(&self) -> bool {
        matches!(self, Self::Replayable(_))
    }

    /// The whole body, when it is kept.
    fn bytes(&self) -> Option<&axum::body::Bytes> {
        match self {
            Self::Replayable(bytes) => Some(bytes),
            Self::Streamed(_) => None,
        }
    }
}

/// `body` kept to be sent again when it holds at most `limit` bytes,
/// streamed otherwise: its `Content-Length` says so before anything is
/// read, or else the bytes read so far are sent ahead of the rest. A body
/// with trailers is streamed, as only a stream carries them.
async fn replayable(
    mut body: Body,
    headers: &axum::http::HeaderMap,
    limit: usize,
) -> Result<RequestBody, axum::Error> {
    use futures_util::StreamExt;
    use http_body_util::{BodyStream, StreamBody};

    let declared = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit as u64) {
        return Ok(RequestBody::Streamed(Some(body)));
    }
    let mut read: Vec<u8> = Vec::new();
    loop {
        let Some(frame) = body.frame().await else {
            return Ok(RequestBody::Replayable(read.into()));
        };
        let frame = frame?;
        // A part that would take the body past the limit is not copied:
        // it goes on with the stream.
        let past = match frame.into_data() {
            Ok(data) if read.len() + data.len() <= limit => {
                read.extend_from_slice(&data);
                continue;
            }
            Ok(data) => hyper::body::Frame::data(data),
            Err(other) => other,
        };
        let head = std::iter::once(Ok(hyper::body::Frame::data(axum::body::Bytes::from(read))))
            .chain(std::iter::once(Ok(past)));
        let frames = futures_util::stream::iter(head).chain(BodyStream::new(body));
        return Ok(RequestBody::Streamed(Some(Body::new(StreamBody::new(
            frames,
        )))));
    }
}

/// Where a streamed request body is in being sent, and how much of the
/// attempt's time the backend has taken so far (`spent`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Upload {
    /// Up to the backend since `since`: to connect and ask for the body, or
    /// for the next part of it.
    Backend {
        since: tokio::time::Instant,
        spent: std::time::Duration,
    },
    /// Waiting for the client to send the next part: not the backend's time.
    Client { spent: std::time::Duration },
    /// Sent whole, failed, or dropped, at `at`; `failed` when reading it
    /// from the client failed.
    Sent {
        at: tokio::time::Instant,
        spent: std::time::Duration,
        failed: bool,
    },
}

impl Upload {
    /// When an attempt of `limit` runs out, if the backend keeps the turn:
    /// `None` while the client has it.
    fn deadline(self, limit: std::time::Duration) -> Option<tokio::time::Instant> {
        match self {
            Self::Backend { since, spent }
            | Self::Sent {
                at: since, spent, ..
            } => Some(since + limit.saturating_sub(spent)),
            Self::Client { .. } => None,
        }
    }

    /// The backend's time so far, up to `now`.
    fn spent(self, now: tokio::time::Instant) -> std::time::Duration {
        match self {
            Self::Backend { since, spent } => spent + now.saturating_duration_since(since),
            Self::Client { spent } | Self::Sent { spent, .. } => spent,
        }
    }
}

/// Where a streamed request body is in being sent.
type BodySent = tokio::sync::watch::Receiver<Upload>;

/// Moves [`BodySent`] along, and to `Sent` when dropped, which the body is
/// once sent whole, failed or left unsent.
struct SentGuard(tokio::sync::watch::Sender<Upload>);

impl SentGuard {
    /// The client has the turn.
    fn to_client(&self) {
        let now = tokio::time::Instant::now();
        self.0.send_if_modified(|upload| {
            !matches!(upload, Upload::Client { .. }) && {
                *upload = Upload::Client {
                    spent: upload.spent(now),
                };
                true
            }
        });
    }

    /// The backend has the turn.
    fn to_backend(&self) {
        let now = tokio::time::Instant::now();
        self.0.send_modify(|upload| {
            *upload = Upload::Backend {
                since: now,
                spent: upload.spent(now),
            }
        });
    }
}

impl SentGuard {
    /// Sent whole.
    fn finished(self) {
        let now = tokio::time::Instant::now();
        self.0.send_modify(|upload| {
            *upload = Upload::Sent {
                at: now,
                spent: upload.spent(now),
                failed: false,
            }
        });
    }

    /// Reading the body from the client failed.
    fn client_failed(self) {
        let now = tokio::time::Instant::now();
        self.0.send_modify(|upload| {
            *upload = Upload::Sent {
                at: now,
                spent: upload.spent(now),
                failed: true,
            }
        });
    }
}

impl Drop for SentGuard {
    /// Sent, unless dropped on the client's turn: the client kept it
    /// waiting, which is what cancelled it.
    fn drop(&mut self) {
        let now = tokio::time::Instant::now();
        self.0.send_if_modified(|upload| {
            !matches!(upload, Upload::Sent { .. } | Upload::Client { .. }) && {
                *upload = Upload::Sent {
                    at: now,
                    spent: upload.spent(now),
                    failed: false,
                };
                true
            }
        });
    }
}

/// A streamed request body telling where it is in being sent. Its length
/// and end are those of the body it wraps, so the request keeps its framing.
struct Watched {
    inner: Body,
    /// `None` once the body is sent whole or failed.
    guard: Option<SentGuard>,
}

impl hyper::body::Body for Watched {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = &mut *self;
        // Asked for the next part: the client's turn until it comes.
        if let Some(guard) = &this.guard {
            guard.to_client();
        }
        let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(_))) => {
                if let Some(guard) = &this.guard {
                    guard.to_backend();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if let Some(guard) = this.guard.take() {
                    guard.client_failed();
                }
            }
            Poll::Ready(None) => {
                if let Some(guard) = this.guard.take() {
                    guard.finished();
                }
            }
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// `body`, and what tells where it is in being sent.
fn watch_end(body: Body) -> (Body, BodySent) {
    let (tx, rx) = tokio::sync::watch::channel(Upload::Backend {
        since: tokio::time::Instant::now(),
        spent: std::time::Duration::ZERO,
    });
    let watched = Watched {
        inner: body,
        guard: Some(SentGuard(tx)),
    };
    (Body::new(watched), rx)
}

/// When an attempt of `limit` runs out for its response body, as of its
/// answer: what the backend took of it so far is spent, whatever the
/// request body still to come.
fn attempt_deadline(
    sent: Option<&BodySent>,
    start: tokio::time::Instant,
    limit: std::time::Duration,
) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    match sent.map(|sent| *sent.borrow()) {
        None => start + limit,
        Some(upload @ Upload::Sent { .. }) => upload.deadline(limit).unwrap_or(now),
        Some(upload) => now + limit.saturating_sub(upload.spent(now)),
    }
}

/// Whether reading the body behind `sent` from the client failed: the
/// attempt it broke is not the backend's failure.
fn client_failed(sent: Option<&BodySent>) -> bool {
    sent.is_some_and(|sent| matches!(*sent.borrow(), Upload::Sent { failed: true, .. }))
}

/// Whether the client has the turn on the body behind `sent`: an attempt
/// cut then is not the backend's failure.
fn client_turn(sent: Option<BodySent>) -> impl Fn() -> bool + Send + Sync + 'static {
    move || {
        client_failed(sent.as_ref())
            || sent
                .as_ref()
                .is_some_and(|sent| matches!(*sent.borrow(), Upload::Client { .. }))
    }
}

/// Resolves once an attempt started at `start` has taken `limit` of the
/// backend's time: to connect, to ask for each part of the body, and to
/// answer once the body is sent. The time the client takes to send the body
/// is not the backend's.
async fn attempt_expiry(
    sent: Option<BodySent>,
    start: tokio::time::Instant,
    limit: std::time::Duration,
) {
    let Some(mut sent) = sent else {
        tokio::time::sleep_until(start + limit).await;
        return;
    };
    loop {
        let upload = *sent.borrow_and_update();
        match upload.deadline(limit) {
            Some(deadline) if matches!(upload, Upload::Sent { .. }) => {
                tokio::time::sleep_until(deadline).await;
                return;
            }
            Some(deadline) => {
                tokio::select! {
                    () = tokio::time::sleep_until(deadline) => {
                        // The turn may have passed to the client meanwhile.
                        let now = tokio::time::Instant::now();
                        if (*sent.borrow()).deadline(limit).is_some_and(|d| d <= now) {
                            return;
                        }
                    }
                    changed = sent.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                }
            }
            None => {
                if sent.changed().await.is_err() {
                    break;
                }
            }
        }
    }
    // The body is gone without being sent whole, its client's turn cut
    // short: the rest of the time is the backend's, from now.
    let upload = *sent.borrow();
    let now = tokio::time::Instant::now();
    tokio::time::sleep_until(now + limit.saturating_sub(upload.spent(now))).await;
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

/// The nutcome a response body still owes its route's circuit breaker.
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

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::model::{Backend, EntrypointConfig, RetryConfig};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A backend answering `status` to its first `failures` requests, then
    /// `200`, and the number of requests it got.
    async fn backend(failures: usize, status: u16) -> (u16, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let app = axum::Router::new().fallback(move || {
            let counted = counted.clone();
            async move {
                if counted.fetch_add(1, Ordering::SeqCst) < failures {
                    StatusCode::from_u16(status).unwrap()
                } else {
                    StatusCode::OK
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        (port, hits)
    }

    /// The status a request to a route of `retry` gets from `port`.
    async fn status_through(retry: RetryConfig, port: u16) -> u16 {
        let config = EntrypointConfig {
            hostnames: vec!["retry.test".into()],
            retry: Some(retry),
            ..Default::default()
        };
        send_through(config, port, Body::empty()).await
    }

    /// The status a request of `body` to a route of `config` gets from
    /// `port`.
    async fn send_through(config: EntrypointConfig, port: u16, body: Body) -> u16 {
        respond_through(config, port, body).await.status().as_u16()
    }

    /// The response a request of `body` to a route of `config` gets from
    /// `port`.
    async fn respond_through(config: EntrypointConfig, port: u16, body: Body) -> Response<Body> {
        // A body of unknown length comes chunked, as Sōzu forwards it.
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "retry.test")
            .header("transfer-encoding", "chunked")
            .body(body)
            .unwrap();
        request_through(config, port, request).await
    }

    /// The response `request` to a route of `config` gets from `port`.
    async fn request_through(
        config: EntrypointConfig,
        port: u16,
        request: Request<Body>,
    ) -> Response<Body> {
        let backends = [Backend {
            address: "127.0.0.1".into(),
            port,
            weight: 100,
            headers: Vec::new(),
        }];
        let route = super::super::build_middleware_route(
            "retry",
            &config,
            &backends,
            &super::super::build_forward_auth_client(),
            &super::super::PluginRegistry::new(),
            &crate::middleware::ip_allow_list::TrustedProxies::default(),
        );
        let mut table = super::super::MiddlewareRouteTable::default();
        table.update_routes_for_entrypoint(&config.hostnames, None, route);
        let state = MiddlewareAppState {
            route_table: Arc::new(std::sync::RwLock::new(table)),
            http_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http(),
            h2c: Default::default(),
            request_metrics: Default::default(),
            passive_health: Arc::default(),
        };
        handle_proxy(State(state), request).await.into_response()
    }

    fn on(codes: &[u16], attempts: u32) -> RetryConfig {
        RetryConfig {
            attempts,
            codes: codes.to_vec(),
            backoff_ms: None,
        }
    }

    /// A status the route retries goes to the next attempt, up to the
    /// budget; the last attempt's response is returned.
    #[tokio::test]
    async fn a_retried_status_takes_the_next_attempt() {
        let (port, hits) = backend(2, 500).await;
        assert_eq!(status_through(on(&[500], 3), port).await, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        let (port, hits) = backend(4, 500).await;
        assert_eq!(status_through(on(&[500], 3), port).await, 500);
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    /// Another status, or a route listing none, is returned at once.
    #[tokio::test]
    async fn a_status_not_listed_is_not_retried() {
        let (port, hits) = backend(1, 503).await;
        assert_eq!(status_through(on(&[500], 3), port).await, 503);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let (port, hits) = backend(1, 500).await;
        assert_eq!(status_through(on(&[], 3), port).await, 500);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// A retry waits the backoff first.
    #[tokio::test]
    async fn a_retry_waits_the_backoff() {
        let (port, hits) = backend(1, 502).await;
        let started = std::time::Instant::now();
        let retry = RetryConfig {
            backoff_ms: Some(200),
            ..on(&[502], 2)
        };
        assert_eq!(status_through(retry, port).await, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() >= std::time::Duration::from_millis(200));
    }

    /// A backend reading the whole body, answering `status` to its first
    /// `failures` requests and then `200`, and the body sizes it read.
    async fn reading_backend(
        failures: usize,
        status: u16,
    ) -> (u16, Arc<std::sync::Mutex<Vec<usize>>>) {
        let read = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = read.clone();
        let app = axum::Router::new()
            .fallback(move |body: axum::body::Bytes| {
                let seen = seen.clone();
                async move {
                    let mut seen = seen.lock().unwrap();
                    seen.push(body.len());
                    if seen.len() <= failures {
                        StatusCode::from_u16(status).unwrap()
                    } else {
                        StatusCode::OK
                    }
                }
            })
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        (port, read)
    }

    fn retrying(codes: &[u16], attempts: u32) -> EntrypointConfig {
        EntrypointConfig {
            hostnames: vec!["retry.test".into()],
            retry: Some(on(codes, attempts)),
            ..Default::default()
        }
    }

    /// A body small enough is kept, and sent again on a retry.
    #[tokio::test]
    async fn a_small_body_is_sent_again_on_a_retry() {
        let (port, read) = reading_backend(1, 503).await;
        let body = Body::from(vec![b'a'; 1000]);
        assert_eq!(send_through(retrying(&[503], 2), port, body).await, 200);
        assert_eq!(*read.lock().unwrap(), [1000, 1000]);
    }

    /// A body past the limit is streamed to one attempt, whole, and not
    /// retried: there is nothing left to send again.
    #[tokio::test]
    async fn a_large_body_is_streamed_and_not_retried() {
        let size = REPLAY_BODY_LIMIT + 10;
        let (port, read) = reading_backend(1, 503).await;
        // Without a length, in chunks: read past the limit, then streamed.
        let chunks = futures_util::stream::iter(
            vec![vec![b'a'; 64 * 1024]; size / (64 * 1024)]
                .into_iter()
                .chain(std::iter::once(vec![b'a'; size % (64 * 1024)]))
                .map(|c| Ok::<_, std::io::Error>(axum::body::Bytes::from(c))),
        );
        let body = Body::from_stream(chunks);
        assert_eq!(send_through(retrying(&[503], 3), port, body).await, 503);
        assert_eq!(*read.lock().unwrap(), [size]);
    }

    /// A slow upload is the client's time: the backend timeout counts from
    /// the end of the body.
    #[tokio::test]
    async fn the_backend_timeout_starts_once_the_body_is_sent() {
        let (port, read) = reading_backend(0, 200).await;
        let chunks = futures_util::stream::unfold(0, |n| async move {
            if n == 5 {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Some((
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"chunk")),
                n + 1,
            ))
        });
        let config = EntrypointConfig {
            hostnames: vec!["retry.test".into()],
            backend_timeout: Some(200),
            ..Default::default()
        };
        assert_eq!(
            send_through(config, port, Body::from_stream(chunks)).await,
            200
        );
        assert_eq!(*read.lock().unwrap(), [25]);
    }

    /// Before the backend asks for the body, the attempt is timed from its
    /// start: a connection that never comes up still times out.
    #[tokio::test]
    async fn an_attempt_times_out_before_the_body_is_asked_for() {
        let ms = std::time::Duration::from_millis;
        let (_body, sent) = watch_end(Body::from("x"));
        let start = tokio::time::Instant::now();
        attempt_expiry(Some(sent.clone()), start, ms(100)).await;
        assert!(start.elapsed() >= ms(100) && start.elapsed() < ms(300));

        // Asked for and sent at once: the rest of the time is for the
        // answer.
        let (body, sent) = watch_end(Body::from("x"));
        let start = tokio::time::Instant::now();
        drop(body.collect().await);
        attempt_expiry(Some(sent), start, ms(100)).await;
        assert!(start.elapsed() >= ms(95), "{:?}", start.elapsed());
    }

    /// A backend that stops asking for the body runs out its time; a client
    /// slow to send it does not.
    #[tokio::test]
    async fn only_the_backend_stalling_the_upload_runs_out_the_time() {
        use futures_util::StreamExt;
        let ms = std::time::Duration::from_millis;
        let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(1);
        let client = tokio_stream_from(rx);
        let (body, sent) = watch_end(Body::from_stream(client));
        let mut frames = http_body_util::BodyStream::new(body);
        let start = tokio::time::Instant::now();
        let expiry = tokio::spawn(attempt_expiry(Some(sent), start, ms(100)));
        // The backend asks; the client takes 300 ms to send a part.
        let reader = tokio::spawn(async move {
            let first = frames.next().await;
            (first.is_some(), frames)
        });
        tokio::time::sleep(ms(300)).await;
        assert!(!expiry.is_finished());
        tx.send(axum::body::Bytes::from_static(b"part"))
            .await
            .unwrap();
        let (got, _frames) = reader.await.unwrap();
        assert!(got);
        // Then the backend stops asking: out of time 100 ms later.
        let stalled = tokio::time::Instant::now();
        expiry.await.unwrap();
        assert!(stalled.elapsed() >= ms(90), "{:?}", stalled.elapsed());
    }

    /// A route whose backends speak h2c reaches them over HTTP/2, the
    /// response's trailers passed on: gRPC goes through.
    #[tokio::test]
    async fn an_h2c_route_carries_trailers() {
        use hyper::body::Frame;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service =
                hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
                    assert_eq!(req.version(), axum::http::Version::HTTP_2);
                    // The client's authority, not the backend's address.
                    assert_eq!(
                        req.uri().authority().map(|a| a.as_str()),
                        Some("retry.test")
                    );
                    let frames = futures_util::stream::iter([
                        Ok::<_, std::convert::Infallible>(Frame::data(
                            axum::body::Bytes::from_static(b"reply"),
                        )),
                        Ok(Frame::trailers({
                            let mut t = axum::http::HeaderMap::new();
                            t.insert("grpc-status", "0".parse().unwrap());
                            t
                        })),
                    ]);
                    Ok::<_, std::convert::Infallible>(Response::new(
                        http_body_util::StreamBody::new(frames),
                    ))
                });
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
        let config = EntrypointConfig {
            hostnames: vec!["retry.test".into()],
            h2c_backends: true,
            ..Default::default()
        };
        // Over HTTP/2 from Sōzu: the authority, no Host header.
        let request = Request::builder()
            .method("POST")
            .uri("http://retry.test/svc/Call")
            .version(axum::http::Version::HTTP_2)
            .body(Body::from("call"))
            .unwrap();
        let response = request_through(config, port, request).await;
        assert_eq!(response.status(), 200);
        let collected = response.into_body().collect().await.unwrap();
        assert_eq!(
            collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .map(|v| v.as_bytes()),
            Some(&b"0"[..])
        );
        assert_eq!(collected.to_bytes(), "reply");
    }

    /// A streamed body reaches its mirrors part by part, whole; a mirror
    /// that does not keep up is cut off, the request going on without it.
    #[tokio::test]
    async fn a_streamed_body_is_copied_as_it_goes() {
        let parts = || {
            futures_util::stream::iter(
                (0..200).map(|_| Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"x"))),
            )
        };
        let (primary, mut copies) = tee(Body::from_stream(parts()), 2);
        let reader = copies.remove(0);
        let lagging = copies.remove(0);
        let read = tokio::spawn(async move { reader.collect().await.map(|c| c.to_bytes().len()) });
        // The request is sent whole although one mirror never reads, at
        // the pace of a network the reading mirror keeps up with.
        let mut frames = http_body_util::BodyStream::new(primary);
        let mut sent = 0;
        while let Some(frame) = futures_util::StreamExt::next(&mut frames).await {
            sent += frame.unwrap().into_data().unwrap().len();
            tokio::task::yield_now().await;
        }
        assert_eq!(sent, 200);
        assert_eq!(read.await.unwrap().unwrap(), 200);
        assert!(lagging.collect().await.is_err());

        // A body dropped before its end leaves its copies failed, not short.
        let (primary, mut copies) = tee(Body::from_stream(parts()), 1);
        let mut frames = http_body_util::BodyStream::new(primary);
        let _ = futures_util::StreamExt::next(&mut frames).await;
        drop(frames);
        assert!(copies.remove(0).collect().await.is_err());
    }

    /// A body the client fails to send is the client's fault.
    #[tokio::test]
    async fn a_failed_upload_is_the_clients_fault() {
        let failing = futures_util::stream::iter([
            Ok(axum::body::Bytes::from_static(b"part")),
            Err(std::io::Error::other("client gone")),
        ]);
        let (body, sent) = watch_end(Body::from_stream(failing));
        assert!(body.collect().await.is_err());
        assert!(client_failed(Some(&sent)));

        let (body, sent) = watch_end(Body::from("whole"));
        drop(body.collect().await);
        assert!(!client_failed(Some(&sent)));
    }

    /// Cancelled on the client's turn, an upload stays the client's.
    #[tokio::test]
    async fn an_upload_cut_on_the_clients_turn_stays_the_clients() {
        let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(1);
        let (body, sent) = watch_end(Body::from_stream(tokio_stream_from(rx)));
        let mut frames = http_body_util::BodyStream::new(body);
        // Asked for a part the client does not send.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(20), {
            use futures_util::StreamExt;
            frames.next()
        })
        .await;
        drop(frames);
        drop(tx);
        assert!(client_turn(Some(sent))());
    }

    /// A body dropped on its client's turn leaves the backend the rest of
    /// the time, not none of it.
    #[tokio::test]
    async fn a_dropped_upload_is_no_timeout() {
        let ms = std::time::Duration::from_millis;
        let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(1);
        let (body, sent) = watch_end(Body::from_stream(tokio_stream_from(rx)));
        let mut frames = http_body_util::BodyStream::new(body);
        let _ = tokio::time::timeout(ms(20), {
            use futures_util::StreamExt;
            frames.next()
        })
        .await;
        drop(frames);
        drop(tx);
        let start = tokio::time::Instant::now();
        attempt_expiry(Some(sent), start, ms(100)).await;
        assert!(start.elapsed() >= ms(50), "{:?}", start.elapsed());
    }

    /// A watched body keeps the length of the one it wraps.
    #[test]
    fn a_watched_body_keeps_its_length() {
        use hyper::body::Body as _;
        let (body, _sent) = watch_end(Body::from("hello"));
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    /// A part past the limit is streamed on, not copied.
    #[tokio::test]
    async fn a_part_past_the_limit_is_not_copied() {
        let headers = axum::http::HeaderMap::new();
        let mut streamed = replayable(Body::from("0123456789"), &headers, 5)
            .await
            .unwrap();
        assert!(!streamed.replays());
        let (body, _) = streamed.take().unwrap();
        assert_eq!(body.collect().await.unwrap().to_bytes(), "0123456789");
    }

    /// The backend's turns add up: no single one runs out the time, all
    /// of them do.
    #[test]
    fn the_backend_time_adds_up() {
        let now = tokio::time::Instant::now();
        let ms = std::time::Duration::from_millis;
        let backend = Upload::Backend {
            since: now,
            spent: ms(80),
        };
        assert_eq!(backend.deadline(ms(100)), Some(now + ms(20)));
        assert_eq!(backend.spent(now + ms(10)), ms(90));
        let client = Upload::Client { spent: ms(90) };
        assert_eq!(client.deadline(ms(100)), None);
        let sent = Upload::Sent {
            at: now,
            spent: ms(150),
            failed: false,
        };
        assert_eq!(sent.deadline(ms(100)), Some(now));
    }

    fn tokio_stream_from(
        mut rx: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    ) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|b| b.map(Ok)))
    }

    #[tokio::test]
    async fn a_body_is_kept_up_to_the_limit() {
        let headers = axum::http::HeaderMap::new();
        let kept = replayable(Body::from("hello"), &headers, 5).await.unwrap();
        assert_eq!(kept.bytes().map(|b| b.as_ref()), Some(&b"hello"[..]));

        // Past it, streamed, all of it.
        let mut streamed = replayable(Body::from("hello!"), &headers, 5).await.unwrap();
        assert!(!streamed.replays());
        let (body, _) = streamed.take().unwrap();
        assert_eq!(body.collect().await.unwrap().to_bytes(), "hello!");
        assert!(streamed.take().is_none());

        // A length past it: streamed unread.
        let mut long = axum::http::HeaderMap::new();
        long.insert(axum::http::header::CONTENT_LENGTH, "6".parse().unwrap());
        assert!(
            !replayable(Body::from("hello!"), &long, 5)
                .await
                .unwrap()
                .replays()
        );
    }

    fn with_error_page(status: &[&str]) -> EntrypointConfig {
        EntrypointConfig {
            hostnames: vec!["retry.test".into()],
            errors: Some(crate::model::BackendErrorsConfig {
                status: status.iter().map(|s| s.to_string()).collect(),
                page: Some("<h1>down</h1>".into()),
                url: None,
            }),
            ..Default::default()
        }
    }

    async fn text_of(response: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// A route listing the backend's status serves its page instead, with
    /// that status.
    #[tokio::test]
    async fn the_error_page_replaces_a_backend_error() {
        let (port, _) = backend(1, 503).await;
        let response = respond_through(with_error_page(&["500-599"]), port, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(text_of(response).await, "<h1>down</h1>");
    }

    /// A status the route does not list passes through.
    #[tokio::test]
    async fn the_error_page_leaves_other_statuses() {
        let (port, _) = backend(0, 503).await;
        let response = respond_through(with_error_page(&["500-599"]), port, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(text_of(response).await, "<h1>down</h1>");

        let (port, _) = backend(1, 503).await;
        let response = respond_through(with_error_page(&["404"]), port, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(text_of(response).await, "<h1>down</h1>");
    }

    /// The middleware's own answer for a backend it cannot reach is
    /// replaced too.
    #[tokio::test]
    async fn the_error_page_replaces_an_unreachable_backend() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let response = respond_through(with_error_page(&["502"]), port, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(text_of(response).await, "<h1>down</h1>");
    }
}
