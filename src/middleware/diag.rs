//! Builders for runtime diagnostic responses returned when a request can't be
//! routed. The header `X-Sozune-Diagnostic` is always set so operators can grep
//! for the failure reason without parsing bodies. The body only carries
//! configured-state details (known hosts, configured backends) when
//! `SOZUNE_DEBUG=true`, to avoid leaking topology to the public.

use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;

use crate::util::{debug_enabled, fuzzy::closest_match};

const DIAG_HEADER: &str = "x-sozune-diagnostic";

pub fn no_route_for_host(host: &str, known_hosts: &[String]) -> Response<Body> {
    no_route_for_host_inner(host, known_hosts, debug_enabled())
}

pub fn no_healthy_backend(host: &str, configured_backends: &[(String, u16)]) -> Response<Body> {
    no_healthy_backend_inner(host, configured_backends, debug_enabled())
}

/// 502 Bad Gateway — backend connection failed. `detail` is included in the
/// body when SOZUNE_DEBUG=true.
pub fn backend_unreachable(detail: &str) -> Response<Body> {
    diag_response(
        StatusCode::BAD_GATEWAY,
        "backend-unreachable",
        format!("sozune: backend unreachable.\n\n{detail}\n"),
    )
}

/// 504 Gateway Timeout — backend did not respond within the configured deadline.
pub fn backend_timeout(target: &str, secs: u64) -> Response<Body> {
    diag_response(
        StatusCode::GATEWAY_TIMEOUT,
        "backend-timeout",
        format!("sozune: backend at {target} did not respond within {secs}s.\n"),
    )
}

/// 502 Bad Gateway — generic forwarding error (compression, body read, malformed URI).
pub fn forwarding_failed(reason: &str, detail: &str) -> Response<Body> {
    diag_response(
        StatusCode::BAD_GATEWAY,
        reason,
        format!("sozune: request could not be forwarded ({reason}).\n\n{detail}\n"),
    )
}

/// 500 Internal Server Error — sozune itself is in a bad state.
pub fn internal_error(reason: &str) -> Response<Body> {
    diag_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        reason,
        format!("sozune: internal error ({reason}). The service may need to be restarted.\n"),
    )
}

/// 400 Bad Request — request itself is malformed before any routing.
pub fn bad_request(reason: &str, detail: &str) -> Response<Body> {
    diag_response(
        StatusCode::BAD_REQUEST,
        reason,
        format!("sozune: bad request ({reason}).\n\n{detail}\n"),
    )
}

/// 429 Too Many Requests — rate limit triggered.
pub fn rate_limited(host: &str) -> Response<Body> {
    diag_response(
        StatusCode::TOO_MANY_REQUESTS,
        "rate-limited",
        format!("sozune: too many requests for host '{host}'.\n"),
    )
}

/// 403 Forbidden — the client IP is not in the route's allow-list.
pub fn ip_forbidden(host: &str) -> Response<Body> {
    diag_response(
        StatusCode::FORBIDDEN,
        "ip-forbidden",
        format!("sozune: client IP not allowed for host '{host}'.\n"),
    )
}

pub fn no_match(host: &str) -> Response<Body> {
    diag_response(
        StatusCode::NOT_FOUND,
        "no-match",
        format!("sozune: request did not meet the match conditions for host '{host}'.\n"),
    )
}

fn diag_response(status: StatusCode, reason: &str, debug_body: String) -> Response<Body> {
    let body = if debug_enabled() {
        debug_body
    } else {
        String::new()
    };
    build(status, reason, body)
}

fn no_route_for_host_inner(host: &str, known_hosts: &[String], debug: bool) -> Response<Body> {
    let body = if debug {
        let mut out =
            format!("sozune: no route configured for host '{host}'.\n\nConfigured hosts:\n");
        if known_hosts.is_empty() {
            out.push_str("  (none — no entrypoints loaded)\n");
        } else {
            for h in known_hosts {
                out.push_str(&format!("  - {h}\n"));
            }
        }
        if let Some(suggestion) = suggest_host(host, known_hosts) {
            out.push_str(&format!("\nDid you mean '{suggestion}'?\n"));
        }
        out.push_str("\nSet SOZUNE_DEBUG=false to hide this body in production.\n");
        out
    } else {
        String::new()
    };

    build(StatusCode::BAD_GATEWAY, "no-route-for-host", body)
}

fn no_healthy_backend_inner(
    host: &str,
    configured_backends: &[(String, u16)],
    debug: bool,
) -> Response<Body> {
    let body = if debug {
        let mut out =
            format!("sozune: no backend available for host '{host}'.\n\nConfigured backends:\n");
        if configured_backends.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for (h, p) in configured_backends {
                out.push_str(&format!("  - {h}:{p}\n"));
            }
        }
        out.push_str("\nSet SOZUNE_DEBUG=false to hide this body in production.\n");
        out
    } else {
        String::new()
    };

    build(StatusCode::BAD_GATEWAY, "no-healthy-backend", body)
}

fn suggest_host(host: &str, known_hosts: &[String]) -> Option<String> {
    let refs: Vec<&str> = known_hosts.iter().map(|s| s.as_str()).collect();
    closest_match(host, &refs, 3).map(|s| s.to_string())
}

fn build(status: StatusCode, reason: &str, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(DIAG_HEADER, reason)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn into_parts(resp: Response<Body>) -> (StatusCode, String, String) {
        let status = resp.status();
        let header = resp
            .headers()
            .get(DIAG_HEADER)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, header, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn header_always_set_on_no_route() {
        let resp = no_route_for_host_inner("example.com", &["other.com".to_string()], false);
        let (status, header, body) = into_parts(resp).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(header, "no-route-for-host");
        assert!(body.is_empty(), "expected empty body, got: {body}");
    }

    #[tokio::test]
    async fn debug_body_lists_hosts_and_suggests() {
        let resp = no_route_for_host_inner(
            "exmple.com",
            &["example.com".to_string(), "api.example.com".to_string()],
            true,
        );
        let (_, _, body) = into_parts(resp).await;
        assert!(body.contains("example.com"));
        assert!(body.contains("Did you mean"), "body: {body}");
    }

    #[tokio::test]
    async fn no_backend_diag_with_debug_lists_backends() {
        let resp = no_healthy_backend_inner(
            "example.com",
            &[
                ("10.0.0.1".to_string(), 8080),
                ("10.0.0.2".to_string(), 8080),
            ],
            true,
        );
        let (_, header, body) = into_parts(resp).await;
        assert_eq!(header, "no-healthy-backend");
        assert!(body.contains("10.0.0.1:8080"));
        assert!(body.contains("10.0.0.2:8080"));
    }

    #[tokio::test]
    async fn no_backend_diag_without_debug_is_opaque() {
        let resp = no_healthy_backend_inner("example.com", &[], false);
        let (_, header, body) = into_parts(resp).await;
        assert_eq!(header, "no-healthy-backend");
        assert!(body.is_empty());
    }

    #[test]
    fn debug_enabled_reads_env() {
        unsafe { std::env::set_var("SOZUNE_DEBUG", "true") };
        assert!(debug_enabled());
        unsafe { std::env::set_var("SOZUNE_DEBUG", "1") };
        assert!(debug_enabled());
        unsafe { std::env::set_var("SOZUNE_DEBUG", "false") };
        assert!(!debug_enabled());
        unsafe { std::env::remove_var("SOZUNE_DEBUG") };
        assert!(!debug_enabled());
    }
}
