use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use tracing::{debug, error, warn};

use super::chain::{Flow, Middleware, RequestCtx};
use crate::model::ForwardAuthConfig;

/// Snapshot of the incoming request needed to call the forward-auth endpoint.
/// We extract this before the async call so the handler future stays `Send`
/// (axum `Body` is `!Sync`).
pub struct AuthRequestSnapshot {
    pub method: Method,
    pub uri: String,
    pub host: String,
    pub headers: HeaderMap,
    pub is_tls: bool,
}

pub const TIMEOUT_SECS: u64 = 5;

/// Hop-by-hop headers (RFC 7230 §6.1) that must not be copied between
/// endpoints when relaying through a proxy.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP.iter().any(|h| *h == lower)
}

pub enum ForwardAuthOutcome {
    /// Auth service returned 2xx — caller should forward to backend with these
    /// extra headers stamped onto the request.
    Allow {
        headers: Vec<(HeaderName, HeaderValue)>,
    },
    /// Anything else (3xx/4xx/5xx, network failure): return this response to
    /// the client untouched. Backend is NOT called.
    Deny(Response<Body>),
}

/// Call the configured forward-auth endpoint and return whether the request
/// is allowed. Network failures and non-2xx responses both deny the request.
pub async fn evaluate(
    client: &reqwest::Client,
    cfg: &ForwardAuthConfig,
    snapshot: AuthRequestSnapshot,
    client_addr: Option<SocketAddr>,
) -> ForwardAuthOutcome {
    let url = match reqwest::Url::parse(&cfg.address) {
        Ok(u) => u,
        Err(e) => {
            error!("forward-auth: invalid URL {}: {}", cfg.address, e);
            return ForwardAuthOutcome::Deny(bad_gateway("forward-auth: invalid url"));
        }
    };

    let mut headers =
        build_outgoing_headers(&snapshot.headers, client_addr, cfg.trust_forward_header);

    let proto = if snapshot.is_tls { "https" } else { "http" };

    headers.insert(
        HeaderName::from_static("x-forwarded-method"),
        HeaderValue::from_str(snapshot.method.as_str()).unwrap_or(HeaderValue::from_static("GET")),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-uri"),
        HeaderValue::from_str(&snapshot.uri).unwrap_or(HeaderValue::from_static("/")),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(&snapshot.host).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(if proto == "https" { "https" } else { "http" }),
    );

    let mut req_builder = client.request(Method::GET, url);
    for (name, value) in headers.iter() {
        req_builder = req_builder.header(name.as_str(), value);
    }

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("forward-auth: call to {} failed: {}", cfg.address, e);
            return ForwardAuthOutcome::Deny(bad_gateway("forward-auth: backend unreachable"));
        }
    };

    let status = resp.status();
    debug!("forward-auth: {} returned {}", cfg.address, status);

    if status.is_success() {
        let mut allow = Vec::new();
        for header_name in &cfg.response_headers {
            if let Some(v) = resp.headers().get(header_name)
                && let (Ok(name), Ok(value)) = (
                    HeaderName::try_from(header_name.as_str()),
                    HeaderValue::from_bytes(v.as_bytes()),
                )
            {
                allow.push((name, value));
            }
        }
        return ForwardAuthOutcome::Allow { headers: allow };
    }

    let mut builder = Response::builder().status(status.as_u16());
    if let Some(map) = builder.headers_mut() {
        for (name, value) in resp.headers() {
            if is_hop_by_hop(name.as_str()) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                map.append(n, v);
            }
        }
    }

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!("forward-auth: failed to read response body: {}", e);
            return ForwardAuthOutcome::Deny(bad_gateway("forward-auth: response body unreadable"));
        }
    };

    let response = builder
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| bad_gateway("forward-auth: cannot build response"));
    ForwardAuthOutcome::Deny(response)
}

/// Middleware wrapper: calls the forward-auth endpoint before the backend.
/// On allow, stamps the configured response headers onto the request; on deny,
/// short-circuits with the auth service's response. Matches the previous
/// inline forward-auth step (which ran first in the chain).
pub struct ForwardAuthMiddleware {
    config: ForwardAuthConfig,
    client: reqwest::Client,
}

impl ForwardAuthMiddleware {
    pub fn new(config: ForwardAuthConfig, client: reqwest::Client) -> Self {
        Self { config, client }
    }
}

#[async_trait::async_trait]
impl Middleware for ForwardAuthMiddleware {
    fn name(&self) -> &'static str {
        "forward-auth"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // Snapshot the request before the async call so the future stays Send
        // (axum Body is !Sync).
        let snapshot = AuthRequestSnapshot {
            method: req.method().clone(),
            uri: req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| req.uri().path().to_string()),
            host: ctx.host.clone(),
            headers: req.headers().clone(),
            is_tls: ctx.is_tls,
        };

        match evaluate(&self.client, &self.config, snapshot, ctx.client_addr).await {
            ForwardAuthOutcome::Allow { headers } => {
                for (name, value) in headers {
                    req.headers_mut().insert(name, value);
                }
                Flow::Continue
            }
            ForwardAuthOutcome::Deny(response) => Flow::ShortCircuit(response),
        }
    }
}

fn build_outgoing_headers(
    incoming: &HeaderMap,
    client_addr: Option<SocketAddr>,
    trust_forward_header: bool,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in incoming.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) {
            continue;
        }
        if !trust_forward_header && lower.starts_with("x-forwarded-") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    let client_ip = client_addr.map(|a| a.ip().to_string());
    let appended_xff = match (
        trust_forward_header,
        incoming
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok()),
        client_ip,
    ) {
        (true, Some(existing), Some(ip)) => format!("{existing}, {ip}"),
        (true, Some(existing), None) => existing.to_string(),
        (_, _, Some(ip)) => ip,
        _ => String::new(),
    };
    if !appended_xff.is_empty()
        && let Ok(v) = HeaderValue::from_str(&appended_xff)
    {
        out.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    out
}

fn bad_gateway(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(format!("{reason}\n")))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::BAD_GATEWAY;
            r
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::try_from(*k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn hop_by_hop_headers_are_filtered() {
        let h = headers(&[
            ("Connection", "close"),
            ("Cookie", "a=b"),
            ("Upgrade", "websocket"),
        ]);
        let out = build_outgoing_headers(&h, None, false);
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("upgrade"));
        assert_eq!(out.get("cookie").unwrap(), "a=b");
    }

    #[test]
    fn untrusted_strips_existing_x_forwarded_and_sets_fresh() {
        let h = headers(&[
            ("X-Forwarded-For", "9.9.9.9"),
            ("X-Forwarded-Proto", "https"),
        ]);
        let addr: SocketAddr = "203.0.113.1:5555".parse().unwrap();
        let out = build_outgoing_headers(&h, Some(addr), false);
        assert_eq!(out.get("x-forwarded-for").unwrap(), "203.0.113.1");
        assert!(!out.contains_key("x-forwarded-proto"));
    }

    #[test]
    fn trusted_appends_to_x_forwarded_for() {
        let h = headers(&[("X-Forwarded-For", "9.9.9.9")]);
        let addr: SocketAddr = "203.0.113.1:5555".parse().unwrap();
        let out = build_outgoing_headers(&h, Some(addr), true);
        assert_eq!(out.get("x-forwarded-for").unwrap(), "9.9.9.9, 203.0.113.1");
    }
}
