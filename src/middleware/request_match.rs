use axum::body::Body;
use axum::http::Request;
use tracing::debug;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;
use super::ip_allow_list::{IpAllowList, TrustedProxies, resolve_client_ip};
use crate::model::MatchCondition;

/// Enforces header / query / client-IP match conditions an entrypoint declares.
/// Sōzu routes on host/path/method only, so when a route is additionally scoped
/// to a header, query parameter, or client IP we let Sōzu route it, then this
/// middleware rejects with `404 Not Found` if a condition is not met — as if the
/// route didn't match.
///
/// `404` (not `403`) is deliberate: a failed match means "this route does not
/// apply", which is a not-found, not a forbidden. The client-IP matcher is thus
/// a *routing* construct, distinct from the `ip_allow_list` *access filter*
/// which returns `403`; both reuse the same CIDR parser and `X-Forwarded-For`
/// trust model from [`super::ip_allow_list`].
pub struct RequestMatchMiddleware {
    headers: Vec<MatchCondition>,
    query: Vec<MatchCondition>,
    /// Client-IP allow-list for routing. `None` when no `matchClientIP` was set
    /// (or every entry was invalid) — in that case the IP is not constrained.
    client_ip: Option<IpAllowList>,
    trusted: TrustedProxies,
}

impl RequestMatchMiddleware {
    pub fn new(
        headers: Vec<MatchCondition>,
        query: Vec<MatchCondition>,
        client_ip: Option<IpAllowList>,
        trusted: TrustedProxies,
    ) -> Self {
        Self {
            headers,
            query,
            client_ip,
            trusted,
        }
    }

    /// Every header condition must hold: the header is present and, when the
    /// condition's `value` is non-empty, equals it (case-insensitive name,
    /// exact value). An empty `value` matches on presence alone.
    fn headers_match(&self, req: &Request<Body>) -> bool {
        self.headers.iter().all(|cond| {
            req.headers()
                .get_all(&cond.key)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| cond.value.is_empty() || v == cond.value)
        })
    }

    /// Every query condition must hold against the request's query string.
    /// An empty `value` matches when the key is present with any value.
    fn query_match(&self, req: &Request<Body>) -> bool {
        let query = req.uri().query().unwrap_or("");
        let pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            })
            .collect();
        self.query.iter().all(|cond| {
            pairs
                .iter()
                .any(|(k, v)| *k == cond.key && (cond.value.is_empty() || *v == cond.value))
        })
    }

    /// The client-IP condition holds when no `matchClientIP` is set, or when
    /// the resolved client IP is in the configured list. A request with no
    /// resolvable client IP (no TCP peer, no usable `X-Forwarded-For`) does
    /// *not* match — the route is gated on IP identity it cannot establish.
    fn client_ip_match(&self, req: &Request<Body>, ctx: &RequestCtx) -> bool {
        let Some(list) = self.client_ip.as_ref() else {
            return true;
        };
        match resolve_client_ip(req, ctx, &self.trusted) {
            Some(ip) => list.allows(ip),
            None => false,
        }
    }
}

#[async_trait::async_trait]
impl Middleware for RequestMatchMiddleware {
    fn name(&self) -> &'static str {
        "request-match"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        if !self.headers_match(req) || !self.query_match(req) || !self.client_ip_match(req, ctx) {
            debug!(
                "request-match: conditions not met for {}, returning 404",
                ctx.host
            );
            return Flow::ShortCircuit(diag::no_match(&ctx.host));
        }
        Flow::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond(key: &str, value: &str) -> MatchCondition {
        MatchCondition {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    fn req(headers: &[(&str, &str)], uri: &str) -> Request<Body> {
        let mut b = Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    fn mw(headers: Vec<MatchCondition>, query: Vec<MatchCondition>) -> RequestMatchMiddleware {
        RequestMatchMiddleware::new(headers, query, None, TrustedProxies::default())
    }

    #[test]
    fn header_value_must_equal() {
        let m = mw(vec![cond("X-Env", "prod")], vec![]);
        assert!(m.headers_match(&req(&[("X-Env", "prod")], "/")));
        assert!(!m.headers_match(&req(&[("X-Env", "staging")], "/")));
        assert!(!m.headers_match(&req(&[], "/")));
    }

    #[test]
    fn header_presence_only_when_value_empty() {
        let m = mw(vec![cond("X-Debug", "")], vec![]);
        assert!(m.headers_match(&req(&[("X-Debug", "anything")], "/")));
        assert!(!m.headers_match(&req(&[], "/")));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let m = mw(vec![cond("x-env", "prod")], vec![]);
        assert!(m.headers_match(&req(&[("X-Env", "prod")], "/")));
    }

    #[test]
    fn all_header_conditions_required() {
        let m = mw(vec![cond("X-A", "1"), cond("X-B", "2")], vec![]);
        assert!(m.headers_match(&req(&[("X-A", "1"), ("X-B", "2")], "/")));
        assert!(!m.headers_match(&req(&[("X-A", "1")], "/")));
    }

    #[test]
    fn query_value_must_equal() {
        let m = mw(vec![], vec![cond("version", "2")]);
        assert!(m.query_match(&req(&[], "/?version=2")));
        assert!(!m.query_match(&req(&[], "/?version=1")));
        assert!(!m.query_match(&req(&[], "/")));
    }

    #[test]
    fn query_presence_only_when_value_empty() {
        let m = mw(vec![], vec![cond("beta", "")]);
        assert!(m.query_match(&req(&[], "/?beta")));
        assert!(m.query_match(&req(&[], "/?beta=1")));
        assert!(!m.query_match(&req(&[], "/?other=1")));
    }

    #[test]
    fn query_among_multiple_params() {
        let m = mw(vec![], vec![cond("version", "2")]);
        assert!(m.query_match(&req(&[], "/?a=1&version=2&b=3")));
    }

    #[test]
    fn empty_conditions_always_match() {
        let m = mw(vec![], vec![]);
        assert!(m.headers_match(&req(&[], "/")));
        assert!(m.query_match(&req(&[], "/")));
    }

    // ---- Client-IP matcher -----------------------------------------------

    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    fn ctx(peer: Option<&str>) -> RequestCtx {
        RequestCtx {
            host: "example.com".to_string(),
            client_addr: peer.map(|p| SocketAddr::new(IpAddr::from_str(p).unwrap(), 12345)),
            is_tls: false,
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        }
    }

    fn ip_mw(entries: &[&str]) -> RequestMatchMiddleware {
        let list = IpAllowList::new(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        RequestMatchMiddleware::new(vec![], vec![], Some(list), TrustedProxies::default())
    }

    #[test]
    fn no_client_ip_matcher_matches_everything() {
        let m = mw(vec![], vec![]);
        assert!(m.client_ip_match(&req(&[], "/"), &ctx(Some("198.51.100.7"))));
    }

    #[test]
    fn client_ip_in_range_matches() {
        let m = ip_mw(&["10.0.0.0/8"]);
        assert!(m.client_ip_match(&req(&[], "/"), &ctx(Some("10.1.2.3"))));
    }

    #[test]
    fn client_ip_out_of_range_does_not_match() {
        let m = ip_mw(&["10.0.0.0/8"]);
        assert!(!m.client_ip_match(&req(&[], "/"), &ctx(Some("198.51.100.7"))));
    }

    #[test]
    fn client_ip_unresolvable_does_not_match() {
        // No TCP peer, no trusted proxies → no resolvable IP → route doesn't match.
        let m = ip_mw(&["10.0.0.0/8"]);
        assert!(!m.client_ip_match(&req(&[], "/"), &ctx(None)));
    }

    #[test]
    fn client_ip_spoofed_xff_ignored_without_trusted_proxies() {
        // Public peer spoofs XFF of an allowed IP. With no trusted proxies the
        // peer is what's matched → out of range → no match.
        let m = ip_mw(&["10.0.0.0/8"]);
        let r = req(&[("x-forwarded-for", "10.0.0.1")], "/");
        assert!(!m.client_ip_match(&r, &ctx(Some("198.51.100.7"))));
    }

    #[test]
    fn all_invalid_client_ip_entries_yields_open_matcher() {
        // Mirrors build_middleware_route: an all-invalid list becomes `None`
        // upstream, so here we just assert IpAllowList reports it empty.
        let list = IpAllowList::new(&["nope".to_string()]);
        assert!(list.is_empty());
    }
}
