use axum::body::Body;
use axum::http::Request;
use tracing::debug;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;
use crate::model::MatchCondition;

/// Enforces header / query match conditions an entrypoint declares. Sōzu routes
/// on host/path/method only, so when a route is additionally scoped to a header
/// or query parameter we let Sōzu route it, then this middleware rejects with
/// `404 Not Found` if a condition is not met — as if the route didn't match.
///
/// `404` (not `403`) is deliberate: a failed match means "this route does not
/// apply", which is a not-found, not a forbidden.
pub struct RequestMatchMiddleware {
    headers: Vec<MatchCondition>,
    query: Vec<MatchCondition>,
}

impl RequestMatchMiddleware {
    pub fn new(headers: Vec<MatchCondition>, query: Vec<MatchCondition>) -> Self {
        Self { headers, query }
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
}

#[async_trait::async_trait]
impl Middleware for RequestMatchMiddleware {
    fn name(&self) -> &'static str {
        "request-match"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        if !self.headers_match(req) || !self.query_match(req) {
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
        RequestMatchMiddleware::new(headers, query)
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
}
