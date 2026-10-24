use axum::body::Body;
use axum::http::Request;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;

/// Answers `500` to every request of a route that declares backends none of
/// which could be resolved, as Gateway API requires of such a rule.
pub struct InvalidBackends;

#[async_trait::async_trait]
impl Middleware for InvalidBackends {
    fn name(&self) -> &'static str {
        "invalid-backends"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, _req: &mut Request<Body>) -> Flow {
        Flow::ShortCircuit(diag::invalid_backends(&ctx.host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_request_gets_a_500() {
        let mut ctx = RequestCtx {
            host: "example.com".to_string(),
            client_addr: None,
            is_tls: false,
            method: axum::http::Method::GET,
            path: "/".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        };
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        match InvalidBackends.on_request(&mut ctx, &mut req).await {
            Flow::ShortCircuit(resp) => {
                assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            }
            Flow::Continue => panic!("the request went on"),
        }
    }
}
