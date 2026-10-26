use axum::body::Body;
use axum::http::Request;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;
use crate::model::FixedAnswer;

/// Answers every request of a route that answers them itself (see
/// [`FixedAnswer`]): `500` for a route with no valid backend, as Gateway API
/// requires of such a rule, `404` for a host another listener takes.
pub struct FixedAnswerMiddleware(pub FixedAnswer);

#[async_trait::async_trait]
impl Middleware for FixedAnswerMiddleware {
    fn name(&self) -> &'static str {
        "fixed-answer"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, _req: &mut Request<Body>) -> Flow {
        Flow::ShortCircuit(match self.0 {
            FixedAnswer::InvalidBackends => diag::invalid_backends(&ctx.host),
            FixedAnswer::OtherListener => diag::other_listener(&ctx.host),
        })
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
        match FixedAnswerMiddleware(FixedAnswer::InvalidBackends)
            .on_request(&mut ctx, &mut req)
            .await
        {
            Flow::ShortCircuit(resp) => {
                assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            }
            Flow::Continue => panic!("the request went on"),
        }
    }
}
