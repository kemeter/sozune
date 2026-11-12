//! What the middleware does differently for a gRPC call.
//!
//! A gRPC client reads the outcome of a call in its `grpc-status`, not in
//! the HTTP status. When the middleware answers a call itself (no backend,
//! a timeout, a rate limit, a refused credential), it answers the way a
//! gRPC server would: HTTP `200`, `content-type: application/grpc`, no
//! body, and the status in `grpc-status` and `grpc-message` (the
//! "trailers-only" form). A call the backend answered and that fails
//! mid-way (a timeout, the backend gone) ends with such a status in its
//! trailers too, rather than with a reset stream.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use hyper::body::Frame;

/// Whether the request is a gRPC call: its content type is
/// `application/grpc`, or a subtype of it (`application/grpc+proto`,
/// `application/grpc;charset=…`). gRPC-Web (`application/grpc-web`) is
/// not: it is plain HTTP to the proxy.
pub(crate) fn is_call(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.get(.."application/grpc".len()).map(|head| (head, v)))
        .is_some_and(|(head, value)| {
            head.eq_ignore_ascii_case("application/grpc")
                && matches!(value.as_bytes().get(head.len()), None | Some(b'+' | b';'))
        })
}

/// Set on a response the backend gave, as opposed to one the middleware
/// made: only the latter is turned into a gRPC answer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Relayed;

/// The gRPC codes the middleware answers with.
mod code {
    pub const UNKNOWN: u32 = 2;
    pub const DEADLINE_EXCEEDED: u32 = 4;
    pub const PERMISSION_DENIED: u32 = 7;
    pub const RESOURCE_EXHAUSTED: u32 = 8;
    pub const UNIMPLEMENTED: u32 = 12;
    pub const INTERNAL: u32 = 13;
    pub const UNAVAILABLE: u32 = 14;
    pub const UNAUTHENTICATED: u32 = 16;
}

/// The gRPC status of an answer the middleware gave with HTTP `status`.
/// It follows the mapping gRPC clients apply to an HTTP status (the
/// `http-grpc-status-mapping` of the gRPC docs), except where the
/// middleware knows better: a timeout is `DEADLINE_EXCEEDED` and a rate
/// or concurrency limit `RESOURCE_EXHAUSTED`, which clients do not retry
/// on their own as they do `UNAVAILABLE`.
fn status_of(status: StatusCode) -> u32 {
    match status.as_u16() {
        400 => code::INTERNAL,
        401 => code::UNAUTHENTICATED,
        403 => code::PERMISSION_DENIED,
        404 | 501 => code::UNIMPLEMENTED,
        408 | 504 => code::DEADLINE_EXCEEDED,
        413 | 429 => code::RESOURCE_EXHAUSTED,
        500 => code::INTERNAL,
        502 | 503 => code::UNAVAILABLE,
        _ => code::UNKNOWN,
    }
}

/// `message` as a `grpc-message` value: percent-encoded past printable
/// ASCII, and `%` itself, as the gRPC wire format requires.
fn encode_message(message: &str) -> HeaderValue {
    let mut out = String::with_capacity(message.len());
    for byte in message.bytes() {
        if (0x20..=0x7e).contains(&byte) && byte != b'%' {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    HeaderValue::from_str(&out).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The `grpc-status` and `grpc-message` of status `code` with `message`.
fn status_headers(headers: &mut HeaderMap, code: u32, message: &str) {
    headers.insert("grpc-status", HeaderValue::from(code));
    headers.insert("grpc-message", encode_message(message));
}

/// `response`, an answer the middleware gave to a gRPC call, in the form a
/// gRPC server answers with. A success or a redirect is left as it is, and
/// so is an answer that already carries a `grpc-status` (a plugin's).
pub(crate) fn answer(response: Response<Body>) -> Response<Body> {
    let status = response.status();
    if status.as_u16() < 400 || response.headers().contains_key("grpc-status") {
        return response;
    }
    let (mut parts, _) = response.into_parts();
    let reason = parts
        .headers
        .get("x-sozune-diagnostic")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let message = match reason {
        Some(reason) => format!("sozune: {reason} (HTTP {})", status.as_u16()),
        None => format!(
            "sozune: {} (HTTP {})",
            status
                .canonical_reason()
                .unwrap_or("error")
                .to_ascii_lowercase(),
            status.as_u16()
        ),
    };
    for name in [
        axum::http::header::CONTENT_TYPE,
        axum::http::header::CONTENT_LENGTH,
        axum::http::header::TRANSFER_ENCODING,
    ] {
        parts.headers.remove(name);
    }
    parts.headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    status_headers(&mut parts.headers, status_of(status), &message);
    parts.status = StatusCode::OK;
    Response::from_parts(parts, Body::empty())
}

/// `response`, the backend's answer to a gRPC call, ending with a gRPC
/// status in its trailers if its body fails: `DEADLINE_EXCEEDED` when a
/// timeout cut it short, `UNAVAILABLE` otherwise. Anything but a gRPC
/// answer is left as it is.
pub(crate) fn ends_with_status(response: Response<Body>) -> Response<Body> {
    let grpc_answer = response.status() == StatusCode::OK && is_call(response.headers());
    if !grpc_answer {
        return response;
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(EndsWithStatus {
            inner: body,
            done: false,
        }),
    )
}

/// A gRPC answer's body whose failure ends it with a status in trailers.
struct EndsWithStatus {
    inner: Body,
    done: bool,
}

impl hyper::body::Body for EndsWithStatus {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                let (code, message) = if super::timed_out(&e) {
                    (
                        code::DEADLINE_EXCEEDED,
                        "sozune: the call ran past the route's timeout",
                    )
                } else {
                    (code::UNAVAILABLE, "sozune: the backend failed mid-call")
                };
                let mut trailers = HeaderMap::new();
                status_headers(&mut trailers, code, message);
                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn made(status: StatusCode, reason: Option<&'static str>) -> Response<Body> {
        let mut builder = Response::builder()
            .status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .header("retry-after", "1");
        if let Some(reason) = reason {
            builder = builder.header("x-sozune-diagnostic", reason);
        }
        builder.body(Body::from("details")).unwrap()
    }

    /// An error the middleware made is answered as a gRPC server would:
    /// 200, no body, the status in headers.
    #[tokio::test]
    async fn an_error_is_answered_in_grpc_form() {
        let response = answer(made(
            StatusCode::SERVICE_UNAVAILABLE,
            Some("no-healthy-backend"),
        ));
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers["content-type"], "application/grpc");
        assert_eq!(headers["grpc-status"], "14");
        assert_eq!(
            headers["grpc-message"],
            "sozune: no-healthy-backend (HTTP 503)"
        );
        // The other headers stay: they are the call's metadata.
        assert_eq!(headers["retry-after"], "1");
        assert!(!headers.contains_key("content-length"));
        let body = response.into_body();
        assert!(hyper::body::Body::is_end_stream(&body));
        assert!(body.collect().await.unwrap().to_bytes().is_empty());
    }

    /// Without a diagnostic, the message names the HTTP status.
    #[test]
    fn an_error_without_a_reason_names_its_status() {
        let response = answer(made(StatusCode::UNAUTHORIZED, None));
        assert_eq!(response.headers()["grpc-status"], "16");
        assert_eq!(
            response.headers()["grpc-message"],
            "sozune: unauthorized (HTTP 401)"
        );
    }

    /// A success, a redirect, or an answer with its own gRPC status is
    /// left as it is.
    #[test]
    fn other_answers_are_left_alone() {
        for status in [StatusCode::OK, StatusCode::PERMANENT_REDIRECT] {
            let response = answer(made(status, None));
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key("grpc-status"));
        }
        let mut own = made(StatusCode::FORBIDDEN, None);
        own.headers_mut()
            .insert("grpc-status", HeaderValue::from_static("7"));
        let response = answer(own);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn each_status_has_its_grpc_code() {
        let cases = [
            (400, code::INTERNAL),
            (401, code::UNAUTHENTICATED),
            (403, code::PERMISSION_DENIED),
            (404, code::UNIMPLEMENTED),
            (429, code::RESOURCE_EXHAUSTED),
            (500, code::INTERNAL),
            (502, code::UNAVAILABLE),
            (503, code::UNAVAILABLE),
            (504, code::DEADLINE_EXCEEDED),
            (418, code::UNKNOWN),
        ];
        for (status, expected) in cases {
            assert_eq!(
                status_of(StatusCode::from_u16(status).unwrap()),
                expected,
                "{status}"
            );
        }
    }

    #[test]
    fn the_message_is_percent_encoded() {
        assert_eq!(encode_message("plain text"), "plain text");
        assert_eq!(encode_message("100% sure"), "100%25 sure");
        assert_eq!(encode_message("café\n"), "caf%C3%A9%0A");
    }

    fn grpc_answer(body: Body) -> Response<Body> {
        Response::builder()
            .header("content-type", "application/grpc")
            .body(body)
            .unwrap()
    }

    /// The trailers a failing body of a gRPC answer ends with.
    async fn trailers_after(error: std::io::Error) -> HeaderMap {
        let frames = futures_util::stream::iter([
            Ok(axum::body::Bytes::from_static(b"message")),
            Err(error),
        ]);
        let response = ends_with_status(grpc_answer(Body::from_stream(frames)));
        let collected = response.into_body().collect().await.unwrap();
        assert_eq!(collected.trailers().map(|t| t.len()), Some(2));
        collected.trailers().unwrap().clone()
    }

    /// A call cut short by a timeout ends with DEADLINE_EXCEEDED, one whose
    /// backend failed with UNAVAILABLE.
    #[tokio::test]
    async fn a_call_failing_mid_way_ends_with_a_status() {
        let timed_out = trailers_after(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "past the timeout",
        ))
        .await;
        assert_eq!(timed_out["grpc-status"], "4");
        let failed = trailers_after(std::io::Error::other("reset")).await;
        assert_eq!(failed["grpc-status"], "14");
    }

    /// A body that ends well is untouched, its trailers its own.
    #[tokio::test]
    async fn a_call_ending_well_is_untouched() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let frames = [
            Ok::<_, axum::Error>(Frame::data(axum::body::Bytes::from_static(b"message"))),
            Ok(Frame::trailers(trailers)),
        ];
        let body = Body::new(http_body_util::StreamBody::new(futures_util::stream::iter(
            frames,
        )));
        let collected = ends_with_status(grpc_answer(body))
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
        assert_eq!(collected.to_bytes(), "message");
    }

    fn with_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::CONTENT_TYPE, value.parse().unwrap());
        headers
    }

    #[test]
    fn a_grpc_content_type_is_a_call() {
        for value in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc;charset=utf-8",
            "Application/GRPC",
        ] {
            assert!(is_call(&with_type(value)), "{value}");
        }
    }

    #[test]
    fn other_content_types_are_not_calls() {
        for value in [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/json",
            "application/grpcx",
            "application/grp",
        ] {
            assert!(!is_call(&with_type(value)), "{value}");
        }
        assert!(!is_call(&HeaderMap::new()));
    }
}
