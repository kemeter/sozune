//! gRPC-Web: the gRPC that browsers can send, translated into gRPC for the
//! backends and back (as Traefik's `grpcWeb` and Envoy's `grpc_web` do).
//!
//! A gRPC-Web call is the same length-prefixed messages over HTTP/1.1 or
//! HTTP/2, without HTTP trailers, which browsers cannot read: the answer
//! carries its trailers (the call's `grpc-status`) as a last message,
//! flagged `0x80`. In the `-text` variant both bodies are base64.

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hyper::body::Frame;

use crate::model::{CorsConfig, EntrypointConfig};

const GRPC_WEB: &str = "application/grpc-web";
const GRPC_WEB_TEXT: &str = "application/grpc-web-text";

/// The kind of a gRPC-Web call: base64 or not, and the message format it
/// names (`+proto`, `+json`), kept for the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Kind {
    text: bool,
    format: String,
}

impl Kind {
    /// The kind of the call `headers` start, `None` for anything else.
    pub(crate) fn of(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
        let value = value.split(';').next().unwrap_or("").trim();
        let lower = value.to_ascii_lowercase();
        let (text, rest) = if let Some(rest) = lower.strip_prefix(GRPC_WEB_TEXT) {
            (true, rest)
        } else {
            (false, lower.strip_prefix(GRPC_WEB)?)
        };
        if !(rest.is_empty() || rest.starts_with('+')) {
            return None;
        }
        Some(Self {
            text,
            format: rest.to_string(),
        })
    }

    /// The content type of the gRPC call it becomes.
    fn grpc_type(&self) -> HeaderValue {
        HeaderValue::from_str(&format!("application/grpc{}", self.format))
            .unwrap_or_else(|_| HeaderValue::from_static("application/grpc"))
    }

    /// The content type of the answer the browser gets.
    pub(crate) fn web_type(&self) -> HeaderValue {
        let base = if self.text { GRPC_WEB_TEXT } else { GRPC_WEB };
        HeaderValue::from_str(&format!("{base}{}", self.format))
            .unwrap_or_else(|_| HeaderValue::from_static(GRPC_WEB))
    }
}

/// The route's CORS policy, with what gRPC-Web pages need added when its
/// `grpc_web` allows other origins: their preflight lets them send a call
/// (`POST`, with its content type and gRPC-Web headers), and they may read
/// the call's status.
pub(crate) fn cors(config: &EntrypointConfig) -> Option<CorsConfig> {
    let origins = config
        .grpc_web
        .as_ref()
        .map(|web| web.allow_origins.as_slice())
        .filter(|origins| !origins.is_empty());
    let Some(origins) = origins else {
        return config.cors.clone();
    };
    let mut cors = config.cors.clone().unwrap_or_default();
    let add = |list: &mut Vec<String>, wanted: &[&str]| {
        if list.iter().any(|v| v == "*") {
            return;
        }
        for value in wanted {
            if !list.iter().any(|v| v.eq_ignore_ascii_case(value)) {
                list.push((*value).to_string());
            }
        }
    };
    add(
        &mut cors.allow_origins,
        &origins.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    add(&mut cors.allow_methods, &["POST"]);
    add(
        &mut cors.allow_headers,
        &["content-type", "x-grpc-web", "x-user-agent", "grpc-timeout"],
    );
    add(&mut cors.expose_headers, &["grpc-status", "grpc-message"]);
    Some(cors)
}

/// `request`, a gRPC-Web call of `kind`, as the gRPC call the backend
/// takes: its content type, `te: trailers`, and its body decoded from
/// base64 for a `-text` one.
pub(crate) fn into_grpc(request: Request<Body>, kind: &Kind) -> Request<Body> {
    let (mut parts, body) = request.into_parts();
    parts.headers.insert(header::CONTENT_TYPE, kind.grpc_type());
    parts
        .headers
        .insert(header::TE, HeaderValue::from_static("trailers"));
    let body = if kind.text {
        // Its length changes.
        parts.headers.remove(header::CONTENT_LENGTH);
        Body::new(Decoded {
            inner: body,
            pending: Vec::new(),
            done: false,
        })
    } else {
        body
    };
    Request::from_parts(parts, body)
}

/// `response`, the backend's gRPC answer to a call of `kind`, as the
/// gRPC-Web answer the browser reads: its trailers become a last message,
/// and the whole body base64 for a `-text` call. Anything but a gRPC
/// answer is left as it is.
pub(crate) fn from_grpc(response: Response<Body>, kind: &Kind) -> Response<Body> {
    if response.status() != StatusCode::OK || !super::grpc::is_call(response.headers()) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    parts.headers.insert(header::CONTENT_TYPE, kind.web_type());
    parts.headers.remove(header::CONTENT_LENGTH);
    let body = Body::new(Encoded {
        inner: body,
        text: kind.text,
        pending: Vec::new(),
        done: false,
    });
    Response::from_parts(parts, body)
}

/// The message gRPC-Web carries `trailers` in: flag `0x80`, its length,
/// then the trailers as `name:value` lines.
fn trailers_message(trailers: &HeaderMap) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in trailers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.push(b':');
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    let mut message = Vec::with_capacity(5 + block.len());
    message.push(0x80);
    message.extend_from_slice(&(block.len() as u32).to_be_bytes());
    message.extend_from_slice(&block);
    message
}

/// A gRPC answer's body, as gRPC-Web.
struct Encoded {
    inner: Body,
    text: bool,
    /// For a `-text` answer, the bytes not yet base64: a multiple of 3 is
    /// encoded as it comes, so no padding falls mid-way.
    pending: Vec<u8>,
    done: bool,
}

impl Encoded {
    /// `bytes` as the answer sends them on: as they are, or base64 up to
    /// the last whole 3 bytes, the rest kept (all of it when `last`).
    fn out(&mut self, bytes: &[u8], last: bool) -> Bytes {
        if !self.text {
            return Bytes::copy_from_slice(bytes);
        }
        self.pending.extend_from_slice(bytes);
        let whole = if last {
            self.pending.len()
        } else {
            self.pending.len() - self.pending.len() % 3
        };
        let encoded = STANDARD.encode(&self.pending[..whole]);
        self.pending.drain(..whole);
        Bytes::from(encoded)
    }
}

impl hyper::body::Body for Encoded {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let out = this.out(&data, false);
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                    Err(frame) => {
                        let Ok(trailers) = frame.into_trailers() else {
                            continue;
                        };
                        this.done = true;
                        // The data left goes first, with its padding: the
                        // trailers are a base64 run of their own.
                        let mut out = this.out(&[], true).to_vec();
                        let message = trailers_message(&trailers);
                        out.extend_from_slice(&this.out(&message, true));
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                    }
                },
                Poll::Ready(None) => {
                    this.done = true;
                    let out = this.out(&[], true);
                    if out.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

/// A `-text` call's body, decoded from base64 as it comes.
struct Decoded {
    inner: Body,
    /// Characters not yet decoded: a group of 4 is decoded once whole.
    pending: Vec<u8>,
    done: bool,
}

/// The bytes of `text`, base64 in groups of 4 where a group may end a run
/// with its padding and another run follow. `None` when it is not base64.
fn decode_runs(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut start = 0;
    for (index, group) in text.chunks(4).enumerate() {
        let end = (index + 1) * 4;
        if group.contains(&b'=') || end == text.len() {
            out.extend(STANDARD.decode(&text[start..end.min(text.len())]).ok()?);
            start = end;
        }
    }
    Some(out)
}

impl hyper::body::Body for Decoded {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            let last = match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        this.pending
                            .extend(data.iter().filter(|b| !b.is_ascii_whitespace()));
                    }
                    false
                }
                Poll::Ready(None) => {
                    this.done = true;
                    true
                }
            };
            let whole = this.pending.len() - this.pending.len() % 4;
            let take = if last { this.pending.len() } else { whole };
            if take == 0 {
                continue;
            }
            let text: Vec<u8> = this.pending.drain(..take).collect();
            return match decode_runs(&text) {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes))))),
                None => {
                    this.done = true;
                    Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the gRPC-Web call is not base64",
                    )))))
                }
            };
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GrpcWebConfig;
    use http_body_util::BodyExt;

    fn with_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, value.parse().unwrap());
        headers
    }

    #[test]
    fn the_kind_of_a_call_is_its_content_type() {
        let binary = Kind::of(&with_type("application/grpc-web+proto")).unwrap();
        assert!(!binary.text);
        assert_eq!(binary.grpc_type(), "application/grpc+proto");
        assert_eq!(binary.web_type(), "application/grpc-web+proto");

        let text = Kind::of(&with_type("application/grpc-web-text")).unwrap();
        assert!(text.text);
        assert_eq!(text.grpc_type(), "application/grpc");
        assert_eq!(text.web_type(), "application/grpc-web-text");

        let charset = Kind::of(&with_type("Application/GRPC-Web; charset=utf-8")).unwrap();
        assert_eq!(charset.grpc_type(), "application/grpc");

        for other in [
            "application/grpc",
            "application/grpc-webx",
            "application/json",
        ] {
            assert!(Kind::of(&with_type(other)).is_none(), "{other}");
        }
    }

    /// A gRPC message frame of `payload`.
    fn message(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn a_call_becomes_a_grpc_call() {
        let request = Request::builder()
            .header("content-type", "application/grpc-web+proto")
            .header("content-length", "8")
            .body(Body::from(message(b"abc")))
            .unwrap();
        let kind = Kind::of(request.headers()).unwrap();
        let grpc = into_grpc(request, &kind);
        assert_eq!(grpc.headers()["content-type"], "application/grpc+proto");
        assert_eq!(grpc.headers()["te"], "trailers");
        assert_eq!(grpc.headers()["content-length"], "8");
        let body = grpc.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), message(b"abc"));
    }

    /// A `-text` call is decoded, in whatever parts it comes, padded runs
    /// one after another included.
    #[tokio::test]
    async fn a_text_call_is_decoded_as_it_comes() {
        let first = message(b"first");
        let second = message(b"second message");
        let text = format!("{}{}", STANDARD.encode(&first), STANDARD.encode(&second));
        let parts: Vec<Result<Bytes, std::io::Error>> = text
            .as_bytes()
            .chunks(5)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let request = Request::builder()
            .header("content-type", "application/grpc-web-text")
            .header("content-length", text.len().to_string())
            .body(Body::from_stream(futures_util::stream::iter(parts)))
            .unwrap();
        let kind = Kind::of(request.headers()).unwrap();
        let grpc = into_grpc(request, &kind);
        assert!(!grpc.headers().contains_key("content-length"));
        let body = grpc.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), [first, second].concat());
    }

    #[tokio::test]
    async fn a_text_call_that_is_not_base64_fails() {
        let request = Request::builder()
            .header("content-type", "application/grpc-web-text")
            .body(Body::from("not*base64"))
            .unwrap();
        let kind = Kind::of(request.headers()).unwrap();
        assert!(
            into_grpc(request, &kind)
                .into_body()
                .collect()
                .await
                .is_err()
        );
    }

    /// A gRPC answer: `messages`, then `grpc-status: 0` in trailers.
    fn grpc_answer(messages: &[&[u8]]) -> Response<Body> {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let frames: Vec<Result<Frame<Bytes>, axum::Error>> = messages
            .iter()
            .map(|m| Ok(Frame::data(Bytes::from(message(m)))))
            .chain(std::iter::once(Ok(Frame::trailers(trailers))))
            .collect();
        Response::builder()
            .header("content-type", "application/grpc+proto")
            .header("content-length", "99")
            .body(Body::new(http_body_util::StreamBody::new(
                futures_util::stream::iter(frames),
            )))
            .unwrap()
    }

    /// The answer's trailers come as its last message, and no HTTP
    /// trailers are left.
    #[tokio::test]
    async fn the_answer_carries_its_trailers_as_a_message() {
        let kind = Kind::of(&with_type("application/grpc-web+proto")).unwrap();
        let web = from_grpc(grpc_answer(&[b"reply"]), &kind);
        assert_eq!(web.headers()["content-type"], "application/grpc-web+proto");
        assert!(!web.headers().contains_key("content-length"));
        let collected = web.into_body().collect().await.unwrap();
        assert!(collected.trailers().is_none());
        let mut expected = message(b"reply");
        expected.extend_from_slice(&[0x80, 0, 0, 0, 15]);
        expected.extend_from_slice(b"grpc-status:0\r\n");
        assert_eq!(collected.to_bytes().as_ref(), expected);
    }

    /// A `-text` answer is base64, in runs that decode back to the binary
    /// answer.
    #[tokio::test]
    async fn a_text_answer_is_base64() {
        let binary = Kind::of(&with_type("application/grpc-web+proto")).unwrap();
        let text = Kind::of(&with_type("application/grpc-web-text+proto")).unwrap();
        let answer = &[&b"one"[..], &b"second reply"[..]];
        let expected = from_grpc(grpc_answer(answer), &binary)
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let web = from_grpc(grpc_answer(answer), &text);
        assert_eq!(
            web.headers()["content-type"],
            "application/grpc-web-text+proto"
        );
        let encoded = web.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(decode_runs(&encoded).unwrap(), expected.as_ref());
    }

    /// An answer that is not gRPC is left as it is.
    #[test]
    fn another_answer_is_left_alone() {
        let kind = Kind::of(&with_type("application/grpc-web")).unwrap();
        let html = Response::builder()
            .status(503)
            .header("content-type", "text/html")
            .body(Body::empty())
            .unwrap();
        let left = from_grpc(html, &kind);
        assert_eq!(left.status(), 503);
        assert_eq!(left.headers()["content-type"], "text/html");
    }

    #[test]
    fn other_origins_get_the_cors_grpc_web_needs() {
        let config = EntrypointConfig {
            grpc_web: Some(GrpcWebConfig {
                allow_origins: vec!["https://app.example".into()],
            }),
            ..Default::default()
        };
        let policy = cors(&config).unwrap();
        assert_eq!(policy.allow_origins, ["https://app.example"]);
        assert_eq!(policy.allow_methods, ["POST"]);
        assert!(policy.allow_headers.contains(&"x-grpc-web".to_string()));
        assert_eq!(policy.expose_headers, ["grpc-status", "grpc-message"]);

        // The route's own policy is kept, and completed.
        let config = EntrypointConfig {
            cors: Some(CorsConfig {
                allow_origins: vec!["https://other.example".into()],
                allow_headers: vec!["*".into()],
                ..Default::default()
            }),
            ..config
        };
        let policy = cors(&config).unwrap();
        assert_eq!(
            policy.allow_origins,
            ["https://other.example", "https://app.example"]
        );
        assert_eq!(policy.allow_headers, ["*"]);

        // Without other origins, no policy is added.
        let own = EntrypointConfig {
            grpc_web: Some(GrpcWebConfig::default()),
            ..Default::default()
        };
        assert!(cors(&own).is_none());
    }
}
