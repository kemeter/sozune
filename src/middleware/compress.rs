use axum::body::Body;
use axum::http::{HeaderMap, Request, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use tracing::debug;

use super::chain::{Flow, Middleware, RequestCtx};

const COMPRESSIBLE_TYPES: &[&str] = &[
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml",
    "application/rss",
    "application/atom",
    "image/svg",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Zstd,
    Brotli,
    Gzip,
}

impl Encoding {
    pub fn header_value(self) -> &'static str {
        match self {
            Encoding::Zstd => "zstd",
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }
}

/// Pick the best supported encoding from the client's Accept-Encoding header.
/// Order of preference: zstd > brotli > gzip.
pub fn pick_encoding(headers: &HeaderMap) -> Option<Encoding> {
    let raw = headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())?;
    let tokens: Vec<&str> = raw.split(',').map(|s| s.trim()).collect();

    let accepts = |needle: &str| {
        tokens.iter().any(|tok| {
            let name = tok.split(';').next().unwrap_or("").trim();
            name.eq_ignore_ascii_case(needle)
        })
    };

    if accepts("zstd") {
        Some(Encoding::Zstd)
    } else if accepts("br") {
        Some(Encoding::Brotli)
    } else if accepts("gzip") {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

pub fn is_compressible(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| COMPRESSIBLE_TYPES.iter().any(|t| ct.contains(t)))
}

pub fn is_already_compressed(headers: &HeaderMap) -> bool {
    headers.contains_key("content-encoding")
}

/// A compressor fed a response part by part. Each part goes out compressed
/// as soon as it comes in, flushed: a stream (Server-Sent Events, a long
/// download) reaches the client as it goes, never held whole in memory.
enum StreamEncoder {
    Gzip(GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl StreamEncoder {
    fn new(encoding: Encoding) -> std::io::Result<Self> {
        Ok(match encoding {
            Encoding::Gzip => Self::Gzip(GzEncoder::new(Vec::new(), Compression::fast())),
            Encoding::Brotli => Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                4,
                22,
            ))),
            Encoding::Zstd => Self::Zstd(zstd::stream::write::Encoder::new(Vec::new(), 3)?),
        })
    }

    /// `data` compressed, with whatever the compressor held back before.
    fn part(&mut self, data: &[u8]) -> std::io::Result<axum::body::Bytes> {
        let out = match self {
            Self::Gzip(e) => {
                e.write_all(data)?;
                e.flush()?;
                e.get_mut()
            }
            Self::Brotli(e) => {
                e.write_all(data)?;
                e.flush()?;
                e.get_mut()
            }
            Self::Zstd(e) => {
                e.write_all(data)?;
                e.flush()?;
                e.get_mut()
            }
        };
        Ok(std::mem::take(out).into())
    }

    /// The end of the compressed body.
    fn finish(self) -> std::io::Result<axum::body::Bytes> {
        Ok(match self {
            Self::Gzip(e) => e.finish()?,
            Self::Brotli(e) => e.into_inner(),
            Self::Zstd(e) => e.finish()?,
        }
        .into())
    }
}

/// `body` compressed by `encoder`, part by part. Its trailers follow the
/// end of the compressed data; an error from it ends the body as it would
/// have uncompressed.
fn compressed(body: Body, encoder: StreamEncoder) -> Body {
    use futures_util::StreamExt;
    use http_body_util::{BodyStream, StreamBody};
    use hyper::body::Frame;

    type Item = Result<Frame<axum::body::Bytes>, axum::Error>;
    let frames =
        futures_util::stream::unfold(Some((BodyStream::new(body), encoder)), |state| async move {
            let (mut frames, mut encoder) = state?;
            loop {
                let next: Vec<Item> = match frames.next().await {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(data) => match encoder.part(&data) {
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => vec![Ok(Frame::data(out))],
                            Err(e) => return Some((vec![Err(axum::Error::new(e))], None)),
                        },
                        // Trailers come last: the compressed data ends first.
                        Err(trailers) => {
                            let end = encoder.finish().map_err(axum::Error::new);
                            return Some((vec![end.map(Frame::data), Ok(trailers)], None));
                        }
                    },
                    Some(Err(e)) => return Some((vec![Err(e)], None)),
                    None => {
                        let end = encoder.finish().map_err(axum::Error::new);
                        return Some((vec![end.map(Frame::data)], None));
                    }
                };
                return Some((next, Some((frames, encoder))));
            }
        })
        .flat_map(futures_util::stream::iter);
    Body::new(StreamBody::new(frames))
}

/// Middleware wrapper: compresses the response body when the client accepts a
/// supported encoding and the content is compressible. The encoding is
/// negotiated from the request (`ctx.client_encoding`) and applied here on the
/// response. Behavior matches the previous inline compression step.
pub struct CompressMiddleware;

#[async_trait::async_trait]
impl Middleware for CompressMiddleware {
    fn name(&self) -> &'static str {
        "compress"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // Negotiate now, on the request, but apply on the response.
        ctx.client_encoding = pick_encoding(req.headers());
        Flow::Continue
    }

    async fn on_response(&self, ctx: &RequestCtx, resp: Response<Body>) -> Response<Body> {
        let (mut parts, body) = resp.into_parts();

        let encoding = ctx
            .client_encoding
            .filter(|_| is_compressible(&parts.headers) && !is_already_compressed(&parts.headers));

        let Some(encoding) = encoding else {
            return Response::from_parts(parts, body);
        };

        // The compressed body is streamed: its length is not known ahead.
        let encoder = match StreamEncoder::new(encoding) {
            Ok(encoder) => encoder,
            Err(e) => {
                debug!("Compression unavailable, sending uncompressed: {}", e);
                return Response::from_parts(parts, body);
            }
        };
        let body = compressed(body, encoder);
        parts
            .headers
            .insert("content-encoding", encoding.header_value().parse().unwrap());
        parts.headers.remove("content-length");
        Response::from_parts(parts, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};
    use flate2::read::GzDecoder;
    use std::io::Read;
    use std::str::FromStr;

    fn headers_with(key: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str(key).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    /// A body cut short by the route's timeout ends the compressed body with
    /// the error, as it would end an uncompressed one.
    #[tokio::test]
    async fn a_body_cut_short_ends_the_compressed_body() {
        let ctx = RequestCtx {
            host: "example.com".to_string(),
            client_addr: None,
            is_tls: false,
            method: axum::http::Method::GET,
            path: "/".to_string(),
            client_encoding: Some(Encoding::Gzip),
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        };
        let cut = futures_util::stream::iter([Err::<axum::body::Bytes, _>(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "past the route's timeout",
        ))]);
        let resp = Response::builder()
            .header("content-type", "text/plain")
            .body(Body::from_stream(cut))
            .unwrap();
        let resp = CompressMiddleware.on_response(&ctx, resp).await;
        assert!(
            http_body_util::BodyExt::collect(resp.into_body())
                .await
                .is_err()
        );
    }

    /// Each part goes out compressed as it comes, and the whole decodes to
    /// the body, trailers kept, whatever the encoding.
    #[tokio::test]
    async fn a_body_is_compressed_part_by_part() {
        use futures_util::StreamExt;
        use hyper::body::Frame;
        for encoding in [Encoding::Gzip, Encoding::Brotli, Encoding::Zstd] {
            let parts = futures_util::stream::iter([
                Ok::<_, std::convert::Infallible>(Frame::data(axum::body::Bytes::from_static(
                    b"data: one\n\n",
                ))),
                Ok(Frame::data(axum::body::Bytes::from_static(
                    b"data: two\n\n",
                ))),
                Ok(Frame::trailers({
                    let mut t = HeaderMap::new();
                    t.insert("x-done", "1".parse().unwrap());
                    t
                })),
            ]);
            let body = compressed(
                Body::new(http_body_util::StreamBody::new(parts)),
                StreamEncoder::new(encoding).unwrap(),
            );
            let mut frames = http_body_util::BodyStream::new(body);
            // The first part is out before the rest comes.
            let first = frames.next().await.unwrap().unwrap().into_data().unwrap();
            assert!(!first.is_empty());
            let mut wire = first.to_vec();
            let mut trailers = None;
            while let Some(frame) = frames.next().await {
                match frame.unwrap().into_data() {
                    Ok(data) => wire.extend_from_slice(&data),
                    Err(frame) => trailers = frame.into_trailers().ok(),
                }
            }
            let plain = match encoding {
                Encoding::Gzip => {
                    let mut out = String::new();
                    GzDecoder::new(&wire[..]).read_to_string(&mut out).unwrap();
                    out.into_bytes()
                }
                Encoding::Brotli => {
                    let mut out = Vec::new();
                    brotli::BrotliDecompress(&mut std::io::Cursor::new(&wire), &mut out).unwrap();
                    out
                }
                Encoding::Zstd => zstd::decode_all(std::io::Cursor::new(&wire)).unwrap(),
            };
            assert_eq!(plain, b"data: one\n\ndata: two\n\n", "{encoding:?}");
            assert_eq!(trailers.unwrap()["x-done"], "1");
        }
    }

    #[test]
    fn picks_gzip_when_only_gzip_offered() {
        let headers = headers_with("accept-encoding", "gzip, deflate");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Gzip));
    }

    #[test]
    fn prefers_brotli_over_gzip() {
        let headers = headers_with("accept-encoding", "gzip, br");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Brotli));
    }

    #[test]
    fn picks_brotli_when_only_brotli_offered() {
        let headers = headers_with("accept-encoding", "br");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Brotli));
    }

    #[test]
    fn picks_zstd_when_only_zstd_offered() {
        let headers = headers_with("accept-encoding", "zstd");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Zstd));
    }

    #[test]
    fn prefers_zstd_over_brotli_and_gzip() {
        let headers = headers_with("accept-encoding", "gzip, br, zstd");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Zstd));
    }

    #[test]
    fn returns_none_without_accept_encoding() {
        assert_eq!(pick_encoding(&HeaderMap::new()), None);
    }

    #[test]
    fn returns_none_for_unsupported_encoding() {
        let headers = headers_with("accept-encoding", "deflate, snappy");
        assert_eq!(pick_encoding(&headers), None);
    }

    #[test]
    fn ignores_quality_values() {
        let headers = headers_with("accept-encoding", "gzip;q=1.0, br;q=0.5");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Brotli));
    }

    #[test]
    fn detects_compressible_types() {
        assert!(is_compressible(&headers_with(
            "content-type",
            "text/html; charset=utf-8"
        )));
        assert!(is_compressible(&headers_with(
            "content-type",
            "application/json"
        )));
        assert!(is_compressible(&headers_with(
            "content-type",
            "image/svg+xml"
        )));
        assert!(!is_compressible(&headers_with("content-type", "image/png")));
        assert!(!is_compressible(&headers_with(
            "content-type",
            "application/octet-stream"
        )));
    }

    #[test]
    fn detects_already_compressed_responses() {
        assert!(is_already_compressed(&headers_with(
            "content-encoding",
            "gzip"
        )));
        assert!(is_already_compressed(&headers_with(
            "content-encoding",
            "br"
        )));
        assert!(!is_already_compressed(&HeaderMap::new()));
    }

    #[test]
    fn encoding_header_values() {
        assert_eq!(Encoding::Gzip.header_value(), "gzip");
        assert_eq!(Encoding::Brotli.header_value(), "br");
        assert_eq!(Encoding::Zstd.header_value(), "zstd");
    }
}
