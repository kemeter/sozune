use axum::body::Body;
use axum::http::{HeaderMap, Request, Response};
use axum::response::IntoResponse;
use brotli::enc::BrotliEncoderParams;
use flate2::Compression;
use flate2::write::GzEncoder;
use http_body_util::BodyExt;
use std::io::Write;
use tracing::{debug, error};

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;

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

pub fn compress(data: &[u8], encoding: Encoding) -> Result<Vec<u8>, std::io::Error> {
    match encoding {
        Encoding::Gzip => gzip_compress(data),
        Encoding::Brotli => brotli_compress(data),
        Encoding::Zstd => zstd_compress(data),
    }
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    encoder.finish()
}

fn brotli_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::with_capacity(data.len());
    let params = BrotliEncoderParams {
        quality: 4,
        ..Default::default()
    };
    brotli::BrotliCompress(&mut std::io::Cursor::new(data), &mut out, &params)?;
    Ok(out)
}

fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
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

        let body = Body::new(body.map_err(|e| axum::Error::new(std::io::Error::other(e))));
        match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(bytes) => match compress(&bytes, encoding) {
                Ok(compressed) => {
                    parts
                        .headers
                        .insert("content-encoding", encoding.header_value().parse().unwrap());
                    parts.headers.insert(
                        "content-length",
                        compressed.len().to_string().parse().unwrap(),
                    );
                    parts.headers.remove("transfer-encoding");
                    Response::from_parts(parts, Body::from(compressed))
                }
                Err(e) => {
                    debug!("Compression failed, sending uncompressed: {}", e);
                    Response::from_parts(parts, Body::from(bytes))
                }
            },
            Err(e) => {
                error!("Failed to read response body for compression: {}", e);
                diag::forwarding_failed("response-body-read-failed", &e.to_string()).into_response()
            }
        }
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
    fn gzip_roundtrip() {
        let original = b"Hello, World! This is a test of gzip compression.";
        let compressed = compress(original, Encoding::Gzip).unwrap();
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed.as_bytes(), original);
    }

    #[test]
    fn brotli_roundtrip() {
        let original = b"Hello, World! This is a test of brotli compression. \
                         Repetitive text compresses very well with brotli, \
                         which usually beats gzip on HTML and JSON payloads.";
        let compressed = compress(original, Encoding::Brotli).unwrap();
        let mut decompressed = Vec::new();
        brotli::BrotliDecompress(&mut std::io::Cursor::new(&compressed), &mut decompressed)
            .unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn zstd_roundtrip() {
        let original = b"Hello, World! This is a test of zstd compression. \
                         Repetitive text compresses very well with zstd, \
                         which usually beats gzip and matches brotli on speed.";
        let compressed = compress(original, Encoding::Zstd).unwrap();
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn encoding_header_values() {
        assert_eq!(Encoding::Gzip.header_value(), "gzip");
        assert_eq!(Encoding::Brotli.header_value(), "br");
        assert_eq!(Encoding::Zstd.header_value(), "zstd");
    }
}
