use axum::http::HeaderMap;
use brotli::enc::BrotliEncoderParams;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

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
    Brotli,
    Gzip,
}

impl Encoding {
    pub fn header_value(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }
}

/// Pick the best supported encoding from the client's Accept-Encoding header.
/// Brotli is preferred over gzip when both are accepted.
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

    if accepts("br") {
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
    }
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    encoder.finish()
}

fn brotli_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::with_capacity(data.len());
    let mut params = BrotliEncoderParams::default();
    params.quality = 4;
    brotli::BrotliCompress(&mut std::io::Cursor::new(data), &mut out, &params)?;
    Ok(out)
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
    fn prefers_brotli_when_both_offered() {
        let headers = headers_with("accept-encoding", "gzip, br");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Brotli));
    }

    #[test]
    fn picks_brotli_when_only_brotli_offered() {
        let headers = headers_with("accept-encoding", "br");
        assert_eq!(pick_encoding(&headers), Some(Encoding::Brotli));
    }

    #[test]
    fn returns_none_without_accept_encoding() {
        assert_eq!(pick_encoding(&HeaderMap::new()), None);
    }

    #[test]
    fn returns_none_for_unsupported_encoding() {
        let headers = headers_with("accept-encoding", "deflate, zstd");
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
    fn encoding_header_values() {
        assert_eq!(Encoding::Gzip.header_value(), "gzip");
        assert_eq!(Encoding::Brotli.header_value(), "br");
    }
}
