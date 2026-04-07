use axum::http::HeaderMap;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

/// Content types that benefit from compression
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

/// Check if the client accepts gzip encoding
pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"))
}

/// Check if the response content type is compressible
pub fn is_compressible(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| COMPRESSIBLE_TYPES.iter().any(|t| ct.contains(t)))
}

/// Check if the response is already compressed
pub fn is_already_compressed(headers: &HeaderMap) -> bool {
    headers.contains_key("content-encoding")
}

/// Compress bytes with gzip
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    encoder.finish()
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
    fn test_accepts_gzip() {
        assert!(accepts_gzip(&headers_with("accept-encoding", "gzip, deflate")));
        assert!(accepts_gzip(&headers_with("accept-encoding", "gzip")));
        assert!(!accepts_gzip(&headers_with("accept-encoding", "br")));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }

    #[test]
    fn test_is_compressible() {
        assert!(is_compressible(&headers_with("content-type", "text/html; charset=utf-8")));
        assert!(is_compressible(&headers_with("content-type", "application/json")));
        assert!(is_compressible(&headers_with("content-type", "application/javascript")));
        assert!(is_compressible(&headers_with("content-type", "image/svg+xml")));
        assert!(!is_compressible(&headers_with("content-type", "image/png")));
        assert!(!is_compressible(&headers_with("content-type", "application/octet-stream")));
    }

    #[test]
    fn test_already_compressed() {
        assert!(is_already_compressed(&headers_with("content-encoding", "gzip")));
        assert!(!is_already_compressed(&HeaderMap::new()));
    }

    #[test]
    fn test_gzip_roundtrip() {
        let original = b"Hello, World! This is a test of gzip compression.";
        let compressed = gzip_compress(original).unwrap();

        assert!(compressed.len() < original.len() + 30); // gzip has overhead for small data

        // Decompress and verify
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed.as_bytes(), original);
    }
}
