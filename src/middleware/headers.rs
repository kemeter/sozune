use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use tracing::warn;

/// Inject custom headers into the request header map
pub fn inject_headers(headers: &mut HeaderMap, custom_headers: &HashMap<String, String>) {
    for (key, value) in custom_headers {
        let header_name = match key.parse::<HeaderName>() {
            Ok(name) => name,
            Err(e) => {
                warn!("Invalid header name '{}': {}", key, e);
                continue;
            }
        };

        let header_value = match HeaderValue::from_str(value) {
            Ok(val) => val,
            Err(e) => {
                warn!("Invalid header value for '{}': {}", key, e);
                continue;
            }
        };

        headers.insert(header_name, header_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_headers() {
        let mut headers = HeaderMap::new();
        let mut custom = HashMap::new();
        custom.insert("X-Custom-Header".to_string(), "value1".to_string());
        custom.insert("X-Another".to_string(), "value2".to_string());

        inject_headers(&mut headers, &custom);

        assert_eq!(headers.get("X-Custom-Header").unwrap(), "value1");
        assert_eq!(headers.get("X-Another").unwrap(), "value2");
    }

    #[test]
    fn test_inject_overwrites_existing() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Existing", HeaderValue::from_static("old"));

        let mut custom = HashMap::new();
        custom.insert("X-Existing".to_string(), "new".to_string());

        inject_headers(&mut headers, &custom);

        assert_eq!(headers.get("X-Existing").unwrap(), "new");
    }

    #[test]
    fn test_inject_invalid_header_name_skipped() {
        let mut headers = HeaderMap::new();
        let mut custom = HashMap::new();
        custom.insert("invalid header name with spaces".to_string(), "value".to_string());
        custom.insert("X-Valid".to_string(), "ok".to_string());

        inject_headers(&mut headers, &custom);

        assert!(headers.get("invalid header name with spaces").is_none());
        assert_eq!(headers.get("X-Valid").unwrap(), "ok");
    }

    #[test]
    fn test_inject_empty_map() {
        let mut headers = HeaderMap::new();
        let custom = HashMap::new();

        inject_headers(&mut headers, &custom);

        assert!(headers.is_empty());
    }
}
