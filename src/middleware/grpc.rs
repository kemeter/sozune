//! What the middleware does differently for a gRPC call.

use axum::http::HeaderMap;

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

#[cfg(test)]
mod tests {
    use super::*;

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
