use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tracing::error;

use crate::model::BasicAuthUser;

/// Constant-time byte comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Check basic auth credentials from the Authorization header.
/// Returns Ok(()) if auth passes, Err(Response) with 401 if it fails.
pub fn check_basic_auth(
    req: &Request<Body>,
    users: &[BasicAuthUser],
) -> Result<(), Response<Body>> {
    let unauthorized = || {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"restricted\"")
            .body(Body::from("Unauthorized"))
            .unwrap_or_else(|e| {
                error!("Failed to build 401 response: {}", e);
                Response::new(Body::from("Unauthorized"))
            })
    };

    let auth_header = match req.headers().get(header::AUTHORIZATION) {
        Some(h) => h,
        None => return Err(unauthorized()),
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return Err(unauthorized()),
    };

    if !auth_str.starts_with("Basic ") {
        return Err(unauthorized());
    }

    let decoded = match BASE64.decode(&auth_str[6..]) {
        Ok(d) => d,
        Err(_) => return Err(unauthorized()),
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => return Err(unauthorized()),
    };

    let (username, password) = match credentials.split_once(':') {
        Some(pair) => pair,
        None => return Err(unauthorized()),
    };

    // Match against configured users with constant-time comparison
    for user in users {
        if constant_time_eq(user.username.as_bytes(), username.as_bytes())
            && constant_time_eq(user.password_hash.as_bytes(), password.as_bytes())
        {
            return Ok(());
        }
    }

    Err(unauthorized())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn make_users() -> Vec<BasicAuthUser> {
        vec![BasicAuthUser {
            username: "admin".to_string(),
            password_hash: "secret".to_string(),
        }]
    }

    fn make_request(auth_header: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/test");
        if let Some(auth) = auth_header {
            builder = builder.header("Authorization", auth);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn test_valid_credentials() {
        let users = make_users();
        let encoded = BASE64.encode("admin:secret");
        let req = make_request(Some(&format!("Basic {}", encoded)));
        assert!(check_basic_auth(&req, &users).is_ok());
    }

    #[test]
    fn test_invalid_password() {
        let users = make_users();
        let encoded = BASE64.encode("admin:wrong");
        let req = make_request(Some(&format!("Basic {}", encoded)));
        assert!(check_basic_auth(&req, &users).is_err());
    }

    #[test]
    fn test_missing_header() {
        let users = make_users();
        let req = make_request(None);
        assert!(check_basic_auth(&req, &users).is_err());
    }

    #[test]
    fn test_non_basic_scheme() {
        let users = make_users();
        let req = make_request(Some("Bearer token123"));
        assert!(check_basic_auth(&req, &users).is_err());
    }

    #[test]
    fn test_invalid_base64() {
        let users = make_users();
        let req = make_request(Some("Basic not-valid-base64!!!"));
        assert!(check_basic_auth(&req, &users).is_err());
    }

    #[test]
    fn test_unknown_user() {
        let users = make_users();
        let encoded = BASE64.encode("unknown:secret");
        let req = make_request(Some(&format!("Basic {}", encoded)));
        assert!(check_basic_auth(&req, &users).is_err());
    }

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
