/// Strip a prefix from a path. If the path starts with the prefix,
/// return the remaining path (ensuring it starts with '/').
/// If the path doesn't start with the prefix, return it unchanged.
pub fn strip(prefix: &str, path: &str) -> String {
    let normalized_prefix = prefix.trim_end_matches('/');

    if path == normalized_prefix || path.starts_with(&format!("{}/", normalized_prefix)) {
        let remaining = &path[normalized_prefix.len()..];
        if remaining.is_empty() || remaining == "/" {
            "/".to_string()
        } else {
            remaining.to_string()
        }
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_simple_prefix() {
        assert_eq!(strip("/api", "/api/users"), "/users");
    }

    #[test]
    fn test_strip_prefix_exact_match() {
        assert_eq!(strip("/api", "/api"), "/");
    }

    #[test]
    fn test_strip_prefix_with_trailing_slash() {
        assert_eq!(strip("/api/", "/api/users"), "/users");
    }

    #[test]
    fn test_strip_prefix_no_match() {
        assert_eq!(strip("/api", "/other/path"), "/other/path");
    }

    #[test]
    fn test_strip_prefix_root() {
        assert_eq!(strip("/", "/anything"), "/anything");
    }

    #[test]
    fn test_strip_prefix_partial_match_not_stripped() {
        // /api should not strip /apiv2
        assert_eq!(strip("/api", "/apiv2/test"), "/apiv2/test");
    }

    #[test]
    fn test_strip_prefix_nested() {
        assert_eq!(strip("/api/v1", "/api/v1/users/123"), "/users/123");
    }

    #[test]
    fn test_strip_prefix_trailing_slash_only() {
        assert_eq!(strip("/api", "/api/"), "/");
    }
}
