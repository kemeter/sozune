use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{HeaderConfig, HeaderDirection};
use std::collections::HashMap;

/// Headers that must not be injected from labels to prevent request smuggling,
/// SSRF, and host header attacks.
pub const BLOCKED_HEADERS: &[&str] = &[
    "host",
    "transfer-encoding",
    "content-length",
    "connection",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
    "cookie",
    "authorization",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
];

/// Parse `headers.<name>`, `headers.response.<name>`, `headers.both.<name>`
/// labels into `HeaderConfig` values. Headers in `BLOCKED_HEADERS` emit
/// `W008` and are dropped.
pub fn parse_headers(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<HeaderConfig> {
    let header_prefix = format!("{prefix}headers.");
    let mut headers = Vec::new();

    // Iterate in a deterministic order so diagnostics come out predictably.
    let mut keys: Vec<&String> = labels.keys().collect();
    keys.sort();

    for key in keys {
        let Some(remainder) = key.strip_prefix(&header_prefix) else {
            continue;
        };
        let value = &labels[key];

        let (direction, header_name) = if let Some(name) = remainder.strip_prefix("response.") {
            (HeaderDirection::Response, name)
        } else if let Some(name) = remainder.strip_prefix("both.") {
            (HeaderDirection::Both, name)
        } else {
            (HeaderDirection::Request, remainder)
        };

        if BLOCKED_HEADERS
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(header_name))
        {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W008BlockedHeader,
                    format!("header '{header_name}' is on the blocklist, dropped"),
                )
                .with_label(key)
                .with_value(value)
                .with_hint("blocked headers can enable request smuggling, SSRF, or host header attacks"),
            );
            continue;
        }

        headers.push(HeaderConfig {
            name: header_name.to_string(),
            value: value.clone(),
            direction,
        });
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn no_headers_returns_empty() {
        let mut diags = Vec::new();
        assert!(parse_headers(&labels(&[]), "sozune.http.web.", &mut diags).is_empty());
        assert!(diags.is_empty());
    }

    #[test]
    fn request_header_default_direction() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[("sozune.http.web.headers.X-Source", "api")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name, "X-Source");
        assert_eq!(h[0].value, "api");
        assert_eq!(h[0].direction, HeaderDirection::Request);
    }

    #[test]
    fn response_direction_parsed() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[("sozune.http.web.headers.response.X-Cache", "HIT")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(h[0].name, "X-Cache");
        assert_eq!(h[0].direction, HeaderDirection::Response);
    }

    #[test]
    fn both_direction_parsed() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[("sozune.http.web.headers.both.X-Trace", "abc")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(h[0].name, "X-Trace");
        assert_eq!(h[0].direction, HeaderDirection::Both);
    }

    #[test]
    fn blocked_header_emits_w008() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[("sozune.http.web.headers.Host", "evil.com")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(h.is_empty());
        assert_eq!(diags[0].code, DiagnosticCode::W008BlockedHeader);
    }

    #[test]
    fn blocked_header_case_insensitive() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[("sozune.http.web.headers.AUTHORIZATION", "Bearer x")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(h.is_empty());
        assert_eq!(diags[0].code, DiagnosticCode::W008BlockedHeader);
    }

    #[test]
    fn unrelated_labels_ignored() {
        let mut diags = Vec::new();
        let h = parse_headers(
            &labels(&[
                ("sozune.http.web.port", "8080"),
                ("sozune.http.web.headers.X-Foo", "bar"),
                ("sozune.http.other.headers.X-Bar", "baz"),
            ]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name, "X-Foo");
    }
}
