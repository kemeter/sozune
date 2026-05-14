use crate::error_pages::{is_supported_status, sanitize_provider_error_pages};
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::{BTreeMap, HashMap};

/// Parse `<prefix>errorPages.<code>=<value>` labels.
///
/// Provider-sourced labels are non-trusted input: `file://` references are
/// dropped (with a `W020` diagnostic), and unsupported status codes are
/// dropped too. Inline literal bodies pass through unchanged.
pub fn parse_error_pages(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, String> {
    let error_prefix = format!("{prefix}errorPages.");
    let mut raw: BTreeMap<String, String> = BTreeMap::new();

    let mut keys: Vec<&String> = labels.keys().collect();
    keys.sort();

    for key in keys {
        let Some(code) = key.strip_prefix(&error_prefix) else {
            continue;
        };
        let value = labels[key].clone();

        if !is_supported_status(code) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W020InvalidErrorPage,
                    format!("error_pages: status '{code}' is not supported by sozu, dropped"),
                )
                .with_label(key)
                .with_value(&value)
                .with_hint(
                    "supported statuses: 301, 400, 401, 404, 408, 413, 421, 429, 502, 503, 504, 507",
                ),
            );
            continue;
        }
        if value.starts_with("file://") {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W020InvalidErrorPage,
                    format!(
                        "error_pages: file:// is refused for provider labels (code {code}), dropped"
                    ),
                )
                .with_label(key)
                .with_value(&value)
                .with_hint("inline the response body in the label value, or set it in static config under `proxy.http.error_pages` / `entrypoints[*].error_pages`"),
            );
            continue;
        }
        raw.insert(code.to_string(), value);
    }

    // Defence-in-depth: route through the shared sanitiser so the same
    // rules apply whether the values arrive from labels or from any
    // future provider-sourced path.
    let (clean, _) = sanitize_provider_error_pages(&raw);
    clean
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
    fn no_labels_returns_empty() {
        let mut diags = Vec::new();
        let r = parse_error_pages(&labels(&[]), "sozune.http.web.", &mut diags);
        assert!(r.is_empty());
        assert!(diags.is_empty());
    }

    #[test]
    fn inline_body_parsed() {
        let mut diags = Vec::new();
        let r = parse_error_pages(
            &labels(&[("sozune.http.web.errorPages.503", "<h1>maintenance</h1>")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r.get("503"), Some(&"<h1>maintenance</h1>".to_string()));
        assert!(diags.is_empty());
    }

    #[test]
    fn file_uri_is_refused_with_w020() {
        let mut diags = Vec::new();
        let r = parse_error_pages(
            &labels(&[("sozune.http.web.errorPages.503", "file:///etc/passwd")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(r.is_empty());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W020InvalidErrorPage);
        assert!(diags[0].message.contains("file://"));
    }

    #[test]
    fn unsupported_status_is_dropped_with_w020() {
        let mut diags = Vec::new();
        let r = parse_error_pages(
            &labels(&[("sozune.http.web.errorPages.418", "I'm a teapot")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(r.is_empty());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W020InvalidErrorPage);
        assert!(diags[0].message.contains("418"));
    }

    #[test]
    fn unrelated_labels_ignored() {
        let mut diags = Vec::new();
        let r = parse_error_pages(
            &labels(&[
                ("sozune.http.web.port", "8080"),
                ("sozune.http.web.errorPages.404", "missing"),
                ("sozune.http.other.errorPages.503", "down"),
            ]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("404"), Some(&"missing".to_string()));
    }
}
