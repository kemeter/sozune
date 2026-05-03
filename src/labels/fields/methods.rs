use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

const KNOWN_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
];

/// Parse `<prefix>methods=GET,POST,PUT` into a deduplicated list of uppercase
/// method names. Unknown verbs are dropped with a `W014` diagnostic.
pub fn parse_methods(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<String> {
    let key = format!("{prefix}methods");
    let raw = match labels.get(&key) {
        Some(v) => v.trim(),
        None => return Vec::new(),
    };
    if raw.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for token in raw.split(',') {
        let m = token.trim().to_ascii_uppercase();
        if m.is_empty() {
            continue;
        }
        if !KNOWN_METHODS.contains(&m.as_str()) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W014InvalidMethod,
                    "HTTP method not recognized, ignoring",
                )
                .with_label(&key)
                .with_value(&m)
                .with_hint(format!("expected one of: {}", KNOWN_METHODS.join(" | "))),
            );
            continue;
        }
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
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
    fn empty_when_label_absent() {
        let mut diags = Vec::new();
        let r = parse_methods(&labels(&[]), "sozune.http.web.", &mut diags);
        assert!(r.is_empty());
        assert!(diags.is_empty());
    }

    #[test]
    fn parses_csv_and_uppercases() {
        let mut diags = Vec::new();
        let r = parse_methods(
            &labels(&[("sozune.http.web.methods", "get, Post,put")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r, vec!["GET", "POST", "PUT"]);
        assert!(diags.is_empty());
    }

    #[test]
    fn deduplicates() {
        let mut diags = Vec::new();
        let r = parse_methods(
            &labels(&[("sozune.http.web.methods", "GET,GET,get")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r, vec!["GET"]);
    }

    #[test]
    fn unknown_method_emits_w014_and_is_dropped() {
        let mut diags = Vec::new();
        let r = parse_methods(
            &labels(&[("sozune.http.web.methods", "GET,FOOBAR,POST")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r, vec!["GET", "POST"]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W014InvalidMethod);
    }

    #[test]
    fn empty_string_yields_no_methods_no_diags() {
        let mut diags = Vec::new();
        let r = parse_methods(
            &labels(&[("sozune.http.web.methods", "")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(r.is_empty());
        assert!(diags.is_empty());
    }
}
