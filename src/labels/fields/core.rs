use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

/// Parse a port label, falling back to the protocol default when absent or
/// non-numeric. Emits diagnostics describing the fallback so callers can
/// surface them.
///
/// `prefix` is `sozune.<protocol>.<service>.` (trailing dot included).
pub fn parse_port(
    labels: &HashMap<String, String>,
    prefix: &str,
    protocol: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> u16 {
    let key = format!("{prefix}port");
    let default = default_port_for(protocol);

    match labels.get(&key) {
        None => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::I002PortDefaulted,
                    format!("no port label, using protocol default ({default})"),
                )
                .with_label(&key),
            );
            default
        }
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W001InvalidPort,
                        format!("port is not a valid u16, falling back to {default}"),
                    )
                    .with_label(&key)
                    .with_value(raw)
                    .with_hint("port must be a positive integer between 0 and 65535"),
                );
                default
            }
        },
    }
}

fn default_port_for(protocol: &str) -> u16 {
    match protocol {
        "http" => 80,
        "https" => 443,
        _ => 8080,
    }
}

/// Parse the priority label. Defaults to 0 when absent. Non-numeric values
/// emit `W002` and also fall back to 0.
pub fn parse_priority(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> i32 {
    let key = format!("{prefix}priority");
    match labels.get(&key) {
        None => 0,
        Some(raw) => match raw.parse::<i32>() {
            Ok(p) => p,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W002InvalidPriority,
                        "priority is not a valid integer, defaulting to 0",
                    )
                    .with_label(&key)
                    .with_value(raw),
                );
                0
            }
        },
    }
}

/// Parse the backendTimeout label (milliseconds). Returns `None` when absent
/// or invalid; non-numeric values emit `W003`.
pub fn parse_backend_timeout(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let key = format!("{prefix}backendTimeout");
    let raw = labels.get(&key)?;
    match raw.parse::<u64>() {
        Ok(t) => Some(t),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W003InvalidTimeout,
                    "backendTimeout is not a valid integer, no timeout applied",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected milliseconds as a positive integer"),
            );
            None
        }
    }
}

/// Parse a boolean label. Treats `"true"` (case-sensitive) as true, anything
/// else as false. No diagnostic — matches existing `map_or(false, |v| v == "true")`
/// semantics.
pub fn parse_bool(labels: &HashMap<String, String>, key: &str) -> bool {
    labels.get(key).is_some_and(|v| v == "true")
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
    fn returns_explicit_port_when_valid() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "8080")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 8080);
        assert!(diags.is_empty());
    }

    #[test]
    fn missing_port_emits_i002_and_uses_http_default() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.http.web.", "http", &mut diags);
        assert_eq!(port, 80);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::I002PortDefaulted);
    }

    #[test]
    fn missing_port_uses_https_default() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.https.web.", "https", &mut diags);
        assert_eq!(port, 443);
    }

    #[test]
    fn missing_port_uses_8080_for_unknown_protocol() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.tcp.db.", "tcp", &mut diags);
        assert_eq!(port, 8080);
    }

    #[test]
    fn non_numeric_port_emits_w001_and_falls_back() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "abc")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 80);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W001InvalidPort);
        assert_eq!(diags[0].label.as_deref(), Some("sozune.http.web.port"));
        assert_eq!(diags[0].value.as_deref(), Some("abc"));
        assert!(diags[0].hint.is_some());
    }

    #[test]
    fn out_of_range_port_emits_w001() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "99999")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 80);
        assert_eq!(diags[0].code, DiagnosticCode::W001InvalidPort);
    }

    #[test]
    fn priority_defaults_to_zero_when_absent() {
        let mut diags = Vec::new();
        assert_eq!(parse_priority(&labels(&[]), "sozune.http.web.", &mut diags), 0);
        assert!(diags.is_empty());
    }

    #[test]
    fn priority_parses_valid_int() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_priority(
                &labels(&[("sozune.http.web.priority", "10")]),
                "sozune.http.web.",
                &mut diags,
            ),
            10,
        );
    }

    #[test]
    fn priority_invalid_emits_w002() {
        let mut diags = Vec::new();
        let p = parse_priority(
            &labels(&[("sozune.http.web.priority", "high")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p, 0);
        assert_eq!(diags[0].code, DiagnosticCode::W002InvalidPriority);
    }

    #[test]
    fn timeout_returns_none_when_absent() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_backend_timeout(&labels(&[]), "sozune.http.web.", &mut diags),
            None,
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn timeout_parses_valid_value() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_backend_timeout(
                &labels(&[("sozune.http.web.backendTimeout", "5000")]),
                "sozune.http.web.",
                &mut diags,
            ),
            Some(5000),
        );
    }

    #[test]
    fn timeout_invalid_emits_w003() {
        let mut diags = Vec::new();
        let t = parse_backend_timeout(
            &labels(&[("sozune.http.web.backendTimeout", "soon")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(t, None);
        assert_eq!(diags[0].code, DiagnosticCode::W003InvalidTimeout);
    }

    #[test]
    fn bool_true_only_for_literal_true() {
        let l = labels(&[("a", "true"), ("b", "True"), ("c", "1"), ("d", "false")]);
        assert!(parse_bool(&l, "a"));
        assert!(!parse_bool(&l, "b"));
        assert!(!parse_bool(&l, "c"));
        assert!(!parse_bool(&l, "d"));
        assert!(!parse_bool(&l, "missing"));
    }
}
