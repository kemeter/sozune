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
}
