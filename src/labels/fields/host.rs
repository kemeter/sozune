use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

/// Parse the required `host` label, comma-separated. Emits `E002` and returns
/// `None` when the label is absent — this blocks routing for the service.
pub fn parse_hostnames(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Vec<String>> {
    let key = format!("{prefix}host");
    let raw = match labels.get(&key) {
        Some(v) => v,
        None => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::E002MissingHost,
                    "required host label is missing",
                )
                .with_label(&key)
                .with_hint(format!("add `{key}=<your-domain>` to enable routing")),
            );
            return None;
        }
    };

    let hosts: Vec<String> = raw
        .split(',')
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    if hosts.is_empty() {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::E002MissingHost,
                "host label is set but contains no usable hostname",
            )
            .with_label(&key)
            .with_value(raw),
        );
        return None;
    }

    Some(hosts)
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
    fn missing_host_emits_e002() {
        let mut diags = Vec::new();
        assert!(parse_hostnames(&labels(&[]), "sozune.http.web.", &mut diags).is_none());
        assert_eq!(diags[0].code, DiagnosticCode::E002MissingHost);
        assert!(diags[0].hint.is_some());
    }

    #[test]
    fn single_host_parses() {
        let mut diags = Vec::new();
        let hosts = parse_hostnames(
            &labels(&[("sozune.http.web.host", "example.com")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(hosts, vec!["example.com"]);
        assert!(diags.is_empty());
    }

    #[test]
    fn comma_separated_hosts_split() {
        let mut diags = Vec::new();
        let hosts = parse_hostnames(
            &labels(&[("sozune.http.web.host", "a.com, b.com ,c.com")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(hosts, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn empty_host_value_emits_e002() {
        let mut diags = Vec::new();
        assert!(parse_hostnames(
            &labels(&[("sozune.http.web.host", "  , ,  ")]),
            "sozune.http.web.",
            &mut diags,
        )
        .is_none());
        assert_eq!(diags[0].code, DiagnosticCode::E002MissingHost);
    }
}
