use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

/// Whether a name can be installed as a route.
///
/// Sozu reads a hostname containing `/` as a regex and a bare `*` as
/// `DomainRule::Any`, so an unvalidated label could claim every host on the
/// proxy — frontends go in at `RulePosition::Pre`, ahead of every legitimate
/// route. Only a leading `*.` is a wildcard, which Sozu handles natively.
///
/// Same shapes `AcmeManager::validate_hostname` already refuses; the routing
/// path had no equivalent gate.
pub fn is_routable_hostname(hostname: &str) -> bool {
    let trailing = hostname.strip_prefix("*.").unwrap_or(hostname);
    !trailing.is_empty()
        && !trailing.contains('*')
        && !trailing.contains('/')
        && !trailing.contains('\\')
        && !trailing.contains('\0')
        && trailing != "."
        && !trailing.contains("..")
}

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

    if let Some(bad) = hosts.iter().find(|h| !is_routable_hostname(h)) {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::E002MissingHost,
                "host label contains a name that is not a hostname",
            )
            .with_label(&key)
            .with_value(bad)
            .with_hint(
                "use a plain hostname, or `*.example.com` for a wildcard: a name holding \
                 `/` or a bare `*` is read as a pattern and would match hosts this service \
                 was never given",
            ),
        );
        return None;
    }

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

    /// Sozu reads any hostname containing `/` as a regex, and a bare `*` as
    /// "every host". A container that can set its own labels could therefore
    /// claim the whole proxy:
    ///
    /// ```yaml
    /// sozune.http.evil.host: "/.*/"
    /// ```
    ///
    /// Frontends are installed at `RulePosition::Pre`, so that rule sits in
    /// front of every legitimate route and captures other tenants' traffic —
    /// credentials and session cookies included. ACME already refused these
    /// shapes; the routing path did not.
    #[test]
    fn a_regex_hostname_is_refused() {
        for raw in ["/.*/", "/example\\.com/", "*", "a/b.com"] {
            let mut diags = Vec::new();
            assert!(
                parse_hostnames(
                    &labels(&[("sozune.http.web.host", raw)]),
                    "sozune.http.web.",
                    &mut diags,
                )
                .is_none(),
                "`{raw}` must not become a route"
            );
            assert_eq!(diags[0].code, DiagnosticCode::E002MissingHost);
        }
    }

    /// One bad name must not carry the usable ones with it, and must not let
    /// them through either: the entrypoint is refused as a whole, so an
    /// operator sees the mistake instead of half a route.
    #[test]
    fn one_bad_name_refuses_the_whole_label() {
        let mut diags = Vec::new();
        assert!(
            parse_hostnames(
                &labels(&[("sozune.http.web.host", "good.example.com,/.*/")]),
                "sozune.http.web.",
                &mut diags,
            )
            .is_none()
        );
    }

    /// A leading `*.` is a wildcard Sozu handles natively, and the shape ACME
    /// already accepts. It must keep working.
    #[test]
    fn a_leading_wildcard_is_still_accepted() {
        let mut diags = Vec::new();
        let hosts = parse_hostnames(
            &labels(&[("sozune.http.web.host", "*.example.com")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(hosts, vec!["*.example.com"]);
    }

    #[test]
    fn empty_host_value_emits_e002() {
        let mut diags = Vec::new();
        assert!(
            parse_hostnames(
                &labels(&[("sozune.http.web.host", "  , ,  ")]),
                "sozune.http.web.",
                &mut diags,
            )
            .is_none()
        );
        assert_eq!(diags[0].code, DiagnosticCode::E002MissingHost);
    }
}
