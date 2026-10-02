use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

/// Whether a name can be installed as a route.
///
/// Sozu reads a bare `*` as `DomainRule::Any` and a hostname containing `/` as
/// a regex, so an unvalidated label could claim every host on the proxy —
/// frontends go in at `RulePosition::Pre`, ahead of every legitimate route.
/// A leading `*.` is a wildcard Sozu handles natively. A regex hostname is
/// accepted when it cannot match outside a fixed domain, see
/// [`is_routable_regex_hostname`].
pub fn is_routable_hostname(hostname: &str) -> bool {
    if hostname.contains('\0') {
        return false;
    }
    if hostname.contains('/') {
        return is_routable_regex_hostname(hostname);
    }
    let trailing = hostname.strip_prefix("*.").unwrap_or(hostname);
    !trailing.is_empty()
        && !trailing.contains('*')
        && !trailing.contains('\\')
        && trailing != "."
        && !trailing.contains("..")
}

/// One dot-separated piece of a hostname, as Sozu's
/// `convert_regex_domain_rule` splits it.
enum Segment<'a> {
    Literal(&'a str),
    Regex(&'a str),
}

/// Split a hostname the way Sozu does before building its regex: a segment
/// opening with `/` runs to the next `/` (dots included), any other segment
/// runs to the next `.`. `None` when Sozu would refuse the shape.
fn split_segments(hostname: &str) -> Option<Vec<Segment<'_>>> {
    let mut segments = Vec::new();
    let mut rest = hostname;
    loop {
        let after = if let Some(inner) = rest.strip_prefix('/') {
            let end = inner.find('/')?;
            segments.push(Segment::Regex(&inner[..end]));
            &inner[end + 1..]
        } else {
            let end = rest.find('.').unwrap_or(rest.len());
            segments.push(Segment::Literal(&rest[..end]));
            &rest[end..]
        };
        if after.is_empty() {
            return Some(segments);
        }
        rest = after.strip_prefix('.')?;
    }
}

/// Sozu turns `/cdn[0-9]+/.example.com` into `\Acdn[0-9]+\.example\.com\z`,
/// so a regex hostname is held to its literal suffix — provided that suffix
/// exists and the anchoring holds:
///
/// - the last two segments are literal labels, so the name stays inside one
///   domain (`/.*/` or `/.*/.com` would match hosts of every tenant);
/// - no regex segment alternates at its top level: `/.*|/.example.com` becomes
///   `\A.*|\.example\.com\z`, whose first branch matches any host.
fn is_routable_regex_hostname(hostname: &str) -> bool {
    let Some(segments) = split_segments(hostname) else {
        return false;
    };
    let suffix_is_literal = segments.len() >= 3
        && segments[segments.len() - 2..]
            .iter()
            .all(|s| matches!(s, Segment::Literal(_)));
    suffix_is_literal
        && segments.iter().all(|s| match s {
            Segment::Literal(label) => is_literal_label(label),
            Segment::Regex(pattern) => is_anchorable_regex(pattern),
        })
}

fn is_literal_label(label: &str) -> bool {
    !label.is_empty() && !label.contains(['*', '/', '\\'])
}

fn is_anchorable_regex(pattern: &str) -> bool {
    use regex_syntax::ast::{Ast, parse::Parser};
    !pattern.is_empty()
        && regex::Regex::new(pattern).is_ok()
        && Parser::new()
            .parse(pattern)
            .is_ok_and(|ast| !matches!(ast, Ast::Alternation(_)))
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
                "use a plain hostname, `*.example.com` for a wildcard, or a regex label \
                 under a fixed domain such as `/cdn[0-9]+/.example.com`: a bare `*`, or a \
                 regex without that literal domain, would match hosts this service was \
                 never given",
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

    /// Sozu reads a bare `*` as "every host", and a regex hostname matches
    /// whatever its pattern allows. A container that can set its own labels
    /// could therefore claim the whole proxy:
    ///
    /// ```yaml
    /// sozune.http.evil.host: "/.*/"
    /// ```
    ///
    /// Frontends are installed at `RulePosition::Pre`, so that rule sits in
    /// front of every legitimate route and captures other tenants' traffic —
    /// credentials and session cookies included. A regex is only held to a
    /// domain by literal labels after it, and by an anchoring that a top-level
    /// alternation escapes.
    #[test]
    fn a_hostname_matching_outside_its_domain_is_refused() {
        for raw in [
            "/.*/",
            "/example\\.com/",
            "*",
            "a/b.com",
            "/.*/.com",
            "example./.*/",
            "/.*|/.example.com",
            "/a|b/.example.com",
            "//.example.com",
            "/[/.example.com",
            "/cdn/x.example.com",
            "/cdn.example.com",
            "*./cdn/.example.com",
            "/cdn/..example.com",
        ] {
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

    /// The regex hostnames the docs describe: a pattern on one or more labels,
    /// under a literal domain. An alternation inside a group stays anchored.
    #[test]
    fn a_regex_under_a_literal_domain_is_accepted() {
        for raw in [
            "/cdn[0-9]+/.example.com",
            "/v[0-9]+/./api[a-z]/.example.com",
            "api./v[0-9]+/.example.com",
            "/(?:eu|us)-cdn/.example.com",
            "/cdn\\d+/.example.com",
        ] {
            let mut diags = Vec::new();
            let hosts = parse_hostnames(
                &labels(&[("sozune.http.web.host", raw)]),
                "sozune.http.web.",
                &mut diags,
            );
            assert_eq!(hosts, Some(vec![raw.to_string()]), "`{raw}` must route");
            assert!(diags.is_empty());
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
