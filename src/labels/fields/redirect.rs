use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{RedirectPolicy, RedirectScheme};
use std::collections::HashMap;

pub fn parse_redirect_policy(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RedirectPolicy> {
    let key = format!("{prefix}redirect");
    let raw = labels.get(&key)?;
    match raw.as_str() {
        "forward" => Some(RedirectPolicy::Forward),
        "permanent" => Some(RedirectPolicy::Permanent),
        "unauthorized" => Some(RedirectPolicy::Unauthorized),
        "close" => Some(RedirectPolicy::Close),
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W005InvalidRedirectPolicy,
                    "redirect policy not recognized, ignoring",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected one of: forward | permanent | unauthorized | close"),
            );
            None
        }
    }
}

pub fn parse_redirect_scheme(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RedirectScheme> {
    let key = format!("{prefix}redirectScheme");
    let raw = labels.get(&key)?;
    match raw.as_str() {
        "use_same" => Some(RedirectScheme::UseSame),
        "use_http" => Some(RedirectScheme::UseHttp),
        "use_https" => Some(RedirectScheme::UseHttps),
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W006InvalidRedirectScheme,
                    "redirect scheme not recognized, ignoring",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected one of: use_same | use_http | use_https"),
            );
            None
        }
    }
}

pub fn parse_https_redirect_port(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u16> {
    let key = format!("{prefix}httpsRedirectPort");
    let raw = labels.get(&key)?;
    match raw.parse::<u16>() {
        Ok(p) => Some(p),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W001InvalidPort,
                    "httpsRedirectPort is not a valid u16, ignoring",
                )
                .with_label(&key)
                .with_value(raw),
            );
            None
        }
    }
}

/// Parse the `redirectHost` label: the host a permanent redirect sends the
/// client to, path and query kept. Only a plain hostname is accepted (no
/// wildcard, regex, port, scheme or path); anything else emits `W031` and the
/// label is ignored.
pub fn parse_redirect_host(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let key = format!("{prefix}redirectHost");
    let raw = labels.get(&key)?;
    let host = raw.trim();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if valid {
        return Some(host.to_ascii_lowercase());
    }
    diagnostics.push(
        Diagnostic::new(
            DiagnosticCode::W031InvalidRedirectHost,
            "redirectHost is not a plain hostname, ignoring",
        )
        .with_label(&key)
        .with_value(raw)
        .with_hint("write the bare host, e.g. www.example.com: no scheme, port, path or wildcard"),
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_host_accepts_a_plain_hostname() {
        let mut d = Vec::new();
        let host = parse_redirect_host(
            &labels(&[("sozune.http.app.redirectHost", " WWW.Example.com ")]),
            "sozune.http.app.",
            &mut d,
        );
        assert_eq!(host.as_deref(), Some("www.example.com"));
        assert!(d.is_empty());
    }

    #[test]
    fn redirect_host_refuses_anything_but_a_hostname() {
        for value in [
            "",
            "https://example.com",
            "example.com:8443",
            "example.com/path",
            "*.example.com",
            "example..com",
            "-example.com",
            "example-.com",
            &format!("{}.com", "a".repeat(64)),
        ] {
            let mut d = Vec::new();
            let host = parse_redirect_host(
                &labels(&[("sozune.http.app.redirectHost", value)]),
                "sozune.http.app.",
                &mut d,
            );
            assert!(host.is_none(), "{value}");
            assert_eq!(
                d[0].code,
                DiagnosticCode::W031InvalidRedirectHost,
                "{value}"
            );
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn redirect_policy_parses_known_values() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_redirect_policy(
                &labels(&[("sozune.http.web.redirect", "permanent")]),
                "sozune.http.web.",
                &mut diags,
            ),
            Some(RedirectPolicy::Permanent),
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn redirect_policy_parses_close() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_redirect_policy(
                &labels(&[("sozune.http.web.redirect", "close")]),
                "sozune.http.web.",
                &mut diags,
            ),
            Some(RedirectPolicy::Close),
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn redirect_policy_unknown_emits_w005() {
        let mut diags = Vec::new();
        let r = parse_redirect_policy(
            &labels(&[("sozune.http.web.redirect", "later")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r, None);
        assert_eq!(diags[0].code, DiagnosticCode::W005InvalidRedirectPolicy);
    }

    #[test]
    fn redirect_policy_absent_returns_none_quietly() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_redirect_policy(&labels(&[]), "sozune.http.web.", &mut diags),
            None,
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn redirect_scheme_parses_known_values() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_redirect_scheme(
                &labels(&[("sozune.http.web.redirectScheme", "use_https")]),
                "sozune.http.web.",
                &mut diags,
            ),
            Some(RedirectScheme::UseHttps),
        );
    }

    #[test]
    fn redirect_scheme_unknown_emits_w006() {
        let mut diags = Vec::new();
        let r = parse_redirect_scheme(
            &labels(&[("sozune.http.web.redirectScheme", "tls")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(r, None);
        assert_eq!(diags[0].code, DiagnosticCode::W006InvalidRedirectScheme);
    }

    #[test]
    fn https_redirect_port_invalid_emits_w001() {
        let mut diags = Vec::new();
        let p = parse_https_redirect_port(
            &labels(&[("sozune.http.web.httpsRedirectPort", "abc")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p, None);
        assert_eq!(diags[0].code, DiagnosticCode::W001InvalidPort);
    }
}
