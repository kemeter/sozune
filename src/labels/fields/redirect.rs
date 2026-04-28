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
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W005InvalidRedirectPolicy,
                    "redirect policy not recognized, ignoring",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected one of: forward | permanent | unauthorized"),
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
