use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::labels::fields::core;
use crate::model::ForwardAuthConfig;
use std::collections::HashMap;

/// Parse the `forwardAuth.*` labels. `forwardAuth.address` is required to
/// enable the middleware; an invalid URL emits `W019` and disables it.
pub fn parse_forward_auth(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ForwardAuthConfig> {
    let address_key = format!("{prefix}forwardAuth.address");
    let raw = labels.get(&address_key)?.trim();
    if raw.is_empty() {
        return None;
    }

    let parsed = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(e) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W019InvalidForwardAuth,
                    format!("forwardAuth.address is not a valid URL ({e}), middleware disabled"),
                )
                .with_label(&address_key)
                .with_value(raw)
                .with_hint("expected an absolute URL like `http://authelia:9091/api/verify`"),
            );
            return None;
        }
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W019InvalidForwardAuth,
                "forwardAuth.address must use http or https, middleware disabled",
            )
            .with_label(&address_key)
            .with_value(raw)
            .with_hint("expected `http://…` or `https://…`"),
        );
        return None;
    }

    let response_headers = labels
        .get(&format!("{prefix}forwardAuth.responseHeaders"))
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let trust_forward_header =
        core::parse_bool(labels, &format!("{prefix}forwardAuth.trustForwardHeader"));

    Some(ForwardAuthConfig {
        address: raw.to_string(),
        response_headers,
        trust_forward_header,
    })
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
    fn absent_returns_none_quietly() {
        let mut diags = Vec::new();
        assert!(parse_forward_auth(&labels(&[]), "sozune.http.web.", &mut diags).is_none());
        assert!(diags.is_empty());
    }

    #[test]
    fn empty_address_returns_none() {
        let mut diags = Vec::new();
        assert!(
            parse_forward_auth(
                &labels(&[("sozune.http.web.forwardAuth.address", "  ")]),
                "sozune.http.web.",
                &mut diags
            )
            .is_none()
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn valid_url_parses() {
        let mut diags = Vec::new();
        let cfg = parse_forward_auth(
            &labels(&[(
                "sozune.http.web.forwardAuth.address",
                "http://authelia:9091/api/verify",
            )]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(cfg.address, "http://authelia:9091/api/verify");
        assert!(cfg.response_headers.is_empty());
        assert!(!cfg.trust_forward_header);
        assert!(diags.is_empty());
    }

    #[test]
    fn response_headers_split_and_trimmed() {
        let mut diags = Vec::new();
        let cfg = parse_forward_auth(
            &labels(&[
                (
                    "sozune.http.web.forwardAuth.address",
                    "http://authelia:9091/api/verify",
                ),
                (
                    "sozune.http.web.forwardAuth.responseHeaders",
                    "Remote-User, Remote-Email ,Remote-Groups",
                ),
            ]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(
            cfg.response_headers,
            vec!["Remote-User", "Remote-Email", "Remote-Groups"]
        );
    }

    #[test]
    fn trust_forward_header_true_parses() {
        let mut diags = Vec::new();
        let cfg = parse_forward_auth(
            &labels(&[
                (
                    "sozune.http.web.forwardAuth.address",
                    "http://authelia:9091/",
                ),
                ("sozune.http.web.forwardAuth.trustForwardHeader", "true"),
            ]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert!(cfg.trust_forward_header);
    }

    #[test]
    fn invalid_url_emits_w019_and_returns_none() {
        let mut diags = Vec::new();
        let cfg = parse_forward_auth(
            &labels(&[("sozune.http.web.forwardAuth.address", "not a url")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(cfg.is_none());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W019InvalidForwardAuth);
    }

    #[test]
    fn non_http_scheme_emits_w019() {
        let mut diags = Vec::new();
        let cfg = parse_forward_auth(
            &labels(&[(
                "sozune.http.web.forwardAuth.address",
                "ftp://authelia/verify",
            )]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(cfg.is_none());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W019InvalidForwardAuth);
    }
}
