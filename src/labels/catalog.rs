use std::collections::HashMap;

use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::util::fuzzy::closest_match;

const GLOBAL_LABELS: &[&str] = &["enable", "network"];

const SERVICE_FIELDS: &[&str] = &[
    "host",
    "port",
    "priority",
    "backendTimeout",
    "healthCheck.path",
    "healthCheck.status",
    "healthCheck.timeout",
    "loadBalancer",
    "retry.attempts",
    "tls",
    "stripPrefix",
    "addPrefix",
    "httpsRedirect",
    "httpsRedirectPort",
    "stickySession",
    "compress",
    "path",
    "prefix",
    "pathRegex",
    "redirect",
    "redirectScheme",
    "redirectTemplate",
    "wwwAuthenticate",
    "ratelimit.average",
    "ratelimit.burst",
    "auth.basic",
    "forwardAuth.address",
    "forwardAuth.responseHeaders",
    "forwardAuth.trustForwardHeader",
    "entrypoint",
    "methods",
    "plugins",
    "matchHeaders",
    "matchQuery",
    "matchClientIP",
    "ipAllowList",
];

/// Field suffixes that accept arbitrary sub-keys (e.g. `headers.X-Foo`).
/// Anything beginning with one of these is considered known.
const SERVICE_FIELD_PREFIXES: &[&str] = &["headers.", "errorPages."];

const SUPPORTED_PROTOCOLS: &[&str] = &["http", "tcp", "udp"];

/// Scan all labels and emit `W013UnknownLabel` for every `sozune.*` key that
/// does not match a known shape. Typos like `sozune.http.web.timout` would be
/// silently ignored otherwise; this surfaces them with a did-you-mean hint.
pub fn detect_unknown_labels(labels: &HashMap<String, String>, diagnostics: &mut Vec<Diagnostic>) {
    let mut unknown: Vec<&String> = labels
        .keys()
        .filter(|k| k.starts_with("sozune."))
        .filter(|k| !is_known(k))
        .collect();
    unknown.sort();

    for key in unknown {
        let value = &labels[key];
        let mut diag = Diagnostic::new(
            DiagnosticCode::W013UnknownLabel,
            format!("unknown label '{key}', ignored"),
        )
        .with_label(key)
        .with_value(value);
        if let Some(suggestion) = suggest(key) {
            diag = diag.with_hint(format!("did you mean `{suggestion}`?"));
        } else {
            diag = diag
                .with_hint("see https://sozune.dev/docs/labels for the list of supported labels");
        }
        diagnostics.push(diag);
    }
}

fn is_known(full_key: &str) -> bool {
    let Some(rest) = full_key.strip_prefix("sozune.") else {
        return false;
    };
    if GLOBAL_LABELS.contains(&rest) {
        return true;
    }
    let mut parts = rest.splitn(3, '.');
    let (Some(protocol), Some(_service), Some(suffix)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !SUPPORTED_PROTOCOLS.contains(&protocol) {
        // Unknown protocols are reported by W012, not W013.
        return true;
    }
    if SERVICE_FIELDS.contains(&suffix) {
        return true;
    }
    SERVICE_FIELD_PREFIXES
        .iter()
        .any(|p| suffix.starts_with(p) && suffix.len() > p.len())
}

/// Build a did-you-mean suggestion for an unknown key by replacing only the
/// segments that don't match a known value, using Levenshtein distance.
fn suggest(full_key: &str) -> Option<String> {
    let rest = full_key.strip_prefix("sozune.")?;

    if let Some(closest) = closest_match(rest, GLOBAL_LABELS, 2) {
        return Some(format!("sozune.{closest}"));
    }

    let mut parts: Vec<&str> = rest.splitn(3, '.').collect();
    if parts.len() < 3 {
        return None;
    }
    let (protocol, service, suffix) = (parts[0], parts[1], parts[2]);

    let protocol_fixed = if SUPPORTED_PROTOCOLS.contains(&protocol) {
        protocol.to_string()
    } else {
        closest_match(protocol, SUPPORTED_PROTOCOLS, 2)?.to_string()
    };

    let suffix_fixed = if SERVICE_FIELDS.contains(&suffix)
        || SERVICE_FIELD_PREFIXES
            .iter()
            .any(|p| suffix.starts_with(p) && suffix.len() > p.len())
    {
        suffix.to_string()
    } else {
        closest_match(suffix, SERVICE_FIELDS, 2)?.to_string()
    };

    parts[0] = &protocol_fixed;
    parts[2] = &suffix_fixed;
    let _ = service;
    Some(format!(
        "sozune.{}.{}.{}",
        protocol_fixed, parts[1], suffix_fixed
    ))
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
    fn known_labels_are_silent() {
        let mut diags = Vec::new();
        detect_unknown_labels(
            &labels(&[
                ("sozune.enable", "true"),
                ("sozune.network", "internal"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.port", "8080"),
                ("sozune.http.web.ratelimit.average", "100"),
                ("sozune.http.web.auth.basic", "u:h"),
                ("sozune.http.web.headers.X-Foo", "bar"),
                ("sozune.http.web.headers.response.X-Bar", "baz"),
                ("non.sozune.key", "ignored"),
            ]),
            &mut diags,
        );
        assert!(diags.is_empty(), "got: {:?}", diags);
    }

    #[test]
    fn unknown_protocol_is_not_reported_here() {
        let mut diags = Vec::new();
        detect_unknown_labels(&labels(&[("sozune.ftp.legacy.host", "x")]), &mut diags);
        assert!(diags.is_empty(), "W012 owns this case, not W013");
    }

    #[test]
    fn typo_in_field_emits_w013_with_suggestion() {
        let mut diags = Vec::new();
        detect_unknown_labels(&labels(&[("sozune.http.web.timeout", "5s")]), &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W013UnknownLabel);
        let hint = diags[0].hint.as_deref().unwrap();
        assert!(
            hint.contains("backendTimeout"),
            "expected suggestion, got: {hint}"
        );
    }

    #[test]
    fn small_typo_in_field_emits_w013_with_suggestion() {
        let mut diags = Vec::new();
        detect_unknown_labels(&labels(&[("sozune.http.web.prt", "8080")]), &mut diags);
        assert_eq!(diags.len(), 1);
        let hint = diags[0].hint.as_deref().unwrap();
        assert!(hint.contains("port"), "got: {hint}");
    }

    #[test]
    fn typo_in_global_emits_w013() {
        let mut diags = Vec::new();
        detect_unknown_labels(&labels(&[("sozune.netwrok", "internal")]), &mut diags);
        assert_eq!(diags.len(), 1);
        let hint = diags[0].hint.as_deref().unwrap();
        assert!(hint.contains("network"), "got: {hint}");
    }

    #[test]
    fn unknown_label_without_close_match_falls_back_to_doc_link() {
        let mut diags = Vec::new();
        detect_unknown_labels(
            &labels(&[("sozune.http.web.completely_made_up_field", "x")]),
            &mut diags,
        );
        assert_eq!(diags.len(), 1);
        let hint = diags[0].hint.as_deref().unwrap();
        assert!(hint.contains("sozune.dev"));
    }

    #[test]
    fn missing_third_segment_is_unknown() {
        let mut diags = Vec::new();
        detect_unknown_labels(&labels(&[("sozune.http.web", "x")]), &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W013UnknownLabel);
    }
}
