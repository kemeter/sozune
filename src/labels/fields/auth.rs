use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{AuthConfig, BasicAuthUser};
use std::collections::HashMap;

/// Parse the `auth.basic` label, a comma-separated list of `username:hash`.
/// Malformed entries (missing `:`) emit `W007` and are skipped. If all entries
/// are malformed the result is `None` and `W011` is emitted.
pub fn parse_auth(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<AuthConfig> {
    let key = format!("{prefix}auth.basic");
    let raw = labels.get(&key)?;
    let mut users = Vec::new();

    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.split_once(':') {
            Some((user, hash)) => users.push(BasicAuthUser {
                username: user.to_string(),
                password_hash: hash.to_string(),
            }),
            None => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W007MalformedBasicAuthEntry,
                        "basic auth entry missing ':', skipping",
                    )
                    .with_label(&key)
                    .with_value(trimmed)
                    .with_hint("expected `username:password_hash`"),
                );
            }
        }
    }

    if users.is_empty() {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W011EmptyBasicAuth,
                "all basic auth entries were malformed, auth disabled",
            )
            .with_label(&key),
        );
        return None;
    }

    Some(AuthConfig { basic: Some(users) })
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
        assert!(parse_auth(&labels(&[]), "sozune.http.web.", &mut diags).is_none());
        assert!(diags.is_empty());
    }

    #[test]
    fn single_valid_user_parses() {
        let mut diags = Vec::new();
        let auth = parse_auth(
            &labels(&[("sozune.http.web.auth.basic", "alice:hash1")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        let users = auth.basic.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].password_hash, "hash1");
        assert!(diags.is_empty());
    }

    #[test]
    fn multiple_users_split_on_comma() {
        let mut diags = Vec::new();
        let auth = parse_auth(
            &labels(&[(
                "sozune.http.web.auth.basic",
                "alice:hash1,bob:hash2,carol:hash3",
            )]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(auth.basic.unwrap().len(), 3);
    }

    #[test]
    fn malformed_entry_emits_w007_and_is_skipped() {
        let mut diags = Vec::new();
        let auth = parse_auth(
            &labels(&[(
                "sozune.http.web.auth.basic",
                "alice:hash1,bobnohash,carol:hash3",
            )]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(auth.basic.unwrap().len(), 2);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W007MalformedBasicAuthEntry);
        assert_eq!(diags[0].value.as_deref(), Some("bobnohash"));
    }

    #[test]
    fn all_malformed_emits_w011_and_returns_none() {
        let mut diags = Vec::new();
        let auth = parse_auth(
            &labels(&[("sozune.http.web.auth.basic", "alicebobcarol")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert!(auth.is_none());
        assert!(
            diags
                .iter()
                .any(|d| d.code == DiagnosticCode::W007MalformedBasicAuthEntry)
        );
        assert!(
            diags
                .iter()
                .any(|d| d.code == DiagnosticCode::W011EmptyBasicAuth)
        );
    }

    #[test]
    fn hash_with_colon_is_preserved() {
        let mut diags = Vec::new();
        let auth = parse_auth(
            &labels(&[("sozune.http.web.auth.basic", "alice:$2y$10:cost:hash")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        let users = auth.basic.unwrap();
        assert_eq!(users[0].password_hash, "$2y$10:cost:hash");
    }
}
