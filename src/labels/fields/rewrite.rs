//! `replacePath`, `replacePathRegex.*` and `redirectRegex.*`: rewrites of the
//! path and redirects by regex, which the middleware applies.

use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{RedirectRegex, RegexReplacement, valid_replace_path};
use std::collections::HashMap;

/// Parse `replacePath`, the path the backend receives. A value that is not a
/// path emits `W032` and is ignored.
pub fn parse_replace_path(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let key = format!("{prefix}replacePath");
    let raw = labels.get(&key)?.trim();
    if valid_replace_path(raw) {
        return Some(raw.to_string());
    }
    diagnostics.push(
        Diagnostic::new(
            DiagnosticCode::W032InvalidReplacePath,
            "replacePath is not a path, ignoring",
        )
        .with_label(&key)
        .with_value(raw)
        .with_hint("write a path starting with `/`, without query or spaces, e.g. /api/v2"),
    );
    None
}

/// Parse `replacePathRegex.regex` and `replacePathRegex.replacement`. Both
/// are needed, the regex must compile and the replacement be non-empty;
/// otherwise `W032` and the rewrite is ignored.
pub fn parse_replace_path_regex(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RegexReplacement> {
    let regex_key = format!("{prefix}replacePathRegex.regex");
    let replacement_key = format!("{prefix}replacePathRegex.replacement");
    let regex = labels.get(&regex_key);
    let replacement = labels.get(&replacement_key);
    if regex.is_none() && replacement.is_none() {
        return None;
    }
    let problem = match (regex, replacement) {
        (None, _) => Some((
            &replacement_key,
            "replacePathRegex.replacement without a regex, ignoring",
        )),
        (Some(_), None) => Some((
            &regex_key,
            "replacePathRegex.regex without a replacement, ignoring",
        )),
        (Some(r), Some(_)) if regex::Regex::new(r).is_err() => Some((
            &regex_key,
            "replacePathRegex.regex does not compile, ignoring",
        )),
        (Some(_), Some(rep)) if rep.is_empty() => Some((
            &replacement_key,
            "replacePathRegex.replacement is empty, ignoring",
        )),
        _ => None,
    };
    if let Some((key, message)) = problem {
        diagnostics.push(
            Diagnostic::new(DiagnosticCode::W032InvalidReplacePath, message)
                .with_label(key)
                .with_value(labels.get(key).map(String::as_str).unwrap_or_default())
                .with_hint("set both replacePathRegex.regex and a non-empty replacePathRegex.replacement, e.g. ^/foo/(.*) and /bar/$1"),
        );
        return None;
    }
    Some(RegexReplacement {
        regex: regex?.clone(),
        replacement: replacement?.clone(),
    })
}

/// Parse `redirectRegex.regex`, `redirectRegex.replacement` and
/// `redirectRegex.permanent`. The regex and replacement are both needed and
/// the regex must compile, `permanent` is `true` or `false`; otherwise `W033`
/// and the redirect is ignored.
pub fn parse_redirect_regex(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RedirectRegex> {
    let regex_key = format!("{prefix}redirectRegex.regex");
    let replacement_key = format!("{prefix}redirectRegex.replacement");
    let permanent_key = format!("{prefix}redirectRegex.permanent");
    let regex = labels.get(&regex_key);
    let replacement = labels.get(&replacement_key);
    let permanent = labels.get(&permanent_key);
    if regex.is_none() && replacement.is_none() && permanent.is_none() {
        return None;
    }
    let problem = match (regex, replacement, permanent.map(String::as_str)) {
        (None, _, _) => Some((&regex_key, "redirectRegex without a regex, ignoring")),
        (Some(_), None, _) => Some((
            &replacement_key,
            "redirectRegex.regex without a replacement, ignoring",
        )),
        (Some(r), Some(_), _) if regex::Regex::new(r).is_err() => {
            Some((&regex_key, "redirectRegex.regex does not compile, ignoring"))
        }
        (_, _, Some(p)) if p != "true" && p != "false" => Some((
            &permanent_key,
            "redirectRegex.permanent is not true or false, ignoring the redirect",
        )),
        _ => None,
    };
    if let Some((key, message)) = problem {
        diagnostics.push(
            Diagnostic::new(DiagnosticCode::W033InvalidRedirectRegex, message)
                .with_label(key)
                .with_value(labels.get(key).map(String::as_str).unwrap_or_default())
                .with_hint("set redirectRegex.regex and redirectRegex.replacement, e.g. ^https?://example\\.com/(.*) and https://www.example.com/$1"),
        );
        return None;
    }
    Some(RedirectRegex {
        regex: regex?.clone(),
        replacement: replacement?.clone(),
        permanent: permanent.is_some_and(|p| p == "true"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "sozune.http.web.";

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (format!("{PREFIX}{k}"), (*v).to_string()))
            .collect()
    }

    #[test]
    fn replace_path_parses() {
        let mut diags = Vec::new();
        let path = parse_replace_path(&labels(&[("replacePath", "/api/v2")]), PREFIX, &mut diags);
        assert_eq!(path.as_deref(), Some("/api/v2"));
        assert!(diags.is_empty());
    }

    #[test]
    fn replace_path_that_is_not_a_path_emits_w032() {
        for value in ["api", "/a?b=1", "/a b", ""] {
            let mut diags = Vec::new();
            let path = parse_replace_path(&labels(&[("replacePath", value)]), PREFIX, &mut diags);
            assert!(path.is_none(), "{value}");
            assert_eq!(
                diags[0].code,
                DiagnosticCode::W032InvalidReplacePath,
                "{value}"
            );
        }
    }

    #[test]
    fn replace_path_regex_parses() {
        let mut diags = Vec::new();
        let rewrite = parse_replace_path_regex(
            &labels(&[
                ("replacePathRegex.regex", "^/foo/(.*)"),
                ("replacePathRegex.replacement", "/bar/$1"),
            ]),
            PREFIX,
            &mut diags,
        )
        .unwrap();
        assert_eq!(rewrite.regex, "^/foo/(.*)");
        assert_eq!(rewrite.replacement, "/bar/$1");
        assert!(diags.is_empty());
    }

    #[test]
    fn incomplete_or_invalid_replace_path_regex_emits_w032() {
        let cases: &[&[(&str, &str)]] = &[
            &[("replacePathRegex.regex", "^/foo")],
            &[("replacePathRegex.replacement", "/bar")],
            &[
                ("replacePathRegex.regex", "^/(foo"),
                ("replacePathRegex.replacement", "/bar"),
            ],
            &[
                ("replacePathRegex.regex", "^/foo"),
                ("replacePathRegex.replacement", ""),
            ],
        ];
        for case in cases {
            let mut diags = Vec::new();
            assert!(
                parse_replace_path_regex(&labels(case), PREFIX, &mut diags).is_none(),
                "{case:?}"
            );
            assert_eq!(
                diags[0].code,
                DiagnosticCode::W032InvalidReplacePath,
                "{case:?}"
            );
        }
    }

    #[test]
    fn redirect_regex_parses() {
        let mut diags = Vec::new();
        let redirect = parse_redirect_regex(
            &labels(&[
                ("redirectRegex.regex", "^http://localhost/(.*)"),
                ("redirectRegex.replacement", "http://mydomain/$1"),
                ("redirectRegex.permanent", "true"),
            ]),
            PREFIX,
            &mut diags,
        )
        .unwrap();
        assert_eq!(redirect.replacement, "http://mydomain/$1");
        assert!(redirect.permanent);
        assert!(diags.is_empty());
    }

    #[test]
    fn redirect_regex_is_temporary_by_default() {
        let mut diags = Vec::new();
        let redirect = parse_redirect_regex(
            &labels(&[
                ("redirectRegex.regex", "^x"),
                ("redirectRegex.replacement", "y"),
            ]),
            PREFIX,
            &mut diags,
        )
        .unwrap();
        assert!(!redirect.permanent);
    }

    #[test]
    fn incomplete_or_invalid_redirect_regex_emits_w033() {
        let cases: &[&[(&str, &str)]] = &[
            &[("redirectRegex.regex", "^x")],
            &[("redirectRegex.replacement", "y")],
            &[("redirectRegex.permanent", "true")],
            &[
                ("redirectRegex.regex", "(x"),
                ("redirectRegex.replacement", "y"),
            ],
            &[
                ("redirectRegex.regex", "^x"),
                ("redirectRegex.replacement", "y"),
                ("redirectRegex.permanent", "yes"),
            ],
        ];
        for case in cases {
            let mut diags = Vec::new();
            assert!(
                parse_redirect_regex(&labels(case), PREFIX, &mut diags).is_none(),
                "{case:?}"
            );
            assert_eq!(
                diags[0].code,
                DiagnosticCode::W033InvalidRedirectRegex,
                "{case:?}"
            );
        }
    }
}
