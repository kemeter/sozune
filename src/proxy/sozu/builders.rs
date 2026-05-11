//! Stateless conversion helpers from sōzune's domain model
//! (`crate::model::*`) into the Sōzu wire types
//! (`sozu_command_lib::proto::command::*`). Pure functions: no I/O, no shared
//! state — pulled out of `mod.rs` to keep the orchestration code focused on
//! its lifecycle.

use crate::model::{
    AuthConfig, HeaderConfig, HeaderDirection, PathConfig, PathRuleType, RedirectPolicy,
    RedirectScheme,
};
use sozu_command_lib::proto::command::{
    Header, HeaderPosition, PathRule, RedirectPolicy as SozuRedirectPolicy,
    RedirectScheme as SozuRedirectScheme,
};
use tracing::{debug, warn};

/// Sōzu's `RequestHttpFrontend.method` accepts a single method per frontend.
/// To support multi-method routing (`methods: ["GET","POST"]`) we register one
/// frontend per method. An empty list means "any method" → a single frontend
/// with `method: None`.
pub(super) fn methods_for_frontend(methods: &[String]) -> Vec<Option<String>> {
    if methods.is_empty() {
        vec![None]
    } else {
        methods.iter().map(|m| Some(m.clone())).collect()
    }
}

pub(super) fn build_frontend_headers(edits: &[HeaderConfig]) -> Vec<Header> {
    edits
        .iter()
        .map(|edit| Header {
            position: match edit.direction {
                HeaderDirection::Request => HeaderPosition::Request as i32,
                HeaderDirection::Response => HeaderPosition::Response as i32,
                HeaderDirection::Both => HeaderPosition::Both as i32,
            },
            key: edit.name.clone(),
            val: edit.value.clone(),
        })
        .collect()
}

pub(super) fn build_authorized_hashes(auth: &Option<AuthConfig>) -> Vec<String> {
    let Some(cfg) = auth else {
        return Vec::new();
    };
    let Some(ref users) = cfg.basic else {
        return Vec::new();
    };
    users
        .iter()
        .map(|u| format!("{}:{}", u.username, u.password_hash))
        .collect()
}

pub(super) fn map_redirect_policy(policy: RedirectPolicy) -> i32 {
    match policy {
        RedirectPolicy::Forward => SozuRedirectPolicy::Forward as i32,
        RedirectPolicy::Permanent => SozuRedirectPolicy::Permanent as i32,
        RedirectPolicy::Unauthorized => SozuRedirectPolicy::Unauthorized as i32,
    }
}

pub(super) fn map_redirect_scheme(scheme: RedirectScheme) -> i32 {
    match scheme {
        RedirectScheme::UseSame => SozuRedirectScheme::UseSame as i32,
        RedirectScheme::UseHttp => SozuRedirectScheme::UseHttp as i32,
        RedirectScheme::UseHttps => SozuRedirectScheme::UseHttps as i32,
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' | '^' | '$' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

pub(super) fn build_path_and_rewrite(
    path_config: Option<&PathConfig>,
    strip_prefix: bool,
    add_prefix: Option<&str>,
    cluster_id: &str,
) -> (PathRule, Option<String>) {
    if strip_prefix && add_prefix.is_some() {
        warn!(
            "strip_prefix and add_prefix are mutually exclusive on {}; add_prefix takes precedence",
            cluster_id
        );
    }

    if let Some(prefix) = add_prefix {
        return build_add_prefix_rewrite(path_config, prefix);
    }

    let Some(path_config) = path_config else {
        return (
            PathRule {
                value: "/".to_string(),
                kind: 0,
            },
            None,
        );
    };

    if !strip_prefix {
        let kind = match path_config.rule_type {
            PathRuleType::Prefix => 0,
            PathRuleType::Regex => 1,
            PathRuleType::Exact => 2,
        };
        return (
            PathRule {
                value: path_config.value.clone(),
                kind,
            },
            None,
        );
    }

    match path_config.rule_type {
        PathRuleType::Prefix => {
            let escaped = regex_escape(path_config.value.trim_end_matches('/'));
            let pattern = format!("^{}(?:/(.*))?$", escaped);
            (
                PathRule {
                    value: pattern,
                    kind: 1,
                },
                Some("/$PATH[1]".to_string()),
            )
        }
        PathRuleType::Exact => (
            PathRule {
                value: path_config.value.clone(),
                kind: 2,
            },
            Some("/".to_string()),
        ),
        PathRuleType::Regex => {
            debug!(
                "strip_prefix on Regex path is not supported natively for {}; configure rewrite via Sozu directly if needed",
                cluster_id
            );
            (
                PathRule {
                    value: path_config.value.clone(),
                    kind: 1,
                },
                None,
            )
        }
    }
}

fn normalize_add_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn build_add_prefix_rewrite(
    path_config: Option<&PathConfig>,
    prefix: &str,
) -> (PathRule, Option<String>) {
    let normalized = normalize_add_prefix(prefix);
    if normalized.is_empty() {
        return (
            PathRule {
                value: "/".to_string(),
                kind: 0,
            },
            None,
        );
    }

    match path_config {
        None => (
            PathRule {
                value: "^(/.*)$".to_string(),
                kind: 1,
            },
            Some(format!("{normalized}$PATH[1]")),
        ),
        Some(pc) => match pc.rule_type {
            PathRuleType::Prefix => {
                let escaped = regex_escape(pc.value.trim_end_matches('/'));
                let pattern = format!("^({}(?:/.*)?)$", escaped);
                (
                    PathRule {
                        value: pattern,
                        kind: 1,
                    },
                    Some(format!("{normalized}$PATH[1]")),
                )
            }
            PathRuleType::Exact => (
                PathRule {
                    value: pc.value.clone(),
                    kind: 2,
                },
                Some(format!("{normalized}{}", pc.value)),
            ),
            PathRuleType::Regex => (
                PathRule {
                    value: pc.value.clone(),
                    kind: 1,
                },
                Some(format!("{normalized}$PATH[1]")),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_prefix_without_path_matches_root_and_prepends() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, Some("/foo"), "test");
        assert_eq!(path_rule.kind, 1, "expected regex kind for capture");
        assert_eq!(path_rule.value, "^(/.*)$");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_normalizes_missing_leading_slash() {
        let (_, rewrite) = build_path_and_rewrite(None, false, Some("foo"), "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_strips_trailing_slash() {
        let (_, rewrite) = build_path_and_rewrite(None, false, Some("/foo/"), "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_empty_value_is_treated_as_no_op() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, Some("/"), "test");
        assert_eq!(path_rule.value, "/");
        assert_eq!(path_rule.kind, 0);
        assert!(rewrite.is_none());
    }

    #[test]
    fn add_prefix_with_prefix_path_matcher_keeps_filter() {
        let path = PathConfig {
            rule_type: PathRuleType::Prefix,
            value: "/api".to_string(),
        };
        let (path_rule, rewrite) = build_path_and_rewrite(Some(&path), false, Some("/foo"), "test");
        assert_eq!(path_rule.kind, 1);
        assert!(path_rule.value.contains("/api"));
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_with_exact_path_matcher_uses_static_rewrite() {
        let path = PathConfig {
            rule_type: PathRuleType::Exact,
            value: "/health".to_string(),
        };
        let (path_rule, rewrite) = build_path_and_rewrite(Some(&path), false, Some("/foo"), "test");
        assert_eq!(path_rule.kind, 2);
        assert_eq!(path_rule.value, "/health");
        assert_eq!(rewrite.as_deref(), Some("/foo/health"));
    }

    #[test]
    fn add_prefix_takes_precedence_over_strip_prefix() {
        // Mutually exclusive: when both set, add_prefix wins.
        let (_, rewrite) = build_path_and_rewrite(None, true, Some("/foo"), "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn no_add_prefix_keeps_default_behaviour() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, None, "test");
        assert_eq!(path_rule.value, "/");
        assert_eq!(path_rule.kind, 0);
        assert!(rewrite.is_none());
    }
}
