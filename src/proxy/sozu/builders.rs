//! Stateless conversion helpers from sōzune's domain model
//! (`crate::model::*`) into the Sōzu wire types
//! (`sozu_command_lib::proto::command::*`). Pure functions: no I/O, no shared
//! state — pulled out of `mod.rs` to keep the orchestration code focused on
//! its lifecycle.

use crate::model::{
    AuthConfig, EntrypointConfig, HeaderConfig, HeaderDirection, MatchCondition, PathConfig,
    PathRewrite, PathRuleType, RedirectPolicy, RedirectScheme, UrlRewrite,
};
use sozu_command_lib::config::validate_header_predicate;
use sozu_command_lib::proto::command::{
    Header, HeaderMatchKind, HeaderPosition, HeaderPredicate, PathRule,
    RedirectPolicy as SozuRedirectPolicy, RedirectScheme as SozuRedirectScheme,
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

/// Sōzu appends a header edit next to any header of the same name and reads
/// an empty value as a delete, applying every delete of a batch before any
/// insert. A set is therefore sent as a delete followed by the new value, so
/// the label value replaces what the client or backend sent; an append is
/// sent as the value alone.
pub(super) fn build_frontend_headers(edits: &[HeaderConfig]) -> Vec<Header> {
    let mut headers = Vec::with_capacity(edits.len() * 2);
    for edit in edits {
        let position = match edit.direction {
            HeaderDirection::Request => HeaderPosition::Request as i32,
            HeaderDirection::Response => HeaderPosition::Response as i32,
            HeaderDirection::Both => HeaderPosition::Both as i32,
        };
        if !edit.append || edit.value.is_empty() {
            headers.push(Header {
                position,
                key: edit.name.clone(),
                val: String::new(),
            });
        }
        if !edit.value.is_empty() {
            headers.push(Header {
                position,
                key: edit.name.clone(),
                val: edit.value.clone(),
            });
        }
    }
    headers
}

/// The Sōzu predicate for a header condition, or `None` when Sōzu cannot route
/// on it: `Host`, `Cookie` and a name that is not a header token. Those stay
/// with the middleware, which answers 404 when they fail; a predicate instead
/// lets the request fall through to the next route.
pub(crate) fn header_predicate(condition: &MatchCondition) -> Option<HeaderPredicate> {
    let predicate = if condition.regex {
        HeaderPredicate {
            name: condition.key.clone(),
            kind: HeaderMatchKind::Regex as i32,
            value: Some(condition.value.clone()),
        }
    } else if condition.value.is_empty() {
        HeaderPredicate {
            name: condition.key.clone(),
            kind: HeaderMatchKind::Present as i32,
            value: None,
        }
    } else {
        HeaderPredicate {
            name: condition.key.clone(),
            kind: HeaderMatchKind::Exact as i32,
            value: Some(condition.value.clone()),
        }
    };
    validate_header_predicate(&predicate)
        .ok()
        .map(|_| predicate)
}

pub(super) fn build_header_predicates(conditions: &[MatchCondition]) -> Vec<HeaderPredicate> {
    conditions.iter().filter_map(header_predicate).collect()
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
        RedirectPolicy::Found => SozuRedirectPolicy::Found as i32,
        RedirectPolicy::Unauthorized => SozuRedirectPolicy::Unauthorized as i32,
        RedirectPolicy::Close => SozuRedirectPolicy::SilentClose as i32,
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
    rewrite: Option<&UrlRewrite>,
    cluster_id: &str,
) -> (PathRule, Option<String>) {
    // The Gateway API `urlRewrite` filter is an explicit, complete rewrite
    // intent — it wins over the coarser strip_prefix / add_prefix knobs when
    // both are set. (hostname rewrites live on a separate frontend field and
    // don't affect the path rule built here.)
    if let Some(path_mode) = rewrite.and_then(|rw| rw.path.as_ref()) {
        if strip_prefix || add_prefix.is_some() {
            warn!(
                "urlRewrite path rewrite and strip_prefix/add_prefix are mutually exclusive on {}; urlRewrite takes precedence",
                cluster_id
            );
        }
        return build_url_rewrite_path(path_config, path_mode, cluster_id);
    }

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
        let rule = match path_config.rule_type {
            PathRuleType::Prefix => segment_prefix_rule(&path_config.value),
            PathRuleType::Regex => user_regex_rule(&path_config.value),
            PathRuleType::Exact => exact_rule(&path_config.value),
        };
        return (rule, None);
    }

    match path_config.rule_type {
        PathRuleType::Prefix => (
            prefix_rule_capturing_rest(&path_config.value),
            Some("/$PATH[1]$PATH[2]".to_string()),
        ),
        PathRuleType::Exact => (
            exact_rule_capturing_query(&path_config.value),
            Some("/$PATH[1]".to_string()),
        ),
        PathRuleType::Regex => {
            debug!(
                "strip_prefix on Regex path is not supported natively for {}; configure rewrite via Sozu directly if needed",
                cluster_id
            );
            (user_regex_rule(&path_config.value), None)
        }
    }
}

/// The most query conditions Sōzu routes on: the rule tries each of their
/// orders, which grow as their factorial.
const MAX_ROUTED_QUERY_CONDITIONS: usize = 3;

/// Whether Sōzu routes on the query conditions of a route, in its path rule:
/// a request failing them then goes on to the next route. Not with a path
/// rewrite, whose rule captures parts of the path, nor a path regex, nor a
/// regex condition, nor a condition holding `%`, which the middleware reads as written or as the
/// start of an encoding depending on what follows; the middleware then
/// answers `404` when they fail.
pub(crate) fn routes_on_query(config: &EntrypointConfig) -> bool {
    !config.match_query.is_empty()
        && !config.match_query.iter().any(|c| c.regex)
        && !config
            .match_query
            .iter()
            .any(|c| c.key.contains('%') || c.value.contains('%'))
        && config.match_query.len() <= MAX_ROUTED_QUERY_CONDITIONS
        && config.rewrite.as_ref().is_none_or(|r| r.path.is_none())
        && !config.strip_prefix
        && config.add_prefix.is_none()
        && config
            .path
            .as_ref()
            .is_none_or(|p| p.rule_type != PathRuleType::Regex)
}

/// The path rule of a route whose query conditions Sōzu routes on (see
/// [`routes_on_query`]): its path, then a query holding every condition, in
/// any order.
pub(crate) fn query_path_rule(config: &EntrypointConfig) -> Option<PathRule> {
    if !routes_on_query(config) {
        return None;
    }
    let path = match &config.path {
        None => "/[^?]*".to_string(),
        Some(p) if p.rule_type == PathRuleType::Exact => regex_escape(&p.value),
        Some(p) => {
            let trimmed = p.value.trim_end_matches('/');
            if trimmed.is_empty() {
                "/[^?]*".to_string()
            } else {
                format!("{}(?:/[^?]*)?", regex_escape(trimmed))
            }
        }
    };
    // One parameter can meet several conditions: a repeated one, or a
    // presence check next to a value on the same key. Each must not ask for
    // an occurrence of its own.
    let mut kept: Vec<&crate::model::MatchCondition> = Vec::new();
    for c in &config.match_query {
        let covered = kept
            .iter()
            .any(|k| k.key == c.key && (c.value.is_empty() || k.value == c.value));
        if covered {
            continue;
        }
        if !c.value.is_empty() {
            kept.retain(|k| !(k.key == c.key && k.value.is_empty()));
        }
        kept.push(c);
    }
    let conditions: Vec<String> = kept
        .iter()
        .map(|c| {
            if c.value.is_empty() {
                format!("{}(?:=[^&]*)?", query_literal(&c.key, false))
            } else {
                format!(
                    "{}={}",
                    query_literal(&c.key, false),
                    query_literal(&c.value, true)
                )
            }
        })
        .collect();
    let orders: Vec<String> = permutations(&conditions)
        .into_iter()
        .map(|order| order.join("&(?:.*&)?"))
        .collect();
    Some(PathRule {
        value: format!(r"^{path}\?(?:.*&)?(?:{})(?:&.*)?$", orders.join("|")),
        kind: 1,
    })
}

/// A regex matching `text` in a query as written or percent-encoded, as the
/// middleware compares it decoded: `2` matches `2` and `%32`. A character
/// that would end the parameter (`&`, `#`, and `=` in a key) or start an
/// encoding (`%`) only matches encoded; a value may hold a raw `=`, as the
/// middleware splits a parameter on its first one.
fn query_literal(text: &str, value: bool) -> String {
    text.chars()
        .map(|c| {
            let mut bytes = [0u8; 4];
            let encoded: String = c
                .encode_utf8(&mut bytes)
                .bytes()
                .map(|b| format!("%{b:02x}"))
                .collect();
            if matches!(c, '&' | '#' | '%') || (c == '=' && !value) {
                format!("(?i:{encoded})")
            } else {
                format!("(?:{}|(?i:{encoded}))", regex_escape(&c.to_string()))
            }
        })
        .collect()
}

/// Every order of `items`.
fn permutations(items: &[String]) -> Vec<Vec<String>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for (i, first) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(i);
        for mut order in permutations(&rest) {
            order.insert(0, first.clone());
            out.push(order);
        }
    }
    out
}

/// Sōzu matches a path rule against the request path *with* its query
/// (`/login?next=/`), and a rewrite replaces both. Every anchored rule below
/// therefore accepts an optional query, and every rewrite carries it over.
const QUERY: &str = r"(\?.*)?";

/// `value` exactly, with or without a query: Sōzu's own exact rule would
/// compare `/login` against `/login?next=/` and refuse it.
fn exact_rule(value: &str) -> PathRule {
    PathRule {
        value: format!(r"^{}(?:\?.*)?$", regex_escape(value)),
        kind: 1,
    }
}

/// `value` exactly, the query (if any) captured as `$PATH[1]` for a rewrite.
fn exact_rule_capturing_query(value: &str) -> PathRule {
    PathRule {
        value: format!("^{}{QUERY}$", regex_escape(value)),
        kind: 1,
    }
}

/// The segments below `prefix` as `$PATH[1]` (without the leading `/`) and
/// the query as `$PATH[2]`: `/api/users?x=1` → `users`, `?x=1`; `/api?x=1` →
/// ``, `?x=1`.
fn prefix_rule_capturing_rest(prefix: &str) -> PathRule {
    PathRule {
        value: format!(
            "^{}(?:/([^?]*))?{QUERY}$",
            regex_escape(prefix.trim_end_matches('/'))
        ),
        kind: 1,
    }
}

/// A prefix that matches on segment boundaries: `/app` covers `/app`,
/// `/app/users` and `/app?x=1`, but not `/apple`. Sōzu's own prefix rule
/// compares bytes, which would hand `/apple` to the `/app` route, so the rule
/// goes as an anchored regex. Sōzu matches it against the path with its query,
/// hence `?` as a boundary too. `/` alone stays a plain prefix: it covers
/// everything either way.
fn segment_prefix_rule(prefix: &str) -> PathRule {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return PathRule {
            value: "/".to_string(),
            kind: 0,
        };
    }
    PathRule {
        value: format!("^{}(?:[/?].*)?$", regex_escape(trimmed)),
        kind: 1,
    }
}

/// A `pathRegex` as written by the user, searched anywhere in what Sōzu
/// matches: the path with its query, unless the user anchors it. Sōzu anchors
/// a path regex at both ends, so the pattern goes between a lazy `.*?`, which
/// keeps the first occurrence (the one a `$PATH[n]` rewrite captures), and
/// `.*`. `^` and `$` written by the user keep their meaning, and its groups
/// their numbers.
fn user_regex_rule(value: &str) -> PathRule {
    // A pattern that does not compile on its own goes as written, for Sōzu
    // to refuse: the wrapping could otherwise balance it into a valid one.
    let value = if regex::Regex::new(value).is_ok() {
        format!(".*?(?:{value}).*")
    } else {
        value.to_string()
    };
    PathRule { value, kind: 1 }
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
            PathRuleType::Prefix => (
                // The whole path as $PATH[1], the query as $PATH[2].
                PathRule {
                    value: format!(
                        "^({}(?:/[^?]*)?){QUERY}$",
                        regex_escape(pc.value.trim_end_matches('/'))
                    ),
                    kind: 1,
                },
                Some(format!("{normalized}$PATH[1]$PATH[2]")),
            ),
            PathRuleType::Exact => (
                exact_rule_capturing_query(&pc.value),
                Some(format!("{normalized}{}$PATH[1]", pc.value)),
            ),
            PathRuleType::Regex => (
                user_regex_rule(&pc.value),
                Some(format!("{normalized}$PATH[1]")),
            ),
        },
    }
}

/// Build the path rule + native Sōzu rewrite string for a Gateway API
/// `urlRewrite` path filter (transparent rewrite, no redirect).
///
/// - `ReplaceFullPath(new)`: match the route path, rewrite to the literal
///   `new` regardless of any trailing segments. For a Prefix path the rule is
///   a regex that also matches sub-paths so the whole match collapses to
///   `new`; for an Exact path it's an exact match.
/// - `ReplacePrefixMatch(new)`: match the route prefix and keep the trailing
///   segments, swapping only the prefix: `/api/users` → `/v2/users`, and a
///   bare `/api` → exactly `/v2`. A replacement of `/` strips the prefix as
///   strip_prefix does, a bare `/api` giving `/`.
fn build_url_rewrite_path(
    path_config: Option<&PathConfig>,
    mode: &PathRewrite,
    cluster_id: &str,
) -> (PathRule, Option<String>) {
    match mode {
        PathRewrite::ReplaceFullPath(new) => build_replace_full_path(path_config, new),
        PathRewrite::ReplacePrefixMatch(new) => {
            build_replace_prefix_match(path_config, new, cluster_id)
        }
    }
}

fn build_replace_full_path(
    path_config: Option<&PathConfig>,
    new: &str,
) -> (PathRule, Option<String>) {
    // The path is replaced, the query kept: it is not part of the path.
    let keep_query = Some(format!("{new}$PATH[1]"));
    match path_config {
        // No route path constraint — match any path and collapse to `new`.
        None => (
            PathRule {
                value: format!("^/[^?]*{QUERY}$"),
                kind: 1,
            },
            keep_query,
        ),
        Some(pc) => match pc.rule_type {
            PathRuleType::Prefix => (
                PathRule {
                    value: format!(
                        "^{}(?:/[^?]*)?{QUERY}$",
                        regex_escape(pc.value.trim_end_matches('/'))
                    ),
                    kind: 1,
                },
                keep_query,
            ),
            PathRuleType::Exact => (exact_rule_capturing_query(&pc.value), keep_query),
            PathRuleType::Regex => (user_regex_rule(&pc.value), Some(new.to_string())),
        },
    }
}

fn build_replace_prefix_match(
    path_config: Option<&PathConfig>,
    new: &str,
    cluster_id: &str,
) -> (PathRule, Option<String>) {
    // Reuse add_prefix's normalisation: trim trailing slash, ensure a single
    // leading slash, empty → "". With an empty replacement the prefix is just
    // stripped, leaving the suffix (`/$PATH[1]`), matching strip_prefix.
    let normalized = normalize_add_prefix(new);
    let suffix_rewrite = format!("{normalized}/$PATH[1]");
    // A replacement ending in `/` keeps it on a bare prefix (`/v2/`); one
    // without gives exactly itself (`/v2`).
    let keeps_no_slash = !normalized.is_empty() && !new.trim().ends_with('/');

    // No path match is the `/` prefix, as Gateway API reads it.
    let root = PathConfig {
        rule_type: PathRuleType::Prefix,
        value: "/".to_string(),
    };
    let pc = path_config.unwrap_or(&root);

    match pc.rule_type {
        // Same capture as strip_prefix: the trailing segments (if any) land in
        // $PATH[1], the query in $PATH[2]. `/api/users` → `/v2/users`; a bare
        // `/api` (empty capture) → `/v2/` for a replacement ending in `/`, or
        // `/` for `/`, as strip_prefix does.
        // Any other replacement keeps the slash of the trailing
        // segments in the capture: a bare `/api` becomes exactly `/v2`, as
        // the spec says, not `/v2/`.
        // On the `/` prefix, a bare `/` is the prefix itself: it becomes
        // exactly the replacement, `/x` its replacement followed by `/x`.
        PathRuleType::Prefix if keeps_no_slash && pc.value.trim_end_matches('/').is_empty() => (
            PathRule {
                value: format!("^(/[^?]+)?/?{QUERY}$"),
                kind: 1,
            },
            Some(format!("{normalized}$PATH[1]$PATH[2]")),
        ),
        PathRuleType::Prefix if keeps_no_slash => (
            PathRule {
                value: format!(
                    "^{}(/[^?]*)?{QUERY}$",
                    regex_escape(pc.value.trim_end_matches('/'))
                ),
                kind: 1,
            },
            Some(format!("{normalized}$PATH[1]$PATH[2]")),
        ),
        PathRuleType::Prefix => (
            prefix_rule_capturing_rest(&pc.value),
            Some(format!("{suffix_rewrite}$PATH[2]")),
        ),
        PathRuleType::Exact => {
            // An exact match has no trailing segments to keep — the path is
            // exactly the prefix, so it becomes exactly the replacement.
            let target = if normalized.is_empty() {
                "/".to_string()
            } else {
                normalized
            };
            (
                exact_rule_capturing_query(&pc.value),
                Some(format!("{target}$PATH[1]")),
            )
        }
        PathRuleType::Regex => {
            warn!(
                "urlRewrite ReplacePrefixMatch on a Regex path is not supported natively for {}; leaving the request path unchanged",
                cluster_id
            );
            (user_regex_rule(&pc.value), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn condition(key: &str, value: &str) -> MatchCondition {
        MatchCondition {
            key: key.into(),
            value: value.into(),
            regex: false,
        }
    }

    #[test]
    fn a_header_condition_with_a_value_must_equal_it() {
        let predicate = header_predicate(&condition("X-Env", "prod")).unwrap();
        assert_eq!(predicate.name, "X-Env");
        assert_eq!(predicate.kind, HeaderMatchKind::Exact as i32);
        assert_eq!(predicate.value.as_deref(), Some("prod"));
    }

    #[test]
    fn a_header_condition_without_a_value_asks_for_presence() {
        let predicate = header_predicate(&condition("X-Debug", "")).unwrap();
        assert_eq!(predicate.kind, HeaderMatchKind::Present as i32);
        assert_eq!(predicate.value, None);
    }

    /// Sōzu refuses these names; the middleware keeps checking them.
    #[test]
    fn host_cookie_and_invalid_names_are_not_routed_by_sozu() {
        for key in ["Host", "cookie", "X Env", ""] {
            assert!(header_predicate(&condition(key, "v")).is_none(), "{key}");
        }
        let predicates =
            build_header_predicates(&[condition("Cookie", "beta=1"), condition("X-Env", "prod")]);
        assert_eq!(predicates.len(), 1);
        assert_eq!(predicates[0].name, "X-Env");
    }

    fn header(name: &str, value: &str, direction: HeaderDirection) -> HeaderConfig {
        HeaderConfig {
            name: name.into(),
            value: value.into(),
            direction,
            append: false,
        }
    }

    #[test]
    fn an_appended_header_keeps_the_existing_one() {
        let built = build_frontend_headers(&[HeaderConfig {
            append: true,
            ..header("X-Foo", "bar", HeaderDirection::Request)
        }]);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].key, "X-Foo");
        assert_eq!(built[0].val, "bar");
    }

    #[test]
    fn a_header_value_replaces_the_existing_one() {
        let built = build_frontend_headers(&[header("X-Foo", "bar", HeaderDirection::Response)]);
        let edits: Vec<(i32, &str, &str)> = built
            .iter()
            .map(|h| (h.position, h.key.as_str(), h.val.as_str()))
            .collect();
        let response = HeaderPosition::Response as i32;
        assert_eq!(
            edits,
            vec![(response, "X-Foo", ""), (response, "X-Foo", "bar")]
        );
    }

    #[test]
    fn an_empty_header_value_only_deletes() {
        let built = build_frontend_headers(&[header("Server", "", HeaderDirection::Both)]);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].position, HeaderPosition::Both as i32);
        assert_eq!(built[0].key, "Server");
        assert!(built[0].val.is_empty());
    }

    #[test]
    fn add_prefix_without_path_matches_root_and_prepends() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, Some("/foo"), None, "test");
        assert_eq!(path_rule.kind, 1, "expected regex kind for capture");
        assert_eq!(path_rule.value, "^(/.*)$");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_normalizes_missing_leading_slash() {
        let (_, rewrite) = build_path_and_rewrite(None, false, Some("foo"), None, "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_strips_trailing_slash() {
        let (_, rewrite) = build_path_and_rewrite(None, false, Some("/foo/"), None, "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn add_prefix_empty_value_is_treated_as_no_op() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, Some("/"), None, "test");
        assert_eq!(path_rule.value, "/");
        assert_eq!(path_rule.kind, 0);
        assert!(rewrite.is_none());
    }

    #[test]
    fn add_prefix_with_prefix_path_matcher_keeps_filter() {
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/api")),
                false,
                Some("/foo"),
                None,
                "test",
            )
        };
        assert_eq!(
            forwarded(built(), "/api/users").as_deref(),
            Some("/foo/api/users")
        );
        assert_eq!(
            forwarded(built(), "/api?x=1").as_deref(),
            Some("/foo/api?x=1")
        );
        assert_eq!(
            forwarded(built(), "/api/users?x=1").as_deref(),
            Some("/foo/api/users?x=1")
        );
        assert_eq!(forwarded(built(), "/apidocs"), None);
    }

    #[test]
    fn add_prefix_with_exact_path_matcher_uses_static_rewrite() {
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Exact, "/health")),
                false,
                Some("/foo"),
                None,
                "test",
            )
        };
        assert_eq!(
            forwarded(built(), "/health").as_deref(),
            Some("/foo/health")
        );
        assert_eq!(
            forwarded(built(), "/health?full=1").as_deref(),
            Some("/foo/health?full=1")
        );
        assert_eq!(forwarded(built(), "/health/x"), None);
    }

    #[test]
    fn add_prefix_takes_precedence_over_strip_prefix() {
        // Mutually exclusive: when both set, add_prefix wins.
        let (_, rewrite) = build_path_and_rewrite(None, true, Some("/foo"), None, "test");
        assert_eq!(rewrite.as_deref(), Some("/foo$PATH[1]"));
    }

    #[test]
    fn no_add_prefix_keeps_default_behaviour() {
        let (path_rule, rewrite) = build_path_and_rewrite(None, false, None, None, "test");
        assert_eq!(path_rule.value, "/");
        assert_eq!(path_rule.kind, 0);
        assert!(rewrite.is_none());
    }

    fn url_rewrite(path: Option<PathRewrite>, hostname: Option<&str>) -> UrlRewrite {
        UrlRewrite {
            path,
            hostname: hostname.map(String::from),
        }
    }

    fn rule(rule_type: PathRuleType, value: &str) -> PathConfig {
        PathConfig {
            rule_type,
            value: value.to_string(),
        }
    }

    /// The path the backend receives for `request`, as Sōzu's own router
    /// computes it from the rule and rewrite built here; `None` when the rule
    /// does not match. The request path carries its query, as in Sōzu.
    fn forwarded(built: (PathRule, Option<String>), request: &str) -> Option<String> {
        use sozu_command_lib::proto::command::{RequestHttpFrontend, RulePosition, SocketAddress};
        use sozu_lib::protocol::kawa_h1::parser::Method;
        use sozu_lib::router::Router;

        let (path, rewrite_path) = built;
        let front = RequestHttpFrontend {
            cluster_id: Some("test".to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, 80),
            hostname: "example.com".to_string(),
            path,
            rewrite_path,
            position: RulePosition::Pre as i32,
            ..Default::default()
        }
        .to_frontend()
        .unwrap();
        let mut router = Router::new();
        router.add_http_front(&front).unwrap();
        let result = router
            .lookup("example.com", request, &Method::new(b"GET"))
            .ok()?;
        Some(result.rewritten_path.unwrap_or_else(|| request.to_string()))
    }

    #[test]
    fn url_rewrite_replace_full_path_on_prefix_collapses_to_literal() {
        // `/api` (Prefix) → ReplaceFullPath("/new"): any sub-path collapses
        // to the literal `/new`; the query is not part of the path and stays.
        let rw = url_rewrite(Some(PathRewrite::ReplaceFullPath("/new".into())), None);
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/api")),
                false,
                None,
                Some(&rw),
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/api/a/b").as_deref(), Some("/new"));
        assert_eq!(forwarded(built(), "/api?x=1").as_deref(), Some("/new?x=1"));
        assert_eq!(forwarded(built(), "/apidocs"), None);
    }

    #[test]
    fn url_rewrite_replace_full_path_on_exact_uses_exact_match() {
        let rw = url_rewrite(Some(PathRewrite::ReplaceFullPath("/up".into())), None);
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Exact, "/health")),
                false,
                None,
                Some(&rw),
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/health").as_deref(), Some("/up"));
        assert_eq!(
            forwarded(built(), "/health?x=1").as_deref(),
            Some("/up?x=1")
        );
        assert_eq!(forwarded(built(), "/health/x"), None);
    }

    #[test]
    fn url_rewrite_replace_prefix_keeps_suffix() {
        // `/api` (Prefix) → ReplacePrefixMatch("/v2"): suffix preserved.
        // `/api/users` → `/v2/users`; a bare `/api` → exactly `/v2`.
        let rw = url_rewrite(Some(PathRewrite::ReplacePrefixMatch("/v2".into())), None);
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/api")),
                false,
                None,
                Some(&rw),
                "test",
            )
        };
        assert_eq!(
            forwarded(built(), "/api/users").as_deref(),
            Some("/v2/users")
        );
        assert_eq!(forwarded(built(), "/api").as_deref(), Some("/v2"));
        assert_eq!(forwarded(built(), "/api/").as_deref(), Some("/v2/"));
        assert_eq!(forwarded(built(), "/api?x=1").as_deref(), Some("/v2?x=1"));
        assert_eq!(forwarded(built(), "/apix"), None);

        // A replacement ending in `/` keeps it, and adds no second one.
        let slash = url_rewrite(Some(PathRewrite::ReplacePrefixMatch("/v2/".into())), None);
        let with_slash = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/api")),
                false,
                None,
                Some(&slash),
                "test",
            )
        };
        assert_eq!(forwarded(with_slash(), "/api").as_deref(), Some("/v2/"));
        assert_eq!(
            forwarded(with_slash(), "/api/users").as_deref(),
            Some("/v2/users")
        );

        // On the `/` prefix, `/` itself becomes exactly the replacement.
        let root = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/")),
                false,
                None,
                Some(&rw),
                "test",
            )
        };
        assert_eq!(forwarded(root(), "/").as_deref(), Some("/v2"));
        assert_eq!(forwarded(root(), "/users").as_deref(), Some("/v2/users"));
        assert_eq!(forwarded(root(), "/?x=1").as_deref(), Some("/v2?x=1"));
        // No path match reads as the `/` prefix.
        let none = || build_path_and_rewrite(None, false, None, Some(&rw), "test");
        assert_eq!(forwarded(none(), "/").as_deref(), Some("/v2"));
        assert_eq!(forwarded(none(), "/users").as_deref(), Some("/v2/users"));
        assert_eq!(
            forwarded(built(), "/api/users?x=1").as_deref(),
            Some("/v2/users?x=1")
        );
    }

    #[test]
    fn url_rewrite_replace_prefix_normalizes_replacement() {
        // A replacement with a trailing slash and no leading slash is
        // normalised like add_prefix: `v2/` → `/v2`.
        let rw = url_rewrite(Some(PathRewrite::ReplacePrefixMatch("v2/".into())), None);
        let built = build_path_and_rewrite(
            Some(&rule(PathRuleType::Prefix, "/api")),
            false,
            None,
            Some(&rw),
            "test",
        );
        assert_eq!(forwarded(built, "/api/users").as_deref(), Some("/v2/users"));
    }

    #[test]
    fn url_rewrite_replace_prefix_on_exact_uses_static_target() {
        let rw = url_rewrite(Some(PathRewrite::ReplacePrefixMatch("/v2".into())), None);
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Exact, "/api")),
                false,
                None,
                Some(&rw),
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/api").as_deref(), Some("/v2"));
        assert_eq!(forwarded(built(), "/api?x=1").as_deref(), Some("/v2?x=1"));
    }

    #[test]
    fn url_rewrite_takes_precedence_over_strip_and_add_prefix() {
        let rw = url_rewrite(Some(PathRewrite::ReplacePrefixMatch("/v2".into())), None);
        let built = build_path_and_rewrite(
            Some(&rule(PathRuleType::Prefix, "/api")),
            true,
            Some("/foo"),
            Some(&rw),
            "test",
        );
        assert_eq!(forwarded(built, "/api/users").as_deref(), Some("/v2/users"));
    }

    #[test]
    fn url_rewrite_hostname_only_leaves_path_rule_unchanged() {
        // A hostname-only rewrite carries no path mode; the path rule is
        // built from the route path as usual (the hostname is wired onto the
        // frontend's rewrite_host elsewhere).
        let path = PathConfig {
            rule_type: PathRuleType::Prefix,
            value: "/api".to_string(),
        };
        let rw = url_rewrite(None, Some("internal.svc"));
        let (path_rule, rewrite) =
            build_path_and_rewrite(Some(&path), false, None, Some(&rw), "test");
        assert_eq!(path_rule.kind, 1);
        assert_eq!(path_rule.value, "^/api(?:[/?].*)?$");
        assert!(rewrite.is_none());
    }

    /// Sōzu matches against the path with its query: a query right after the
    /// prefix (`/api?x=1`) used to fall outside `^/api(?:/(.*))?$`, and a
    /// query after a sub-path was kept only by accident of the capture.
    #[test]
    fn strip_prefix_keeps_the_query_and_matches_it_after_the_prefix() {
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Prefix, "/api")),
                true,
                None,
                None,
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/api/users").as_deref(), Some("/users"));
        assert_eq!(forwarded(built(), "/api").as_deref(), Some("/"));
        assert_eq!(forwarded(built(), "/api?x=1").as_deref(), Some("/?x=1"));
        assert_eq!(
            forwarded(built(), "/api/users?x=1").as_deref(),
            Some("/users?x=1")
        );
        assert_eq!(forwarded(built(), "/apidocs"), None);
    }

    #[test]
    fn strip_prefix_on_an_exact_path_keeps_the_query() {
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Exact, "/api")),
                true,
                None,
                None,
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/api").as_deref(), Some("/"));
        assert_eq!(forwarded(built(), "/api?x=1").as_deref(), Some("/?x=1"));
    }

    /// An exact route compared `/login` with `/login?next=/` and refused
    /// every request carrying a query.
    #[test]
    fn an_exact_path_matches_with_a_query() {
        let built = || {
            build_path_and_rewrite(
                Some(&rule(PathRuleType::Exact, "/login")),
                false,
                None,
                None,
                "test",
            )
        };
        assert_eq!(forwarded(built(), "/login").as_deref(), Some("/login"));
        assert_eq!(
            forwarded(built(), "/login?next=/").as_deref(),
            Some("/login?next=/")
        );
        assert_eq!(forwarded(built(), "/login/x"), None);
        assert_eq!(forwarded(built(), "/loginx"), None);
    }

    /// Checked with Sōzu's own matcher: the rule is what decides, in the
    /// worker, which requests reach the route.
    #[test]
    fn a_prefix_matches_on_segment_boundaries_in_sozu() {
        use sozu_lib::router::{PathRule as SozuPathRule, PathRuleResult};
        let matches = |prefix: &str, path: &str| {
            let path_config = PathConfig {
                rule_type: PathRuleType::Prefix,
                value: prefix.to_string(),
            };
            let (rule, _) = build_path_and_rewrite(Some(&path_config), false, None, None, "test");
            SozuPathRule::from_config(rule)
                .is_some_and(|r| r.matches(path.as_bytes()) != PathRuleResult::None)
        };

        assert!(matches("/app", "/app"));
        assert!(matches("/app", "/app/users"));
        assert!(matches("/app", "/app?x=1"));
        assert!(matches("/app/", "/app"));
        assert!(!matches("/app", "/apple"));
        assert!(!matches("/app", "/"));
        assert!(matches("/", "/anything"));
        assert!(matches("/a.b", "/a.b/c"));
        assert!(!matches("/a.b", "/axb/c"));
    }

    /// Pins what the path matching docs say: Sōzu searches a `pathRegex`
    /// in the path with its query, and a leading `^` keeps the query out.
    #[test]
    fn a_path_regex_is_searched_in_the_path_and_its_query_in_sozu() {
        use sozu_lib::router::{PathRule as SozuPathRule, PathRuleResult};
        let matches = |regex: &str, path: &str| {
            let path_config = PathConfig {
                rule_type: PathRuleType::Regex,
                value: regex.to_string(),
            };
            let (rule, _) = build_path_and_rewrite(Some(&path_config), false, None, None, "test");
            SozuPathRule::from_config(rule)
                .is_some_and(|r| r.matches(path.as_bytes()) != PathRuleResult::None)
        };

        assert!(matches("/users/[0-9]+", "/v1/users/42"));
        assert!(matches("/users/[0-9]+", "/health?next=/users/42"));
        assert!(matches("^/users/[0-9]+", "/users/42/profile"));
        assert!(matches("^/users/[0-9]+", "/users/42?page=2"));
        assert!(!matches("^/users/[0-9]+", "/v1/users/42"));
        assert!(!matches("^/users/[0-9]+", "/health?next=/users/42"));
        assert!(!matches("^/users/[0-9]+$", "/users/42?page=2"));
    }

    /// A rewrite captures the first occurrence, as an unanchored search does.
    #[test]
    fn a_path_regex_rewrite_captures_the_first_occurrence() {
        let path_config = PathConfig {
            rule_type: PathRuleType::Regex,
            value: "/(a|b)".to_string(),
        };
        let (rule, _) = build_path_and_rewrite(Some(&path_config), false, Some("/p"), None, "test");
        let regex = regex::Regex::new(&format!(r"\A(?:{})\z", rule.value)).unwrap();
        let captures = regex.captures("/a/b").unwrap();
        assert_eq!(captures.get(1).map(|m| m.as_str()), Some("a"));
    }
}
