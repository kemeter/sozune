//! Translation of Gateway API `HTTPRoute` per-match conditions
//! (`matches[].headers`, `matches[].queryParams`, `matches[].method`) into
//! the sōzune entrypoint model.
//!
//! Path matching is handled inline in `gateway::rule_to_entrypoints`; this
//! module covers the other three match dimensions. All three reuse existing
//! `EntrypointConfig` fields (`match_headers`, `match_query`, `methods`)
//! that the label/YAML providers already populate, so enforcement is shared:
//! headers/query are checked by the request-match middleware (404 on a
//! miss), methods are enforced natively by Sōzu (one frontend per verb).
//!
//! Within a single Gateway API match, `path`, `headers`, `queryParams` and
//! `method` are ANDed — every listed condition must hold. Across matches in
//! a rule they are ORed, which the caller models by emitting one entrypoint
//! per match.
//!
//! A `type: RegularExpression` header or query match must match the whole
//! value. One that does not compile is reported unsupported by
//! [`match_has_unsupported_conditions`] and the whole route is rejected
//! upstream, exactly like an unsupported filter, rather than served too
//! widely.

use crate::model::MatchCondition;
use gateway_api::apis::standard::httproutes::{
    HttpRouteRulesMatches, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParamsType,
};

/// Translate a match's `headers[]` into `match_headers` conditions. A
/// header with `type: Exact` (or unset — Exact is the spec default) becomes
/// a condition on its value, one with `RegularExpression` a regex condition
/// the whole value must match. Header names are matched case-insensitively
/// downstream, matching the spec.
pub fn match_headers_from(m: &HttpRouteRulesMatches) -> Vec<MatchCondition> {
    m.headers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|h| MatchCondition {
            key: h.name.clone(),
            value: h.value.clone(),
            regex: matches!(
                h.r#type,
                Some(HttpRouteRulesMatchesHeadersType::RegularExpression)
            ),
        })
        .collect()
}

/// Translate a match's `queryParams[]` into `match_query` conditions.
/// Mirrors [`match_headers_from`].
pub fn match_query_from(m: &HttpRouteRulesMatches) -> Vec<MatchCondition> {
    m.query_params
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|q| MatchCondition {
            key: q.name.clone(),
            value: q.value.clone(),
            regex: matches!(
                q.r#type,
                Some(HttpRouteRulesMatchesQueryParamsType::RegularExpression)
            ),
        })
        .collect()
}

/// Translate a match's `method` into the entrypoint's `methods` list (a
/// single uppercase verb, or empty for a match with no method constraint).
/// The verb strings are the ones Sōzu and the label provider already use.
pub fn methods_from(m: &HttpRouteRulesMatches) -> Vec<String> {
    match &m.method {
        Some(method) => vec![method_verb(method).to_string()],
        None => Vec::new(),
    }
}

/// Map a Gateway API method enum variant to its uppercase HTTP verb. The
/// crate enum has no wire-name accessor, so the mapping is explicit; all
/// nine standard verbs are covered.
fn method_verb(method: &HttpRouteRulesMatchesMethod) -> &'static str {
    match method {
        HttpRouteRulesMatchesMethod::Get => "GET",
        HttpRouteRulesMatchesMethod::Head => "HEAD",
        HttpRouteRulesMatchesMethod::Post => "POST",
        HttpRouteRulesMatchesMethod::Put => "PUT",
        HttpRouteRulesMatchesMethod::Delete => "DELETE",
        HttpRouteRulesMatchesMethod::Connect => "CONNECT",
        HttpRouteRulesMatchesMethod::Options => "OPTIONS",
        HttpRouteRulesMatchesMethod::Trace => "TRACE",
        HttpRouteRulesMatchesMethod::Patch => "PATCH",
    }
}

/// True iff a single match declares a condition sōzune cannot represent: a
/// `RegularExpression` header or query match that does not compile, or a
/// `RegularExpression` path match, which Sōzu would match against the path
/// with its query. The caller aggregates this across a route's matches to
/// reject the route with a clear status rather than serve it with the
/// condition dropped.
pub fn match_has_unsupported_conditions(m: &HttpRouteRulesMatches) -> bool {
    // Checked as it is served.
    let invalid = |pattern: &str| crate::model::anchored_regex(pattern).is_none();
    let header_regex = m.headers.as_deref().unwrap_or_default().iter().any(|h| {
        matches!(
            h.r#type,
            Some(HttpRouteRulesMatchesHeadersType::RegularExpression)
        ) && invalid(&h.value)
    });
    let query_regex = m
        .query_params
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|q| {
            matches!(
                q.r#type,
                Some(HttpRouteRulesMatchesQueryParamsType::RegularExpression)
            ) && invalid(&q.value)
        });
    let path_regex = m.path.as_ref().is_some_and(|p| {
        matches!(
            p.r#type,
            Some(HttpRouteRulesMatchesPathType::RegularExpression)
        )
    });
    header_regex || query_regex || path_regex
}
