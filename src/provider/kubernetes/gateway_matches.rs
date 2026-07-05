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
//! Representability: the model matches header/query values exactly (or on
//! presence, via an empty value), so a `type: RegularExpression` header or
//! query match has no faithful mapping. Rather than silently widen the
//! route (routing more traffic than the author asked for — a correctness
//! and security hazard), a match carrying an unsupported regex condition is
//! reported unsupported by [`match_has_unsupported_conditions`] and the
//! whole route is rejected upstream, exactly like an unsupported filter.

use crate::model::MatchCondition;
use gateway_api::apis::standard::httproutes::{
    HTTPRouteRulesMatches, HTTPRouteRulesMatchesHeadersType, HTTPRouteRulesMatchesMethod,
    HTTPRouteRulesMatchesQueryParamsType,
};

/// Translate a match's `headers[]` into `match_headers` conditions. A
/// header with `type: Exact` (or unset — Exact is the spec default) becomes
/// a `MatchCondition { key: name, value }`. Header names are matched
/// case-insensitively downstream, matching the spec. `RegularExpression`
/// entries are skipped here; the route is rejected before this runs (see
/// [`match_has_unsupported_conditions`]), so a skip never widens a served
/// route.
pub fn match_headers_from(m: &HTTPRouteRulesMatches) -> Vec<MatchCondition> {
    m.headers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|h| {
            !matches!(
                h.r#type,
                Some(HTTPRouteRulesMatchesHeadersType::RegularExpression)
            )
        })
        .map(|h| MatchCondition {
            key: h.name.clone(),
            value: h.value.clone(),
        })
        .collect()
}

/// Translate a match's `queryParams[]` into `match_query` conditions.
/// Mirrors [`match_headers_from`]; `RegularExpression` entries are skipped
/// (the route is rejected upstream when any are present).
pub fn match_query_from(m: &HTTPRouteRulesMatches) -> Vec<MatchCondition> {
    m.query_params
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|q| {
            !matches!(
                q.r#type,
                Some(HTTPRouteRulesMatchesQueryParamsType::RegularExpression)
            )
        })
        .map(|q| MatchCondition {
            key: q.name.clone(),
            value: q.value.clone(),
        })
        .collect()
}

/// Translate a match's `method` into the entrypoint's `methods` list (a
/// single uppercase verb, or empty for a match with no method constraint).
/// The verb strings are the ones Sōzu and the label provider already use.
pub fn methods_from(m: &HTTPRouteRulesMatches) -> Vec<String> {
    match &m.method {
        Some(method) => vec![method_verb(method).to_string()],
        None => Vec::new(),
    }
}

/// Map a Gateway API method enum variant to its uppercase HTTP verb. The
/// crate enum has no wire-name accessor, so the mapping is explicit; all
/// nine standard verbs are covered.
fn method_verb(method: &HTTPRouteRulesMatchesMethod) -> &'static str {
    match method {
        HTTPRouteRulesMatchesMethod::Get => "GET",
        HTTPRouteRulesMatchesMethod::Head => "HEAD",
        HTTPRouteRulesMatchesMethod::Post => "POST",
        HTTPRouteRulesMatchesMethod::Put => "PUT",
        HTTPRouteRulesMatchesMethod::Delete => "DELETE",
        HTTPRouteRulesMatchesMethod::Connect => "CONNECT",
        HTTPRouteRulesMatchesMethod::Options => "OPTIONS",
        HTTPRouteRulesMatchesMethod::Trace => "TRACE",
        HTTPRouteRulesMatchesMethod::Patch => "PATCH",
    }
}

/// True iff a single match declares a condition sōzune cannot represent —
/// currently only a `type: RegularExpression` on a header or query match.
/// The caller aggregates this across a route's matches to reject the route
/// with a clear status rather than serve it with the regex condition
/// dropped.
pub fn match_has_unsupported_conditions(m: &HTTPRouteRulesMatches) -> bool {
    let header_regex = m.headers.as_deref().unwrap_or_default().iter().any(|h| {
        matches!(
            h.r#type,
            Some(HTTPRouteRulesMatchesHeadersType::RegularExpression)
        )
    });
    let query_regex = m
        .query_params
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|q| {
            matches!(
                q.r#type,
                Some(HTTPRouteRulesMatchesQueryParamsType::RegularExpression)
            )
        });
    header_regex || query_regex
}
