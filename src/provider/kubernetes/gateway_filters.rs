//! Translation of Gateway API HTTPRoute filters into Sōzune's
//! `EntrypointConfig`.
//!
//! Supported filters: `requestRedirect` (mapped onto Sōzu's native
//! frontend redirect — scheme, hostname, port, status code),
//! `requestHeaderModifier` / `responseHeaderModifier` (mapped onto Sōzu's
//! native frontend header edits — see [`header_edits_from_filters`]), and
//! `urlRewrite` (transparent path / hostname rewrite onto Sōzu's native
//! frontend `rewrite_path` / `rewrite_host` — see [`url_rewrite_from_filter`]).
//! Filters or sub-fields we can't honour faithfully cause the whole rule
//! to be refused upstream — routing as if they weren't there would
//! silently rewrite user intent. See [`redirect_from_filter`] and
//! [`rule_filters_supported`].

use crate::model::entrypoint::{
    HeaderConfig, HeaderDirection, PathRewrite, RedirectPolicy, RedirectScheme, UrlRewrite,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRouteRules, HTTPRouteRulesBackendRefs, HTTPRouteRulesFilters,
    HTTPRouteRulesFiltersRequestHeaderModifier, HTTPRouteRulesFiltersRequestMirrorBackendRef,
    HTTPRouteRulesFiltersRequestRedirect, HTTPRouteRulesFiltersRequestRedirectScheme,
    HTTPRouteRulesFiltersResponseHeaderModifier, HTTPRouteRulesFiltersUrlRewrite,
    HTTPRouteRulesFiltersUrlRewritePath, HTTPRouteRulesFiltersUrlRewritePathType,
};

/// The redirect settings a `requestRedirect` filter maps onto. These line
/// up with `EntrypointConfig`'s `redirect`, `redirect_scheme`, and the
/// `rewrite_host` / `rewrite_path` / `rewrite_port` target overrides, which
/// Sōzu applies natively at the frontend (no middleware hop).
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectMapping {
    pub policy: RedirectPolicy,
    pub scheme: Option<RedirectScheme>,
    pub host: Option<String>,
    pub path: Option<String>,
    /// What the matched prefix becomes, the rest of the path kept.
    pub prefix: Option<String>,
    pub port: Option<u16>,
}

/// Whether every filter on a rule is one we can faithfully execute.
///
/// Supported filters: a mappable `requestRedirect` (see
/// [`redirect_from_filter`]), `requestHeaderModifier`,
/// `responseHeaderModifier`, and `urlRewrite` (see
/// [`url_rewrite_from_filter`]). Header modifiers freely mix with either a
/// redirect or a rewrite. `requestRedirect` and `urlRewrite` *conflict*,
/// though — one redirects the client, the other transparently rewrites the
/// forwarded request, and both fight over Sōzu's frontend `rewrite_path` —
/// so a rule carrying both is refused. `requestMirror` and `extensionRef`
/// remain unsupported; a rule carrying either (alone or mixed) is refused,
/// since partial execution would misrepresent intent.
pub fn rule_filters_supported(filters: &[HTTPRouteRulesFilters]) -> bool {
    let has_redirect = filters.iter().any(|f| f.request_redirect.is_some());
    let has_rewrite = filters.iter().any(|f| f.url_rewrite.is_some());
    if has_redirect && has_rewrite {
        // Conflicting intents over the same frontend rewrite — refuse.
        return false;
    }
    filters.iter().all(filter_supported)
}

/// A rule's filters with those of its backendRefs, `None` when the latter
/// cannot be represented. Sōzu edits headers per route, not per backend: the
/// backendRefs that can take traffic (`usable`) must all carry the same
/// filters, header modifiers only, which then apply to the whole rule.
pub fn effective_rule_filters(
    rule: &HTTPRouteRules,
    usable: &dyn Fn(&HTTPRouteRulesBackendRefs) -> bool,
) -> Option<Vec<HTTPRouteRulesFilters>> {
    let mut filters = rule.filters.clone().unwrap_or_default();
    // A redirect forwards nothing: no backend filter runs.
    if filters.iter().any(|f| f.request_redirect.is_some()) {
        return Some(filters);
    }
    let backend_refs: Vec<&HTTPRouteRulesBackendRefs> = rule
        .backend_refs
        .iter()
        .flatten()
        .filter(|b| usable(b))
        .collect();
    let Some(first) = backend_refs.first() else {
        return Some(filters);
    };
    let shared = first.filters.clone().unwrap_or_default();
    let same = backend_refs
        .iter()
        .all(|b| b.filters.as_deref().unwrap_or_default() == shared.as_slice());
    if !same {
        return None;
    }
    for filter in &shared {
        // Same schema as a rule filter: converted through its JSON form.
        let converted: HTTPRouteRulesFilters =
            serde_json::from_value(serde_json::to_value(filter).ok()?).ok()?;
        let headers_only = converted.request_redirect.is_none()
            && converted.url_rewrite.is_none()
            && converted.request_mirror.is_none()
            && converted.extension_ref.is_none()
            && (converted.request_header_modifier.is_some()
                || converted.response_header_modifier.is_some());
        if !headers_only {
            return None;
        }
        filters.push(converted);
    }
    Some(filters)
}

fn filter_supported(filter: &HTTPRouteRulesFilters) -> bool {
    // An entry carrying a still-unsupported variant fails outright.
    if filter.extension_ref.is_some() {
        return false;
    }
    // A `requestMirror` entry carries nothing else: one doing more at once
    // is not a filter the spec describes.
    if filter.request_mirror.is_some() {
        return filter.request_redirect.is_none()
            && filter.request_header_modifier.is_none()
            && filter.response_header_modifier.is_none()
            && filter.url_rewrite.is_none();
    }
    // A `urlRewrite` must carry something we recognise (a path mode and/or a
    // hostname). An empty rewrite block is a no-op we refuse, like an empty
    // filter entry — it signals an intent we can't see.
    if let Some(rw) = filter.url_rewrite.as_ref() {
        return url_rewrite_mapping(rw).is_some();
    }
    // Sōzu reads an empty header value as a delete: a `set` or `add` of one
    // cannot be represented.
    let request_values = filter.request_header_modifier.iter().flat_map(|m| {
        let set = m.set.iter().flatten().map(|h| h.value.as_str());
        set.chain(m.add.iter().flatten().map(|h| h.value.as_str()))
    });
    let response_values = filter.response_header_modifier.iter().flat_map(|m| {
        let set = m.set.iter().flatten().map(|h| h.value.as_str());
        set.chain(m.add.iter().flatten().map(|h| h.value.as_str()))
    });
    if request_values.chain(response_values).any(str::is_empty) {
        return false;
    }
    // A `requestRedirect` must be in a form we can map; an empty filter
    // entry (no variant populated) carries nothing we recognise and is
    // refused. Header modifiers are otherwise always mappable.
    match &filter.request_redirect {
        Some(rr) => redirect_from_redirect_filter(rr).is_some(),
        None => {
            filter.request_header_modifier.is_some() || filter.response_header_modifier.is_some()
        }
    }
}

/// The backendRefs a rule's `requestMirror` filters copy its requests to.
pub fn mirror_backend_refs(
    filters: &[HTTPRouteRulesFilters],
) -> Vec<&HTTPRouteRulesFiltersRequestMirrorBackendRef> {
    filters
        .iter()
        .filter_map(|f| f.request_mirror.as_ref())
        .map(|m| &m.backend_ref)
        .collect()
}

/// Map a header modifier's `set` / `add` / `remove` lists onto
/// [`HeaderConfig`] entries in the given direction.
///
/// - `set` → `HeaderConfig { name, value, direction }` (replace).
/// - `add` → the same, appended next to any header of the same name.
/// - `remove` → `HeaderConfig { name, value: "", direction }` (an empty
///   value deletes the header at the Sōzu frontend, HAProxy `del-header`
///   parity).
fn header_edits_from_modifier(
    set: Option<&[(String, String)]>,
    add: Option<&[(String, String)]>,
    remove: Option<&[String]>,
    direction: HeaderDirection,
    out: &mut Vec<HeaderConfig>,
) {
    for (list, append) in [(set, false), (add, true)] {
        for (name, value) in list.unwrap_or_default() {
            out.push(HeaderConfig {
                name: name.clone(),
                value: value.clone(),
                direction,
                append,
            });
        }
    }
    if let Some(remove) = remove {
        for name in remove {
            out.push(HeaderConfig {
                name: name.clone(),
                value: String::new(),
                direction,
                append: false,
            });
        }
    }
}

/// Extract the combined request + response header edits a rule's filters
/// describe, as [`HeaderConfig`] entries applied natively by Sōzu at the
/// frontend. Returns an empty Vec when no header modifier is present.
///
/// `requestHeaderModifier` entries map to [`HeaderDirection::Request`],
/// `responseHeaderModifier` to [`HeaderDirection::Response`]. See
/// [`header_edits_from_modifier`] for the per-list semantics.
pub fn header_edits_from_filters(filters: &[HTTPRouteRulesFilters]) -> Vec<HeaderConfig> {
    let mut out = Vec::new();
    for filter in filters {
        if let Some(m) = filter.request_header_modifier.as_ref() {
            push_request_header_edits(m, &mut out);
        }
        if let Some(m) = filter.response_header_modifier.as_ref() {
            push_response_header_edits(m, &mut out);
        }
    }
    // Filters apply in order: a set or remove replaces what earlier edits did
    // to the header. Sōzu applies every delete before any insert, so the
    // earlier edits go rather than stack up.
    let mut folded: Vec<HeaderConfig> = Vec::with_capacity(out.len());
    for edit in out {
        if !edit.append {
            folded.retain(|earlier| {
                !(earlier.direction == edit.direction
                    && earlier.name.eq_ignore_ascii_case(&edit.name))
            });
        }
        folded.push(edit);
    }
    folded
}

fn push_request_header_edits(
    m: &HTTPRouteRulesFiltersRequestHeaderModifier,
    out: &mut Vec<HeaderConfig>,
) {
    let set: Option<Vec<(String, String)>> = m.set.as_ref().map(|s| {
        s.iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    });
    let add: Option<Vec<(String, String)>> = m.add.as_ref().map(|s| {
        s.iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    });
    header_edits_from_modifier(
        set.as_deref(),
        add.as_deref(),
        m.remove.as_deref(),
        HeaderDirection::Request,
        out,
    );
}

fn push_response_header_edits(
    m: &HTTPRouteRulesFiltersResponseHeaderModifier,
    out: &mut Vec<HeaderConfig>,
) {
    let set: Option<Vec<(String, String)>> = m.set.as_ref().map(|s| {
        s.iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    });
    let add: Option<Vec<(String, String)>> = m.add.as_ref().map(|s| {
        s.iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    });
    header_edits_from_modifier(
        set.as_deref(),
        add.as_deref(),
        m.remove.as_deref(),
        HeaderDirection::Response,
        out,
    );
}

/// Extract the transparent URL rewrite a rule's filters describe, if any.
///
/// Returns `Some` for the first `urlRewrite` filter that carries a path mode
/// and/or a hostname. Returns `None` when the rule declares no `urlRewrite`
/// (the caller then leaves `EntrypointConfig.rewrite` unset). The unsupported
/// cases (empty rewrite, redirect+rewrite conflict) never reach here —
/// [`rule_filters_supported`] gates them first.
pub fn url_rewrite_from_filter(filters: &[HTTPRouteRulesFilters]) -> Option<UrlRewrite> {
    filters
        .iter()
        .find_map(|f| f.url_rewrite.as_ref())
        .and_then(url_rewrite_mapping)
}

/// Map a single `urlRewrite` filter onto a [`UrlRewrite`].
///
/// `None` means the filter is a no-op we can't act on (no path mode and no
/// hostname). A path's `ReplaceFullPath` / `ReplacePrefixMatch` carries its
/// replacement string; an empty path block (a `type` with neither field
/// populated) is treated as no path rewrite.
fn url_rewrite_mapping(rw: &HTTPRouteRulesFiltersUrlRewrite) -> Option<UrlRewrite> {
    let path = rw.path.as_ref().and_then(path_rewrite_mapping);
    let hostname = rw.hostname.clone();
    if path.is_none() && hostname.is_none() {
        return None;
    }
    Some(UrlRewrite { path, hostname })
}

fn path_rewrite_mapping(p: &HTTPRouteRulesFiltersUrlRewritePath) -> Option<PathRewrite> {
    match p.r#type {
        HTTPRouteRulesFiltersUrlRewritePathType::ReplaceFullPath => p
            .replace_full_path
            .clone()
            .map(PathRewrite::ReplaceFullPath),
        HTTPRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch => p
            .replace_prefix_match
            .clone()
            .map(PathRewrite::ReplacePrefixMatch),
    }
}

/// Extract the redirect mapping a rule's filters describe, if any.
///
/// Returns `Some` when the rule has exactly one `requestRedirect` filter
/// we can map. Returns `None` when the rule has no filters (the caller
/// routes normally) — and the unsupported case never reaches here
/// because [`rule_filters_supported`] gates it first.
pub fn redirect_from_filter(filters: &[HTTPRouteRulesFilters]) -> Option<RedirectMapping> {
    filters
        .iter()
        .find_map(|f| f.request_redirect.as_ref())
        .and_then(redirect_from_redirect_filter)
}

/// Map a single `requestRedirect` filter onto a [`RedirectMapping`].
///
/// `None` means "we can't faithfully represent this redirect", so the rule
/// is dropped rather than emitting a misleading `Location`: a status other
/// than `301` and `302`, or an empty path block.
fn redirect_from_redirect_filter(
    rr: &HTTPRouteRulesFiltersRequestRedirect,
) -> Option<RedirectMapping> {
    let scheme = match rr.scheme.as_ref() {
        Some(HTTPRouteRulesFiltersRequestRedirectScheme::Http) => Some(RedirectScheme::UseHttp),
        Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https) => Some(RedirectScheme::UseHttps),
        None => None,
    };

    // Gateway API core status values are 301 and 302.
    let policy = match rr.status_code {
        None | Some(301) => RedirectPolicy::Permanent,
        Some(302) => RedirectPolicy::Found,
        _ => return None,
    };

    // A full-path replacement is a literal target; a prefix replacement
    // keeps the rest of the path, as a urlRewrite does.
    let (path, prefix) = match rr.path.as_ref() {
        Some(p) => match (
            p.replace_full_path.as_deref(),
            p.replace_prefix_match.as_deref(),
        ) {
            (Some(full), _) => (Some(full.to_string()), None),
            (None, Some(prefix)) => (None, Some(prefix.to_string())),
            (None, None) => return None,
        },
        None => (None, None),
    };

    let port = match rr.port {
        Some(p) => Some(u16::try_from(p).ok()?),
        None => None,
    };

    Some(RedirectMapping {
        policy,
        scheme,
        host: rr.hostname.clone(),
        path,
        prefix,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesFiltersRequestRedirectPath, HTTPRouteRulesFiltersRequestRedirectPathType,
    };
    // `HTTPRouteRulesFiltersUrlRewrite*` come in via `super::*`.

    fn redirect_filter(
        scheme: Option<HTTPRouteRulesFiltersRequestRedirectScheme>,
        hostname: Option<&str>,
        port: Option<i32>,
        status_code: Option<i64>,
    ) -> HTTPRouteRulesFilters {
        HTTPRouteRulesFilters {
            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                hostname: hostname.map(String::from),
                path: None,
                port,
                scheme,
                status_code,
            }),
            request_header_modifier: None,
            response_header_modifier: None,
            request_mirror: None,
            url_rewrite: None,
            extension_ref: None,
            r#type: Default::default(),
        }
    }

    #[test]
    fn scheme_only_redirect_maps_to_permanent_use_https() {
        let f = vec![redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        )];
        assert!(rule_filters_supported(&f));
        let m = redirect_from_filter(&f).unwrap();
        assert_eq!(m.policy, RedirectPolicy::Permanent);
        assert_eq!(m.scheme, Some(RedirectScheme::UseHttps));
        assert_eq!(m.host, None);
        assert_eq!(m.path, None);
        assert_eq!(m.port, None);
    }

    #[test]
    fn hostname_and_port_map_to_rewrite_host_and_port() {
        let f = vec![redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            Some("new.example.com"),
            Some(8443),
            Some(301),
        )];
        let m = redirect_from_filter(&f).unwrap();
        assert_eq!(m.host.as_deref(), Some("new.example.com"));
        assert_eq!(m.port, Some(8443));
        assert_eq!(m.path, None);
    }

    #[test]
    fn replace_full_path_maps_to_rewrite_path() {
        let mut f = redirect_filter(None, None, None, None);
        f.request_redirect.as_mut().unwrap().path =
            Some(HTTPRouteRulesFiltersRequestRedirectPath {
                replace_full_path: Some("/new".into()),
                replace_prefix_match: None,
                r#type: HTTPRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath,
            });
        let filters = vec![f];
        assert!(rule_filters_supported(&filters));
        let m = redirect_from_filter(&filters).unwrap();
        assert_eq!(m.path.as_deref(), Some("/new"));
    }

    #[test]
    fn replace_prefix_match_keeps_the_rest_of_the_path() {
        let mut f = redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        f.request_redirect.as_mut().unwrap().path =
            Some(HTTPRouteRulesFiltersRequestRedirectPath {
                replace_full_path: None,
                replace_prefix_match: Some("/new".into()),
                r#type: HTTPRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch,
            });
        let filters = vec![f];
        assert!(rule_filters_supported(&filters));
        let m = redirect_from_filter(&filters).unwrap();
        assert_eq!(m.path, None);
        assert_eq!(m.prefix.as_deref(), Some("/new"));
    }

    #[test]
    fn status_302_is_a_temporary_redirect() {
        let f = vec![redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            Some(302),
        )];
        assert!(rule_filters_supported(&f));
        let mapping = redirect_from_filter(&f).expect("a redirect");
        assert_eq!(mapping.policy, RedirectPolicy::Found);
    }

    #[test]
    fn status_other_than_301_and_302_is_unsupported() {
        let f = vec![redirect_filter(None, None, None, Some(307))];
        assert!(!rule_filters_supported(&f));
    }

    fn url_rewrite_filter(rw: HTTPRouteRulesFiltersUrlRewrite) -> HTTPRouteRulesFilters {
        HTTPRouteRulesFilters {
            url_rewrite: Some(rw),
            ..Default::default()
        }
    }

    #[test]
    fn empty_url_rewrite_is_unsupported() {
        // A `urlRewrite` block with neither path nor hostname carries an
        // intent we can't see — refuse rather than route it as a no-op.
        let f = url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite::default());
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn url_rewrite_replace_full_path_is_supported() {
        let f = vec![url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HTTPRouteRulesFiltersUrlRewritePath {
                replace_full_path: Some("/new".into()),
                replace_prefix_match: None,
                r#type: HTTPRouteRulesFiltersUrlRewritePathType::ReplaceFullPath,
            }),
        })];
        assert!(rule_filters_supported(&f));
        let rw = url_rewrite_from_filter(&f).unwrap();
        assert_eq!(rw.path, Some(PathRewrite::ReplaceFullPath("/new".into())));
        assert_eq!(rw.hostname, None);
    }

    #[test]
    fn url_rewrite_replace_prefix_match_is_supported() {
        let f = vec![url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HTTPRouteRulesFiltersUrlRewritePath {
                replace_full_path: None,
                replace_prefix_match: Some("/v2".into()),
                r#type: HTTPRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
            }),
        })];
        assert!(rule_filters_supported(&f));
        let rw = url_rewrite_from_filter(&f).unwrap();
        assert_eq!(rw.path, Some(PathRewrite::ReplacePrefixMatch("/v2".into())));
    }

    #[test]
    fn url_rewrite_hostname_is_supported() {
        let f = vec![url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite {
            hostname: Some("internal.svc".into()),
            path: None,
        })];
        assert!(rule_filters_supported(&f));
        let rw = url_rewrite_from_filter(&f).unwrap();
        assert_eq!(rw.hostname.as_deref(), Some("internal.svc"));
        assert_eq!(rw.path, None);
    }

    #[test]
    fn redirect_combined_with_url_rewrite_is_unsupported() {
        // Conflicting intents over the same frontend rewrite — refuse.
        let redirect = redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        let rewrite = url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite {
            hostname: Some("internal.svc".into()),
            path: None,
        });
        assert!(!rule_filters_supported(&[redirect, rewrite]));
    }

    #[test]
    fn url_rewrite_mixed_with_header_modifier_is_supported() {
        let mut f = url_rewrite_filter(HTTPRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HTTPRouteRulesFiltersUrlRewritePath {
                replace_full_path: None,
                replace_prefix_match: Some("/v2".into()),
                r#type: HTTPRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
            }),
        });
        f.request_header_modifier = Some(HTTPRouteRulesFiltersRequestHeaderModifier {
            set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                name: "X-Env".into(),
                value: "prod".into(),
            }]),
            ..Default::default()
        });
        let filters = vec![f];
        assert!(rule_filters_supported(&filters));
        assert!(url_rewrite_from_filter(&filters).is_some());
        assert_eq!(header_edits_from_filters(&filters).len(), 1);
    }

    #[test]
    fn a_request_mirror_is_supported_alone_in_its_entry() {
        let mirror = HTTPRouteRulesFilters {
            request_mirror: Some(Default::default()),
            ..Default::default()
        };
        let headers = HTTPRouteRulesFilters {
            request_header_modifier: Some(HTTPRouteRulesFiltersRequestHeaderModifier {
                remove: Some(vec!["X-A".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(rule_filters_supported(&[mirror.clone(), headers]));
        assert_eq!(mirror_backend_refs(&[mirror]).len(), 1);
    }

    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesFiltersRequestHeaderModifier, HTTPRouteRulesFiltersRequestHeaderModifierAdd,
        HTTPRouteRulesFiltersRequestHeaderModifierSet, HTTPRouteRulesFiltersResponseHeaderModifier,
        HTTPRouteRulesFiltersResponseHeaderModifierSet,
    };

    fn req_header_filter(m: HTTPRouteRulesFiltersRequestHeaderModifier) -> HTTPRouteRulesFilters {
        HTTPRouteRulesFilters {
            request_header_modifier: Some(m),
            ..Default::default()
        }
    }

    fn resp_header_filter(m: HTTPRouteRulesFiltersResponseHeaderModifier) -> HTTPRouteRulesFilters {
        HTTPRouteRulesFilters {
            response_header_modifier: Some(m),
            ..Default::default()
        }
    }

    #[test]
    fn request_header_modifier_set_maps_to_request_direction_with_value() {
        let f = vec![req_header_filter(
            HTTPRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Env".into(),
                    value: "prod".into(),
                }]),
                ..Default::default()
            },
        )];
        assert!(rule_filters_supported(&f));
        let edits = header_edits_from_filters(&f);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].name, "X-Env");
        assert_eq!(edits[0].value, "prod");
        assert_eq!(edits[0].direction, HeaderDirection::Request);
    }

    #[test]
    fn request_header_modifier_remove_maps_to_empty_value() {
        let f = vec![req_header_filter(
            HTTPRouteRulesFiltersRequestHeaderModifier {
                remove: Some(vec!["X-Secret".into()]),
                ..Default::default()
            },
        )];
        assert!(rule_filters_supported(&f));
        let edits = header_edits_from_filters(&f);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].name, "X-Secret");
        assert_eq!(edits[0].value, "");
        assert_eq!(edits[0].direction, HeaderDirection::Request);
    }

    #[test]
    fn request_header_modifier_add_appends() {
        let f = vec![req_header_filter(
            HTTPRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierAdd {
                    name: "X-Trace".into(),
                    value: "on".into(),
                }]),
                ..Default::default()
            },
        )];
        assert!(rule_filters_supported(&f));
        let edits = header_edits_from_filters(&f);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].name, "X-Trace");
        assert_eq!(edits[0].value, "on");
        assert_eq!(edits[0].direction, HeaderDirection::Request);
        assert!(edits[0].append);
    }

    /// Header modifiers every backendRef of the rule carries apply to the
    /// rule; different ones, or another kind of filter, cannot be honoured.
    #[test]
    fn backend_ref_header_filters_apply_to_the_rule() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesBackendRefs, HTTPRouteRulesBackendRefsFilters,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet,
            HTTPRouteRulesBackendRefsFiltersRequestMirror,
        };
        let set = |value: &str| HTTPRouteRulesBackendRefsFilters {
            request_header_modifier: Some(HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier {
                set: Some(vec![
                    HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet {
                        name: "X-Header-Set".into(),
                        value: value.into(),
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let backend = |filters: Vec<HTTPRouteRulesBackendRefsFilters>| HTTPRouteRulesBackendRefs {
            name: "svc".into(),
            port: Some(80),
            filters: Some(filters),
            ..Default::default()
        };
        let rule = |refs: Vec<HTTPRouteRulesBackendRefs>| HTTPRouteRules {
            backend_refs: Some(refs),
            ..Default::default()
        };

        let filters =
            effective_rule_filters(&rule(vec![backend(vec![set("v")])]), &|_| true).unwrap();
        let edits = header_edits_from_filters(&filters);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].name, "X-Header-Set");
        assert_eq!(edits[0].value, "v");

        assert!(
            effective_rule_filters(
                &rule(vec![backend(vec![set("a")]), backend(vec![set("b")])]),
                &|_| true
            )
            .is_none()
        );
        let mirror = HTTPRouteRulesBackendRefsFilters {
            request_mirror: Some(HTTPRouteRulesBackendRefsFiltersRequestMirror::default()),
            ..Default::default()
        };
        assert!(effective_rule_filters(&rule(vec![backend(vec![mirror])]), &|_| true).is_none());

        // A redirect forwards nothing: its backends' filters are left alone.
        let mut redirect = rule(vec![backend(vec![set("a")]), backend(vec![set("b")])]);
        redirect.filters = Some(vec![redirect_filter(None, Some("example.org"), None, None)]);
        assert_eq!(
            effective_rule_filters(&redirect, &|_| true).unwrap().len(),
            1
        );
    }

    /// A later set of the same header replaces an earlier one instead of
    /// both reaching the backend.
    #[test]
    fn a_later_set_replaces_an_earlier_one() {
        let set = |value: &str| {
            req_header_filter(HTTPRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Env".into(),
                    value: value.into(),
                }]),
                ..Default::default()
            })
        };
        let edits = header_edits_from_filters(&[set("rule"), set("backend")]);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].value, "backend");
    }

    #[test]
    fn an_empty_header_value_to_set_or_add_is_unsupported() {
        let f = vec![req_header_filter(
            HTTPRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierAdd {
                    name: "X-Trace".into(),
                    value: String::new(),
                }]),
                ..Default::default()
            },
        )];
        assert!(!rule_filters_supported(&f));
    }

    #[test]
    fn response_header_modifier_set_maps_to_response_direction() {
        let f = vec![resp_header_filter(
            HTTPRouteRulesFiltersResponseHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersResponseHeaderModifierSet {
                    name: "X-Powered-By".into(),
                    value: "sozune".into(),
                }]),
                ..Default::default()
            },
        )];
        assert!(rule_filters_supported(&f));
        let edits = header_edits_from_filters(&f);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].direction, HeaderDirection::Response);
        assert_eq!(edits[0].value, "sozune");
    }

    #[test]
    fn redirect_mixed_with_header_modifier_is_supported() {
        // A rule may carry both a mappable requestRedirect and a header
        // modifier — both are honoured, neither drops the route.
        let mut f = redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        f.request_header_modifier = Some(HTTPRouteRulesFiltersRequestHeaderModifier {
            set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                name: "X-Env".into(),
                value: "prod".into(),
            }]),
            ..Default::default()
        });
        let filters = vec![f];
        assert!(rule_filters_supported(&filters));
        assert!(redirect_from_filter(&filters).is_some());
        let edits = header_edits_from_filters(&filters);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].direction, HeaderDirection::Request);
    }

    #[test]
    fn header_modifier_mixed_with_mirror_is_unsupported() {
        let f = HTTPRouteRulesFilters {
            request_header_modifier: Some(Default::default()),
            request_mirror: Some(Default::default()),
            ..Default::default()
        };
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn combined_request_and_response_modifiers_keep_both_directions() {
        let f = vec![
            req_header_filter(HTTPRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Req".into(),
                    value: "1".into(),
                }]),
                ..Default::default()
            }),
            resp_header_filter(HTTPRouteRulesFiltersResponseHeaderModifier {
                remove: Some(vec!["Server".into()]),
                ..Default::default()
            }),
        ];
        assert!(rule_filters_supported(&f));
        let edits = header_edits_from_filters(&f);
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].direction, HeaderDirection::Request);
        assert_eq!(edits[1].direction, HeaderDirection::Response);
        assert_eq!(edits[1].value, "");
    }
}
