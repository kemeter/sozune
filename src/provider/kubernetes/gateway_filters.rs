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
    CorsConfig, HeaderConfig, HeaderDirection, MirrorFraction, PathRewrite, RedirectPolicy,
    RedirectScheme, UrlRewrite,
};
use gateway_api::apis::standard::httproutes::{
    HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteRulesFilters,
    HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestMirror,
    HttpRouteRulesFiltersRequestRedirect, HttpRouteRulesFiltersRequestRedirectScheme,
    HttpRouteRulesFiltersResponseHeaderModifier, HttpRouteRulesFiltersUrlRewrite,
    HttpRouteRulesFiltersUrlRewritePath, HttpRouteRulesFiltersUrlRewritePathType,
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
/// `responseHeaderModifier`, `urlRewrite` (see
/// [`url_rewrite_from_filter`]), `requestMirror` and `cors`. Header modifiers
/// freely mix with either a redirect or a rewrite. `requestRedirect` and
/// `urlRewrite` *conflict*, though — one redirects the client, the other
/// transparently rewrites the forwarded request, and both fight over Sōzu's
/// frontend `rewrite_path` — so a rule carrying both is refused. `extensionRef`
/// remains unsupported; a rule carrying it (alone or mixed) is refused, since
/// partial execution would misrepresent intent.
pub fn rule_filters_supported(filters: &[HttpRouteRulesFilters]) -> bool {
    let has_redirect = filters.iter().any(|f| f.request_redirect.is_some());
    let has_rewrite = filters.iter().any(|f| f.url_rewrite.is_some());
    if has_redirect && has_rewrite {
        // Conflicting intents over the same frontend rewrite — refuse.
        return false;
    }
    // One CORS policy per rule: a second would be silently dropped.
    if filters.iter().filter(|f| f.cors.is_some()).count() > 1 {
        return false;
    }
    filters.iter().all(filter_supported)
}

/// A rule's filters with those of its backendRefs, `None` when the latter
/// cannot be represented: header modifiers only. The backendRefs that can
/// take traffic (`usable`) carrying the same filters, theirs apply to the
/// whole rule, where Sōzu edits the headers; when they differ, each
/// backend's are left to the middleware, which edits what it sends that
/// backend (see [`backend_ref_header_edits`]).
pub fn effective_rule_filters(
    rule: &HttpRouteRules,
    usable: &dyn Fn(&HttpRouteRulesBackendRefs) -> bool,
) -> Option<Vec<HttpRouteRulesFilters>> {
    let mut filters = rule.filters.clone().unwrap_or_default();
    // A redirect forwards nothing: no backend filter runs.
    if filters.iter().any(|f| f.request_redirect.is_some()) {
        return Some(filters);
    }
    let backend_refs = usable_backend_refs(rule, usable);
    let per_ref = backend_refs
        .iter()
        .map(|b| backend_ref_filters(b))
        .collect::<Option<Vec<_>>>()?;
    if backend_refs_share_filters(rule, usable) {
        if let Some(shared) = per_ref.into_iter().next() {
            filters.extend(shared);
        }
    } else if !per_ref.iter().all(|f| rule_filters_supported(f)) {
        // Checked here, as they are not among the rule's.
        return None;
    }
    Some(filters)
}

/// Whether the backendRefs that can take traffic carry the same filters,
/// which then apply to the whole rule.
pub fn backend_refs_share_filters(
    rule: &HttpRouteRules,
    usable: &dyn Fn(&HttpRouteRulesBackendRefs) -> bool,
) -> bool {
    let backend_refs = usable_backend_refs(rule, usable);
    let Some(first) = backend_refs.first() else {
        return true;
    };
    let shared = first.filters.as_deref().unwrap_or_default();
    backend_refs
        .iter()
        .all(|b| b.filters.as_deref().unwrap_or_default() == shared)
}

/// The header edits of a backendRef's own filters, for the middleware to
/// make on what it sends that backend. Empty when one is not a header
/// modifier: such a rule is refused (see [`effective_rule_filters`]).
pub fn backend_ref_header_edits(backend: &HttpRouteRulesBackendRefs) -> Vec<HeaderConfig> {
    header_edits_from_filters(&backend_ref_filters(backend).unwrap_or_default())
}

fn usable_backend_refs<'a>(
    rule: &'a HttpRouteRules,
    usable: &dyn Fn(&HttpRouteRulesBackendRefs) -> bool,
) -> Vec<&'a HttpRouteRulesBackendRefs> {
    rule.backend_refs
        .iter()
        .flatten()
        .filter(|b| usable(b))
        .collect()
}

/// A backendRef's filters as rule filters, `None` when one is not a header
/// modifier.
fn backend_ref_filters(backend: &HttpRouteRulesBackendRefs) -> Option<Vec<HttpRouteRulesFilters>> {
    let mut filters = Vec::new();
    for filter in backend.filters.iter().flatten() {
        // Same schema as a rule filter: converted through its JSON form.
        let converted: HttpRouteRulesFilters =
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

fn filter_supported(filter: &HttpRouteRulesFilters) -> bool {
    // An entry carrying a still-unsupported variant fails outright.
    if filter.extension_ref.is_some() {
        return false;
    }
    // Nor is a `cors` entry carrying anything else.
    if filter.cors.is_some() {
        return filter.request_mirror.is_none()
            && filter.request_redirect.is_none()
            && filter.request_header_modifier.is_none()
            && filter.response_header_modifier.is_none()
            && filter.url_rewrite.is_none();
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

/// The CORS policy of a rule's `cors` filter, the first when it has several.
pub fn cors_from_filters(filters: &[HttpRouteRulesFilters]) -> Option<CorsConfig> {
    let cors = filters.iter().find_map(|f| f.cors.as_ref())?;
    Some(CorsConfig {
        allow_origins: cors.allow_origins.clone().unwrap_or_default(),
        allow_methods: cors.allow_methods.clone().unwrap_or_default(),
        allow_headers: cors.allow_headers.clone().unwrap_or_default(),
        expose_headers: cors.expose_headers.clone().unwrap_or_default(),
        allow_credentials: cors.allow_credentials.unwrap_or(false),
        max_age: cors.max_age.and_then(|age| u32::try_from(age).ok()),
    })
}

/// A rule's `requestMirror` filters.
pub fn request_mirrors(
    filters: &[HttpRouteRulesFilters],
) -> Vec<&HttpRouteRulesFiltersRequestMirror> {
    filters
        .iter()
        .filter_map(|f| f.request_mirror.as_ref())
        .collect()
}

/// The share of the requests a `requestMirror` copies, from its `percent`
/// or its `fraction` (out of `100` when it names no denominator); all of
/// them when it sets neither.
pub fn mirror_fraction(mirror: &HttpRouteRulesFiltersRequestMirror) -> Option<MirrorFraction> {
    let share = |numerator: i32, denominator: i32| {
        let denominator = u32::try_from(denominator).unwrap_or(0).max(1);
        MirrorFraction {
            numerator: u32::try_from(numerator).unwrap_or(0).min(denominator),
            denominator,
        }
    };
    if let Some(percent) = mirror.percent {
        return Some(share(percent, 100));
    }
    mirror
        .fraction
        .as_ref()
        .map(|f| share(f.numerator, f.denominator.unwrap_or(100)))
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
pub fn header_edits_from_filters(filters: &[HttpRouteRulesFilters]) -> Vec<HeaderConfig> {
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
    m: &HttpRouteRulesFiltersRequestHeaderModifier,
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
    m: &HttpRouteRulesFiltersResponseHeaderModifier,
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
pub fn url_rewrite_from_filter(filters: &[HttpRouteRulesFilters]) -> Option<UrlRewrite> {
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
fn url_rewrite_mapping(rw: &HttpRouteRulesFiltersUrlRewrite) -> Option<UrlRewrite> {
    let path = rw.path.as_ref().and_then(path_rewrite_mapping);
    let hostname = rw.hostname.clone();
    if path.is_none() && hostname.is_none() {
        return None;
    }
    Some(UrlRewrite { path, hostname })
}

fn path_rewrite_mapping(p: &HttpRouteRulesFiltersUrlRewritePath) -> Option<PathRewrite> {
    match p.r#type {
        HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath => p
            .replace_full_path
            .clone()
            .map(PathRewrite::ReplaceFullPath),
        HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch => p
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
pub fn redirect_from_filter(filters: &[HttpRouteRulesFilters]) -> Option<RedirectMapping> {
    filters
        .iter()
        .find_map(|f| f.request_redirect.as_ref())
        .and_then(redirect_from_redirect_filter)
}

/// Map a single `requestRedirect` filter onto a [`RedirectMapping`].
///
/// `None` means "we can't faithfully represent this redirect", so the rule
/// is dropped rather than emitting a misleading `Location`: a status other
/// than `301`, `302`, `303`, `307` and `308`, or an empty path block.
fn redirect_from_redirect_filter(
    rr: &HttpRouteRulesFiltersRequestRedirect,
) -> Option<RedirectMapping> {
    let scheme = match rr.scheme.as_ref() {
        Some(HttpRouteRulesFiltersRequestRedirectScheme::Http) => Some(RedirectScheme::UseHttp),
        Some(HttpRouteRulesFiltersRequestRedirectScheme::Https) => Some(RedirectScheme::UseHttps),
        None => None,
    };

    // Gateway API core status values are 301 and 302, 302 the default; 303,
    // 307 and 308 are extended.
    let policy = match rr.status_code {
        Some(301) => RedirectPolicy::Permanent,
        None | Some(302) => RedirectPolicy::Found,
        Some(303) => RedirectPolicy::SeeOther,
        Some(307) => RedirectPolicy::TemporaryRedirect,
        Some(308) => RedirectPolicy::PermanentRedirect,
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
        HttpRouteRulesFiltersRequestRedirectPath, HttpRouteRulesFiltersRequestRedirectPathType,
    };
    // `HTTPRouteRulesFiltersUrlRewrite*` come in via `super::*`.

    fn redirect_filter(
        scheme: Option<HttpRouteRulesFiltersRequestRedirectScheme>,
        hostname: Option<&str>,
        port: Option<i32>,
        status_code: Option<i64>,
    ) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                hostname: hostname.map(String::from),
                path: None,
                port,
                scheme,
                status_code,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn scheme_only_redirect_maps_to_found_use_https() {
        let f = vec![redirect_filter(
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        )];
        assert!(rule_filters_supported(&f));
        let m = redirect_from_filter(&f).unwrap();
        assert_eq!(m.policy, RedirectPolicy::Found);
        assert_eq!(m.scheme, Some(RedirectScheme::UseHttps));
        assert_eq!(m.host, None);
        assert_eq!(m.path, None);
        assert_eq!(m.port, None);
    }

    #[test]
    fn hostname_and_port_map_to_rewrite_host_and_port() {
        let f = vec![redirect_filter(
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
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
            Some(HttpRouteRulesFiltersRequestRedirectPath {
                replace_full_path: Some("/new".into()),
                replace_prefix_match: None,
                r#type: HttpRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath,
            });
        let filters = vec![f];
        assert!(rule_filters_supported(&filters));
        let m = redirect_from_filter(&filters).unwrap();
        assert_eq!(m.path.as_deref(), Some("/new"));
    }

    #[test]
    fn replace_prefix_match_keeps_the_rest_of_the_path() {
        let mut f = redirect_filter(
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        f.request_redirect.as_mut().unwrap().path =
            Some(HttpRouteRulesFiltersRequestRedirectPath {
                replace_full_path: None,
                replace_prefix_match: Some("/new".into()),
                r#type: HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch,
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
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            Some(302),
        )];
        assert!(rule_filters_supported(&f));
        let mapping = redirect_from_filter(&f).expect("a redirect");
        assert_eq!(mapping.policy, RedirectPolicy::Found);
    }

    #[test]
    fn extended_statuses_keep_their_code() {
        for (status, policy) in [
            (303, RedirectPolicy::SeeOther),
            (307, RedirectPolicy::TemporaryRedirect),
            (308, RedirectPolicy::PermanentRedirect),
        ] {
            let f = vec![redirect_filter(None, None, None, Some(status))];
            assert!(rule_filters_supported(&f));
            let mapping = redirect_from_filter(&f).expect("a redirect");
            assert_eq!(mapping.policy, policy);
        }
    }

    #[test]
    fn a_status_that_is_no_redirect_is_unsupported() {
        let f = vec![redirect_filter(None, None, None, Some(304))];
        assert!(!rule_filters_supported(&f));
    }

    fn url_rewrite_filter(rw: HttpRouteRulesFiltersUrlRewrite) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            url_rewrite: Some(rw),
            ..Default::default()
        }
    }

    #[test]
    fn empty_url_rewrite_is_unsupported() {
        // A `urlRewrite` block with neither path nor hostname carries an
        // intent we can't see — refuse rather than route it as a no-op.
        let f = url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite::default());
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn url_rewrite_replace_full_path_is_supported() {
        let f = vec![url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HttpRouteRulesFiltersUrlRewritePath {
                replace_full_path: Some("/new".into()),
                replace_prefix_match: None,
                r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath,
            }),
        })];
        assert!(rule_filters_supported(&f));
        let rw = url_rewrite_from_filter(&f).unwrap();
        assert_eq!(rw.path, Some(PathRewrite::ReplaceFullPath("/new".into())));
        assert_eq!(rw.hostname, None);
    }

    #[test]
    fn url_rewrite_replace_prefix_match_is_supported() {
        let f = vec![url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HttpRouteRulesFiltersUrlRewritePath {
                replace_full_path: None,
                replace_prefix_match: Some("/v2".into()),
                r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
            }),
        })];
        assert!(rule_filters_supported(&f));
        let rw = url_rewrite_from_filter(&f).unwrap();
        assert_eq!(rw.path, Some(PathRewrite::ReplacePrefixMatch("/v2".into())));
    }

    #[test]
    fn url_rewrite_hostname_is_supported() {
        let f = vec![url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite {
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
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        let rewrite = url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite {
            hostname: Some("internal.svc".into()),
            path: None,
        });
        assert!(!rule_filters_supported(&[redirect, rewrite]));
    }

    #[test]
    fn url_rewrite_mixed_with_header_modifier_is_supported() {
        let mut f = url_rewrite_filter(HttpRouteRulesFiltersUrlRewrite {
            hostname: None,
            path: Some(HttpRouteRulesFiltersUrlRewritePath {
                replace_full_path: None,
                replace_prefix_match: Some("/v2".into()),
                r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
            }),
        });
        f.request_header_modifier = Some(HttpRouteRulesFiltersRequestHeaderModifier {
            set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
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
        let mirror = HttpRouteRulesFilters {
            request_mirror: Some(Default::default()),
            ..Default::default()
        };
        let headers = HttpRouteRulesFilters {
            request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                remove: Some(vec!["X-A".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(rule_filters_supported(&[mirror.clone(), headers]));
        assert_eq!(request_mirrors(&[mirror]).len(), 1);
    }

    #[test]
    fn a_mirror_copies_its_percent_or_fraction() {
        use gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersRequestMirrorFraction;
        let share = |numerator, denominator| {
            Some(MirrorFraction {
                numerator,
                denominator,
            })
        };
        let mut mirror = HttpRouteRulesFiltersRequestMirror::default();
        assert_eq!(mirror_fraction(&mirror), None);
        mirror.percent = Some(20);
        assert_eq!(mirror_fraction(&mirror), share(20, 100));
        mirror.percent = Some(0);
        assert_eq!(mirror_fraction(&mirror), share(0, 100));
        mirror.percent = None;
        mirror.fraction = Some(HttpRouteRulesFiltersRequestMirrorFraction {
            numerator: 1,
            denominator: Some(3),
        });
        assert_eq!(mirror_fraction(&mirror), share(1, 3));
        mirror.fraction = Some(HttpRouteRulesFiltersRequestMirrorFraction {
            numerator: 25,
            denominator: None,
        });
        assert_eq!(mirror_fraction(&mirror), share(25, 100));
    }

    #[test]
    fn a_cors_filter_maps_onto_the_route_policy() {
        use gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersCors;
        let cors = HttpRouteRulesFilters {
            cors: Some(HttpRouteRulesFiltersCors {
                allow_origins: Some(vec!["https://*.bar.com".into()]),
                allow_methods: Some(vec!["GET".into()]),
                allow_credentials: Some(true),
                max_age: Some(3600),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(rule_filters_supported(std::slice::from_ref(&cors)));
        assert_eq!(
            cors_from_filters(std::slice::from_ref(&cors)),
            Some(CorsConfig {
                allow_origins: vec!["https://*.bar.com".into()],
                allow_methods: vec!["GET".into()],
                allow_credentials: true,
                max_age: Some(3600),
                ..Default::default()
            })
        );
        // A rule takes one policy.
        assert!(!rule_filters_supported(&[cors.clone(), cors.clone()]));
        // Nor does it carry another filter's settings.
        let mut both = cors;
        both.request_header_modifier = Some(Default::default());
        assert!(!rule_filters_supported(&[both]));
    }

    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesFiltersResponseHeaderModifier,
        HttpRouteRulesFiltersResponseHeaderModifierSet,
    };

    fn req_header_filter(m: HttpRouteRulesFiltersRequestHeaderModifier) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            request_header_modifier: Some(m),
            ..Default::default()
        }
    }

    fn resp_header_filter(m: HttpRouteRulesFiltersResponseHeaderModifier) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            response_header_modifier: Some(m),
            ..Default::default()
        }
    }

    #[test]
    fn request_header_modifier_set_maps_to_request_direction_with_value() {
        let f = vec![req_header_filter(
            HttpRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
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
            HttpRouteRulesFiltersRequestHeaderModifier {
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
            HttpRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
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
            HttpRouteRulesBackendRefs, HttpRouteRulesBackendRefsFilters,
            HttpRouteRulesBackendRefsFiltersRequestHeaderModifier,
            HttpRouteRulesBackendRefsFiltersRequestHeaderModifierSet,
            HttpRouteRulesBackendRefsFiltersRequestMirror,
        };
        let set = |value: &str| HttpRouteRulesBackendRefsFilters {
            request_header_modifier: Some(HttpRouteRulesBackendRefsFiltersRequestHeaderModifier {
                set: Some(vec![
                    HttpRouteRulesBackendRefsFiltersRequestHeaderModifierSet {
                        name: "X-Header-Set".into(),
                        value: value.into(),
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let backend = |filters: Vec<HttpRouteRulesBackendRefsFilters>| HttpRouteRulesBackendRefs {
            name: "svc".into(),
            port: Some(80),
            filters: Some(filters),
            ..Default::default()
        };
        let rule = |refs: Vec<HttpRouteRulesBackendRefs>| HttpRouteRules {
            backend_refs: Some(refs),
            ..Default::default()
        };

        let filters =
            effective_rule_filters(&rule(vec![backend(vec![set("v")])]), &|_| true).unwrap();
        let edits = header_edits_from_filters(&filters);
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].name, "X-Header-Set");
        assert_eq!(edits[0].value, "v");

        // Different filters stay with their backends.
        let split = rule(vec![backend(vec![set("a")]), backend(vec![set("b")])]);
        assert!(
            effective_rule_filters(&split, &|_| true)
                .unwrap()
                .is_empty()
        );
        assert!(!backend_refs_share_filters(&split, &|_| true));
        let edits = backend_ref_header_edits(&split.backend_refs.as_ref().unwrap()[1]);
        assert_eq!(edits[0].value, "b");
        // Checked as the rule's would be: an empty value is refused.
        let empty = rule(vec![backend(vec![set("a")]), backend(vec![set("")])]);
        assert!(effective_rule_filters(&empty, &|_| true).is_none());
        let mirror = HttpRouteRulesBackendRefsFilters {
            request_mirror: Some(HttpRouteRulesBackendRefsFiltersRequestMirror::default()),
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
            req_header_filter(HttpRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
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
            HttpRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
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
            HttpRouteRulesFiltersResponseHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierSet {
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
            Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        f.request_header_modifier = Some(HttpRouteRulesFiltersRequestHeaderModifier {
            set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
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
        let f = HttpRouteRulesFilters {
            request_header_modifier: Some(Default::default()),
            request_mirror: Some(Default::default()),
            ..Default::default()
        };
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn combined_request_and_response_modifiers_keep_both_directions() {
        let f = vec![
            req_header_filter(HttpRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Req".into(),
                    value: "1".into(),
                }]),
                ..Default::default()
            }),
            resp_header_filter(HttpRouteRulesFiltersResponseHeaderModifier {
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
