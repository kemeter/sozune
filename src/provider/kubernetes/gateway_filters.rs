//! Translation of Gateway API HTTPRoute filters into Sōzune's
//! `EntrypointConfig`.
//!
//! Only `requestRedirect` is handled today, and only the parts that map
//! onto Sōzu's native frontend redirect (scheme, hostname, port, status
//! code). Filters or sub-fields we can't honour faithfully cause the
//! whole rule to be refused upstream — routing as if they weren't there
//! would silently rewrite user intent. See [`redirect_from_filter`].

use crate::model::entrypoint::{RedirectPolicy, RedirectScheme};
use gateway_api::apis::standard::httproutes::{
    HTTPRouteRulesFilters, HTTPRouteRulesFiltersRequestRedirect,
    HTTPRouteRulesFiltersRequestRedirectScheme,
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
    pub port: Option<u16>,
}

/// Whether every filter on a rule is one we can faithfully execute.
///
/// Today that means: exactly the filters we support (`requestRedirect`,
/// and only in a form [`redirect_from_filter`] can map), and nothing
/// else. A rule mixing a supported filter with an unsupported one is
/// still refused — partial execution would misrepresent intent.
pub fn rule_filters_supported(filters: &[HTTPRouteRulesFilters]) -> bool {
    filters.iter().all(filter_supported)
}

fn filter_supported(filter: &HTTPRouteRulesFilters) -> bool {
    // A filter entry carries exactly one populated variant in practice.
    // Anything other than a mappable requestRedirect is unsupported.
    match &filter.request_redirect {
        Some(rr) => no_other_filter_set(filter) && redirect_from_redirect_filter(rr).is_some(),
        None => false,
    }
}

fn no_other_filter_set(filter: &HTTPRouteRulesFilters) -> bool {
    filter.request_header_modifier.is_none()
        && filter.response_header_modifier.is_none()
        && filter.request_mirror.is_none()
        && filter.url_rewrite.is_none()
        && filter.extension_ref.is_none()
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
/// is dropped rather than emitting a misleading `Location`. That's the case
/// for a `302` status (Sōzu has no temporary-redirect policy) and for a
/// `replacePrefixMatch` path rewrite (it must keep the request's trailing
/// segments, which needs a `$PATH[n]` capture defined at routing time —
/// Sōzune doesn't set one up for redirect rules).
fn redirect_from_redirect_filter(
    rr: &HTTPRouteRulesFiltersRequestRedirect,
) -> Option<RedirectMapping> {
    let scheme = match rr.scheme.as_ref() {
        Some(HTTPRouteRulesFiltersRequestRedirectScheme::Http) => Some(RedirectScheme::UseHttp),
        Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https) => Some(RedirectScheme::UseHttps),
        None => None,
    };

    // Gateway API core status values are 301 and 302. 301 maps to Sōzu's
    // `Permanent`; 302 (temporary) has no distinct frontend policy, so we
    // refuse rather than silently emit a 301.
    match rr.status_code {
        None | Some(301) => {}
        _ => return None,
    }

    let path = match rr.path.as_ref() {
        // A full-path replacement is a literal target — maps directly.
        Some(p) => match p.replace_full_path.as_deref() {
            Some(full) => Some(full.to_string()),
            // replacePrefixMatch (or an empty path block) can't be honoured.
            None => return None,
        },
        None => None,
    };

    let port = match rr.port {
        Some(p) => Some(u16::try_from(p).ok()?),
        None => None,
    };

    Some(RedirectMapping {
        policy: RedirectPolicy::Permanent,
        scheme,
        host: rr.hostname.clone(),
        path,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesFiltersRequestRedirectPath, HTTPRouteRulesFiltersRequestRedirectPathType,
    };

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
    fn replace_prefix_match_is_unsupported() {
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
        assert!(!rule_filters_supported(&filters));
    }

    #[test]
    fn status_302_is_unsupported() {
        let f = vec![redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            Some(302),
        )];
        assert!(!rule_filters_supported(&f));
    }

    #[test]
    fn header_modifier_is_unsupported() {
        let f = HTTPRouteRulesFilters {
            request_redirect: None,
            request_header_modifier: Some(Default::default()),
            response_header_modifier: None,
            request_mirror: None,
            url_rewrite: None,
            extension_ref: None,
            r#type: Default::default(),
        };
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn url_rewrite_is_unsupported() {
        let f = HTTPRouteRulesFilters {
            request_redirect: None,
            request_header_modifier: None,
            response_header_modifier: None,
            request_mirror: None,
            url_rewrite: Some(Default::default()),
            extension_ref: None,
            r#type: Default::default(),
        };
        assert!(!rule_filters_supported(&[f]));
    }

    #[test]
    fn redirect_mixed_with_header_modifier_is_unsupported() {
        let mut f = redirect_filter(
            Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
            None,
            None,
            None,
        );
        f.request_header_modifier = Some(Default::default());
        assert!(!rule_filters_supported(&[f]));
    }
}
