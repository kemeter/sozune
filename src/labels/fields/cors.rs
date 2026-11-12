//! A route's CORS policy from labels: `cors.*`, or the `headers.accessControl*`
//! options of Traefik's headers middleware, which mean the same.

use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::CorsConfig;
use std::collections::HashMap;

/// Traefik's names for each option, under `headers.`.
const ALLOW_ORIGINS: &str = "accessControlAllowOriginList";
const ALLOW_ORIGIN_REGEX: &str = "accessControlAllowOriginListRegex";
const ALLOW_METHODS: &str = "accessControlAllowMethods";
const ALLOW_HEADERS: &str = "accessControlAllowHeaders";
const EXPOSE_HEADERS: &str = "accessControlExposeHeaders";
const ALLOW_CREDENTIALS: &str = "accessControlAllowCredentials";
const MAX_AGE: &str = "accessControlMaxAge";
/// Traefik's switch for `Vary: Origin`, which Sōzune always sends.
const ADD_VARY: &str = "addVaryHeader";

/// Whether `name`, under `headers.`, is one of Traefik's CORS options
/// rather than a header to send.
pub fn is_traefik_option(name: &str) -> bool {
    [
        ALLOW_ORIGINS,
        ALLOW_ORIGIN_REGEX,
        ALLOW_METHODS,
        ALLOW_HEADERS,
        EXPOSE_HEADERS,
        ALLOW_CREDENTIALS,
        MAX_AGE,
        ADD_VARY,
    ]
    .iter()
    .any(|option| option.eq_ignore_ascii_case(name))
}

/// The value of option `native` under `cors.`, or else of Traefik's
/// `traefik` under `headers.` (its name compared without case), with the
/// label it came from.
fn option<'a>(
    labels: &'a HashMap<String, String>,
    prefix: &str,
    native: &str,
    traefik: &str,
) -> Option<(String, &'a str)> {
    let key = format!("{prefix}cors.{native}");
    if let Some(value) = labels.get(&key) {
        return Some((key, value.as_str()));
    }
    let headers = format!("{prefix}headers.");
    labels.iter().find_map(|(key, value)| {
        key.strip_prefix(&headers)
            .filter(|name| name.eq_ignore_ascii_case(traefik))
            .map(|_| (key.clone(), value.as_str()))
    })
}

/// A comma list, its entries trimmed, the empty ones left out.
fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

fn invalid(key: &str, value: &str, message: String, hint: &str) -> Diagnostic {
    Diagnostic::new(DiagnosticCode::W036InvalidCors, message)
        .with_label(key)
        .with_value(value)
        .with_hint(hint)
}

/// Parse the route's CORS policy: `cors.allowOrigins`, `cors.allowMethods`,
/// `cors.allowHeaders`, `cors.exposeHeaders` (comma lists, `*` for any),
/// `cors.allowCredentials` and `cors.maxAge` (seconds), or their Traefik
/// `headers.accessControl*` names. `None` when none is set, or when the
/// policy allows no origin (`W036`).
pub fn parse_cors(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<CorsConfig> {
    let origins = option(labels, prefix, "allowOrigins", ALLOW_ORIGINS);
    let methods = option(labels, prefix, "allowMethods", ALLOW_METHODS);
    let headers = option(labels, prefix, "allowHeaders", ALLOW_HEADERS);
    let exposed = option(labels, prefix, "exposeHeaders", EXPOSE_HEADERS);
    let credentials = option(labels, prefix, "allowCredentials", ALLOW_CREDENTIALS);
    let max_age = option(labels, prefix, "maxAge", MAX_AGE);
    let regex = option(labels, prefix, "allowOriginsRegex", ALLOW_ORIGIN_REGEX);

    if let Some((key, value)) = &regex {
        diagnostics.push(invalid(
            key,
            value,
            "origin regexes are not supported, dropped".to_string(),
            "list the origins in cors.allowOrigins; a host starting with `*.` stands for the names below it",
        ));
    }
    let set = [
        &origins,
        &methods,
        &headers,
        &exposed,
        &credentials,
        &max_age,
    ]
    .iter()
    .any(|o| o.is_some());
    if !set {
        return None;
    }

    let mut allow_origins = Vec::new();
    if let Some((key, value)) = &origins {
        for origin in list(value) {
            if crate::middleware::cors::is_origin(&origin) {
                allow_origins.push(origin);
            } else {
                diagnostics.push(invalid(
                    key,
                    &origin,
                    format!("'{origin}' is not an origin, dropped"),
                    "an origin is `scheme://host[:port]`, `*`, or `https://*.example.com`",
                ));
            }
        }
    }
    if allow_origins.is_empty() {
        let (key, value) = origins.unwrap_or_else(|| (format!("{prefix}cors.allowOrigins"), ""));
        diagnostics.push(invalid(
            &key,
            value,
            "the CORS policy allows no origin, dropped".to_string(),
            "set cors.allowOrigins to the origins pages call from",
        ));
        return None;
    }

    let allow_credentials = match &credentials {
        None => false,
        Some((_, value)) if value.trim().eq_ignore_ascii_case("true") => true,
        Some((_, value)) if value.trim().eq_ignore_ascii_case("false") => false,
        Some((key, value)) => {
            diagnostics.push(invalid(
                key,
                value,
                "allowCredentials is neither true nor false, credentials not allowed".to_string(),
                "use true or false",
            ));
            false
        }
    };
    let max_age = match &max_age {
        None => None,
        Some((key, value)) => match value.trim().parse::<u32>() {
            Ok(seconds) => Some(seconds),
            Err(_) => {
                diagnostics.push(invalid(
                    key,
                    value,
                    "maxAge is not a number of seconds, the default (5) applies".to_string(),
                    "give the seconds a browser may cache a preflight answer",
                ));
                None
            }
        },
    };
    let entries = |o: &Option<(String, &str)>| o.as_ref().map(|(_, v)| list(v)).unwrap_or_default();
    Some(CorsConfig {
        allow_origins,
        allow_methods: entries(&methods),
        allow_headers: entries(&headers),
        expose_headers: entries(&exposed),
        allow_credentials,
        max_age,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (format!("sozune.http.api.{k}"), v.to_string()))
            .collect()
    }

    fn parse(pairs: &[(&str, &str)]) -> (Option<CorsConfig>, Vec<Diagnostic>) {
        let mut diagnostics = Vec::new();
        let cors = parse_cors(&labels(pairs), "sozune.http.api.", &mut diagnostics);
        (cors, diagnostics)
    }

    #[test]
    fn the_cors_labels_make_a_policy() {
        let (cors, diagnostics) = parse(&[
            (
                "cors.allowOrigins",
                "https://app.example, https://*.example.org",
            ),
            ("cors.allowMethods", "GET,POST"),
            ("cors.allowHeaders", "x-request-id"),
            ("cors.exposeHeaders", "x-total-count"),
            ("cors.allowCredentials", "true"),
            ("cors.maxAge", "3600"),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cors.unwrap(),
            CorsConfig {
                allow_origins: vec!["https://app.example".into(), "https://*.example.org".into()],
                allow_methods: vec!["GET".into(), "POST".into()],
                allow_headers: vec!["x-request-id".into()],
                expose_headers: vec!["x-total-count".into()],
                allow_credentials: true,
                max_age: Some(3600),
            }
        );
    }

    /// Traefik's names, among its headers, mean the same.
    #[test]
    fn the_traefik_names_make_the_same_policy() {
        let (cors, diagnostics) = parse(&[
            (
                "headers.accessControlAllowOriginList",
                "https://app.example",
            ),
            ("headers.accesscontrolallowmethods", "GET"),
            ("headers.accessControlAllowHeaders", "*"),
            ("headers.accessControlExposeHeaders", "x-total-count"),
            ("headers.accessControlAllowCredentials", "true"),
            ("headers.accessControlMaxAge", "100"),
            ("headers.addVaryHeader", "true"),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let cors = cors.unwrap();
        assert_eq!(cors.allow_origins, ["https://app.example"]);
        assert_eq!(cors.allow_methods, ["GET"]);
        assert_eq!(cors.allow_headers, ["*"]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, Some(100));
    }

    #[test]
    fn no_cors_label_is_no_policy() {
        let (cors, diagnostics) = parse(&[("headers.X-Frame-Options", "DENY")]);
        assert!(cors.is_none());
        assert!(diagnostics.is_empty());
    }

    /// A value that is not an origin is dropped; with none left, the
    /// policy goes.
    #[test]
    fn a_policy_needs_an_origin() {
        let (cors, diagnostics) =
            parse(&[("cors.allowOrigins", "app.example, https://ok.example")]);
        assert_eq!(cors.unwrap().allow_origins, ["https://ok.example"]);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::W036InvalidCors);

        let (cors, diagnostics) = parse(&[("cors.allowMethods", "GET")]);
        assert!(cors.is_none());
        assert_eq!(diagnostics[0].code, DiagnosticCode::W036InvalidCors);
    }

    #[test]
    fn bad_values_are_reported() {
        let (cors, diagnostics) = parse(&[
            ("cors.allowOrigins", "*"),
            ("cors.allowCredentials", "yes"),
            ("cors.maxAge", "an hour"),
            ("headers.accessControlAllowOriginListRegex", ".*"),
        ]);
        let cors = cors.unwrap();
        assert!(!cors.allow_credentials);
        assert_eq!(cors.max_age, None);
        assert_eq!(diagnostics.len(), 3, "{diagnostics:?}");
        assert!(
            diagnostics
                .iter()
                .all(|d| d.code == DiagnosticCode::W036InvalidCors)
        );
    }

    #[test]
    fn the_traefik_options_are_not_headers() {
        assert!(is_traefik_option("accessControlAllowOriginList"));
        assert!(is_traefik_option("ACCESSCONTROLMAXAGE"));
        assert!(is_traefik_option("addVaryHeader"));
        assert!(!is_traefik_option("X-Frame-Options"));
    }
}
