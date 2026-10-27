//! Middleware on an Ingress, from its `sozune.*` annotations.
//!
//! An Ingress has no field for auth, rate limits, headers and the like. Its
//! annotations carry them, with the keys of a Service annotation minus the
//! `http.<service>` part: `sozune.auth.basic` on an Ingress is
//! `sozune.http.<service>.auth.basic` on a Service. They are read by the same
//! parser, and apply to every route of the Ingress. The route itself — host,
//! path, TLS, backend — comes from the Ingress spec.

use crate::labels::Candidate;
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{Entrypoint, EntrypointConfig};
use k8s_openapi::api::networking::v1::Ingress;
use std::collections::HashMap;

/// The service name the annotations are parsed under.
const SERVICE: &str = "ingress";

/// Keys that make the route, which the Ingress spec decides instead.
const ROUTING: &[&str] = &[
    "host",
    "port",
    "path",
    "prefix",
    "pathRegex",
    "tls",
    "entrypoint",
    "sni",
    "weight",
];

/// What the `sozune.*` annotations of an Ingress give its routes.
#[derive(Debug, Clone)]
pub(super) struct IngressSettings {
    pub config: EntrypointConfig,
    /// False when the routes answer without reaching a backend (a
    /// `redirect` that is not `forward`): they then keep none.
    pub forwards: bool,
}

/// The settings the `sozune.*` annotations of `ing` give its routes, `None`
/// when it has none, and what the parser said about them.
pub(super) fn ingress_settings(
    ing: &Ingress,
    candidate_id: &str,
) -> (Option<IngressSettings>, Vec<Diagnostic>) {
    let prefix = format!("sozune.http.{SERVICE}.");
    let mut diagnostics = Vec::new();
    let mut labels: HashMap<String, String> = HashMap::new();
    for (key, value) in ing.metadata.annotations.iter().flatten() {
        let Some(field) = key.strip_prefix("sozune.") else {
            continue;
        };
        if ROUTING.contains(&field) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W013UnknownLabel,
                    format!("`{key}` is not used on an Ingress: its rules decide the route"),
                )
                .with_label(key.clone())
                .with_hint("set it in the Ingress spec instead"),
            );
            continue;
        }
        labels.insert(format!("{prefix}{field}"), value.clone());
    }
    if labels.is_empty() {
        return (None, diagnostics);
    }

    // What the parser needs to build a route, which the settings are taken
    // from: the Ingress's own route is built from its spec.
    labels.insert("sozune.enable".into(), "true".into());
    labels.insert(format!("{prefix}host"), "ingress.invalid".into());
    labels.insert(format!("{prefix}port"), "80".into());
    labels.insert(format!("{prefix}prefix"), "/".into());
    let candidate = Candidate {
        provider: super::PROVIDER_NAME,
        id: candidate_id.to_string(),
        display_name: candidate_id.to_string(),
        labels,
        networks: vec![crate::labels::candidate::NetworkInfo {
            name: "ingress".into(),
            ip: Some("127.0.0.1".into()),
        }],
        enabled_default: true,
        health: None,
    };
    let result = crate::labels::parse(&candidate);
    // The parsed route has no TLS: an HTTPS redirect is only a mistake when
    // a route of the Ingress has none either.
    let all_tls = every_route_has_tls(ing);
    let parsed = result
        .diagnostics
        .into_iter()
        .filter(|d| !(all_tls && d.code == DiagnosticCode::W016HttpsRedirectWithoutTls));
    // Name the annotations as they were written.
    let rename = |text: &str| text.replace(&prefix, "sozune.");
    diagnostics.extend(parsed.map(|mut d| {
        d.label = d.label.as_deref().map(rename);
        d.message = rename(&d.message);
        d.hint = d.hint.as_deref().map(rename);
        d
    }));
    let settings = result
        .entrypoints
        .into_values()
        .next()
        .map(|entrypoint| IngressSettings {
            forwards: !entrypoint.backends.is_empty(),
            config: entrypoint.config,
        });
    (settings, diagnostics)
}

/// Whether every route of the Ingress is served over TLS: each rule names a
/// host its `spec.tls` lists, and there is no `defaultBackend`, which has no
/// host to hold a certificate for.
fn every_route_has_tls(ing: &Ingress) -> bool {
    let Some(spec) = ing.spec.as_ref() else {
        return false;
    };
    let tls_hosts: Vec<&str> = spec
        .tls
        .iter()
        .flatten()
        .flat_map(|t| t.hosts.iter().flatten())
        .map(String::as_str)
        .collect();
    let rules = spec.rules.as_deref().unwrap_or_default();
    spec.default_backend.is_none()
        && !rules.is_empty()
        && rules
            .iter()
            .all(|r| r.host.as_deref().is_some_and(|h| tls_hosts.contains(&h)))
}

/// Apply the annotation `settings` to a route of the Ingress, keeping what
/// its spec decides: hostnames, path and TLS.
pub(super) fn apply_settings(entrypoint: &mut Entrypoint, settings: &IngressSettings) {
    let config = &mut entrypoint.config;
    let hostnames = std::mem::take(&mut config.hostnames);
    let path = config.path.take();
    let tls = config.tls;
    *config = EntrypointConfig {
        hostnames,
        path,
        tls,
        ..settings.config.clone()
    };
    if !settings.forwards {
        entrypoint.backends.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annotated(annotations: &[(&str, &str)]) -> Ingress {
        let mut ing = Ingress::default();
        ing.metadata.annotations = Some(
            annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        ing
    }

    #[test]
    fn an_ingress_without_sozune_annotations_has_no_settings() {
        let (settings, diagnostics) =
            ingress_settings(&annotated(&[("other.io/x", "1")]), "ingress:default/web");
        assert!(settings.is_none());
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn annotations_carry_middleware_settings() {
        let (settings, diagnostics) = ingress_settings(
            &annotated(&[
                ("sozune.compress", "true"),
                ("sozune.headers.X-Frame-Options", "DENY"),
                ("sozune.ratelimit.average", "10"),
            ]),
            "ingress:default/web",
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let settings = settings.unwrap();
        assert!(settings.forwards);
        assert!(settings.config.compress);
        assert_eq!(settings.config.headers[0].name, "X-Frame-Options");
        assert!(settings.config.rate_limit.is_some());
    }

    /// A regex condition annotation applies; one that does not compile is a
    /// blocking error, which the routes of the Ingress are dropped on.
    #[test]
    fn regex_annotations_are_conditions_or_errors() {
        let (settings, diagnostics) = ingress_settings(
            &annotated(&[("sozune.matchHeadersRegex.X-Version", "v[0-9]+")]),
            "ingress:default/web",
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let condition = &settings.unwrap().config.match_headers[0];
        assert!(condition.regex && condition.key == "X-Version");

        let (settings, diagnostics) = ingress_settings(
            &annotated(&[("sozune.matchHeadersRegex.X-Version", "v(")]),
            "ingress:default/web",
        );
        assert!(settings.is_none());
        let error = diagnostics
            .iter()
            .find(|d| d.code == DiagnosticCode::E007InvalidMatchRegex)
            .unwrap();
        assert_eq!(
            error.label.as_deref(),
            Some("sozune.matchHeadersRegex.X-Version")
        );
    }

    #[test]
    fn routing_annotations_are_reported_and_ignored() {
        let (settings, diagnostics) = ingress_settings(
            &annotated(&[
                ("sozune.host", "evil.example.com"),
                ("sozune.compress", "true"),
            ]),
            "ingress:default/web",
        );
        assert!(settings.unwrap().config.compress);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].label.as_deref(), Some("sozune.host"));
    }

    #[test]
    fn a_typo_is_reported_under_the_annotation_name() {
        let (_, diagnostics) = ingress_settings(
            &annotated(&[("sozune.compres", "true")]),
            "ingress:default/web",
        );
        let typo = diagnostics
            .iter()
            .find(|d| d.label.as_deref() == Some("sozune.compres"))
            .unwrap_or_else(|| panic!("{diagnostics:?}"));
        assert!(!typo.message.contains("http.ingress"), "{typo:?}");
        assert!(
            typo.hint
                .as_deref()
                .is_none_or(|h| !h.contains("http.ingress")),
            "{typo:?}"
        );
    }

    #[test]
    fn settings_keep_the_route_of_the_ingress() {
        let (settings, _) = ingress_settings(
            &annotated(&[("sozune.compress", "true")]),
            "ingress:default/web",
        );
        let settings = settings.unwrap();
        let mut entrypoint = Entrypoint {
            id: "ingress_default-web_r0p0".into(),
            name: "web".into(),
            backends: vec![crate::model::Backend::new("10.0.0.1", 80)],
            protocol: crate::model::Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec!["api.test".into()],
                tls: true,
                compress: false,
                ..settings.config.clone()
            },
            source: None,
            candidates: Vec::new(),
        };
        apply_settings(&mut entrypoint, &settings);
        assert_eq!(entrypoint.config.hostnames, ["api.test"]);
        assert!(entrypoint.config.tls);
        assert!(entrypoint.config.compress);
        assert_eq!(entrypoint.backends.len(), 1);
    }

    /// A route that only redirects reaches no backend, and keeps none.
    #[test]
    fn a_redirecting_ingress_keeps_no_backend() {
        let (settings, _) = ingress_settings(
            &annotated(&[("sozune.redirect", "close")]),
            "ingress:default/web",
        );
        assert!(!settings.unwrap().forwards);
    }

    /// An HTTPS redirect is only reported when the Ingress has no TLS.
    #[test]
    fn an_https_redirect_is_fine_on_a_tls_ingress() {
        let mut ing = annotated(&[("sozune.httpsRedirect", "true")]);
        let w016 = |ing: &Ingress| {
            ingress_settings(ing, "ingress:default/web")
                .1
                .iter()
                .any(|d| d.code == DiagnosticCode::W016HttpsRedirectWithoutTls)
        };
        use k8s_openapi::api::networking::v1::{IngressRule, IngressSpec, IngressTLS};
        assert!(w016(&ing));
        let rule = |host: &str| IngressRule {
            host: Some(host.into()),
            http: None,
        };
        ing.spec = Some(IngressSpec {
            tls: Some(vec![IngressTLS {
                hosts: Some(vec!["a.test".into()]),
                secret_name: None,
            }]),
            rules: Some(vec![rule("a.test")]),
            ..Default::default()
        });
        assert!(!w016(&ing));
        // A host without TLS is still redirected to HTTPS.
        ing.spec
            .as_mut()
            .unwrap()
            .rules
            .as_mut()
            .unwrap()
            .push(rule("b.test"));
        assert!(w016(&ing));
    }
}
