//! Post-parse lint pass over `Entrypoint`s. Catches semantically-questionable
//! but syntactically-valid configurations that would otherwise route silently.
//!
//! - per-entrypoint checks: `lint_entrypoint`
//! - cross-cutting checks (collisions, global state): `lint_collection`,
//!   `lint_acme_without_tls`, `lint_unknown_resolvers`

use std::collections::HashMap;

use crate::config::AcmeConfig;
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{Entrypoint, Protocol};

/// Run per-entrypoint lints. Called immediately after parsing one candidate.
pub fn lint_entrypoint(ep: &Entrypoint, diagnostics: &mut Vec<Diagnostic>) {
    if ep.config.https_redirect && !ep.config.tls {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W016HttpsRedirectWithoutTls,
                "https_redirect=true but tls=false; clients will be redirected to a port that has no TLS listener for this hostname",
            )
            .with_label("httpsRedirect")
            .with_hint("either set tls=true (and configure a certificate or ACME) or remove httpsRedirect"),
        );
    }

    if let Some(rl) = &ep.config.rate_limit
        && rl.burst < rl.average
    {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W017RateLimitBurstBelowAverage,
                format!(
                    "rate_limit.burst ({}) is lower than rate_limit.average ({}); the burst window is effectively disabled",
                    rl.burst, rl.average
                ),
            )
            .with_label("ratelimit.burst")
            .with_hint("burst should be >= average; a typical setup is burst = 2x average for short spikes"),
        );
    }
}

/// Run lints that need to look at the full set of routed entrypoints (e.g.
/// host+path collisions across services).
pub fn lint_collection(entrypoints: &[(&str, &Entrypoint)]) -> Vec<(String, Diagnostic)> {
    let mut out = Vec::new();
    let mut seen: HashMap<(String, String), Vec<&str>> = HashMap::new();

    for (cand_id, ep) in entrypoints {
        if !matches!(ep.protocol, Protocol::Http) {
            continue;
        }
        let path = ep
            .config
            .path
            .as_ref()
            .map(|p| p.value.clone())
            .unwrap_or_else(|| "/".into());
        for host in &ep.config.hostnames {
            seen.entry((host.clone(), path.clone()))
                .or_default()
                .push(cand_id);
        }
    }

    for ((host, path), candidates) in seen {
        if candidates.len() < 2 {
            continue;
        }
        let mut sorted = candidates.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() < 2 {
            continue;
        }
        for cand_id in &sorted {
            let others: Vec<&&str> = sorted.iter().filter(|c| *c != cand_id).collect();
            let others_str = others
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            out.push((
                cand_id.to_string(),
                Diagnostic::new(
                    DiagnosticCode::W018RouteCollision,
                    format!(
                        "route ({host}{path}) is also defined by: {others_str}; only the highest-priority candidate is reachable"
                    ),
                )
                .with_label("host+path")
                .with_value(format!("{host}{path}"))
                .with_hint("set distinct hostnames or paths, or use `priority` to make the precedence explicit"),
            ));
        }
    }

    out
}

/// Returns a diagnostic if ACME is enabled but no entrypoint actually requests TLS.
pub fn lint_acme_without_tls(
    acme_enabled: bool,
    entrypoints: &[&Entrypoint],
) -> Option<Diagnostic> {
    if !acme_enabled {
        return None;
    }
    let any_tls = entrypoints
        .iter()
        .any(|ep| matches!(ep.protocol, Protocol::Http) && ep.config.tls);
    if any_tls {
        return None;
    }
    Some(
        Diagnostic::new(
            DiagnosticCode::W015AcmeWithoutTls,
            "ACME is enabled in the configuration but no entrypoint declares tls=true; no certificates will ever be requested",
        )
        .with_hint("either disable ACME (acme.enabled=false) or set tls=true on at least one HTTP entrypoint"),
    )
}

/// Flag each TLS route whose `acme.resolver` names a resolver that
/// `acme.resolvers` does not declare. Only checked with ACME enabled: without
/// it, no certificate is ever ordered and the label has no effect. Neither does
/// it on a route whose hostnames are all covered by `file_names`, the names of
/// the certificates loaded from files: ACME orders nothing for them.
pub fn lint_unknown_resolvers(
    acme: Option<&AcmeConfig>,
    file_names: &[String],
    entrypoints: &[(&str, &Entrypoint)],
) -> Vec<(String, Diagnostic)> {
    let Some(acme) = acme.filter(|a| a.enabled) else {
        return Vec::new();
    };
    let mut declared: Vec<&str> = acme.resolvers.keys().map(String::as_str).collect();
    declared.sort_unstable();
    let hint = if declared.is_empty() {
        "declare it under acme.resolvers in config.yaml, or remove the label to use HTTP-01 on challenge_port".to_string()
    } else {
        format!(
            "use one of the declared resolvers ({}), or declare it under acme.resolvers",
            declared.join(", ")
        )
    };

    entrypoints
        .iter()
        .filter(|(_, ep)| ep.config.tls)
        .filter(|(_, ep)| {
            !ep.config
                .hostnames
                .iter()
                .all(|host| crate::manual_certs::covered(file_names, host))
        })
        .filter_map(|(id, ep)| {
            let name = &ep.config.acme.as_ref()?.resolver;
            if acme.resolvers.contains_key(name) {
                return None;
            }
            Some((
                id.to_string(),
                Diagnostic::new(
                    DiagnosticCode::W029UnknownAcmeResolver,
                    format!(
                        "acme.resolver `{name}` is not declared under acme.resolvers; a certificate ordered through it fails"
                    ),
                )
                .with_label("acme.resolver")
                .with_value(name.clone())
                .with_hint(hint.clone()),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolverConfig;
    use crate::model::{
        Backend, EntrypointAcmeConfig, EntrypointConfig, LoadBalancer, PathConfig, PathRuleType,
        RateLimitConfig,
    };

    fn ep(host: &str, path: Option<&str>, tls: bool, https_redirect: bool) -> Entrypoint {
        Entrypoint {
            id: "x".into(),
            backends: vec![Backend::new("10.0.0.1", 80)],
            name: "svc".into(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.into()],
                path: path.map(|p| PathConfig {
                    rule_type: PathRuleType::Prefix,
                    value: p.into(),
                }),
                tls,
                strip_prefix: false,
                add_prefix: None,
                https_redirect,
                https_redirect_port: None,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                rewrite_host: None,
                rewrite_path: None,
                rewrite: None,
                rewrite_port: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                health_check: None,
                load_balancer: LoadBalancer::default(),
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                sni: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: std::collections::BTreeMap::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                ip_allow_list: Vec::new(),
            },
            source: None,
        }
    }

    #[test]
    fn https_redirect_without_tls_emits_w016() {
        let ep = ep("example.com", None, false, true);
        let mut diags = Vec::new();
        lint_entrypoint(&ep, &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W016HttpsRedirectWithoutTls);
    }

    #[test]
    fn https_redirect_with_tls_is_silent() {
        let ep = ep("example.com", None, true, true);
        let mut diags = Vec::new();
        lint_entrypoint(&ep, &mut diags);
        assert!(diags.is_empty());
    }

    #[test]
    fn rate_limit_burst_below_average_emits_w017() {
        let mut ep = ep("example.com", None, false, false);
        ep.config.rate_limit = Some(RateLimitConfig {
            average: 100,
            burst: 50,
        });
        let mut diags = Vec::new();
        lint_entrypoint(&ep, &mut diags);
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].code,
            DiagnosticCode::W017RateLimitBurstBelowAverage
        );
    }

    #[test]
    fn rate_limit_burst_equal_or_above_is_silent() {
        let mut ep = ep("example.com", None, false, false);
        ep.config.rate_limit = Some(RateLimitConfig {
            average: 100,
            burst: 100,
        });
        let mut diags = Vec::new();
        lint_entrypoint(&ep, &mut diags);
        assert!(diags.is_empty());
    }

    #[test]
    fn collision_on_same_host_path_emits_w018_for_each_candidate() {
        let a = ep("example.com", Some("/api"), false, false);
        let b = ep("example.com", Some("/api"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|(_, d)| d.code == DiagnosticCode::W018RouteCollision)
        );
        let owners: Vec<&str> = out.iter().map(|(c, _)| c.as_str()).collect();
        assert!(owners.contains(&"cand-a"));
        assert!(owners.contains(&"cand-b"));
    }

    #[test]
    fn distinct_paths_do_not_collide() {
        let a = ep("example.com", Some("/api"), false, false);
        let b = ep("example.com", Some("/web"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert!(out.is_empty());
    }

    #[test]
    fn distinct_hosts_do_not_collide() {
        let a = ep("a.example.com", Some("/api"), false, false);
        let b = ep("b.example.com", Some("/api"), false, false);
        let pairs = vec![("cand-a", &a), ("cand-b", &b)];
        let out = lint_collection(&pairs);
        assert!(out.is_empty());
    }

    #[test]
    fn acme_without_any_tls_emits_w015() {
        let a = ep("example.com", None, false, false);
        let r = lint_acme_without_tls(true, &[&a]);
        assert!(r.is_some());
        assert_eq!(r.unwrap().code, DiagnosticCode::W015AcmeWithoutTls);
    }

    #[test]
    fn acme_disabled_is_silent() {
        let a = ep("example.com", None, false, false);
        assert!(lint_acme_without_tls(false, &[&a]).is_none());
    }

    #[test]
    fn acme_with_one_tls_endpoint_is_silent() {
        let a = ep("example.com", None, false, false);
        let b = ep("secure.example.com", None, true, false);
        assert!(lint_acme_without_tls(true, &[&a, &b]).is_none());
    }
    fn acme_with(resolvers: &[&str], enabled: bool) -> AcmeConfig {
        AcmeConfig {
            enabled,
            email: String::new(),
            certs_dir: String::from("/tmp"),
            staging: true,
            challenge_port: 80,
            tls_alpn_port: 3038,
            resolvers: resolvers
                .iter()
                .map(|name| (name.to_string(), ResolverConfig::Http01 { ca_server: None }))
                .collect(),
        }
    }

    fn with_resolver(mut ep: Entrypoint, resolver: &str) -> Entrypoint {
        ep.config.acme = Some(EntrypointAcmeConfig {
            resolver: resolver.into(),
        });
        ep
    }

    #[test]
    fn unknown_resolver_emits_w029_with_the_declared_ones() {
        let a = with_resolver(ep("example.com", None, true, false), "letsencrpyt");
        let acme = acme_with(&["letsencrypt", "cloudflare"], true);

        let out = lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "cand-a");
        assert_eq!(out[0].1.code, DiagnosticCode::W029UnknownAcmeResolver);
        let hint = out[0].1.hint.as_deref().unwrap();
        assert!(hint.contains("cloudflare, letsencrypt"), "{hint}");
    }

    #[test]
    fn declared_resolver_is_silent() {
        let a = with_resolver(ep("example.com", None, true, false), "letsencrypt");
        let acme = acme_with(&["letsencrypt"], true);
        assert!(lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]).is_empty());
    }

    #[test]
    fn unknown_resolver_is_ignored_without_acme_or_tls() {
        let tls = with_resolver(ep("example.com", None, true, false), "missing");
        let plain = with_resolver(ep("example.com", None, false, false), "missing");

        assert!(lint_unknown_resolvers(None, &[], &[("cand-a", &tls)]).is_empty());
        let disabled = acme_with(&[], false);
        assert!(lint_unknown_resolvers(Some(&disabled), &[], &[("cand-a", &tls)]).is_empty());
        let enabled = acme_with(&[], true);
        assert!(lint_unknown_resolvers(Some(&enabled), &[], &[("cand-a", &plain)]).is_empty());
    }

    #[test]
    fn route_served_by_a_file_certificate_is_silent() {
        let a = with_resolver(ep("app.example.com", None, true, false), "missing");
        let acme = acme_with(&[], true);
        let file_names = vec!["*.example.com".to_string()];

        assert!(lint_unknown_resolvers(Some(&acme), &file_names, &[("cand-a", &a)]).is_empty());
        let other = with_resolver(ep("app.example.org", None, true, false), "missing");
        assert_eq!(
            lint_unknown_resolvers(Some(&acme), &file_names, &[("cand-b", &other)]).len(),
            1
        );
    }

    #[test]
    fn route_without_resolver_is_silent() {
        let a = ep("example.com", None, true, false);
        let acme = acme_with(&[], true);
        assert!(lint_unknown_resolvers(Some(&acme), &[], &[("cand-a", &a)]).is_empty());
    }
}
