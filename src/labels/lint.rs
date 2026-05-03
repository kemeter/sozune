//! Post-parse lint pass over `Entrypoint`s. Catches semantically-questionable
//! but syntactically-valid configurations that would otherwise route silently.
//!
//! - per-entrypoint checks: `lint_entrypoint`
//! - cross-cutting checks (collisions, global state): `lint_collection`,
//!   `lint_acme`

use std::collections::HashMap;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Backend, EntrypointConfig, RateLimitConfig};

    fn ep(host: &str, path: Option<&str>, tls: bool, https_redirect: bool) -> Entrypoint {
        Entrypoint {
            id: "x".into(),
            backends: vec![Backend::new("10.0.0.1", 80)],
            name: "svc".into(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.into()],
                path: path.map(|p| crate::model::PathConfig {
                    rule_type: crate::model::PathRuleType::Prefix,
                    value: p.into(),
                }),
                tls,
                strip_prefix: false,
                https_redirect,
                https_redirect_port: None,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                rate_limit: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                methods: Vec::new(),
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
}
