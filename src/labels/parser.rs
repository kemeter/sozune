use std::collections::{HashMap, HashSet};

use crate::labels::candidate::Candidate;
use crate::labels::catalog;
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode, ParseResult};
use crate::labels::fields::{auth, core, headers, host, path, ratelimit, redirect};
use crate::labels::network;
use crate::model::{Entrypoint, EntrypointConfig, Protocol};

const SUPPORTED_PROTOCOLS: &[&str] = &["http", "tcp", "udp"];

pub fn parse(candidate: &Candidate) -> ParseResult {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    if !is_enabled(candidate) {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::E001Disabled,
                "candidate is not enabled for sozune",
            )
            .with_label("sozune.enable")
            .with_hint(
                "set `sozune.enable=true` or set `expose_by_default: true` in the provider config",
            ),
        );
        return ParseResult {
            entrypoints: HashMap::new(),
            diagnostics,
        };
    }

    catalog::detect_unknown_labels(&candidate.labels, &mut diagnostics);

    let services = discover_services(&candidate.labels, &mut diagnostics);
    if services.is_empty() {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::E004NoServices,
                "candidate is enabled but declares no sozune.<protocol>.<service>.* labels",
            )
            .with_hint("add labels like `sozune.http.web.host=<your-domain>`"),
        );
        return ParseResult {
            entrypoints: HashMap::new(),
            diagnostics,
        };
    }

    let backend_ip = network::resolve_ip(candidate, &mut diagnostics);

    let mut entrypoints = HashMap::new();
    for (protocol, service_name) in services {
        if let Some(entrypoint) = build_entrypoint(
            &candidate.labels,
            &protocol,
            &service_name,
            &backend_ip,
            &mut diagnostics,
        ) {
            let key = format!("{protocol}_{service_name}");
            entrypoints.insert(key, entrypoint);
        }
    }

    ParseResult {
        entrypoints,
        diagnostics,
    }
}

fn is_enabled(candidate: &Candidate) -> bool {
    candidate
        .labels
        .get("sozune.enable")
        .map_or(candidate.enabled_default, |v| v == "true")
}

/// Walk all labels and collect distinct (protocol, service_name) pairs.
/// Unknown protocols (anything other than http/tcp/udp) emit `W012` and are
/// skipped.
fn discover_services(
    labels: &HashMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<(String, String)> {
    let mut services: HashSet<(String, String)> = HashSet::new();
    let mut unknown_protocols: HashSet<String> = HashSet::new();

    for key in labels.keys() {
        let Some(rest) = key.strip_prefix("sozune.") else {
            continue;
        };
        // Skip global labels that aren't service labels.
        if matches!(rest, "enable" | "network") {
            continue;
        }
        let mut parts = rest.splitn(3, '.');
        let Some(protocol) = parts.next() else {
            continue;
        };
        let Some(service) = parts.next() else {
            continue;
        };
        if parts.next().is_none() {
            // No third segment means this isn't a service label.
            continue;
        }

        if !SUPPORTED_PROTOCOLS.contains(&protocol) {
            unknown_protocols.insert(protocol.to_string());
            continue;
        }
        services.insert((protocol.to_string(), service.to_string()));
    }

    for proto in unknown_protocols {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::W012InvalidProtocol,
                format!("unsupported protocol '{proto}', labels ignored"),
            )
            .with_value(&proto)
            .with_hint(format!(
                "supported protocols: {}",
                SUPPORTED_PROTOCOLS.join(", ")
            )),
        );
    }

    let mut sorted: Vec<_> = services.into_iter().collect();
    sorted.sort();
    sorted
}

fn build_entrypoint(
    labels: &HashMap<String, String>,
    protocol: &str,
    service_name: &str,
    backend_ip: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Entrypoint> {
    let prefix = format!("sozune.{protocol}.{service_name}.");

    let hostnames = host::parse_hostnames(labels, &prefix, diagnostics)?;
    let port = core::parse_port(labels, &prefix, protocol, diagnostics);

    let path = if protocol == "http" {
        Some(path::parse_path(labels, &prefix, diagnostics))
    } else {
        None
    };

    let tls = core::parse_bool(labels, &format!("{prefix}tls"));
    let strip_prefix = core::parse_bool(labels, &format!("{prefix}stripPrefix"));
    let https_redirect = core::parse_bool(labels, &format!("{prefix}httpsRedirect"));
    let https_redirect_port = redirect::parse_https_redirect_port(labels, &prefix, diagnostics);
    let redirect = redirect::parse_redirect_policy(labels, &prefix, diagnostics);
    let redirect_scheme = redirect::parse_redirect_scheme(labels, &prefix, diagnostics);
    let redirect_template = labels.get(&format!("{prefix}redirectTemplate")).cloned();
    let www_authenticate = labels.get(&format!("{prefix}wwwAuthenticate")).cloned();
    let priority = core::parse_priority(labels, &prefix, diagnostics);
    let backend_timeout = core::parse_backend_timeout(labels, &prefix, diagnostics);
    let rate_limit = ratelimit::parse_rate_limit(labels, &prefix, diagnostics);
    let sticky_session = core::parse_bool(labels, &format!("{prefix}stickySession"));
    let compress = core::parse_bool(labels, &format!("{prefix}compress"));
    let auth = auth::parse_auth(labels, &prefix, diagnostics);
    let headers = headers::parse_headers(labels, &prefix, diagnostics);

    let protocol_enum = match protocol {
        "http" => Protocol::Http,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };

    Some(Entrypoint {
        id: format!("{protocol}_{service_name}"),
        backends: vec![backend_ip.to_string()],
        name: service_name.to_string(),
        protocol: protocol_enum,
        backend_weights: HashMap::new(),
        config: EntrypointConfig {
            hostnames,
            port,
            path,
            tls,
            strip_prefix,
            https_redirect,
            https_redirect_port,
            redirect,
            redirect_scheme,
            redirect_template,
            www_authenticate,
            priority,
            auth,
            headers,
            backend_timeout,
            rate_limit,
            sticky_session,
            compress,
        },
        source: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::candidate::NetworkInfo;

    fn candidate(labels: &[(&str, &str)], networks: Vec<NetworkInfo>) -> Candidate {
        Candidate {
            provider: "test",
            id: "container-1".into(),
            display_name: "test-container".into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            networks,
            enabled_default: false,
        }
    }

    fn net(name: &str, ip: &str) -> NetworkInfo {
        NetworkInfo {
            name: name.into(),
            ip: Some(ip.into()),
        }
    }

    fn has_code(result: &ParseResult, code: DiagnosticCode) -> bool {
        result.diagnostics.iter().any(|d| d.code == code)
    }

    #[test]
    fn disabled_candidate_returns_e001_and_no_entrypoints() {
        let c = candidate(&[], vec![]);
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E001Disabled));
    }

    #[test]
    fn explicit_disable_overrides_enabled_default() {
        let mut c = candidate(&[("sozune.enable", "false")], vec![]);
        c.enabled_default = true;
        let r = parse(&c);
        assert!(has_code(&r, DiagnosticCode::E001Disabled));
    }

    #[test]
    fn enabled_default_true_routes_without_label() {
        let mut c = candidate(
            &[("sozune.http.web.host", "example.com")],
            vec![net("bridge", "10.0.0.1")],
        );
        c.enabled_default = true;
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        assert!(!has_code(&r, DiagnosticCode::E001Disabled));
    }

    #[test]
    fn enabled_with_no_service_labels_emits_e004() {
        let c = candidate(&[("sozune.enable", "true")], vec![]);
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E004NoServices));
    }

    #[test]
    fn missing_host_emits_e002_and_drops_service() {
        let c = candidate(
            &[("sozune.enable", "true"), ("sozune.http.web.port", "8080")],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E002MissingHost));
    }

    #[test]
    fn happy_path_routes_with_no_diagnostics_above_info() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.port", "8080"),
                ("sozune.http.web.path", "/api"),
            ],
            vec![net("bridge", "172.18.0.4")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        assert!(!r.has_errors());
        let ep = r.entrypoints.get("http_web").unwrap();
        assert_eq!(ep.config.port, 8080);
        assert_eq!(ep.config.hostnames, vec!["example.com"]);
        assert_eq!(ep.backends, vec!["172.18.0.4"]);
    }

    #[test]
    fn invalid_port_falls_back_and_still_routes_with_w001() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.port", "abc"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        assert!(has_code(&r, DiagnosticCode::W001InvalidPort));
        assert_eq!(r.entrypoints.get("http_web").unwrap().config.port, 80);
    }

    #[test]
    fn unknown_label_emits_w013_but_does_not_block_routing() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.timeout", "5s"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        assert!(has_code(&r, DiagnosticCode::W013UnknownLabel));
    }

    #[test]
    fn unknown_protocol_emits_w012_and_is_skipped() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.ftp.legacy.host", "example.com"),
                ("sozune.http.web.host", "example.com"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        assert!(r.entrypoints.contains_key("http_web"));
        assert!(has_code(&r, DiagnosticCode::W012InvalidProtocol));
    }

    #[test]
    fn no_networks_falls_back_to_localhost_with_w010() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
            ],
            vec![],
        );
        let r = parse(&c);
        assert!(has_code(&r, DiagnosticCode::W010NoIpFellBackToLocalhost));
        assert_eq!(
            r.entrypoints.get("http_web").unwrap().backends,
            vec!["127.0.0.1"]
        );
    }

    #[test]
    fn multiple_services_per_candidate_each_routed() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "web.example.com"),
                ("sozune.http.api.host", "api.example.com"),
                ("sozune.http.api.port", "9000"),
                ("sozune.tcp.db.host", "db.example.com"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 3);
        assert_eq!(r.entrypoints.get("http_api").unwrap().config.port, 9000);
        assert!(matches!(
            r.entrypoints.get("tcp_db").unwrap().protocol,
            Protocol::Tcp
        ));
    }

    #[test]
    fn preferred_network_used_when_attached() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.network", "internal"),
                ("sozune.http.web.host", "example.com"),
            ],
            vec![net("bridge", "172.18.0.4"), net("internal", "10.0.0.5")],
        );
        let r = parse(&c);
        assert_eq!(
            r.entrypoints.get("http_web").unwrap().backends,
            vec!["10.0.0.5"]
        );
    }
}
