use std::collections::{HashMap, HashSet};

use crate::labels::candidate::Candidate;
use crate::labels::catalog;
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode, ParseResult};
use crate::labels::fields::{
    auth, core, error_pages, forward_auth, headers, host, in_flight_req, ip_allow_list, methods,
    path, plugins, ratelimit, redirect, request_match,
};
use crate::labels::network;
use crate::model::{Backend, Entrypoint, EntrypointConfig, Protocol};

const SUPPORTED_PROTOCOLS: &[&str] = &["http", "tcp", "udp"];

pub fn parse(candidate: &Candidate) -> ParseResult {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    if !is_enabled(candidate) {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::E001Disabled,
                "this workload has no `sozune.enable=true` label, so sozune ignores it",
            )
            .with_label("sozune.enable")
            .with_hint(
                "add the label `sozune.enable=true` to opt this workload in, or set `expose_by_default: true` in the provider config to opt every workload in by default",
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
                "this workload is enabled but does not declare any service to expose",
            )
            .with_hint("add at least one label of the form `sozune.http.<service-name>.host=<your-domain>` (or `sozune.tcp.<service-name>.entrypoint=<listener>` for raw TCP)"),
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
            crate::labels::lint::lint_entrypoint(&entrypoint, &mut diagnostics);
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
    // TCP and UDP are L4: no hostname, just a named listener + backends.
    if protocol == "tcp" {
        return build_l4_entrypoint(
            labels,
            "tcp",
            Protocol::Tcp,
            service_name,
            backend_ip,
            diagnostics,
        );
    }
    if protocol == "udp" {
        return build_l4_entrypoint(
            labels,
            "udp",
            Protocol::Udp,
            service_name,
            backend_ip,
            diagnostics,
        );
    }

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
    let add_prefix = labels
        .get(&format!("{prefix}addPrefix"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let https_redirect = core::parse_bool(labels, &format!("{prefix}httpsRedirect"));
    let https_redirect_port = redirect::parse_https_redirect_port(labels, &prefix, diagnostics);
    let redirect = redirect::parse_redirect_policy(labels, &prefix, diagnostics);
    let redirect_scheme = redirect::parse_redirect_scheme(labels, &prefix, diagnostics);
    let redirect_template = labels.get(&format!("{prefix}redirectTemplate")).cloned();
    let www_authenticate = labels.get(&format!("{prefix}wwwAuthenticate")).cloned();
    let priority = core::parse_priority(labels, &prefix, diagnostics);
    let backend_timeout = core::parse_backend_timeout(labels, &prefix, diagnostics);
    let health_check = core::parse_health_check(labels, &prefix, diagnostics);
    // HTTP has no flow key, so hrw/maglev are not honored here (W022).
    let load_balancer = core::parse_load_balancer(labels, &prefix, false, diagnostics);
    let retry = core::parse_retry(labels, &prefix, diagnostics);
    let circuit_breaker = core::parse_circuit_breaker(labels, &prefix, diagnostics);
    let rate_limit = ratelimit::parse_rate_limit(labels, &prefix, diagnostics);
    let in_flight_req = in_flight_req::parse_in_flight_req(labels, &prefix, diagnostics);
    let sticky_session = core::parse_bool(labels, &format!("{prefix}stickySession"));
    let compress = core::parse_bool(labels, &format!("{prefix}compress"));
    let auth = auth::parse_auth(labels, &prefix, diagnostics);
    let forward_auth = forward_auth::parse_forward_auth(labels, &prefix, diagnostics);
    let headers = headers::parse_headers(labels, &prefix, diagnostics);
    let methods = methods::parse_methods(labels, &prefix, diagnostics);
    let plugins = plugins::parse_plugins(labels, &prefix);
    let parsed_error_pages = error_pages::parse_error_pages(labels, &prefix, diagnostics);
    let match_headers = request_match::parse_match_headers(labels, &prefix);
    let match_query = request_match::parse_match_query(labels, &prefix);
    let match_client_ip = request_match::parse_match_client_ip(labels, &prefix);
    let ip_allow_list = ip_allow_list::parse_ip_allow_list(labels, &prefix);

    let protocol_enum = match protocol {
        "http" => Protocol::Http,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };

    Some(Entrypoint {
        id: format!("{protocol}_{service_name}"),
        backends: vec![Backend::new(backend_ip, port)],
        name: service_name.to_string(),
        protocol: protocol_enum,
        config: EntrypointConfig {
            hostnames,
            path,
            tls,
            strip_prefix,
            add_prefix,
            https_redirect,
            https_redirect_port,
            redirect,
            redirect_scheme,
            redirect_template,
            rewrite_host: None,
            rewrite_path: None,
            rewrite: None,
            rewrite_port: None,
            www_authenticate,
            priority,
            auth,
            forward_auth,
            headers,
            backend_timeout,
            health_check,
            load_balancer,
            retry,
            circuit_breaker,
            rate_limit,
            in_flight_req,
            sticky_session,
            compress,
            entrypoint: None,
            methods,
            acme: None,
            plugins,
            error_pages: parsed_error_pages,
            match_headers,
            match_query,
            match_client_ip,
            ip_allow_list,
        },
        source: None,
    })
}

/// Build an L4 (TCP or UDP) entrypoint from labels. Both protocols share the
/// same shape — a named listener reference plus backends, no hostname/path — so
/// they go through one builder parameterized by `proto` (the label segment,
/// `"tcp"` / `"udp"`) and `protocol` (the model enum).
fn build_l4_entrypoint(
    labels: &HashMap<String, String>,
    proto: &str,
    protocol: Protocol,
    service_name: &str,
    backend_ip: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Entrypoint> {
    let prefix = format!("sozune.{proto}.{service_name}.");
    let entrypoint_key = format!("{prefix}entrypoint");

    let entrypoint_ref = match labels.get(&entrypoint_key) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::E005MissingL4Entrypoint,
                    format!("{} service requires an entrypoint reference", proto.to_uppercase()),
                )
                .with_label(&entrypoint_key)
                .with_hint(format!(
                    "set `sozune.{proto}.<name>.entrypoint=<listener-name>` matching a listener declared in `proxy.{proto}`",
                )),
            );
            return None;
        }
    };

    // UDP is a datagram protocol with no sensible default port (the HTTP 8080
    // fallback is meaningless for DNS/syslog/NTP/…), so require it explicitly and
    // drop the route when absent rather than binding the backend to a dead port.
    if proto == "udp" {
        let port_key = format!("{prefix}port");
        if !labels.contains_key(&port_key) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::E006MissingUdpPort,
                    "UDP service requires an explicit port",
                )
                .with_label(&port_key)
                .with_hint(format!(
                    "set `sozune.udp.{service_name}.port=<backend-port>` (no default applies to datagram services)",
                )),
            );
            return None;
        }
    }

    let port = core::parse_port(labels, &prefix, proto, diagnostics);
    let priority = core::parse_priority(labels, &prefix, diagnostics);
    // Flow-affine algorithms (hrw/maglev) are only honored for UDP.
    let load_balancer = core::parse_load_balancer(labels, &prefix, proto == "udp", diagnostics);

    Some(Entrypoint {
        id: format!("{proto}_{service_name}"),
        backends: vec![Backend::new(backend_ip, port)],
        name: service_name.to_string(),
        protocol,
        config: EntrypointConfig {
            hostnames: Vec::new(),
            path: None,
            tls: false,
            strip_prefix: false,
            add_prefix: None,
            https_redirect: false,
            https_redirect_port: None,
            redirect: None,
            redirect_scheme: None,
            redirect_template: None,
            rewrite_host: None,
            rewrite_path: None,
            rewrite: None,
            rewrite_port: None,
            www_authenticate: None,
            priority,
            auth: None,
            forward_auth: None,
            headers: Vec::new(),
            backend_timeout: None,
            health_check: None,
            load_balancer,
            retry: None,
            circuit_breaker: None,
            rate_limit: None,
            in_flight_req: None,
            sticky_session: false,
            compress: false,
            entrypoint: Some(entrypoint_ref),
            methods: Vec::new(),
            acme: None,
            plugins: Vec::new(),
            error_pages: std::collections::BTreeMap::new(),
            match_headers: Vec::new(),
            match_query: Vec::new(),
            match_client_ip: Vec::new(),
            ip_allow_list: Vec::new(),
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
            health: None,
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
        assert_eq!(ep.backends, vec![Backend::new("172.18.0.4", 8080)]);
        assert_eq!(ep.config.hostnames, vec!["example.com"]);
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
        assert_eq!(r.entrypoints.get("http_web").unwrap().backends[0].port, 80);
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
            vec![Backend::new("127.0.0.1", 80)]
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
                ("sozune.tcp.db.entrypoint", "postgres"),
                ("sozune.tcp.db.port", "5432"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 3);
        assert_eq!(
            r.entrypoints.get("http_api").unwrap().backends[0].port,
            9000
        );
        let tcp = r.entrypoints.get("tcp_db").unwrap();
        assert!(matches!(tcp.protocol, Protocol::Tcp));
        assert_eq!(tcp.config.entrypoint.as_deref(), Some("postgres"));
        assert_eq!(tcp.backends[0].port, 5432);
    }

    #[test]
    fn tcp_without_entrypoint_label_is_dropped_with_e005() {
        let c = candidate(
            &[("sozune.enable", "true"), ("sozune.tcp.db.port", "5432")],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E005MissingL4Entrypoint));
    }

    #[test]
    fn udp_service_needs_no_host_and_routes_as_l4() {
        // A UDP service is L4 like TCP: no `host` label required (no E002), just
        // a listener reference and a port.
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.udp.dns.entrypoint", "dnslistener"),
                ("sozune.udp.dns.port", "53"),
            ],
            vec![net("bridge", "10.0.0.7")],
        );
        let r = parse(&c);
        let udp = r.entrypoints.get("udp_dns").unwrap();
        assert!(matches!(udp.protocol, Protocol::Udp));
        assert_eq!(udp.config.entrypoint.as_deref(), Some("dnslistener"));
        assert_eq!(udp.backends[0].port, 53);
        assert!(udp.config.hostnames.is_empty());
        assert!(!has_code(&r, DiagnosticCode::E002MissingHost));
    }

    #[test]
    fn udp_without_entrypoint_label_is_dropped_with_e005() {
        let c = candidate(
            &[("sozune.enable", "true"), ("sozune.udp.dns.port", "53")],
            vec![net("bridge", "10.0.0.7")],
        );
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E005MissingL4Entrypoint));
    }

    #[test]
    fn udp_without_port_label_is_dropped_with_e006() {
        // Unlike TCP, a UDP service has no sensible default port, so a missing
        // `port` label drops the route (E006) instead of binding to 8080.
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.udp.dns.entrypoint", "dnslistener"),
            ],
            vec![net("bridge", "10.0.0.7")],
        );
        let r = parse(&c);
        assert!(r.entrypoints.is_empty());
        assert!(has_code(&r, DiagnosticCode::E006MissingUdpPort));
    }

    #[test]
    fn tcp_without_port_label_still_defaults() {
        // TCP keeps its existing 8080 fallback — only UDP requires an explicit
        // port. A TCP service with just an entrypoint reference still routes.
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.tcp.db.entrypoint", "dblistener"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        let tcp = r.entrypoints.get("tcp_db").unwrap();
        assert_eq!(tcp.backends[0].port, 8080);
        assert!(!has_code(&r, DiagnosticCode::E006MissingUdpPort));
    }

    #[test]
    fn ip_allow_list_label_is_threaded_into_config() {
        // End-to-end: a `ipAllowList` label on the candidate must surface in
        // the resulting EntrypointConfig.ip_allow_list. A regression here is
        // what breaks the e2e suite without breaking any unit test below it.
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.api.host", "api.example.com"),
                ("sozune.http.api.ipAllowList", "10.0.0.0/8, 192.168.1.5"),
            ],
            vec![net("bridge", "172.18.0.4")],
        );
        let r = parse(&c);
        let ep = r.entrypoints.get("http_api").expect("http_api emitted");
        assert_eq!(
            ep.config.ip_allow_list,
            vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()]
        );
    }

    #[test]
    fn match_client_ip_label_is_threaded_into_config() {
        // End-to-end: a `matchClientIP` label must surface in
        // EntrypointConfig.match_client_ip. This is the routing matcher (404),
        // distinct from the ipAllowList access filter (403) above.
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.api.host", "api.example.com"),
                ("sozune.http.api.matchClientIP", "10.0.0.0/8, 192.168.1.5"),
            ],
            vec![net("bridge", "172.18.0.4")],
        );
        let r = parse(&c);
        let ep = r.entrypoints.get("http_api").expect("http_api emitted");
        assert_eq!(
            ep.config.match_client_ip,
            vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()]
        );
    }

    #[test]
    fn tcp_happy_path_minimal() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.tcp.echo.entrypoint", "tcpecho"),
                ("sozune.tcp.echo.port", "9000"),
            ],
            vec![net("bridge", "172.18.0.4")],
        );
        let r = parse(&c);
        assert_eq!(r.entrypoints.len(), 1);
        let ep = r.entrypoints.get("tcp_echo").unwrap();
        assert!(matches!(ep.protocol, Protocol::Tcp));
        assert_eq!(ep.config.entrypoint.as_deref(), Some("tcpecho"));
        assert_eq!(ep.backends, vec![Backend::new("172.18.0.4", 9000)]);
        assert!(ep.config.hostnames.is_empty());
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
            vec![Backend::new("10.0.0.5", 80)]
        );
    }

    #[test]
    fn add_prefix_label_is_parsed() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "expats.example.com"),
                ("sozune.http.web.addPrefix", "/foo"),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        let ep = r.entrypoints.get("http_web").expect("entrypoint");
        assert_eq!(ep.config.add_prefix.as_deref(), Some("/foo"));
    }

    #[test]
    fn empty_add_prefix_label_is_treated_as_unset() {
        let c = candidate(
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "expats.example.com"),
                ("sozune.http.web.addPrefix", "  "),
            ],
            vec![net("bridge", "10.0.0.1")],
        );
        let r = parse(&c);
        let ep = r.entrypoints.get("http_web").expect("entrypoint");
        assert!(ep.config.add_prefix.is_none());
    }
}
