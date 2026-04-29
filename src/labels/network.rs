use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};

const LOCALHOST_FALLBACK: &str = "127.0.0.1";

/// Resolve the backend IP for a candidate.
///
/// Order:
/// 1. If `sozune.network=<name>` is set, use the IP from that network.
/// 2. Otherwise the first network with a non-empty IP.
/// 3. Otherwise `127.0.0.1` with `W010`.
///
/// If a preferred network is requested but not attached, emits `W009` and
/// continues with the fallback.
pub fn resolve_ip(candidate: &Candidate, diagnostics: &mut Vec<Diagnostic>) -> String {
    let preferred = candidate.labels.get("sozune.network").cloned();

    if let Some(ref name) = preferred {
        match find_network(&candidate.networks, name) {
            Some(ip) => return ip,
            None => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W009NetworkNotFound,
                        format!("preferred network '{name}' not attached, falling back"),
                    )
                    .with_label("sozune.network")
                    .with_value(name)
                    .with_hint("ensure the container is attached to this network"),
                );
            }
        }
    }

    if let Some(ip) = first_available(&candidate.networks) {
        return ip;
    }

    diagnostics.push(
        Diagnostic::new(
            DiagnosticCode::W010NoIpFellBackToLocalhost,
            "no usable network IP found, using 127.0.0.1",
        )
        .with_hint("attach the container to a routable network"),
    );
    LOCALHOST_FALLBACK.to_string()
}

fn find_network(networks: &[NetworkInfo], name: &str) -> Option<String> {
    networks
        .iter()
        .find(|n| n.name == name)
        .and_then(|n| n.ip.clone())
        .filter(|ip| !ip.is_empty())
}

fn first_available(networks: &[NetworkInfo]) -> Option<String> {
    networks
        .iter()
        .filter_map(|n| n.ip.clone())
        .find(|ip| !ip.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn candidate(labels: &[(&str, &str)], networks: Vec<NetworkInfo>) -> Candidate {
        Candidate {
            provider: "test",
            id: "id".into(),
            display_name: "name".into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            networks,
            enabled_default: false,
        }
    }

    fn net(name: &str, ip: Option<&str>) -> NetworkInfo {
        NetworkInfo {
            name: name.to_string(),
            ip: ip.map(|s| s.to_string()),
        }
    }

    #[test]
    fn picks_preferred_network_when_present() {
        let mut diags = Vec::new();
        let c = candidate(
            &[("sozune.network", "internal")],
            vec![
                net("bridge", Some("172.18.0.2")),
                net("internal", Some("10.0.0.5")),
            ],
        );
        assert_eq!(resolve_ip(&c, &mut diags), "10.0.0.5");
        assert!(diags.is_empty());
    }

    #[test]
    fn missing_preferred_emits_w009_and_falls_back() {
        let mut diags = Vec::new();
        let c = candidate(
            &[("sozune.network", "missing")],
            vec![net("bridge", Some("172.18.0.2"))],
        );
        assert_eq!(resolve_ip(&c, &mut diags), "172.18.0.2");
        assert_eq!(diags[0].code, DiagnosticCode::W009NetworkNotFound);
    }

    #[test]
    fn first_network_used_without_preference() {
        let mut diags = Vec::new();
        let c = candidate(&[], vec![net("bridge", Some("172.18.0.2"))]);
        assert_eq!(resolve_ip(&c, &mut diags), "172.18.0.2");
        assert!(diags.is_empty());
    }

    #[test]
    fn empty_ip_skipped_falls_through() {
        let mut diags = Vec::new();
        let c = candidate(
            &[],
            vec![
                net("a", Some("")),
                net("b", None),
                net("c", Some("10.0.0.9")),
            ],
        );
        assert_eq!(resolve_ip(&c, &mut diags), "10.0.0.9");
    }

    #[test]
    fn no_networks_emits_w010_and_uses_localhost() {
        let mut diags = Vec::new();
        let c = candidate(&[], vec![]);
        assert_eq!(resolve_ip(&c, &mut diags), "127.0.0.1");
        assert_eq!(diags[0].code, DiagnosticCode::W010NoIpFellBackToLocalhost);
    }
}
