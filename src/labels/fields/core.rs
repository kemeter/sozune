use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{HealthCheckConfig, LoadBalancer, RetryConfig};
use std::collections::HashMap;

/// Parse a port label, falling back to the protocol default when absent or
/// non-numeric. Emits diagnostics describing the fallback so callers can
/// surface them.
///
/// `prefix` is `sozune.<protocol>.<service>.` (trailing dot included).
pub fn parse_port(
    labels: &HashMap<String, String>,
    prefix: &str,
    protocol: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> u16 {
    let key = format!("{prefix}port");
    let default = default_port_for(protocol);

    match labels.get(&key) {
        None => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::I002PortDefaulted,
                    format!("no port label, using protocol default ({default})"),
                )
                .with_label(&key),
            );
            default
        }
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W001InvalidPort,
                        format!("port is not a valid u16, falling back to {default}"),
                    )
                    .with_label(&key)
                    .with_value(raw)
                    .with_hint("port must be a positive integer between 0 and 65535"),
                );
                default
            }
        },
    }
}

fn default_port_for(protocol: &str) -> u16 {
    match protocol {
        "http" => 80,
        "https" => 443,
        _ => 8080,
    }
}

/// Parse the priority label. Defaults to 0 when absent. Non-numeric values
/// emit `W002` and also fall back to 0.
pub fn parse_priority(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> i32 {
    let key = format!("{prefix}priority");
    match labels.get(&key) {
        None => 0,
        Some(raw) => match raw.parse::<i32>() {
            Ok(p) => p,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W002InvalidPriority,
                        "priority is not a valid integer, defaulting to 0",
                    )
                    .with_label(&key)
                    .with_value(raw),
                );
                0
            }
        },
    }
}

/// Parse the backendTimeout label (milliseconds). Returns `None` when absent
/// or invalid; non-numeric values emit `W003`.
pub fn parse_backend_timeout(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let key = format!("{prefix}backendTimeout");
    let raw = labels.get(&key)?;
    match raw.parse::<u64>() {
        Ok(t) => Some(t),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W003InvalidTimeout,
                    "backendTimeout is not a valid integer, no timeout applied",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected milliseconds as a positive integer"),
            );
            None
        }
    }
}

/// Parse a boolean label. Treats `"true"` (case-sensitive) as true, anything
/// else as false. No diagnostic — matches existing `map_or(false, |v| v == "true")`
/// semantics.
pub fn parse_bool(labels: &HashMap<String, String>, key: &str) -> bool {
    labels.get(key).is_some_and(|v| v == "true")
}

/// Parse the HTTP health-check labels:
///
/// - `<prefix>healthCheck.path` — when present and non-empty, enables the HTTP
///   probe. A leading `/` is added if missing.
/// - `<prefix>healthCheck.status` — optional exact status code; `None` accepts
///   any 2xx/3xx. An invalid value emits `W021` and is dropped (the check stays
///   on the 2xx/3xx default rather than being disabled).
///
/// Returns `None` when no `healthCheck.path` is set — the backend keeps the
/// plain TCP probe.
pub fn parse_health_check(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<HealthCheckConfig> {
    let path_key = format!("{prefix}healthCheck.path");
    let raw_path = labels
        .get(&path_key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;
    let path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };

    let status_key = format!("{prefix}healthCheck.status");
    let status = match labels.get(&status_key).map(|s| s.trim()) {
        None | Some("") => None,
        Some(raw) => match raw.parse::<u16>() {
            Ok(code) if (100..=599).contains(&code) => Some(code),
            _ => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W021InvalidHealthCheck,
                        "healthCheck.status is not a valid HTTP status code; falling back to the 2xx/3xx default",
                    )
                    .with_label(&status_key)
                    .with_value(raw)
                    .with_hint("expected an integer between 100 and 599, e.g. 200"),
                );
                None
            }
        },
    };

    let timeout_key = format!("{prefix}healthCheck.timeout");
    let timeout_ms = match labels.get(&timeout_key).map(|s| s.trim()) {
        None | Some("") => None,
        Some(raw) => match raw.parse::<u64>() {
            Ok(ms) if ms > 0 => Some(ms),
            _ => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W021InvalidHealthCheck,
                        "healthCheck.timeout is not a positive integer; falling back to the default timeout",
                    )
                    .with_label(&timeout_key)
                    .with_value(raw)
                    .with_hint("expected milliseconds as a positive integer, e.g. 2000"),
                );
                None
            }
        },
    };

    Some(HealthCheckConfig {
        path,
        status,
        timeout_ms,
    })
}

/// Parse the `<prefix>loadBalancer` label into a [`LoadBalancer`]. Accepts
/// `round_robin`/`roundrobin`, `random`, `power_of_two`/`poweroftwo`,
/// `least_connections`/`leastconn`/`leastconnections` (case-insensitive,
/// hyphens/underscores ignored). Absent → default (round-robin). An
/// unrecognised value emits `W022` and falls back to round-robin.
pub fn parse_load_balancer(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> LoadBalancer {
    let key = format!("{prefix}loadBalancer");
    let Some(raw) = labels.get(&key).map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return LoadBalancer::default();
    };
    // Normalise: lowercase, drop `-`/`_` so `least-conn` == `least_conn`.
    let norm: String = raw
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .collect();
    match norm.as_str() {
        "roundrobin" | "rr" => LoadBalancer::RoundRobin,
        "random" => LoadBalancer::Random,
        "poweroftwo" | "p2c" => LoadBalancer::PowerOfTwo,
        "leastconnections" | "leastconn" | "leastconnection" | "leastloaded" => {
            LoadBalancer::LeastConnections
        }
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W022InvalidLoadBalancer,
                    "loadBalancer is not a recognised algorithm; falling back to round_robin",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("one of: round_robin, random, power_of_two, least_connections"),
            );
            LoadBalancer::default()
        }
    }
}

/// Parse the `<prefix>retry.attempts` label into a [`RetryConfig`]. The value
/// is the total number of attempts (first try + retries). Absent, `<= 1`, or
/// invalid → `None` (no retry); an invalid value emits `W023`.
pub fn parse_retry(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RetryConfig> {
    let key = format!("{prefix}retry.attempts");
    let raw = labels
        .get(&key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;
    match raw.parse::<u32>() {
        // 0 or 1 attempt means "no retry" — nothing to configure.
        Ok(attempts) if attempts <= 1 => None,
        Ok(attempts) => Some(RetryConfig { attempts }),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W023InvalidRetry,
                    "retry.attempts is not a valid positive integer; retries disabled",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected the total number of attempts as an integer >= 2, e.g. 3"),
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn returns_explicit_port_when_valid() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "8080")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 8080);
        assert!(diags.is_empty());
    }

    #[test]
    fn missing_port_emits_i002_and_uses_http_default() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.http.web.", "http", &mut diags);
        assert_eq!(port, 80);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::I002PortDefaulted);
    }

    #[test]
    fn missing_port_uses_https_default() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.https.web.", "https", &mut diags);
        assert_eq!(port, 443);
    }

    #[test]
    fn missing_port_uses_8080_for_unknown_protocol() {
        let mut diags = Vec::new();
        let port = parse_port(&labels(&[]), "sozune.tcp.db.", "tcp", &mut diags);
        assert_eq!(port, 8080);
    }

    #[test]
    fn non_numeric_port_emits_w001_and_falls_back() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "abc")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 80);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W001InvalidPort);
        assert_eq!(diags[0].label.as_deref(), Some("sozune.http.web.port"));
        assert_eq!(diags[0].value.as_deref(), Some("abc"));
        assert!(diags[0].hint.is_some());
    }

    #[test]
    fn out_of_range_port_emits_w001() {
        let mut diags = Vec::new();
        let port = parse_port(
            &labels(&[("sozune.http.web.port", "99999")]),
            "sozune.http.web.",
            "http",
            &mut diags,
        );
        assert_eq!(port, 80);
        assert_eq!(diags[0].code, DiagnosticCode::W001InvalidPort);
    }

    #[test]
    fn priority_defaults_to_zero_when_absent() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_priority(&labels(&[]), "sozune.http.web.", &mut diags),
            0
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn priority_parses_valid_int() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_priority(
                &labels(&[("sozune.http.web.priority", "10")]),
                "sozune.http.web.",
                &mut diags,
            ),
            10,
        );
    }

    #[test]
    fn priority_invalid_emits_w002() {
        let mut diags = Vec::new();
        let p = parse_priority(
            &labels(&[("sozune.http.web.priority", "high")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p, 0);
        assert_eq!(diags[0].code, DiagnosticCode::W002InvalidPriority);
    }

    #[test]
    fn timeout_returns_none_when_absent() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_backend_timeout(&labels(&[]), "sozune.http.web.", &mut diags),
            None,
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn timeout_parses_valid_value() {
        let mut diags = Vec::new();
        assert_eq!(
            parse_backend_timeout(
                &labels(&[("sozune.http.web.backendTimeout", "5000")]),
                "sozune.http.web.",
                &mut diags,
            ),
            Some(5000),
        );
    }

    #[test]
    fn timeout_invalid_emits_w003() {
        let mut diags = Vec::new();
        let t = parse_backend_timeout(
            &labels(&[("sozune.http.web.backendTimeout", "soon")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(t, None);
        assert_eq!(diags[0].code, DiagnosticCode::W003InvalidTimeout);
    }

    #[test]
    fn bool_true_only_for_literal_true() {
        let l = labels(&[("a", "true"), ("b", "True"), ("c", "1"), ("d", "false")]);
        assert!(parse_bool(&l, "a"));
        assert!(!parse_bool(&l, "b"));
        assert!(!parse_bool(&l, "c"));
        assert!(!parse_bool(&l, "d"));
        assert!(!parse_bool(&l, "missing"));
    }

    #[test]
    fn health_check_absent_yields_none() {
        let mut d = Vec::new();
        assert!(parse_health_check(&labels(&[]), "sozune.http.web.", &mut d).is_none());
        assert!(d.is_empty());
    }

    #[test]
    fn health_check_path_enables_with_defaults() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[("sozune.http.web.healthCheck.path", "/health")]),
            "sozune.http.web.",
            &mut d,
        )
        .expect("path enables the check");
        assert_eq!(hc.path, "/health");
        assert_eq!(hc.status, None);
        assert_eq!(hc.timeout_ms, None);
        assert!(d.is_empty());
    }

    #[test]
    fn health_check_path_gets_leading_slash() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[("sozune.http.web.healthCheck.path", "health")]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(hc.path, "/health");
    }

    #[test]
    fn health_check_parses_status_and_timeout() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.path", "/up"),
                ("sozune.http.web.healthCheck.status", "204"),
                ("sozune.http.web.healthCheck.timeout", "2000"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(hc.status, Some(204));
        assert_eq!(hc.timeout_ms, Some(2000));
        assert!(d.is_empty());
    }

    #[test]
    fn health_check_invalid_status_warns_and_defaults() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.path", "/health"),
                ("sozune.http.web.healthCheck.status", "999"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(hc.status, None);
        assert_eq!(d[0].code, DiagnosticCode::W021InvalidHealthCheck);
    }

    #[test]
    fn health_check_invalid_timeout_warns_and_defaults() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.path", "/health"),
                ("sozune.http.web.healthCheck.timeout", "nope"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(hc.timeout_ms, None);
        assert_eq!(d[0].code, DiagnosticCode::W021InvalidHealthCheck);
    }

    #[test]
    fn load_balancer_absent_defaults_to_round_robin() {
        let mut d = Vec::new();
        assert_eq!(
            parse_load_balancer(&labels(&[]), "sozune.http.web.", &mut d),
            LoadBalancer::RoundRobin
        );
        assert!(d.is_empty());
    }

    #[test]
    fn retry_absent_is_none() {
        let mut d = Vec::new();
        assert!(parse_retry(&labels(&[]), "sozune.http.web.", &mut d).is_none());
        assert!(d.is_empty());
    }

    #[test]
    fn load_balancer_parses_known_algorithms() {
        let cases = [
            ("round_robin", LoadBalancer::RoundRobin),
            ("random", LoadBalancer::Random),
            ("power_of_two", LoadBalancer::PowerOfTwo),
            ("least_connections", LoadBalancer::LeastConnections),
            // Aliases / casing / separators.
            ("leastconn", LoadBalancer::LeastConnections),
            ("Least-Connections", LoadBalancer::LeastConnections),
            ("POWEROFTWO", LoadBalancer::PowerOfTwo),
        ];
        for (raw, want) in cases {
            let mut d = Vec::new();
            let got = parse_load_balancer(
                &labels(&[("sozune.http.web.loadBalancer", raw)]),
                "sozune.http.web.",
                &mut d,
            );
            assert_eq!(got, want, "input {raw}");
            assert!(d.is_empty(), "input {raw} should not warn");
        }
    }

    #[test]
    fn load_balancer_unknown_warns_and_defaults() {
        let mut d = Vec::new();
        let got = parse_load_balancer(
            &labels(&[("sozune.http.web.loadBalancer", "magic")]),
            "sozune.http.web.",
            &mut d,
        );
        assert_eq!(got, LoadBalancer::RoundRobin);
        assert_eq!(d[0].code, DiagnosticCode::W022InvalidLoadBalancer);
    }

    #[test]
    fn retry_parses_attempts() {
        let mut d = Vec::new();
        let r = parse_retry(
            &labels(&[("sozune.http.web.retry.attempts", "3")]),
            "sozune.http.web.",
            &mut d,
        )
        .expect("3 attempts enables retry");
        assert_eq!(r.attempts, 3);
        assert!(d.is_empty());
    }

    #[test]
    fn retry_one_or_zero_is_no_retry() {
        let mut d = Vec::new();
        assert!(
            parse_retry(
                &labels(&[("sozune.http.web.retry.attempts", "1")]),
                "sozune.http.web.",
                &mut d
            )
            .is_none()
        );
        assert!(
            parse_retry(
                &labels(&[("sozune.http.web.retry.attempts", "0")]),
                "sozune.http.web.",
                &mut d
            )
            .is_none()
        );
        assert!(d.is_empty(), "1/0 are valid values, no warning");
    }

    #[test]
    fn retry_invalid_warns_and_disables() {
        let mut d = Vec::new();
        let r = parse_retry(
            &labels(&[("sozune.http.web.retry.attempts", "lots")]),
            "sozune.http.web.",
            &mut d,
        );
        assert!(r.is_none());
        assert_eq!(d[0].code, DiagnosticCode::W023InvalidRetry);
    }
}
