use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{
    CircuitBreakerConfig, EntrypointAcmeConfig, HealthCheckConfig, LoadBalancer, RetryConfig,
    SniRejection,
};
use std::collections::{BTreeMap, HashMap};

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
                    .with_hint("port must be an integer between 0 and 65535"),
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
///
/// `0` is accepted and means "no timeout": the request waits as long as the
/// backend takes. It is indistinguishable from a typo, so it is noted in the
/// log rather than left silent.
pub fn parse_backend_timeout(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let key = format!("{prefix}backendTimeout");
    let raw = labels.get(&key)?;
    match raw.parse::<u64>() {
        Ok(0) => {
            tracing::warn!(
                "{key}=0 disables the backend timeout: requests to this route wait indefinitely"
            );
            Some(0)
        }
        Ok(t) => Some(t),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W003InvalidTimeout,
                    "backendTimeout is not a valid integer, the default timeout (30s) applies",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint(
                    "expected milliseconds as a non-negative integer, 0 disables the timeout",
                ),
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

/// Parse `<prefix>acme.resolver`, the named ACME resolver that issues the
/// route's certificates. Absent or blank leaves the route on HTTP-01 through
/// `challenge_port`. Whether the name is declared is checked against the
/// configuration later (`W029`), since labels are parsed without it.
pub fn parse_acme(labels: &HashMap<String, String>, prefix: &str) -> Option<EntrypointAcmeConfig> {
    let resolver = labels.get(&format!("{prefix}acme.resolver"))?.trim();
    if resolver.is_empty() {
        return None;
    }
    Some(EntrypointAcmeConfig {
        resolver: resolver.to_string(),
    })
}

/// Parse the health-check labels (`<prefix>healthCheck.*`):
///
/// - `path` — enables the HTTP probe. A leading `/` is added if missing.
/// - `status` — exact status code the HTTP probe accepts; any 2xx/3xx without.
/// - `timeout` — per-probe timeout, in milliseconds.
/// - `interval` — milliseconds between two probes.
/// - `port` — port the probe dials instead of the backend's.
/// - `headers.<Name>` — request header of the HTTP probe.
/// - `unhealthyThreshold` / `healthyThreshold` — consecutive failures before
///   the backend is unhealthy, successes before it is healthy again.
///
/// An invalid value emits `W021` and is dropped, so the check keeps its
/// default for that setting rather than being disabled. `status` and
/// `headers` only apply to the HTTP probe: without a `path` they emit `W021`.
///
/// Returns `None` when no setting is given — the backend keeps the default
/// TCP probe.
pub fn parse_health_check(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<HealthCheckConfig> {
    let key = |field: &str| format!("{prefix}healthCheck.{field}");
    let value = |field: &str| {
        labels
            .get(&key(field))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
    };
    let invalid =
        |diagnostics: &mut Vec<Diagnostic>, field: &str, raw: &str, message: &str, hint: &str| {
            diagnostics.push(
                Diagnostic::new(DiagnosticCode::W021InvalidHealthCheck, message)
                    .with_label(key(field))
                    .with_value(raw)
                    .with_hint(hint),
            );
        };

    let path = value("path").map(|raw| {
        if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        }
    });

    let status = value("status").and_then(|raw| match raw.parse::<u16>() {
        Ok(code) if (100..=599).contains(&code) => Some(code),
        _ => {
            invalid(
                diagnostics,
                "status",
                raw,
                "healthCheck.status is not a valid HTTP status code; falling back to the 2xx/3xx default",
                "expected an integer between 100 and 599, e.g. 200",
            );
            None
        }
    });

    let positive = |diagnostics: &mut Vec<Diagnostic>,
                    field: &str,
                    message: &str,
                    hint: &str|
     -> Option<u64> {
        let raw = value(field)?;
        match raw.parse::<u64>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                invalid(diagnostics, field, raw, message, hint);
                None
            }
        }
    };
    let timeout_ms = positive(
        diagnostics,
        "timeout",
        "healthCheck.timeout is not a positive integer; falling back to the default timeout",
        "expected milliseconds as a positive integer, e.g. 2000",
    );
    let interval_ms = positive(
        diagnostics,
        "interval",
        "healthCheck.interval is not a positive integer; falling back to the default interval",
        "expected milliseconds as a positive integer, e.g. 5000",
    );
    let unhealthy_threshold = positive(
        diagnostics,
        "unhealthyThreshold",
        "healthCheck.unhealthyThreshold is not a positive integer; falling back to 1",
        "expected a count of consecutive failed probes, e.g. 3",
    )
    .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
    let healthy_threshold = positive(
        diagnostics,
        "healthyThreshold",
        "healthCheck.healthyThreshold is not a positive integer; falling back to 1",
        "expected a count of consecutive successful probes, e.g. 2",
    )
    .map(|n| u32::try_from(n).unwrap_or(u32::MAX));

    let port = value("port").and_then(|raw| match raw.parse::<u16>() {
        Ok(port) if port > 0 => Some(port),
        _ => {
            invalid(
                diagnostics,
                "port",
                raw,
                "healthCheck.port is not a valid port; probing the backend's own port",
                "expected a port between 1 and 65535, e.g. 8081",
            );
            None
        }
    });

    let header_prefix = key("headers.");
    let mut headers = BTreeMap::new();
    for (label, raw) in labels {
        let Some(name) = label.strip_prefix(&header_prefix) else {
            continue;
        };
        let valid = reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
            && reqwest::header::HeaderValue::from_str(raw.trim()).is_ok();
        if valid {
            headers.insert(name.to_string(), raw.trim().to_string());
        } else {
            // The value is left out of the diagnostic: it is often a secret.
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W021InvalidHealthCheck,
                    "health check header name or value is not valid; ignoring it",
                )
                .with_label(label.as_str())
                .with_hint("a header name is a token such as Authorization; a value has no line break or control character"),
            );
        }
    }

    if path.is_none() {
        if let Some(raw) = value("status") {
            invalid(
                diagnostics,
                "status",
                raw,
                "healthCheck.status needs healthCheck.path: the TCP probe has no status",
                "set healthCheck.path, e.g. /health",
            );
        }
        if !headers.is_empty() {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W021InvalidHealthCheck,
                    "healthCheck.headers need healthCheck.path: the TCP probe sends no request",
                )
                .with_label(header_prefix.trim_end_matches('.'))
                .with_hint("set healthCheck.path, e.g. /health"),
            );
            headers.clear();
        }
    }

    let configured = path.is_some()
        || timeout_ms.is_some()
        || interval_ms.is_some()
        || port.is_some()
        || unhealthy_threshold.is_some()
        || healthy_threshold.is_some();
    configured.then(|| HealthCheckConfig {
        status: path.as_ref().and(status),
        path,
        timeout_ms,
        interval_ms,
        port,
        headers,
        unhealthy_threshold,
        healthy_threshold,
    })
}

/// Parse the `<prefix>loadBalancer` label into a [`LoadBalancer`]. Accepts
/// `round_robin`/`roundrobin`, `random`, `power_of_two`/`poweroftwo`,
/// `least_connections`/`leastconn`/`leastconnections`, and the flow-affine
/// `hrw`/`rendezvous` and `maglev` (case-insensitive, hyphens/underscores
/// ignored). Absent → default (round-robin). An unrecognised value emits `W022`
/// and falls back to round-robin.
///
/// `flow_affine_supported` is true only for UDP. The flow-affine algorithms
/// (`hrw`/`maglev`) key on a flow identity Sōzu only computes for UDP; on
/// HTTP/TCP it has no flow key and silently round-robins. So when those algos
/// are requested on a protocol that can't honor them, we emit `W022` and fall
/// back to round-robin explicitly rather than letting the request degrade
/// silently.
pub fn parse_load_balancer(
    labels: &HashMap<String, String>,
    prefix: &str,
    flow_affine_supported: bool,
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
        "hrw" | "rendezvous" | "maglev" if !flow_affine_supported => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W022InvalidLoadBalancer,
                    "flow-affine loadBalancer (hrw/maglev) is only honored for UDP; falling back to round_robin",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("use hrw/maglev on a `sozune.udp.*` service, or pick round_robin/random/power_of_two/least_connections here"),
            );
            LoadBalancer::default()
        }
        "hrw" | "rendezvous" => LoadBalancer::Hrw,
        "maglev" => LoadBalancer::Maglev,
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W022InvalidLoadBalancer,
                    "loadBalancer is not a recognised algorithm; falling back to round_robin",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint(
                    "one of: round_robin, random, power_of_two, least_connections, hrw, maglev",
                ),
            );
            LoadBalancer::default()
        }
    }
}

/// Parse the `<prefix>weight` label into a backend load-balancing weight.
///
/// The weight is a relative share of traffic among the backends of a service:
/// a backend with weight `90` receives roughly nine times the traffic of one
/// with weight `10`. Every balancer honours it. A weight of `0` makes the
/// backend a backup, used only when no other backend can serve.
///
/// Absent or empty → `None` (the backend keeps its default weight). A negative
/// or non-integer value emits `W027` and falls back to `None`.
pub fn parse_weight(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u32> {
    let key = format!("{prefix}weight");
    let raw = labels
        .get(&key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;
    match raw.parse::<u32>() {
        Ok(weight) => Some(weight),
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W027InvalidWeight,
                    "weight is not a valid non-negative integer; backend keeps the default weight",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("expected a non-negative integer, e.g. 90"),
            );
            None
        }
    }
}

/// Parse the `<prefix>sni` label into a TLS passthrough routing pattern.
/// Absent → `None` (the listener keeps its catch-all behaviour); an invalid
/// pattern emits `W028` and also yields `None`.
///
/// The accepted shape lives in [`crate::model::validate_sni`], shared with the
/// Gateway API TLSRoute path so both reject a bad pattern where the operator
/// can see it rather than letting Sōzu refuse it silently in the worker.
pub fn parse_sni(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let key = format!("{prefix}sni");
    let raw = labels
        .get(&key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;

    match crate::model::validate_sni(raw) {
        Ok(normalized) => Some(normalized),
        Err(rejection) => {
            let (reason, hint) = match rejection {
                SniRejection::NonAscii => (
                    "is not ASCII",
                    "use the punycode A-label, e.g. xn--caf-dma.example.com",
                ),
                SniRejection::BadWildcard => (
                    "carries a wildcard beyond a single leading `*.` label",
                    "expected an exact host or one leading wildcard, e.g. *.example.com",
                ),
                SniRejection::Slash => (
                    "contains `/`, which is not valid in a hostname",
                    "expected a bare hostname, e.g. api.example.com",
                ),
                SniRejection::EmptyLabel => (
                    "has an empty label (leading, trailing, or doubled dot)",
                    "expected a well-formed hostname, e.g. api.example.com",
                ),
            };
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W028InvalidSni,
                    format!("sni {reason}; route falls back to the listener catch-all"),
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint(hint.to_string()),
            );
            None
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

/// Parse the `<prefix>circuitBreaker.*` labels into a [`CircuitBreakerConfig`].
///
/// The presence of **any** `circuitBreaker.*` field enables the breaker;
/// omitted fields use the Traefik-flavoured defaults. Recognised fields:
///
/// - `circuitBreaker.threshold` — failure ratio in `(0, 1]` (default `0.5`)
/// - `circuitBreaker.minRequests` — window size before evaluating (default `20`)
/// - `circuitBreaker.cooldown` — open duration in seconds (default `10`)
///
/// Invalid values emit `W024` and fall back to the default for that field.
pub fn parse_circuit_breaker(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<CircuitBreakerConfig> {
    use crate::middleware::circuit_breaker as cb;

    let t_key = format!("{prefix}circuitBreaker.threshold");
    let m_key = format!("{prefix}circuitBreaker.minRequests");
    let c_key = format!("{prefix}circuitBreaker.cooldown");

    // Enabled only if at least one field is present.
    let present = [&t_key, &m_key, &c_key]
        .iter()
        .any(|k| labels.get(*k).is_some_and(|v| !v.trim().is_empty()));
    if !present {
        return None;
    }

    let threshold = match labels.get(&t_key).map(|s| s.trim()) {
        None | Some("") => cb::DEFAULT_THRESHOLD,
        Some(raw) => match raw.parse::<f64>() {
            Ok(v) if v > 0.0 && v <= 1.0 => v,
            _ => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W024InvalidCircuitBreaker,
                        "circuitBreaker.threshold must be a ratio in (0, 1]; using the default",
                    )
                    .with_label(&t_key)
                    .with_value(raw)
                    .with_hint("e.g. 0.5 trips at a 50% failure rate"),
                );
                cb::DEFAULT_THRESHOLD
            }
        },
    };

    let min_requests = match labels.get(&m_key).map(|s| s.trim()) {
        None | Some("") => cb::DEFAULT_MIN_REQUESTS,
        Some(raw) => match raw.parse::<u32>() {
            Ok(v) if v >= 1 => v,
            _ => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W024InvalidCircuitBreaker,
                        "circuitBreaker.minRequests must be a positive integer; using the default",
                    )
                    .with_label(&m_key)
                    .with_value(raw)
                    .with_hint("number of recent requests before evaluating the failure rate"),
                );
                cb::DEFAULT_MIN_REQUESTS
            }
        },
    };

    let cooldown_secs = match labels.get(&c_key).map(|s| s.trim()) {
        None | Some("") => cb::DEFAULT_COOLDOWN_SECS,
        Some(raw) => match raw.parse::<u64>() {
            Ok(v) if v >= 1 => v,
            _ => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W024InvalidCircuitBreaker,
                        "circuitBreaker.cooldown must be a positive integer (seconds); using the default",
                    )
                    .with_label(&c_key)
                    .with_value(raw)
                    .with_hint("seconds the breaker stays open before probing again"),
                );
                cb::DEFAULT_COOLDOWN_SECS
            }
        },
    };

    Some(CircuitBreakerConfig {
        threshold,
        min_requests,
        cooldown_secs,
    })
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
        assert_eq!(hc.path.as_deref(), Some("/health"));
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
        assert_eq!(hc.path.as_deref(), Some("/health"));
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
    fn health_check_parses_interval_port_thresholds_and_headers() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.path", "/health"),
                ("sozune.http.web.healthCheck.interval", "5000"),
                ("sozune.http.web.healthCheck.port", "8081"),
                ("sozune.http.web.healthCheck.unhealthyThreshold", "3"),
                ("sozune.http.web.healthCheck.healthyThreshold", "2"),
                (
                    "sozune.http.web.healthCheck.headers.Authorization",
                    "Bearer abc",
                ),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(hc.interval_ms, Some(5000));
        assert_eq!(hc.port, Some(8081));
        assert_eq!(hc.unhealthy_threshold, Some(3));
        assert_eq!(hc.healthy_threshold, Some(2));
        assert_eq!(hc.headers["Authorization"], "Bearer abc");
        assert!(d.is_empty());
    }

    /// Without a path the probe is a TCP connect: a port or an interval
    /// alone configure it, and HTTP-only settings warn instead of applying.
    #[test]
    fn health_check_without_path_is_a_tcp_probe() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.port", "9000"),
                ("sozune.http.web.healthCheck.status", "200"),
                ("sozune.http.web.healthCheck.headers.X-Token", "t"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .expect("a port configures the check");
        assert_eq!(hc.path, None);
        assert_eq!(hc.port, Some(9000));
        assert_eq!(hc.status, None);
        assert!(hc.headers.is_empty());
        assert_eq!(d.len(), 2);
        assert!(
            d.iter()
                .all(|d| d.code == DiagnosticCode::W021InvalidHealthCheck)
        );
    }

    /// A header the probe cannot send is dropped, without its value in the
    /// diagnostic: values are often secrets.
    #[test]
    fn health_check_invalid_header_warns_without_its_value() {
        let mut d = Vec::new();
        let hc = parse_health_check(
            &labels(&[
                ("sozune.http.web.healthCheck.path", "/health"),
                ("sozune.http.web.healthCheck.headers.Bad Name", "secret"),
                ("sozune.http.web.healthCheck.port", "0"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert!(hc.headers.is_empty());
        assert_eq!(hc.port, None);
        let header = d
            .iter()
            .find(|d| d.label.as_deref().is_some_and(|l| l.contains("headers")))
            .unwrap();
        assert_eq!(header.value, None);
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
            parse_load_balancer(&labels(&[]), "sozune.http.web.", false, &mut d),
            LoadBalancer::RoundRobin
        );
        assert!(d.is_empty());
    }

    #[test]
    fn circuit_breaker_absent_is_none() {
        let mut d = Vec::new();
        assert!(parse_circuit_breaker(&labels(&[]), "sozune.http.web.", &mut d).is_none());
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
        // flow_affine_supported=true (UDP) so hrw/maglev parse without warning.
        let cases = [
            ("round_robin", LoadBalancer::RoundRobin),
            ("random", LoadBalancer::Random),
            ("power_of_two", LoadBalancer::PowerOfTwo),
            ("least_connections", LoadBalancer::LeastConnections),
            ("hrw", LoadBalancer::Hrw),
            ("maglev", LoadBalancer::Maglev),
            // Aliases / casing / separators.
            ("leastconn", LoadBalancer::LeastConnections),
            ("Least-Connections", LoadBalancer::LeastConnections),
            ("POWEROFTWO", LoadBalancer::PowerOfTwo),
            ("rendezvous", LoadBalancer::Hrw),
            ("MAGLEV", LoadBalancer::Maglev),
        ];
        for (raw, want) in cases {
            let mut d = Vec::new();
            let got = parse_load_balancer(
                &labels(&[("sozune.udp.dns.loadBalancer", raw)]),
                "sozune.udp.dns.",
                true,
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
            false,
            &mut d,
        );
        assert_eq!(got, LoadBalancer::RoundRobin);
        assert_eq!(d[0].code, DiagnosticCode::W022InvalidLoadBalancer);
    }

    #[test]
    fn flow_affine_algorithms_warn_and_default_when_unsupported() {
        // hrw/maglev on a non-UDP (no flow key) protocol must not silently
        // degrade to round-robin: W022 is emitted and the result is round-robin.
        for raw in ["hrw", "rendezvous", "maglev"] {
            let mut d = Vec::new();
            let got = parse_load_balancer(
                &labels(&[("sozune.http.web.loadBalancer", raw)]),
                "sozune.http.web.",
                false,
                &mut d,
            );
            assert_eq!(got, LoadBalancer::RoundRobin, "input {raw}");
            assert_eq!(
                d[0].code,
                DiagnosticCode::W022InvalidLoadBalancer,
                "input {raw} should warn"
            );
        }
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
    fn circuit_breaker_any_field_enables_with_defaults() {
        use crate::middleware::circuit_breaker as cb;
        let mut d = Vec::new();
        let c = parse_circuit_breaker(
            &labels(&[("sozune.http.web.circuitBreaker.threshold", "0.3")]),
            "sozune.http.web.",
            &mut d,
        )
        .expect("any field enables the breaker");
        assert_eq!(c.threshold, 0.3);
        // Omitted fields fall back to defaults.
        assert_eq!(c.min_requests, cb::DEFAULT_MIN_REQUESTS);
        assert_eq!(c.cooldown_secs, cb::DEFAULT_COOLDOWN_SECS);
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

    #[test]
    fn circuit_breaker_parses_all_fields() {
        let mut d = Vec::new();
        let c = parse_circuit_breaker(
            &labels(&[
                ("sozune.http.web.circuitBreaker.threshold", "0.8"),
                ("sozune.http.web.circuitBreaker.minRequests", "50"),
                ("sozune.http.web.circuitBreaker.cooldown", "30"),
            ]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(c.threshold, 0.8);
        assert_eq!(c.min_requests, 50);
        assert_eq!(c.cooldown_secs, 30);
        assert!(d.is_empty());
    }

    #[test]
    fn circuit_breaker_invalid_threshold_warns_and_defaults() {
        use crate::middleware::circuit_breaker as cb;
        let mut d = Vec::new();
        let c = parse_circuit_breaker(
            &labels(&[("sozune.http.web.circuitBreaker.threshold", "5")]),
            "sozune.http.web.",
            &mut d,
        )
        .unwrap();
        assert_eq!(c.threshold, cb::DEFAULT_THRESHOLD);
        assert_eq!(d[0].code, DiagnosticCode::W024InvalidCircuitBreaker);
    }
}
