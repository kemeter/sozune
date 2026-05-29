//! `/metrics` endpoint with two output formats negotiated via `Accept`.
//!
//! Reads the live state (entrypoint store, unhealthy backends, diagnostics,
//! Sōzu worker snapshot) and renders it in either:
//!
//! - Prometheus text exposition `version=0.0.4` (default — what Prometheus
//!   scrapers expect when no `Accept` is sent);
//! - JSON, when the client sends `Accept: application/json`. Same data,
//!   structured for direct consumption by the dashboard or any other client
//!   that prefers to skip the text-parsing step.
//!
//! No moving parts, no background aggregator — every scrape recomputes from
//! authoritative state, so values are always consistent with what the rest of
//! the API would return.
//!
//! Endpoint is intentionally unauthenticated: Prometheus scrapers default to
//! no auth and operators front the API with TLS / network ACLs anyway.

use crate::api::server::AppState;
use crate::labels::diagnostic::Severity;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Write;
use tracing::error;

const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let snap = Snapshot::collect(&state);

    let (body, content_type) = if wants_json(&headers) {
        let body = serde_json::to_string(&snap).unwrap_or_else(|e| {
            error!("metrics: JSON serialization failed: {}", e);
            "{}".to_string()
        });
        (body, JSON_CONTENT_TYPE)
    } else {
        (render_prom(&snap), PROM_CONTENT_TYPE)
    };

    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// Returns true when the request's `Accept` header asks for JSON. Anything
/// else — including no `Accept`, `*/*`, or the Prometheus content-type — falls
/// back to Prometheus text so existing scrapers are never surprised by a JSON
/// body.
fn wants_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim())
        .any(|media| media.eq_ignore_ascii_case("application/json"))
}

/// Numeric snapshot of every metric we expose, computed once per scrape from
/// the live `AppState`. Both renderers (Prometheus text and JSON) read from
/// this struct so the two formats can never drift on values.
#[derive(Debug, Serialize)]
struct Snapshot {
    #[serde(rename = "static")]
    static_metrics: StaticMetrics,
    proxy: ProxyMetrics,
}

#[derive(Debug, Serialize)]
struct StaticMetrics {
    entrypoints: usize,
    entrypoints_by_protocol: HashMap<&'static str, usize>,
    entrypoints_tls: usize,
    backends: usize,
    backends_unhealthy: usize,
    diagnostics: DiagnosticsCounts,
    acme_enabled: bool,
}

#[derive(Debug, Serialize)]
struct DiagnosticsCounts {
    error: usize,
    warn: usize,
    info: usize,
}

#[derive(Debug, Serialize)]
struct ProxyMetrics {
    /// Unix timestamp (seconds) of the last successful Sōzu worker poll.
    /// `0` if no poll has ever succeeded.
    last_poll_seconds: u64,
    /// Per-key proxy counters/gauges as reported by Sōzu workers.
    metrics: HashMap<String, i128>,
}

impl Snapshot {
    fn collect(state: &AppState) -> Self {
        let (entrypoints_total, backends_total, tls_total, by_protocol) = match state.storage.read()
        {
            Ok(guard) => {
                let entrypoints = guard.len();
                let backends: usize = guard.values().map(|e| e.backends.len()).sum();
                let tls = guard.values().filter(|e| e.config.tls).count();
                let mut by_proto: HashMap<&'static str, usize> = HashMap::new();
                for ep in guard.values() {
                    let key = match ep.protocol {
                        crate::model::Protocol::Http => "http",
                        crate::model::Protocol::Tcp => "tcp",
                        crate::model::Protocol::Udp => "udp",
                    };
                    *by_proto.entry(key).or_insert(0) += 1;
                }
                (entrypoints, backends, tls, by_proto)
            }
            Err(e) => {
                error!("metrics: storage lock poisoned: {}", e);
                (0, 0, 0, HashMap::new())
            }
        };

        let unhealthy_total = match state.unhealthy_backends.read() {
            Ok(guard) => guard.len(),
            Err(e) => {
                error!("metrics: unhealthy_backends lock poisoned: {}", e);
                0
            }
        };

        let (errors, warnings, infos) = match state.diagnostics.read() {
            Ok(guard) => {
                let mut e = 0usize;
                let mut w = 0usize;
                let mut i = 0usize;
                for diags in guard.values() {
                    for d in diags {
                        match d.severity() {
                            Severity::Error => e += 1,
                            Severity::Warn => w += 1,
                            Severity::Info => i += 1,
                        }
                    }
                }
                (e, w, i)
            }
            Err(e) => {
                error!("metrics: diagnostics lock poisoned: {}", e);
                (0, 0, 0)
            }
        };

        let proxy = ProxyMetrics::collect(state);

        Snapshot {
            static_metrics: StaticMetrics {
                entrypoints: entrypoints_total,
                entrypoints_by_protocol: by_protocol,
                entrypoints_tls: tls_total,
                backends: backends_total,
                backends_unhealthy: unhealthy_total,
                diagnostics: DiagnosticsCounts {
                    error: errors,
                    warn: warnings,
                    info: infos,
                },
                acme_enabled: state.acme_enabled,
            },
            proxy,
        }
    }
}

impl ProxyMetrics {
    fn collect(state: &AppState) -> Self {
        use crate::proxy::metrics_snapshot::MetricValue;

        let snap = match state.metrics.read() {
            Ok(g) => g.clone(),
            Err(e) => {
                error!("metrics: snapshot lock poisoned: {}", e);
                return ProxyMetrics {
                    last_poll_seconds: 0,
                    metrics: HashMap::new(),
                };
            }
        };

        let mut metrics: HashMap<String, i128> = HashMap::with_capacity(snap.proxy.len());
        for (key, value) in &snap.proxy {
            let safe = sanitize_metric_name(key);
            let v: i128 = match value {
                MetricValue::Gauge(g) => *g as i128,
                MetricValue::Count(c) => *c as i128,
                MetricValue::Time(t) => *t as i128,
            };
            metrics.insert(safe, v);
        }

        ProxyMetrics {
            last_poll_seconds: snap.last_poll_unix,
            metrics,
        }
    }
}

fn render_prom(snap: &Snapshot) -> String {
    let mut out = String::with_capacity(1024);
    let s = &snap.static_metrics;

    write_gauge(
        &mut out,
        "sozune_entrypoints",
        "Number of entrypoints currently loaded.",
        s.entrypoints,
    );

    let _ = writeln!(
        &mut out,
        "# HELP sozune_entrypoints_by_protocol Number of entrypoints per protocol."
    );
    let _ = writeln!(&mut out, "# TYPE sozune_entrypoints_by_protocol gauge");
    for (proto, count) in &s.entrypoints_by_protocol {
        let _ = writeln!(
            &mut out,
            "sozune_entrypoints_by_protocol{{protocol=\"{proto}\"}} {count}"
        );
    }

    write_gauge(
        &mut out,
        "sozune_entrypoints_tls",
        "Number of entrypoints with TLS enabled.",
        s.entrypoints_tls,
    );
    write_gauge(
        &mut out,
        "sozune_backends",
        "Total number of backends across all entrypoints.",
        s.backends,
    );
    write_gauge(
        &mut out,
        "sozune_backends_unhealthy",
        "Number of backends currently marked unhealthy by the active health check.",
        s.backends_unhealthy,
    );

    let _ = writeln!(
        &mut out,
        "# HELP sozune_diagnostics Active diagnostics by severity."
    );
    let _ = writeln!(&mut out, "# TYPE sozune_diagnostics gauge");
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics{{severity=\"error\"}} {}",
        s.diagnostics.error
    );
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics{{severity=\"warn\"}} {}",
        s.diagnostics.warn
    );
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics{{severity=\"info\"}} {}",
        s.diagnostics.info
    );

    write_gauge(
        &mut out,
        "sozune_acme_enabled",
        "1 if ACME is enabled, 0 otherwise.",
        if s.acme_enabled { 1 } else { 0 },
    );

    write_gauge(
        &mut out,
        "sozune_proxy_last_poll_seconds",
        "Unix timestamp of the last successful Sōzu metrics poll. 0 means never.",
        snap.proxy.last_poll_seconds as usize,
    );

    if !snap.proxy.metrics.is_empty() {
        let _ = writeln!(
            &mut out,
            "# HELP sozune_proxy_metric Proxy metric forwarded from Sōzu workers (gauge or counter)."
        );
        let _ = writeln!(&mut out, "# TYPE sozune_proxy_metric untyped");
        for (key, value) in &snap.proxy.metrics {
            let _ = writeln!(&mut out, "sozune_proxy_metric{{key=\"{key}\"}} {value}");
        }
    }

    out
}

fn sanitize_metric_name(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => c,
            _ => '_',
        })
        .collect()
}

fn write_gauge(out: &mut String, name: &str, help: &str, value: usize) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiUser, Role};
    use crate::model::{Backend, Entrypoint, EntrypointConfig, Protocol};
    use crate::proxy::health::{UnhealthyKind, UnhealthyReason};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, RwLock};
    use tokio::sync::mpsc;

    fn empty_state() -> AppState {
        let (reload_tx, _) = mpsc::channel::<()>(1);
        AppState {
            storage: Arc::new(RwLock::new(BTreeMap::new())),
            reload_tx,
            users: Vec::<ApiUser>::new(),
            unhealthy_backends: Arc::new(RwLock::new(HashMap::new())),
            diagnostics: crate::diagnostics::new_store(),
            acme_enabled: false,
            providers: crate::config::ProvidersConfig::default(),
            metrics: crate::proxy::metrics_snapshot::new_store(),
            config: Arc::new(crate::config::AppConfig::default()),
        }
    }

    fn make_ep(id: &str, host: &str, tls: bool, backends: usize) -> Entrypoint {
        Entrypoint {
            id: id.to_string(),
            name: id.to_string(),
            backends: (0..backends)
                .map(|i| Backend::new("10.0.0.1", 8000 + i as u16))
                .collect(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.to_string()],
                path: None,
                tls,
                strip_prefix: false,
                https_redirect: false,
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
                add_prefix: None,
                rewrite_host: None,
                rewrite_path: None,
                rewrite_port: None,
                forward_auth: None,
                acme: None,
                error_pages: std::collections::BTreeMap::new(),
                plugins: Vec::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                ip_allow_list: Vec::new(),
            },
            source: Some("api".to_string()),
        }
    }

    #[test]
    fn renders_zeros_for_empty_state() {
        let body = render_prom(&Snapshot::collect(&empty_state()));
        assert!(body.contains("sozune_entrypoints 0"));
        assert!(body.contains("sozune_backends 0"));
        assert!(body.contains("sozune_backends_unhealthy 0"));
        assert!(body.contains("sozune_acme_enabled 0"));
        assert!(body.contains("sozune_diagnostics{severity=\"error\"} 0"));
    }

    #[test]
    fn counts_entrypoints_backends_and_tls() {
        let state = empty_state();
        {
            let mut s = state.storage.write().unwrap();
            s.insert("a".into(), make_ep("a", "a.example.com", false, 2));
            s.insert("b".into(), make_ep("b", "b.example.com", true, 3));
        }
        let body = render_prom(&Snapshot::collect(&state));
        assert!(body.contains("sozune_entrypoints 2"));
        assert!(body.contains("sozune_backends 5"));
        assert!(body.contains("sozune_entrypoints_tls 1"));
        assert!(body.contains("sozune_entrypoints_by_protocol{protocol=\"http\"} 2"));
    }

    #[test]
    fn surfaces_unhealthy_backends() {
        let state = empty_state();
        state.unhealthy_backends.write().unwrap().insert(
            "10.0.0.1:8000".into(),
            UnhealthyReason {
                kind: UnhealthyKind::ConnectionRefused,
                message: "Connection refused".to_string(),
                since: 0,
                last_checked: 0,
            },
        );
        let body = render_prom(&Snapshot::collect(&state));
        assert!(body.contains("sozune_backends_unhealthy 1"));
    }

    #[test]
    fn aggregates_diagnostics_by_severity() {
        let state = empty_state();
        crate::diagnostics::set(
            &state.diagnostics,
            "ep-1",
            vec![
                crate::labels::diagnostic::Diagnostic::new(
                    crate::labels::diagnostic::DiagnosticCode::W001InvalidPort,
                    "bad port",
                ),
                crate::labels::diagnostic::Diagnostic::new(
                    crate::labels::diagnostic::DiagnosticCode::W001InvalidPort,
                    "bad port 2",
                ),
            ],
        );
        let body = render_prom(&Snapshot::collect(&state));
        assert!(body.contains("sozune_diagnostics{severity=\"warn\"} 2"));
    }

    #[test]
    fn acme_enabled_reflects_state() {
        let mut state = empty_state();
        state.acme_enabled = true;
        let body = render_prom(&Snapshot::collect(&state));
        assert!(body.contains("sozune_acme_enabled 1"));
    }

    #[test]
    fn proxy_metrics_section_present_with_zero_poll() {
        let body = render_prom(&Snapshot::collect(&empty_state()));
        assert!(body.contains("sozune_proxy_last_poll_seconds 0"));
        assert!(!body.contains("sozune_proxy_metric{"));
    }

    #[test]
    fn proxy_metrics_section_renders_polled_values() {
        use crate::proxy::metrics_snapshot::MetricValue;
        let state = empty_state();
        {
            let mut snap = state.metrics.write().unwrap();
            snap.last_poll_unix = 12345;
            snap.proxy
                .insert("http.requests".into(), MetricValue::Count(42));
            snap.proxy
                .insert("connections".into(), MetricValue::Gauge(7));
        }
        let body = render_prom(&Snapshot::collect(&state));
        assert!(body.contains("sozune_proxy_last_poll_seconds 12345"));
        assert!(body.contains("sozune_proxy_metric{key=\"http_requests\"} 42"));
        assert!(body.contains("sozune_proxy_metric{key=\"connections\"} 7"));
    }

    #[test]
    fn sanitize_replaces_dots_and_dashes() {
        assert_eq!(
            sanitize_metric_name("http.requests-total"),
            "http_requests_total"
        );
        assert_eq!(sanitize_metric_name("ok_name"), "ok_name");
    }

    #[test]
    fn output_is_prometheus_text_format() {
        let body = render_prom(&Snapshot::collect(&empty_state()));
        // Each metric must be preceded by HELP and TYPE lines.
        assert!(body.contains("# HELP sozune_entrypoints"));
        assert!(body.contains("# TYPE sozune_entrypoints gauge"));
    }

    /// Prometheus client libraries reject responses whose `Content-Type` does
    /// not match the exposition format. Keep this in lockstep with
    /// `CONTENT_TYPE` — changing the header without bumping scrapers'
    /// expectations would silently break ingestion.
    #[tokio::test]
    async fn content_type_is_prometheus_text_format_004() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, header};
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/metrics", get(super::metrics))
            .with_state(empty_state());

        let response = app
            .oneshot(
                Request::get("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let header_value = response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header present")
            .to_str()
            .expect("ASCII header");
        assert_eq!(header_value, "text/plain; version=0.0.4; charset=utf-8");
    }

    /// `Accept: application/json` must return a JSON body with the right
    /// content-type. The dashboard relies on this so it can render metrics
    /// without parsing the text format.
    #[tokio::test]
    async fn accept_json_returns_json_body() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, header};
        use axum::routing::get;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let state = empty_state();
        let app = Router::new()
            .route("/metrics", get(super::metrics))
            .with_state(state);

        let response = app
            .oneshot(
                Request::get("/metrics")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response body is valid JSON");

        // The top-level shape is stable contract for the dashboard.
        assert!(json["static"]["entrypoints"].is_number());
        assert!(json["static"]["backends"].is_number());
        assert!(json["static"]["diagnostics"]["error"].is_number());
        assert!(json["static"]["acme_enabled"].is_boolean());
        assert!(json["proxy"]["last_poll_seconds"].is_number());
        assert!(json["proxy"]["metrics"].is_object());
    }

    /// JSON and Prometheus must always agree on the numeric values — they read
    /// from the same `Snapshot`. This guards against future refactors that
    /// would let one format drift from the other.
    #[tokio::test]
    async fn prom_and_json_agree_on_values() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, header};
        use axum::routing::get;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let state = empty_state();
        // Seed with one unhealthy backend so the comparison covers a non-zero
        // value, not just defaults.
        state.unhealthy_backends.write().unwrap().insert(
            "10.0.0.99:80".into(),
            UnhealthyReason {
                kind: UnhealthyKind::Timeout,
                message: "timeout".into(),
                since: 0,
                last_checked: 0,
            },
        );

        let app = Router::new()
            .route("/metrics", get(super::metrics))
            .with_state(state);

        let prom_bytes = app
            .clone()
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let prom = std::str::from_utf8(&prom_bytes).unwrap().to_string();

        let json_bytes = app
            .oneshot(
                Request::get("/metrics")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert!(prom.contains("sozune_backends_unhealthy 1"));
        assert_eq!(json["static"]["backends_unhealthy"], 1);
    }

    #[test]
    fn wants_json_recognizes_application_json() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            "application/json".parse().unwrap(),
        );
        assert!(wants_json(&h));
    }

    #[test]
    fn wants_json_handles_multiple_media_types() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            "text/html, application/json;q=0.9, */*;q=0.8"
                .parse()
                .unwrap(),
        );
        assert!(wants_json(&h));
    }

    #[test]
    fn wants_json_defaults_to_false_for_text() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::ACCEPT, "text/plain".parse().unwrap());
        assert!(!wants_json(&h));
    }

    #[test]
    fn wants_json_defaults_to_false_when_absent() {
        let h = axum::http::HeaderMap::new();
        assert!(!wants_json(&h));
    }
}
