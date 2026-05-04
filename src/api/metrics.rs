//! Prometheus text-format `/metrics` endpoint.
//!
//! Reads the live state (entrypoint store, unhealthy backends, diagnostics)
//! and renders a snapshot in Prometheus exposition format. No moving parts,
//! no background aggregator — every scrape recomputes from authoritative
//! state, so the values are always consistent with what the API would
//! return.
//!
//! Endpoint is intentionally unauthenticated: Prometheus scrapers default
//! to no auth and operators front the API with TLS / network ACLs anyway.

use crate::api::server::AppState;
use crate::labels::diagnostic::Severity;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::fmt::Write;
use tracing::error;

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn metrics(State(state): State<AppState>) -> Response {
    let body = render(&state);
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    response
}

fn render(state: &AppState) -> String {
    let mut out = String::with_capacity(1024);

    let (entrypoints_total, backends_total, tls_total, by_protocol) = match state.storage.read() {
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

    write_gauge(
        &mut out,
        "sozune_entrypoints_total",
        "Number of entrypoints currently loaded.",
        entrypoints_total,
    );

    let _ = writeln!(
        &mut out,
        "# HELP sozune_entrypoints_by_protocol Number of entrypoints per protocol."
    );
    let _ = writeln!(&mut out, "# TYPE sozune_entrypoints_by_protocol gauge");
    for (proto, count) in &by_protocol {
        let _ = writeln!(
            &mut out,
            "sozune_entrypoints_by_protocol{{protocol=\"{proto}\"}} {count}"
        );
    }

    write_gauge(
        &mut out,
        "sozune_entrypoints_tls_total",
        "Number of entrypoints with TLS enabled.",
        tls_total,
    );
    write_gauge(
        &mut out,
        "sozune_backends_total",
        "Total number of backends across all entrypoints.",
        backends_total,
    );
    write_gauge(
        &mut out,
        "sozune_backends_unhealthy_total",
        "Number of backends currently marked unhealthy by the active health check.",
        unhealthy_total,
    );

    let _ = writeln!(
        &mut out,
        "# HELP sozune_diagnostics_total Active diagnostics by severity."
    );
    let _ = writeln!(&mut out, "# TYPE sozune_diagnostics_total gauge");
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics_total{{severity=\"error\"}} {errors}"
    );
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics_total{{severity=\"warn\"}} {warnings}"
    );
    let _ = writeln!(
        &mut out,
        "sozune_diagnostics_total{{severity=\"info\"}} {infos}"
    );

    write_gauge(
        &mut out,
        "sozune_acme_enabled",
        "1 if ACME is enabled, 0 otherwise.",
        if state.acme_enabled { 1 } else { 0 },
    );

    out
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
            },
            source: Some("api".to_string()),
        }
    }

    #[test]
    fn renders_zeros_for_empty_state() {
        let body = render(&empty_state());
        assert!(body.contains("sozune_entrypoints_total 0"));
        assert!(body.contains("sozune_backends_total 0"));
        assert!(body.contains("sozune_backends_unhealthy_total 0"));
        assert!(body.contains("sozune_acme_enabled 0"));
        assert!(body.contains("sozune_diagnostics_total{severity=\"error\"} 0"));
    }

    #[test]
    fn counts_entrypoints_backends_and_tls() {
        let state = empty_state();
        {
            let mut s = state.storage.write().unwrap();
            s.insert("a".into(), make_ep("a", "a.example.com", false, 2));
            s.insert("b".into(), make_ep("b", "b.example.com", true, 3));
        }
        let body = render(&state);
        assert!(body.contains("sozune_entrypoints_total 2"));
        assert!(body.contains("sozune_backends_total 5"));
        assert!(body.contains("sozune_entrypoints_tls_total 1"));
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
        let body = render(&state);
        assert!(body.contains("sozune_backends_unhealthy_total 1"));
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
        let body = render(&state);
        assert!(body.contains("sozune_diagnostics_total{severity=\"warn\"} 2"));
    }

    #[test]
    fn acme_enabled_reflects_state() {
        let mut state = empty_state();
        state.acme_enabled = true;
        let body = render(&state);
        assert!(body.contains("sozune_acme_enabled 1"));
    }

    #[test]
    fn output_is_prometheus_text_format() {
        let body = render(&empty_state());
        // Each metric must be preceded by HELP and TYPE lines.
        assert!(body.contains("# HELP sozune_entrypoints_total"));
        assert!(body.contains("# TYPE sozune_entrypoints_total gauge"));
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
}
