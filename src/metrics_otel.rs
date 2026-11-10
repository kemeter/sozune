//! OpenTelemetry metrics export.
//!
//! When `metrics.otlp.enabled`, this builds an OTLP metric exporter (gRPC or
//! HTTP) behind a [`PeriodicReader`] and registers the same series `/metrics`
//! serves:
//!
//! - gauges read from the live state at each push (entrypoints, backends,
//!   diagnostics, Sōzu worker values), through the same snapshot the
//!   Prometheus endpoint renders. One snapshot is taken per push and shared
//!   by every gauge, so the values of a push all come from the same state;
//! - the middleware latency histogram and per-status-class request counter,
//!   recorded on the request path (see [`crate::proxy::request_metrics`]).
//!
//! [`MetricsGuard`] holds the provider so the last batch is flushed on
//! shutdown.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use tracing::error;

use crate::api::metrics::Snapshot;
use crate::api::server::AppState;
use crate::config::OtlpMetricsConfig;
use crate::proxy::request_metrics::{BUCKET_BOUNDS_SECONDS, OtelInstruments, STATUS_CLASS_LABELS};

/// Keeps the meter provider alive and flushes pending metrics on drop.
pub struct MetricsGuard {
    provider: SdkMeterProvider,
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            error!("metrics: failed to flush OTLP metrics on shutdown: {e}");
        }
    }
}

/// Build the OTLP metrics pipeline and start pushing.
///
/// Returns `Err` if the exporter can't be built, so the caller can carry on
/// without OTLP metrics rather than crash.
pub fn start(cfg: &OtlpMetricsConfig, state: &AppState) -> anyhow::Result<MetricsGuard> {
    let exporter = crate::otlp::metric_exporter(&cfg.endpoint(), &cfg.exporter)?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(cfg.push_interval.max(1)))
        .build();

    let resource = crate::otlp::resource(&cfg.service_name, &cfg.exporter);

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    let meter = provider.meter("sozune");
    register_instruments(&meter, state);

    Ok(MetricsGuard { provider })
}

/// How long a snapshot is reused by the gauge callbacks. The callbacks of one
/// collection run back to back, well within this window, and two pushes are
/// at least a second apart, so each push reads exactly one snapshot.
const SNAPSHOT_REUSE: Duration = Duration::from_millis(500);

/// A snapshot and when it was taken.
type TimedSnapshot = (Instant, Arc<Snapshot>);

/// Snapshot shared by the gauge callbacks of one collection.
#[derive(Clone)]
struct SharedSnapshot {
    state: AppState,
    last: Arc<Mutex<Option<TimedSnapshot>>>,
}

impl SharedSnapshot {
    fn new(state: &AppState) -> Self {
        Self {
            state: state.clone(),
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// The snapshot of the current collection, taken by its first callback.
    fn get(&self) -> Arc<Snapshot> {
        let mut last = match self.last.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((taken, snap)) = last.as_ref()
            && taken.elapsed() < SNAPSHOT_REUSE
        {
            return Arc::clone(snap);
        }
        let snap = Arc::new(Snapshot::collect(&self.state));
        *last = Some((Instant::now(), Arc::clone(&snap)));
        snap
    }
}

/// Register every instrument on `meter`. Observable callbacks read the
/// snapshot of the current collection.
fn register_instruments(meter: &Meter, state: &AppState) {
    let snapshot = SharedSnapshot::new(state);
    gauge(
        meter,
        &snapshot,
        "sozune_entrypoints",
        "Number of entrypoints currently loaded.",
        |s, o| {
            o.push((s.static_metrics.entrypoints as u64, vec![]));
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_entrypoints_by_protocol",
        "Number of entrypoints per protocol.",
        |s, o| {
            for (proto, count) in &s.static_metrics.entrypoints_by_protocol {
                o.push((*count as u64, vec![KeyValue::new("protocol", *proto)]));
            }
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_entrypoints_tls",
        "Number of entrypoints with TLS enabled.",
        |s, o| {
            o.push((s.static_metrics.entrypoints_tls as u64, vec![]));
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_backends",
        "Total number of backends across all entrypoints.",
        |s, o| {
            o.push((s.static_metrics.backends as u64, vec![]));
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_backends_unhealthy",
        "Number of backends currently marked unhealthy by the active health check.",
        |s, o| {
            o.push((s.static_metrics.backends_unhealthy as u64, vec![]));
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_diagnostics",
        "Active diagnostics by severity.",
        |s, o| {
            let d = &s.static_metrics.diagnostics;
            for (severity, count) in [("error", d.error), ("warn", d.warn), ("info", d.info)] {
                o.push((count as u64, vec![KeyValue::new("severity", severity)]));
            }
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_acme_enabled",
        "1 if ACME is enabled, 0 otherwise.",
        |s, o| {
            o.push((u64::from(s.static_metrics.acme_enabled), vec![]));
        },
    );
    gauge(
        meter,
        &snapshot,
        "sozune_proxy_last_poll_seconds",
        "Unix timestamp of the last successful Sōzu metrics poll. 0 means never.",
        |s, o| {
            o.push((s.proxy.last_poll_seconds, vec![]));
        },
    );

    let proxy_snapshot = snapshot.clone();
    meter
        .i64_observable_gauge("sozune_proxy_metric")
        .with_description("Proxy metric forwarded from Sōzu workers (gauge or counter).")
        .with_callback(move |observer| {
            let snap = proxy_snapshot.get();
            for (key, value) in &snap.proxy.metrics {
                let v = (*value).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
                observer.observe(v, &[KeyValue::new("key", key.clone())]);
            }
        })
        .build();

    let duration = meter
        .f64_histogram("sozune_middleware_request_duration_seconds")
        .with_description(
            "Latency of requests served through the Sōzune middleware layer, in seconds.",
        )
        .with_unit("s")
        .with_boundaries(BUCKET_BOUNDS_SECONDS.to_vec())
        .build();
    let requests = meter
        .u64_counter("sozune_middleware_requests_total")
        .with_description(
            "Requests served through the Sōzune middleware layer, by HTTP status class.",
        )
        .build();
    // Every class is exported from the first push, at zero, as on `/metrics`,
    // so an error-rate query returns 0 rather than no data.
    for class in STATUS_CLASS_LABELS {
        requests.add(0, &[KeyValue::new("class", class)]);
    }
    snapshot
        .state
        .request_metrics
        .attach_otel(OtelInstruments { duration, requests });
}

type Observations = Vec<(u64, Vec<KeyValue>)>;

/// Register a `u64` observable gauge whose values come from `read`, applied to
/// the snapshot of each push.
fn gauge<F>(
    meter: &Meter,
    snapshot: &SharedSnapshot,
    name: &'static str,
    help: &'static str,
    read: F,
) where
    F: Fn(&Snapshot, &mut Observations) + Send + Sync + 'static,
{
    let snapshot = snapshot.clone();
    meter
        .u64_observable_gauge(name)
        .with_description(help)
        .with_callback(move |observer| {
            let snap = snapshot.get();
            let mut values = Observations::new();
            read(&snap, &mut values);
            for (value, attrs) in values {
                observer.observe(value, &attrs);
            }
        })
        .build();
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader};

    fn collect(state: &AppState) -> Vec<ResourceMetrics> {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        register_instruments(&provider.meter("sozune"), state);
        state.request_metrics.record(Duration::from_millis(20), 200);
        state.request_metrics.record(Duration::from_millis(20), 503);
        provider.force_flush().unwrap();
        exporter.get_finished_metrics().unwrap()
    }

    fn names(metrics: &[ResourceMetrics]) -> Vec<String> {
        metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .map(|m| m.name().to_string())
            .collect()
    }

    #[test]
    fn exports_gauges_histogram_and_counter() {
        let state = crate::api::metrics::tests::empty_state();
        let metrics = collect(&state);
        let names = names(&metrics);
        for expected in [
            "sozune_entrypoints",
            "sozune_backends",
            "sozune_diagnostics",
            "sozune_middleware_request_duration_seconds",
            "sozune_middleware_requests_total",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing {expected} in {names:?}"
            );
        }
    }

    #[test]
    fn every_status_class_is_exported() {
        let state = crate::api::metrics::tests::empty_state();
        let metrics = collect(&state);
        let counter = metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == "sozune_middleware_requests_total")
            .expect("counter exported");
        let AggregatedMetrics::U64(MetricData::Sum(sum)) = counter.data() else {
            panic!("expected a u64 sum");
        };
        let mut classes: Vec<(String, u64)> = sum
            .data_points()
            .map(|p| {
                let class = p.attributes().next().expect("class").value.to_string();
                (class, p.value())
            })
            .collect();
        classes.sort();
        assert_eq!(
            classes,
            [
                ("1xx", 0),
                ("2xx", 1),
                ("3xx", 0),
                ("4xx", 0),
                ("5xx", 1),
                ("other", 0)
            ]
            .map(|(c, v)| (c.to_string(), v))
        );
    }

    #[test]
    fn gauges_of_one_push_share_a_snapshot() {
        let state = crate::api::metrics::tests::empty_state();
        let shared = SharedSnapshot::new(&state);
        let first = shared.get();
        assert!(Arc::ptr_eq(&first, &shared.get()));
    }

    #[test]
    fn histogram_uses_the_prometheus_bucket_bounds() {
        let state = crate::api::metrics::tests::empty_state();
        let metrics = collect(&state);
        let histogram = metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == "sozune_middleware_request_duration_seconds")
            .expect("histogram exported");
        let AggregatedMetrics::F64(MetricData::Histogram(h)) = histogram.data() else {
            panic!("expected an f64 histogram");
        };
        let point = h.data_points().next().expect("one data point");
        assert_eq!(point.count(), 2);
        assert_eq!(point.bounds().collect::<Vec<_>>(), BUCKET_BOUNDS_SECONDS);
    }
}
