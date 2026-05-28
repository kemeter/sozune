//! Snapshot of the latest metrics polled from Sōzu workers.
//!
//! The proxy mainloop owns the worker `Channel`s and is the only thing that
//! can talk to a worker without locking. Asking workers for metrics from the
//! API thread would either require locking the channels (intrusive) or
//! blocking on a `oneshot` per scrape (fragile under load).
//!
//! Instead we run a small poller in the proxy mainloop that periodically asks
//! each worker for its metrics and writes the merged result into a shared
//! `Arc<RwLock<MetricsSnapshot>>`. The `/metrics` endpoint just reads the
//! snapshot — no cross-thread channel work on the scrape path.
//!
//! Trade-off: scrape values lag the poll interval. With a default poll of
//! 5 s and Prometheus scraping every 5 s the worst case is ~10 s old data,
//! which is acceptable for the values we expose (rates, gauges).

use sozu_command_lib::proto::command::{FilteredMetrics, filtered_metrics::Inner};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

pub type MetricsSnapshotStore = Arc<RwLock<MetricsSnapshot>>;

/// Last successful metrics read from the workers, plus per-worker proxying
/// counters merged across all workers we polled.
#[derive(Default, Clone, Debug)]
pub struct MetricsSnapshot {
    /// Unix timestamp (seconds) of the last successful poll. `0` if we have
    /// never polled, surfaced as `sozune_proxy_last_poll_seconds` so an alert
    /// can flag stale data.
    pub last_poll_unix: u64,
    /// `sozu` proxy-wide counters and gauges, merged across workers.
    /// Examples: `connections`, `http.requests`, `http.errors`.
    pub proxy: BTreeMap<String, MetricValue>,
}

/// Reduced view of `FilteredMetrics` — we only forward gauge/count values to
/// Prometheus. Histograms / time series exist in Sōzu but mapping them to
/// Prometheus histograms would require knowing bucket bounds; we skip them
/// for now and surface only what is unambiguous.
#[derive(Clone, Debug)]
pub enum MetricValue {
    Gauge(u64),
    Count(i64),
    Time(u64),
}

pub fn new_store() -> MetricsSnapshotStore {
    Arc::new(RwLock::new(MetricsSnapshot::default()))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert a single `FilteredMetrics` value into our reduced `MetricValue`.
/// Returns `None` for kinds we do not export (Percentiles, TimeSerie,
/// Histogram).
pub fn convert(m: &FilteredMetrics) -> Option<MetricValue> {
    match &m.inner {
        Some(Inner::Gauge(g)) => Some(MetricValue::Gauge(*g)),
        Some(Inner::Count(c)) => Some(MetricValue::Count(*c)),
        Some(Inner::Time(t)) => Some(MetricValue::Time(*t)),
        Some(Inner::Percentiles(_)) | Some(Inner::TimeSerie(_)) | Some(Inner::Histogram(_)) => None,
        None => None,
    }
}

/// Merge two snapshots of proxy metrics from different workers. For counts
/// we sum, for gauges we sum (gauges from independent workers describe
/// disjoint state — e.g. each worker's open connections), for times we keep
/// the max (worst observed). Same key reaching us twice from the same poll
/// should be rare; this rule is a defensive fallback.
pub fn merge_into(target: &mut BTreeMap<String, MetricValue>, key: String, value: MetricValue) {
    use MetricValue::*;
    match target.get_mut(&key) {
        None => {
            target.insert(key, value);
        }
        Some(existing) => {
            *existing = match (&existing, &value) {
                (Gauge(a), Gauge(b)) => Gauge(a + b),
                (Count(a), Count(b)) => Count(a + b),
                (Time(a), Time(b)) => Time(*a.max(b)),
                _ => value,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sozu_command_lib::proto::command::FilteredMetrics;

    fn gauge(v: u64) -> FilteredMetrics {
        FilteredMetrics {
            inner: Some(Inner::Gauge(v)),
        }
    }
    fn count(v: i64) -> FilteredMetrics {
        FilteredMetrics {
            inner: Some(Inner::Count(v)),
        }
    }

    #[test]
    fn convert_gauge_and_count() {
        assert!(matches!(convert(&gauge(42)), Some(MetricValue::Gauge(42))));
        assert!(matches!(convert(&count(7)), Some(MetricValue::Count(7))));
    }

    #[test]
    fn convert_unsupported_returns_none() {
        let none = FilteredMetrics { inner: None };
        assert!(convert(&none).is_none());
    }

    #[test]
    fn merge_sums_counts() {
        let mut t = BTreeMap::new();
        merge_into(&mut t, "k".into(), MetricValue::Count(3));
        merge_into(&mut t, "k".into(), MetricValue::Count(4));
        assert!(matches!(t.get("k"), Some(MetricValue::Count(7))));
    }

    #[test]
    fn merge_sums_gauges_across_workers() {
        let mut t = BTreeMap::new();
        merge_into(&mut t, "open".into(), MetricValue::Gauge(2));
        merge_into(&mut t, "open".into(), MetricValue::Gauge(5));
        assert!(matches!(t.get("open"), Some(MetricValue::Gauge(7))));
    }

    #[test]
    fn merge_keeps_max_time() {
        let mut t = BTreeMap::new();
        merge_into(&mut t, "t".into(), MetricValue::Time(10));
        merge_into(&mut t, "t".into(), MetricValue::Time(5));
        assert!(matches!(t.get("t"), Some(MetricValue::Time(10))));
    }
}
