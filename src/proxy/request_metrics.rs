//! Live request-latency histogram, fed by the proxy handler and read by the
//! `/metrics` endpoint.
//!
//! Unlike [`super::metrics_snapshot`] (which mirrors values *polled* from Sōzu
//! workers), this is computed by Sōzune itself: every proxied request records
//! its wall-clock duration here as it completes. `/metrics` then renders a
//! Prometheus histogram (`sozune_request_duration_seconds`) plus the
//! conventional `_sum` and `_count` series, so a scraper can compute averages
//! and `histogram_quantile`-based percentiles (p50/p95/p99).
//!
//! The hot path (one `record` per request) is lock-free: each bucket, the
//! count, and the summed milliseconds are plain atomics. A scrape reads them
//! with `Ordering::Relaxed` — exact cross-bucket consistency is not required
//! for monitoring, and avoiding a lock keeps the proxy path cheap.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Cumulative upper bounds, in seconds, for the latency histogram. Chosen to
/// cover sub-millisecond proxy overhead through multi-second slow backends.
/// These match the canonical Prometheus client default ladder closely enough
/// to be familiar to operators.
pub const BUCKET_BOUNDS_SECONDS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub type RequestMetricsStore = Arc<RequestMetrics>;

/// Lock-free request-latency histogram. One counter per bucket (each counting
/// observations whose value is `<=` that bucket's bound — i.e. already
/// cumulative on read), plus a total `count` and the summed duration in
/// milliseconds.
#[derive(Debug)]
pub struct RequestMetrics {
    /// Per-bucket observation counts, aligned with [`BUCKET_BOUNDS_SECONDS`].
    /// `buckets[i]` counts observations with `duration <= BUCKET_BOUNDS[i]`.
    buckets: Vec<AtomicU64>,
    /// Total number of observations (the `+Inf` bucket / `_count`).
    count: AtomicU64,
    /// Sum of all observed durations, in milliseconds, to avoid float atomics.
    /// Rendered as seconds (`/ 1000`) in the `_sum` series.
    sum_millis: AtomicU64,
    /// Per-status-class response counters: index 0 = 1xx, 1 = 2xx, 2 = 3xx,
    /// 3 = 4xx, 4 = 5xx, 5 = other (status < 100 or > 599, shouldn't happen).
    status_classes: [AtomicU64; 6],
}

/// Labels for the six status-class counters, aligned with
/// `RequestMetrics::status_classes` / `RequestMetricsSnapshot::status_classes`.
pub const STATUS_CLASS_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Map an HTTP status code to its `status_classes` index.
fn status_class_index(status: u16) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self {
            buckets: BUCKET_BOUNDS_SECONDS
                .iter()
                .map(|_| AtomicU64::new(0))
                .collect(),
            count: AtomicU64::new(0),
            sum_millis: AtomicU64::new(0),
            status_classes: Default::default(),
        }
    }
}

impl RequestMetrics {
    /// Record one completed request: its latency (into the histogram) and its
    /// response status class (into the per-class counters). Increments every
    /// bucket whose bound is `>= duration`, the total count, the running sum,
    /// and the matching status-class counter.
    pub fn record(&self, duration: Duration, status: u16) {
        let secs = duration.as_secs_f64();
        for (i, bound) in BUCKET_BOUNDS_SECONDS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        // Saturating millis: a single request over ~584M years would overflow.
        self.sum_millis
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        self.status_classes[status_class_index(status)].fetch_add(1, Ordering::Relaxed);
    }

    /// Read a consistent-enough snapshot for rendering. Values are read with
    /// `Relaxed` ordering; a concurrent `record` may land between reads, which
    /// is acceptable for monitoring data.
    pub fn snapshot(&self) -> RequestMetricsSnapshot {
        RequestMetricsSnapshot {
            buckets: BUCKET_BOUNDS_SECONDS
                .iter()
                .zip(&self.buckets)
                .map(|(bound, b)| (*bound, b.load(Ordering::Relaxed)))
                .collect(),
            count: self.count.load(Ordering::Relaxed),
            sum_seconds: self.sum_millis.load(Ordering::Relaxed) as f64 / 1000.0,
            status_classes: std::array::from_fn(|i| self.status_classes[i].load(Ordering::Relaxed)),
        }
    }
}

/// Point-in-time view of the histogram, used by both metric renderers.
#[derive(Debug, Clone)]
pub struct RequestMetricsSnapshot {
    /// `(upper_bound_seconds, cumulative_count)` pairs, in ascending bound
    /// order. The `+Inf` bucket equals `count` and is added by the renderer.
    pub buckets: Vec<(f64, u64)>,
    /// Total observations (`_count` and the implicit `+Inf` bucket).
    pub count: u64,
    /// Sum of all observed durations, in seconds (`_sum`).
    pub sum_seconds: f64,
    /// Response counts per status class, aligned with [`STATUS_CLASS_LABELS`]
    /// (`1xx, 2xx, 3xx, 4xx, 5xx, other`).
    pub status_classes: [u64; 6],
}

pub fn new_store() -> RequestMetricsStore {
    Arc::new(RequestMetrics::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn empty_snapshot_is_all_zero() {
        let m = RequestMetrics::default();
        let s = m.snapshot();
        assert_eq!(s.count, 0);
        assert_eq!(s.sum_seconds, 0.0);
        assert!(s.buckets.iter().all(|(_, c)| *c == 0));
        assert_eq!(s.status_classes, [0; 6]);
    }

    #[test]
    fn record_increments_count_and_sum() {
        let m = RequestMetrics::default();
        m.record(ms(20), 200);
        m.record(ms(30), 200);
        let s = m.snapshot();
        assert_eq!(s.count, 2);
        // 50ms total = 0.05s.
        assert!((s.sum_seconds - 0.05).abs() < 1e-9);
    }

    #[test]
    fn buckets_are_cumulative() {
        let m = RequestMetrics::default();
        // 20ms = 0.02s: falls in every bucket with bound >= 0.025.
        m.record(ms(20), 200);
        let s = m.snapshot();
        // bound 0.005 and 0.01 must NOT count it; 0.025 and up must.
        for (bound, c) in &s.buckets {
            if *bound >= 0.025 {
                assert_eq!(*c, 1, "bound {bound} should include 20ms");
            } else {
                assert_eq!(*c, 0, "bound {bound} should exclude 20ms");
            }
        }
    }

    #[test]
    fn fast_request_lands_in_first_bucket() {
        let m = RequestMetrics::default();
        m.record(Duration::from_micros(100), 200); // 0.0001s <= 0.005
        let s = m.snapshot();
        assert_eq!(s.buckets[0].1, 1);
        assert_eq!(s.count, 1);
    }

    #[test]
    fn slow_request_only_in_count_not_top_bucket() {
        let m = RequestMetrics::default();
        m.record(Duration::from_secs(30), 200); // beyond the 10s top bound
        let s = m.snapshot();
        // No finite bucket counts it; only the total count (the +Inf bucket).
        assert!(s.buckets.iter().all(|(_, c)| *c == 0));
        assert_eq!(s.count, 1);
    }

    #[test]
    fn status_classes_are_bucketed_by_first_digit() {
        let m = RequestMetrics::default();
        m.record(ms(1), 200);
        m.record(ms(1), 204);
        m.record(ms(1), 301);
        m.record(ms(1), 404);
        m.record(ms(1), 500);
        m.record(ms(1), 503);
        let s = m.snapshot();
        // [1xx, 2xx, 3xx, 4xx, 5xx, other]
        assert_eq!(s.status_classes, [0, 2, 1, 1, 2, 0]);
        assert_eq!(s.count, 6);
    }

    #[test]
    fn out_of_range_status_goes_to_other() {
        let m = RequestMetrics::default();
        m.record(ms(1), 99);
        m.record(ms(1), 700);
        let s = m.snapshot();
        assert_eq!(s.status_classes[5], 2); // "other"
    }
}
