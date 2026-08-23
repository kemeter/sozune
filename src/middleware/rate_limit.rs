use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use tracing::warn;

use crate::middleware::ip_allow_list::{TrustedProxies, resolve_client_ip};

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;

/// Token bucket rate limiter per source IP. `average` is the sustained refill
/// rate (tokens per second, fractional) and `burst` the bucket capacity.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    average: f64,
    burst: f64,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// How many sources a limiter tracks before it sweeps the idle ones.
///
/// The map holds one bucket per source, so without a bound it grows for every
/// address ever seen — on a public port, unbounded growth driven by
/// unauthenticated traffic. Sweeping when the map crosses this mark keeps that
/// finite while leaving ordinary traffic untouched: a proxy fronting a few
/// thousand clients never reaches it.
const MAX_TRACKED_SOURCES: usize = 10_000;

/// How long a bucket survives without being used.
const BUCKET_IDLE_TTL_SECS: u64 = 3600;

/// Result of a rate limit check
pub enum RateLimitResult {
    Allowed,
    Limited,
}

impl RateLimiter {
    pub fn new(average: u64, burst: u64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            average: average as f64,
            burst: burst as f64,
        }
    }

    /// Build a limiter from a connection-rate spec: allow `max_conns` per
    /// `per_seconds` window. The sustained rate is `max_conns / per_seconds`
    /// tokens/s and the bucket capacity is `max_conns`, so a full burst of
    /// `max_conns` is absorbed at once, then refills at the sustained rate.
    /// `per_seconds == 0` is treated as 1 to avoid a divide-by-zero.
    pub fn with_rate(max_conns: u32, per_seconds: u32) -> Self {
        let per = per_seconds.max(1) as f64;
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            average: max_conns as f64 / per,
            burst: max_conns as f64,
        }
    }

    /// Check if a request from the given source IP is allowed
    pub fn check(&self, source_ip: &str) -> RateLimitResult {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return RateLimitResult::Allowed, // fail open
        };

        let now = Instant::now();

        // Sweep before inserting, so a flood of one-shot sources cannot push
        // the map past the cap.
        if buckets.len() >= MAX_TRACKED_SOURCES {
            // Idle buckets first: nothing is lost by forgetting a source that
            // has not been seen in an hour.
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_refill).as_secs() < BUCKET_IDLE_TTL_SECS
            });

            // A flood of fresh addresses leaves nothing idle to drop, so age
            // alone cannot hold the line. Drop the buckets that have spent
            // little: forgetting a source at full tokens grants it nothing,
            // while a source under its limit — the one the limiter exists to
            // hold back — keeps its depleted bucket.
            //
            // One pass over the map, keeping whatever is below half its
            // capacity. Sorting every key instead cost a millisecond under the
            // lock every request on the route waits on, which a distributed
            // flood can trigger over and over.
            if buckets.len() >= MAX_TRACKED_SOURCES {
                let spent_enough = self.burst / 2.0;
                buckets.retain(|_, bucket| bucket.tokens < spent_enough);

                // Still full: every source is at or near its burst, so none is
                // being held back and the map can start over. Better a moment
                // of amnesia than a map that grows without bound.
                if buckets.len() >= MAX_TRACKED_SOURCES {
                    buckets.clear();
                }
            }
        }

        let bucket = buckets
            .entry(source_ip.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.burst,
                last_refill: now,
            });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.average).min(self.burst);
        bucket.last_refill = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitResult::Allowed
        } else {
            RateLimitResult::Limited
        }
    }

    /// How many sources are currently tracked. Test-only: the sweep runs
    /// inside `check`, so nothing in the runtime needs to ask.
    #[cfg(test)]
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Forget the sources that have not been seen in a while. `check` does
    /// this itself once the map crosses `MAX_TRACKED_SOURCES`; this exposes
    /// the same sweep on its own.
    #[cfg(test)]
    pub fn cleanup(&self) {
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs() < BUCKET_IDLE_TTL_SECS
        });
    }
}

/// The identity a bucket is charged to.
///
/// Goes through `resolve_client_ip`, so `X-Forwarded-For` is only believed
/// when the peer is a trusted proxy. Keying on the leftmost entry — which the
/// client writes — handed every request a fresh bucket, so the limiter never
/// fired, and each forged value left a permanent map entry behind.
fn source_key(req: &Request<Body>, ctx: &RequestCtx, trusted: &TrustedProxies) -> String {
    match resolve_client_ip(req, ctx, trusted) {
        Some(ip) => ip.to_string(),
        // No peer and nothing trustworthy to read: charge the hostname, so a
        // route still has one shared bucket rather than none at all.
        None => ctx.host.clone(),
    }
}

/// Middleware wrapper: short-circuits with a 429-equivalent diagnostic when
/// the source IP exceeds its bucket. Behavior matches the previous inline
/// rate-limit step in `handle_proxy`.
pub struct RateLimitMiddleware {
    limiter: RateLimiter,
    trusted: TrustedProxies,
}

impl RateLimitMiddleware {
    pub fn new(limiter: RateLimiter, trusted: TrustedProxies) -> Self {
        Self { limiter, trusted }
    }
}

#[async_trait::async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        let source_ip = source_key(req, ctx, &self.trusted);

        if matches!(self.limiter.check(&source_ip), RateLimitResult::Limited) {
            warn!("Rate limited request from {} to {}", source_ip, ctx.host);
            return Flow::ShortCircuit(diag::rate_limited(&ctx.host));
        }
        Flow::Continue
    }
}

#[cfg(test)]
mod growth_tests {
    use super::*;

    /// `cleanup` existed, carried a comment describing the very leak it was
    /// meant to prevent, and was marked `#[allow(dead_code)]` — nothing ever
    /// called it. One bucket per source seen, kept forever: on a public port
    /// that is unbounded growth from unauthenticated traffic.
    #[test]
    fn buckets_do_not_accumulate_for_every_source_ever_seen() {
        let limiter = RateLimiter::new(1000, 1000);

        // Past the cap, so the sweep has to have run for the map to stay under.
        for n in 0..(MAX_TRACKED_SOURCES + 5_000) {
            limiter.check(&format!("10.{}.{}.{}", n / 65536, (n / 256) % 256, n % 256));
        }

        assert!(
            limiter.bucket_count() <= MAX_TRACKED_SOURCES,
            "tracked {} sources, cap is {}",
            limiter.bucket_count(),
            MAX_TRACKED_SOURCES
        );
    }

    /// The sweep runs under the global mutex, so whatever it costs is a stall
    /// every request on the route pays, and a distributed flood can trigger it
    /// over and over. Sorting meant cloning all 10k keys into a vector first;
    /// deciding per bucket needs neither the copy nor the ordering.
    ///
    /// Asserted on behaviour rather than on a stopwatch: a timing bound that
    /// fits release is exceeded three times over in debug, and the ratio
    /// between a sweeping and a non-sweeping check is too noisy to separate
    /// the two shapes. What holds either way is that a sweep leaves the map
    /// under the cap in one pass, so no second sweep is queued behind it.
    #[test]
    fn one_sweep_is_enough_to_get_back_under_the_cap() {
        let limiter = RateLimiter::new(0, 10);

        for n in 0..MAX_TRACKED_SOURCES {
            limiter.check(&format!("10.{}.{}.{}", n / 65536, (n / 256) % 256, n % 256));
        }

        limiter.check("203.0.113.7");

        assert!(
            limiter.bucket_count() < MAX_TRACKED_SOURCES,
            "still {} sources after a sweep: the next check sweeps again",
            limiter.bucket_count()
        );
    }

    /// Eviction picks the buckets closest to full, so what it forgets are the
    /// sources that have spent nothing — forgetting those grants them nothing.
    /// A depleted bucket, the one the limiter exists to hold back, outlives a
    /// full one.
    #[test]
    fn eviction_forgets_the_sources_that_spent_nothing_first() {
        let limiter = RateLimiter::new(0, 10);

        // Spend this one down to empty.
        for _ in 0..10 {
            limiter.check("203.0.113.7");
        }

        // Every flooding source spends one of its ten tokens, so each sits at
        // nine — above the depleted one, and dropped ahead of it.
        for n in 0..(MAX_TRACKED_SOURCES + 5_000) {
            limiter.check(&format!("10.{}.{}.{}", n / 65536, (n / 256) % 256, n % 256));
        }

        assert!(
            matches!(limiter.check("203.0.113.7"), RateLimitResult::Limited),
            "an emptied bucket must outlive the full ones a flood creates"
        );
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::middleware::ip_allow_list::TrustedProxies;
    use std::net::SocketAddr;

    fn ctx(peer: &str) -> RequestCtx {
        RequestCtx {
            host: "app.example.com".to_string(),
            client_addr: Some(peer.parse::<SocketAddr>().unwrap()),
            is_tls: false,
            method: axum::http::Method::GET,
            path: "/".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        }
    }

    /// The limiter keyed on the leftmost `X-Forwarded-For` entry, which the
    /// client writes. A fresh forged value per request meant a fresh bucket per
    /// request: the limiter never fired, and every forged value also added a
    /// permanent map entry, so unauthenticated traffic grew memory without
    /// bound. `ip_allow_list` already had the answer — only believe the header
    /// when the peer is a trusted proxy.
    #[test]
    fn a_forged_header_does_not_buy_a_fresh_bucket() {
        let trusted = TrustedProxies::new(&[]);
        let ctx = ctx("203.0.113.7:5000");

        let first = source_key(&header("1.2.3.4"), &ctx, &trusted);
        let second = source_key(&header("5.6.7.8"), &ctx, &trusted);

        assert_eq!(
            first, second,
            "with no trusted proxy the peer is the client, whatever the header says"
        );
        assert_eq!(first, "203.0.113.7");
    }

    /// Behind a proxy we do trust, the header is how the real client is known,
    /// so it must still be honoured — read right to left, as `resolve_client_ip`
    /// does.
    #[test]
    fn a_trusted_proxy_s_header_is_still_honoured() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let ctx = ctx("10.0.0.9:5000");

        assert_eq!(
            source_key(&header("203.0.113.7"), &ctx, &trusted),
            "203.0.113.7"
        );
    }

    fn header(value: &str) -> Request<Body> {
        Request::builder()
            .header("x-forwarded-for", value)
            .body(Body::empty())
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_within_limit() {
        let limiter = RateLimiter::new(10, 10);

        for _ in 0..10 {
            assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Allowed));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(10, 5);

        // Consume all 5 burst tokens
        for _ in 0..5 {
            assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Allowed));
        }

        // 6th request should be limited
        assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Limited));
    }

    #[test]
    fn test_separate_buckets_per_ip() {
        let limiter = RateLimiter::new(10, 2);

        // Exhaust IP 1
        assert!(matches!(limiter.check("1.1.1.1"), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("1.1.1.1"), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("1.1.1.1"), RateLimitResult::Limited));

        // IP 2 should still work
        assert!(matches!(limiter.check("2.2.2.2"), RateLimitResult::Allowed));
    }

    #[test]
    fn test_tokens_refill() {
        let limiter = RateLimiter::new(1000, 1);

        // Use the one token
        assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Limited));

        // Manually advance the bucket's last_refill
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            let bucket = buckets.get_mut("1.2.3.4").unwrap();
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(1);
        }

        // Should be allowed again after refill
        assert!(matches!(limiter.check("1.2.3.4"), RateLimitResult::Allowed));
    }

    #[test]
    fn test_cleanup_removes_stale() {
        let limiter = RateLimiter::new(10, 10);

        limiter.check("1.2.3.4");
        assert_eq!(limiter.buckets.lock().unwrap().len(), 1);

        // Make the bucket stale
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            let bucket = buckets.get_mut("1.2.3.4").unwrap();
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(7200);
        }

        limiter.cleanup();
        assert_eq!(limiter.buckets.lock().unwrap().len(), 0);
    }
}
