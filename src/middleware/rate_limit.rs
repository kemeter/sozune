use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use tracing::warn;

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

    /// Remove stale buckets that haven't been used recently. Exercised by
    /// the rate_limit tests; not yet wired into the runtime — should be
    /// called periodically (every minute or so) to prevent unbounded growth
    /// when many ephemeral clients hit the limiter.
    #[allow(dead_code)]
    pub fn cleanup(&self) {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill).as_secs() < 3600);
    }
}

/// Middleware wrapper: short-circuits with a 429-equivalent diagnostic when
/// the source IP exceeds its bucket. Behavior matches the previous inline
/// rate-limit step in `handle_proxy`.
pub struct RateLimitMiddleware {
    limiter: RateLimiter,
}

impl RateLimitMiddleware {
    pub fn new(limiter: RateLimiter) -> Self {
        Self { limiter }
    }
}

#[async_trait::async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // Prefer the leftmost X-Forwarded-For entry; fall back to the host,
        // matching the prior inline behavior.
        let source_ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| ctx.host.clone());

        if matches!(self.limiter.check(&source_ip), RateLimitResult::Limited) {
            warn!("Rate limited request from {} to {}", source_ip, ctx.host);
            return Flow::ShortCircuit(diag::rate_limited(&ctx.host));
        }
        Flow::Continue
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
