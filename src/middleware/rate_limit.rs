use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Token bucket rate limiter per source IP
#[derive(Debug)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    average: u64,
    burst: u64,
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
            average,
            burst,
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
                tokens: self.burst as f64,
                last_refill: now,
            });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.average as f64).min(self.burst as f64);
        bucket.last_refill = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitResult::Allowed
        } else {
            RateLimitResult::Limited
        }
    }

    /// Remove stale buckets that haven't been used recently
    pub fn cleanup(&self) {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill).as_secs() < 3600);
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
