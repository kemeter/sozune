use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use tracing::warn;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;

/// Counts concurrent in-flight requests per source IP and caps them at `max`.
///
/// A slot is acquired on request entry ([`try_acquire`](Self::try_acquire)) and
/// released when the returned [`InFlightGuard`] is dropped. The proxy handler
/// has many return paths, so the guard is stored in the request context and
/// released on `Drop` — never relying on a response-phase hook.
#[derive(Debug)]
pub struct InFlightLimiter {
    counts: Arc<Mutex<HashMap<String, usize>>>,
    max: usize,
}

impl InFlightLimiter {
    pub fn new(max: u64) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            max: max as usize,
        }
    }

    /// Try to reserve a slot for `ip`. Returns `Some(guard)` when a slot was
    /// taken (the guard releases it on drop) or `None` when the IP is already
    /// at its limit. Fails open: a poisoned lock returns a no-op guard so the
    /// request is allowed through rather than wedged.
    pub fn try_acquire(&self, ip: &str) -> Option<InFlightGuard> {
        let mut counts = match self.counts.lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Fail open: allow the request, hand back a guard that does
                // nothing on drop so we don't touch the poisoned map.
                return Some(InFlightGuard {
                    counts: None,
                    ip: ip.to_string(),
                });
            }
        };

        let current = counts.get(ip).copied().unwrap_or(0);
        if current >= self.max {
            return None;
        }

        counts.insert(ip.to_string(), current + 1);
        Some(InFlightGuard {
            counts: Some(Arc::clone(&self.counts)),
            ip: ip.to_string(),
        })
    }
}

/// RAII guard that decrements the per-IP in-flight count when dropped. Lives in
/// [`RequestCtx`] so it is released exactly once, on every return path of the
/// proxy handler.
pub struct InFlightGuard {
    /// `None` when the guard is a no-op (acquired under a poisoned lock).
    counts: Option<Arc<Mutex<HashMap<String, usize>>>>,
    ip: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let Some(counts) = self.counts.as_ref() else {
            return;
        };
        let mut counts = match counts.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if let Some(current) = counts.get(&self.ip).copied() {
            if current <= 1 {
                // Remove the entry at zero so the map doesn't grow unbounded
                // with one key per IP ever seen.
                counts.remove(&self.ip);
            } else {
                counts.insert(self.ip.clone(), current - 1);
            }
        }
    }
}

/// Middleware wrapper: short-circuits with a 503 diagnostic when the source IP
/// already has `max` requests in flight. On success it pushes the slot guard
/// into the request context so the slot is held for the request's lifetime.
pub struct InFlightReqMiddleware {
    limiter: InFlightLimiter,
    trusted: super::ip_allow_list::TrustedProxies,
}

impl InFlightReqMiddleware {
    pub fn new(limiter: InFlightLimiter, trusted: super::ip_allow_list::TrustedProxies) -> Self {
        Self { limiter, trusted }
    }
}

#[async_trait::async_trait]
impl Middleware for InFlightReqMiddleware {
    fn name(&self) -> &'static str {
        "in-flight-req"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // The client as the rate limit resolves it, `trusted_proxies` applied.
        let source_ip = super::rate_limit::source_key(req, ctx, &self.trusted);

        match self.limiter.try_acquire(&source_ip) {
            Some(guard) => {
                ctx.in_flight_guards.push(guard);
                Flow::Continue
            }
            None => {
                warn!(
                    "Too many in-flight requests from {} to {}",
                    source_ip, ctx.host
                );
                Flow::ShortCircuit(diag::too_many_in_flight(&ctx.host))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_within_limit() {
        let limiter = InFlightLimiter::new(3);

        let _g1 = limiter.try_acquire("1.2.3.4");
        let _g2 = limiter.try_acquire("1.2.3.4");
        let g3 = limiter.try_acquire("1.2.3.4");

        assert!(_g1.is_some());
        assert!(_g2.is_some());
        assert!(g3.is_some());
    }

    #[test]
    fn test_blocks_at_limit() {
        let limiter = InFlightLimiter::new(2);

        let _g1 = limiter.try_acquire("1.2.3.4");
        let _g2 = limiter.try_acquire("1.2.3.4");

        // Third concurrent request is rejected.
        assert!(limiter.try_acquire("1.2.3.4").is_none());
    }

    #[test]
    fn test_separate_counters_per_ip() {
        let limiter = InFlightLimiter::new(1);

        let _g1 = limiter.try_acquire("1.1.1.1");
        assert!(limiter.try_acquire("1.1.1.1").is_none());

        // A different IP has its own counter.
        assert!(limiter.try_acquire("2.2.2.2").is_some());
    }

    #[test]
    fn test_guard_drop_releases_slot() {
        let limiter = InFlightLimiter::new(2);

        let g1 = limiter.try_acquire("1.2.3.4");
        let _g2 = limiter.try_acquire("1.2.3.4");

        // At the limit.
        assert!(limiter.try_acquire("1.2.3.4").is_none());

        // Drop one guard, freeing a slot.
        drop(g1);
        assert!(limiter.try_acquire("1.2.3.4").is_some());
    }

    #[test]
    fn test_entry_removed_when_count_hits_zero() {
        let limiter = InFlightLimiter::new(5);

        let g1 = limiter.try_acquire("1.2.3.4");
        assert_eq!(limiter.counts.lock().unwrap().len(), 1);

        drop(g1);
        // Dropping the last guard for an IP removes its map entry.
        assert!(limiter.counts.lock().unwrap().is_empty());
    }

    /// The client is the address Sōzu saw, not what it claims in
    /// `X-Forwarded-For`: a forged leftmost entry gets no slot of its own.
    #[tokio::test]
    async fn the_client_cannot_pick_its_own_slot() {
        let middleware = InFlightReqMiddleware::new(
            InFlightLimiter::new(1),
            super::super::ip_allow_list::TrustedProxies::new(&[]),
        );
        let request = |forged: &str| {
            Request::builder()
                .uri("/")
                .header("x-forwarded-for", format!("{forged}, 203.0.113.7"))
                .body(Body::empty())
                .unwrap()
        };
        let ctx = || RequestCtx {
            host: "example.com".to_string(),
            client_addr: Some("127.0.0.1:40000".parse().unwrap()),
            is_tls: false,
            method: axum::http::Method::GET,
            path: "/".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        };
        let mut first = ctx();
        assert!(matches!(
            middleware
                .on_request(&mut first, &mut request("10.0.0.1"))
                .await,
            Flow::Continue
        ));
        // Same client, another forged entry: still its one slot, taken.
        assert!(matches!(
            middleware
                .on_request(&mut ctx(), &mut request("10.0.0.2"))
                .await,
            Flow::ShortCircuit(_)
        ));
    }
}
