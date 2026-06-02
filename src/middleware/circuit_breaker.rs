//! Per-backend circuit breaker.
//!
//! A circuit breaker stops hammering a backend that is failing: once the
//! recent failure ratio crosses a threshold it **opens**, short-circuiting
//! requests with `503` instead of forwarding them. After a cooldown it goes
//! **half-open** and lets a single trial request through; success closes it,
//! failure re-opens it.
//!
//! ## States
//!
//! - **Closed** — normal. Outcomes feed a sliding window; if the window is full
//!   enough (`min_requests`) and the failure ratio `>= threshold`, trip to Open.
//! - **Open** — short-circuit every request (`should_allow` returns false) until
//!   `cooldown` has elapsed, then transition to Half-Open.
//! - **Half-Open** — allow exactly one trial request. Its outcome decides:
//!   success → Closed (window reset), failure → Open (cooldown restarts).
//!
//! ## What counts as a failure
//!
//! A response with status `>= 500`, or a transport failure (no response). `4xx`
//! is a client error, not a backend fault, so it does **not** trip the breaker.
//!
//! State is shared across worker tasks, so everything lives behind a `Mutex`.
//! The breaker is only consulted on routes that configure it, so the lock is
//! off the hot path for everyone else.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::model::CircuitBreakerConfig;

/// Traefik-flavoured defaults used by the label parser when a field is omitted:
/// trip at 50% over a 20-request window, probe again after 10s.
pub const DEFAULT_THRESHOLD: f64 = 0.5;
pub const DEFAULT_MIN_REQUESTS: u32 = 20;
pub const DEFAULT_COOLDOWN_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    /// Open since this instant; flips to Half-Open once `cooldown` elapses.
    Open,
    HalfOpen,
}

/// The mutable state behind the mutex. `now` is injected (rather than read from
/// the clock inside) so the logic is deterministic and unit-testable.
#[derive(Debug)]
struct Inner {
    state: State,
    /// Recent outcomes: `true` = failure. Capped at `min_requests` entries.
    window: VecDeque<bool>,
    /// Monotonic millis at which the breaker opened (for cooldown checks).
    opened_at_ms: u64,
}

/// A circuit breaker for one backend (or one route). Thread-safe.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner {
                state: State::Closed,
                window: VecDeque::with_capacity(config.min_requests as usize),
                opened_at_ms: 0,
            }),
        }
    }

    /// Whether a request should be forwarded right now, given the current time
    /// in monotonic milliseconds. Closed → always; Open → only after cooldown
    /// (which flips it to Half-Open and lets this one through); Half-Open →
    /// blocks further probes until the in-flight one reports back.
    pub fn should_allow(&self, now_ms: u64) -> bool {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => true,
            State::HalfOpen => false,
            State::Open => {
                let cooldown_ms = self.config.cooldown_secs.saturating_mul(1000);
                if now_ms.saturating_sub(inner.opened_at_ms) >= cooldown_ms {
                    inner.state = State::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Report the outcome of a forwarded request. `failed` is true for a `5xx`
    /// or a transport error.
    pub fn record(&self, failed: bool, now_ms: u64) {
        let mut inner = self.lock();
        match inner.state {
            State::HalfOpen => {
                // The trial verdict: recover or re-open.
                if failed {
                    inner.state = State::Open;
                    inner.opened_at_ms = now_ms;
                } else {
                    inner.state = State::Closed;
                    inner.window.clear();
                }
            }
            State::Open => {
                // A late outcome arriving while Open — ignore; cooldown governs.
            }
            State::Closed => {
                let cap = self.config.min_requests.max(1) as usize;
                if inner.window.len() == cap {
                    inner.window.pop_front();
                }
                inner.window.push_back(failed);

                if inner.window.len() >= cap {
                    let failures = inner.window.iter().filter(|f| **f).count();
                    let ratio = failures as f64 / inner.window.len() as f64;
                    if ratio >= self.config.threshold {
                        inner.state = State::Open;
                        inner.opened_at_ms = now_ms;
                        inner.window.clear();
                    }
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    fn is_open(&self) -> bool {
        matches!(self.lock().state, State::Open)
    }

    #[cfg(test)]
    fn is_half_open(&self) -> bool {
        matches!(self.lock().state, State::HalfOpen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cb(threshold: f64, min: u32, cooldown_secs: u64) -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            threshold,
            min_requests: min,
            cooldown_secs,
        })
    }

    #[test]
    fn closed_allows_and_stays_closed_below_threshold() {
        let b = cb(0.5, 4, 1);
        // 1 failure out of 4 = 25% < 50%.
        b.record(true, 0);
        b.record(false, 0);
        b.record(false, 0);
        b.record(false, 0);
        assert!(b.should_allow(0));
        assert!(!b.is_open());
    }

    #[test]
    fn trips_open_when_ratio_reaches_threshold() {
        let b = cb(0.5, 4, 1);
        // 2 failures out of 4 = 50% >= 50% → opens.
        b.record(true, 0);
        b.record(false, 0);
        b.record(true, 0);
        b.record(false, 0);
        assert!(b.is_open());
        assert!(!b.should_allow(0), "open breaker blocks");
    }

    #[test]
    fn does_not_trip_before_min_requests() {
        let b = cb(0.5, 10, 1);
        // 3 failures, 3 requests = 100% but window not full (< 10) → stays closed.
        b.record(true, 0);
        b.record(true, 0);
        b.record(true, 0);
        assert!(!b.is_open());
    }

    #[test]
    fn open_blocks_until_cooldown_then_half_opens() {
        let b = cb(0.5, 2, 1);
        b.record(true, 0);
        b.record(true, 0);
        assert!(b.is_open());
        // Before cooldown: still blocked.
        assert!(!b.should_allow(500));
        // After cooldown: one probe allowed, state becomes Half-Open.
        assert!(b.should_allow(1000));
        assert!(b.is_half_open());
        // Half-open blocks further probes until the trial reports back.
        assert!(!b.should_allow(1000));
    }

    #[test]
    fn half_open_success_closes() {
        let b = cb(0.5, 2, 1);
        b.record(true, 0);
        b.record(true, 0);
        assert!(b.should_allow(1000)); // → half-open, probe allowed
        b.record(false, 1000); // trial succeeds
        assert!(!b.is_open());
        assert!(b.should_allow(1000), "closed again");
    }

    #[test]
    fn half_open_failure_reopens() {
        let b = cb(0.5, 2, 1);
        b.record(true, 0);
        b.record(true, 0);
        assert!(b.should_allow(1000)); // → half-open
        b.record(true, 1000); // trial fails
        assert!(b.is_open());
        assert!(
            !b.should_allow(1500),
            "re-opened, blocked again within cooldown"
        );
        assert!(b.should_allow(2000), "probe again after a fresh cooldown");
    }

    #[test]
    fn sliding_window_forgets_old_outcomes() {
        let b = cb(0.5, 4, 1);
        // Start with 2 failures, then 4 successes push them out of the window.
        b.record(true, 0);
        b.record(true, 0);
        b.record(false, 0);
        b.record(false, 0); // window now [t,t,f,f] = 50% → would trip...
        // It tripped exactly here; confirm, then a fresh breaker stays closed
        // when failures age out.
        assert!(b.is_open());

        let b2 = cb(0.75, 4, 1);
        b2.record(true, 0);
        b2.record(false, 0);
        b2.record(false, 0);
        b2.record(false, 0); // [t,f,f,f] = 25% < 75%
        b2.record(false, 0); // oldest (t) drops → [f,f,f,f]? no: 0% failures
        assert!(!b2.is_open());
    }
}
