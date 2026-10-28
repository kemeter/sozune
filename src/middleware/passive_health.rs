//! Passive health: the backends the middleware stops sending requests to for
//! a while, after several requests in a row got no response from them.
//!
//! Sōzu does the same for the routes it serves itself. Without it, a dead
//! backend behind the middleware keeps its share of requests, each one paying
//! a failed attempt before a retry, until an active health check, when the
//! route has one, takes it out.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Requests in a row a backend gives no response to before it is left out.
pub const MAX_FAILURES: u32 = 3;

/// How long a backend is left out. Past it, the next request it is picked for
/// tries it again: a response brings it back, a failure leaves it out again.
pub const COOLDOWN: Duration = Duration::from_secs(10);

/// How many backends the middleware keeps an account of. Past it, those that
/// are not left out are forgotten: they had failed fewer than
/// [`MAX_FAILURES`] times in a row.
const MAX_TRACKED: usize = 4096;

/// A backend, as the middleware forwards to it.
pub type BackendKey = (String, u16);

#[derive(Default)]
struct BackendState {
    failures: u32,
    down_until: Option<Instant>,
}

/// The failures of every backend the middleware forwards to, whatever its
/// route: shared by the routes a reload rebuilds.
#[derive(Default)]
pub struct PassiveHealth {
    backends: Mutex<HashMap<BackendKey, BackendState>>,
}

impl PassiveHealth {
    /// Whether `backend` is left out now.
    pub fn is_down(&self, backend: &BackendKey) -> bool {
        self.is_down_at(backend, Instant::now())
    }

    /// `backend` answered: it is healthy again.
    pub fn succeeded(&self, backend: &BackendKey) {
        let mut backends = self.lock();
        backends.remove(backend);
    }

    /// `backend` gave no response, a connection failure or a timeout.
    pub fn failed(&self, backend: &BackendKey) {
        self.failed_at(backend, Instant::now());
    }

    fn is_down_at(&self, backend: &BackendKey, now: Instant) -> bool {
        self.lock()
            .get(backend)
            .and_then(|state| state.down_until)
            .is_some_and(|until| now < until)
    }

    fn failed_at(&self, backend: &BackendKey, now: Instant) {
        let mut backends = self.lock();
        if backends.len() >= MAX_TRACKED && !backends.contains_key(backend) {
            backends.retain(|_, state| state.down_until.is_some_and(|until| now < until));
            // Every one of them left out: this backend goes untracked, so
            // neither the memory nor the time under the lock grows.
            if backends.len() >= MAX_TRACKED {
                return;
            }
        }
        let state = backends.entry(backend.clone()).or_default();
        state.failures = state.failures.saturating_add(1);
        if state.failures >= MAX_FAILURES {
            state.down_until = Some(now + COOLDOWN);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BackendKey, BackendState>> {
        // The state is a cache of failures: one a panic left half-written is
        // still usable.
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One attempt on a backend. Settled by its outcome; dropped unsettled, as
/// when the request's deadline cancels it, it counts as a failure: the
/// backend gave no response either.
pub struct Attempt {
    health: std::sync::Arc<PassiveHealth>,
    backend: BackendKey,
    settled: bool,
}

impl Attempt {
    pub fn new(health: std::sync::Arc<PassiveHealth>, backend: BackendKey) -> Self {
        Self {
            health,
            backend,
            settled: false,
        }
    }

    /// The backend answered.
    pub fn succeeded(mut self) {
        self.settled = true;
        self.health.succeeded(&self.backend);
    }

    /// The backend gave no response.
    pub fn failed(mut self) {
        self.settled = true;
        self.health.failed(&self.backend);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.settled {
            self.health.failed(&self.backend);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str) -> BackendKey {
        (host.to_string(), 80)
    }

    #[test]
    fn a_backend_is_left_out_after_failures_in_a_row() {
        let health = PassiveHealth::default();
        let now = Instant::now();
        for _ in 1..MAX_FAILURES {
            health.failed_at(&key("a"), now);
        }
        assert!(!health.is_down_at(&key("a"), now));
        health.failed_at(&key("a"), now);
        assert!(health.is_down_at(&key("a"), now));
        assert!(!health.is_down_at(&key("b"), now));
    }

    #[test]
    fn a_response_brings_a_backend_back() {
        let health = PassiveHealth::default();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES {
            health.failed_at(&key("a"), now);
        }
        health.succeeded(&key("a"));
        assert!(!health.is_down_at(&key("a"), now));
        // Its failures start over.
        health.failed_at(&key("a"), now);
        assert!(!health.is_down_at(&key("a"), now));
    }

    #[test]
    fn no_more_backends_are_tracked_than_the_limit() {
        let health = PassiveHealth::default();
        let now = Instant::now();
        for i in 0..MAX_TRACKED + 10 {
            for _ in 0..MAX_FAILURES {
                health.failed_at(&(format!("10.0.{}.{}", i / 256, i % 256), 80), now);
            }
        }
        assert_eq!(health.lock().len(), MAX_TRACKED);
    }

    #[test]
    fn an_attempt_dropped_unsettled_is_a_failure() {
        let health = std::sync::Arc::new(PassiveHealth::default());
        for _ in 0..MAX_FAILURES {
            drop(Attempt::new(health.clone(), key("a")));
        }
        assert!(health.is_down(&key("a")));
        Attempt::new(health.clone(), key("a")).succeeded();
        assert!(!health.is_down(&key("a")));
    }

    #[test]
    fn past_the_cooldown_one_failure_leaves_it_out_again() {
        let health = PassiveHealth::default();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES {
            health.failed_at(&key("a"), now);
        }
        let later = now + COOLDOWN;
        assert!(!health.is_down_at(&key("a"), later));
        health.failed_at(&key("a"), later);
        assert!(health.is_down_at(&key("a"), later));
    }
}
