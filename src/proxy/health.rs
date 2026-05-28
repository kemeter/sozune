use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::model::Entrypoint;

/// Map of backend `host:port` keys to the reason they were marked down. Shared
/// between [`HealthChecker`] and the API layer so `GET /entrypoints` can return
/// a structured reason instead of just listing addresses.
pub type UnhealthyMap = HashMap<String, UnhealthyReason>;

/// Classification of why a backend probe failed. Derived from the OS error of
/// the failed [`tokio::net::TcpStream::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnhealthyKind {
    ConnectionRefused,
    NoRouteToHost,
    NetworkUnreachable,
    HostUnreachable,
    Timeout,
    DnsFailure,
    Other,
}

impl UnhealthyKind {
    fn from_io_error(err: &io::Error) -> Self {
        use io::ErrorKind;
        match err.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::TimedOut => Self::Timeout,
            ErrorKind::HostUnreachable => Self::HostUnreachable,
            ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            _ => {
                let raw = err.raw_os_error();
                let msg = err.to_string();
                if matches!(raw, Some(113)) || msg.contains("No route to host") {
                    Self::NoRouteToHost
                } else if matches!(raw, Some(101)) || msg.contains("Network is unreachable") {
                    Self::NetworkUnreachable
                } else if msg.contains("Name or service not known")
                    || msg.contains("failed to lookup address")
                {
                    Self::DnsFailure
                } else {
                    Self::Other
                }
            }
        }
    }
}

/// Reason a backend is marked unhealthy plus when it first failed and was
/// last checked. Timestamps are seconds since the Unix epoch.
#[derive(Debug, Clone, Serialize)]
pub struct UnhealthyReason {
    pub kind: UnhealthyKind,
    pub message: String,
    pub since: u64,
    pub last_checked: u64,
}

impl UnhealthyReason {
    fn new(kind: UnhealthyKind, message: String, now: u64) -> Self {
        Self {
            kind,
            message,
            since: now,
            last_checked: now,
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Active health checker that probes backends and triggers reload when status changes
pub struct HealthChecker {
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    interval: Duration,
    timeout: Duration,
    unhealthy_backends: Arc<RwLock<UnhealthyMap>>,
}

impl HealthChecker {
    pub fn new(
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
    ) -> Self {
        Self {
            storage,
            reload_tx,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            unhealthy_backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn unhealthy_backends(&self) -> Arc<RwLock<UnhealthyMap>> {
        Arc::clone(&self.unhealthy_backends)
    }

    pub async fn run(&self) {
        let mut interval = tokio::time::interval(self.interval);
        loop {
            interval.tick().await;
            self.check_all_backends().await;
        }
    }

    async fn check_all_backends(&self) {
        let backends = self.collect_backends();
        if backends.is_empty() {
            return;
        }

        let mut changed = false;

        for (backend_key, addr) in &backends {
            let outcome = self.probe_backend(addr).await;
            let now = now_epoch_secs();

            let mut unhealthy = match self.unhealthy_backends.write() {
                Ok(guard) => guard,
                Err(_) => continue,
            };

            match outcome {
                Ok(()) => {
                    if unhealthy.remove(backend_key).is_some() {
                        info!("Backend {} is back up", backend_key);
                        changed = true;
                    }
                }
                Err(mut reason) => {
                    if let Some(existing) = unhealthy.get_mut(backend_key) {
                        let kind_changed = existing.kind != reason.kind;
                        existing.kind = reason.kind;
                        existing.message = reason.message;
                        existing.last_checked = now;
                        if kind_changed {
                            warn!(
                                "Backend {} still down, reason changed to {:?}: {}",
                                backend_key, existing.kind, existing.message
                            );
                            changed = true;
                        }
                    } else {
                        reason.since = now;
                        reason.last_checked = now;
                        warn!(
                            "Backend {} is down ({:?}): {}",
                            backend_key, reason.kind, reason.message
                        );
                        unhealthy.insert(backend_key.clone(), reason);
                        changed = true;
                    }
                }
            }
        }

        // Drop backends that no longer exist in storage so the unhealthy map
        // doesn't grow unbounded after entrypoint removal.
        if let Ok(mut unhealthy) = self.unhealthy_backends.write() {
            let live: HashSet<&String> = backends.keys().collect();
            unhealthy.retain(|k, _| live.contains(k));
        }

        if changed && let Err(e) = self.reload_tx.send(()).await {
            error!(
                "could not apply configuration update; will retry on next change: {}",
                e
            );
        }
    }

    fn collect_backends(&self) -> HashMap<String, String> {
        let storage = match self.storage.read() {
            Ok(guard) => guard,
            Err(_) => return HashMap::new(),
        };

        let mut backends = HashMap::new();
        for entrypoint in storage.values() {
            for backend in &entrypoint.backends {
                let key = backend.to_string();
                backends.insert(key.clone(), key);
            }
        }
        backends
    }

    async fn probe_backend(&self, addr: &str) -> Result<(), UnhealthyReason> {
        let now = now_epoch_secs();
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Health check passed for {}", addr);
                Ok(())
            }
            Ok(Err(e)) => {
                debug!("Health check failed for {}: {}", addr, e);
                Err(UnhealthyReason::new(
                    UnhealthyKind::from_io_error(&e),
                    e.to_string(),
                    now,
                ))
            }
            Err(_) => {
                debug!("Health check timed out for {}", addr);
                Err(UnhealthyReason::new(
                    UnhealthyKind::Timeout,
                    format!("connect timed out after {:?}", self.timeout),
                    now,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_unreachable_backend() {
        let (reload_tx, _rx) = mpsc::channel(64);
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let checker = HealthChecker::new(storage, reload_tx);

        // Port that should not be listening
        let result = checker.probe_backend("127.0.0.1:19999").await;
        let reason = result.expect_err("connect to closed port must fail");
        assert_eq!(reason.kind, UnhealthyKind::ConnectionRefused);
        assert!(reason.since > 0);
        assert_eq!(reason.since, reason.last_checked);
    }

    #[test]
    fn test_unhealthy_map_starts_empty() {
        let unhealthy: UnhealthyMap = HashMap::new();
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_kind_from_io_error_classifies_route_113() {
        let err = io::Error::from_raw_os_error(113);
        let kind = UnhealthyKind::from_io_error(&err);
        // Linux maps 113 -> EHOSTUNREACH. Newer std maps it to HostUnreachable;
        // older std reports it as Uncategorized + raw_os_error(113). Accept either.
        assert!(matches!(
            kind,
            UnhealthyKind::HostUnreachable | UnhealthyKind::NoRouteToHost
        ));
    }

    #[test]
    fn test_kind_from_io_error_refused() {
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(
            UnhealthyKind::from_io_error(&err),
            UnhealthyKind::ConnectionRefused
        );
    }

    #[test]
    fn test_kind_from_io_error_dns_failure() {
        let err = io::Error::other("failed to lookup address information: nope");
        assert_eq!(
            UnhealthyKind::from_io_error(&err),
            UnhealthyKind::DnsFailure
        );
    }
}
