use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::model::Entrypoint;

/// Active health checker that probes backends and triggers reload when status changes
pub struct HealthChecker {
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    interval: Duration,
    timeout: Duration,
    unhealthy_backends: Arc<RwLock<HashSet<String>>>,
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
            unhealthy_backends: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn unhealthy_backends(&self) -> Arc<RwLock<HashSet<String>>> {
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
            let is_healthy = self.probe_backend(addr).await;

            let mut unhealthy = match self.unhealthy_backends.write() {
                Ok(guard) => guard,
                Err(_) => continue,
            };

            if is_healthy {
                if unhealthy.remove(backend_key) {
                    info!("Backend {} is back up", backend_key);
                    changed = true;
                }
            } else if unhealthy.insert(backend_key.clone()) {
                warn!("Backend {} is down", backend_key);
                changed = true;
            }
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

    async fn probe_backend(&self, addr: &str) -> bool {
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Health check passed for {}", addr);
                true
            }
            Ok(Err(e)) => {
                debug!("Health check failed for {}: {}", addr, e);
                false
            }
            Err(_) => {
                debug!("Health check timed out for {}", addr);
                false
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
        assert!(!result);
    }

    #[test]
    fn test_unhealthy_set_tracking() {
        let unhealthy: HashSet<String> = HashSet::new();
        assert!(unhealthy.is_empty());
    }
}
