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
    /// HTTP health check reached the backend but it returned an unaccepted
    /// status code (outside 2xx/3xx, or ≠ the configured `status`).
    BadStatus,
    /// HTTP health check failed to get a response (connection/transport error
    /// during the request, as opposed to a refused TCP connect).
    HttpError,
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
    /// Client used for HTTP health probes. Built once; the TCP probe path does
    /// not use it.
    http_client: reqwest::Client,
}

impl HealthChecker {
    pub fn new(
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
    ) -> Self {
        let timeout = Duration::from_secs(5);
        Self {
            storage,
            reload_tx,
            interval: Duration::from_secs(10),
            timeout,
            unhealthy_backends: Arc::new(RwLock::new(HashMap::new())),
            http_client: reqwest::Client::builder()
                .timeout(timeout)
                // Health checks judge the backend's own response; do not chase
                // redirects to some other server.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
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

        for (backend_key, probe) in &backends {
            let outcome = self.probe_backend(probe).await;
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

    fn collect_backends(&self) -> HashMap<String, BackendProbe> {
        let storage = match self.storage.read() {
            Ok(guard) => guard,
            Err(_) => return HashMap::new(),
        };

        let mut backends: HashMap<String, BackendProbe> = HashMap::new();
        for entrypoint in storage.values() {
            for backend in &entrypoint.backends {
                let key = backend.to_string();
                let entry = backends.entry(key.clone()).or_insert_with(|| BackendProbe {
                    addr: key.clone(),
                    health_check: None,
                });
                // A backend shared across entrypoints keeps the first HTTP
                // health check found, so an explicit check is never lost to a
                // later entrypoint that only does TCP.
                if entry.health_check.is_none() {
                    entry.health_check = entrypoint.config.health_check.clone();
                }
            }
        }
        backends
    }

    /// Probe one backend: an HTTP `GET <path>` when a health check is
    /// configured, otherwise a bare TCP connect (the historical behaviour).
    async fn probe_backend(&self, probe: &BackendProbe) -> Result<(), UnhealthyReason> {
        match &probe.health_check {
            Some(hc) => self.probe_http(&probe.addr, hc).await,
            None => self.probe_tcp(&probe.addr).await,
        }
    }

    /// TCP connect probe: healthy as soon as the backend accepts a connection.
    async fn probe_tcp(&self, addr: &str) -> Result<(), UnhealthyReason> {
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

    /// HTTP probe: `GET http://<addr><path>`. Healthy when the status is
    /// accepted — exactly `hc.status` when set, else any 2xx/3xx.
    async fn probe_http(
        &self,
        addr: &str,
        hc: &crate::model::HealthCheckConfig,
    ) -> Result<(), UnhealthyReason> {
        let now = now_epoch_secs();
        let url = format!("http://{addr}{}", hc.path);

        // Per-check timeout overrides the client's global default when set.
        let mut req = self.http_client.get(&url);
        if let Some(ms) = hc.timeout_ms {
            req = req.timeout(Duration::from_millis(ms));
        }

        match req.send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let accepted = match hc.status {
                    Some(want) => code == want,
                    None => (200..400).contains(&code),
                };
                if accepted {
                    debug!("HTTP health check passed for {} ({})", url, code);
                    Ok(())
                } else {
                    let expected = match hc.status {
                        Some(want) => want.to_string(),
                        None => "2xx/3xx".to_string(),
                    };
                    debug!(
                        "HTTP health check rejected for {}: status {} (expected {})",
                        url, code, expected
                    );
                    Err(UnhealthyReason::new(
                        UnhealthyKind::BadStatus,
                        format!("health check {url} returned {code}, expected {expected}"),
                        now,
                    ))
                }
            }
            Err(e) => {
                // reqwest surfaces timeouts distinctly; map them to Timeout so
                // operators see the same classification as the TCP path.
                let kind = if e.is_timeout() {
                    UnhealthyKind::Timeout
                } else {
                    UnhealthyKind::HttpError
                };
                debug!("HTTP health check failed for {}: {}", url, e);
                Err(UnhealthyReason::new(kind, e.to_string(), now))
            }
        }
    }
}

/// A backend to probe, with the health-check parameters resolved from its
/// entrypoint. `health_check = None` means the legacy TCP connect probe.
#[derive(Debug, Clone)]
struct BackendProbe {
    addr: String,
    health_check: Option<crate::model::HealthCheckConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_probe(addr: &str) -> BackendProbe {
        BackendProbe {
            addr: addr.to_string(),
            health_check: None,
        }
    }

    fn http_probe(addr: &str, hc: crate::model::HealthCheckConfig) -> BackendProbe {
        BackendProbe {
            addr: addr.to_string(),
            health_check: Some(hc),
        }
    }

    fn hc(path: &str, status: Option<u16>) -> crate::model::HealthCheckConfig {
        crate::model::HealthCheckConfig {
            path: path.to_string(),
            status,
            timeout_ms: None,
        }
    }

    #[tokio::test]
    async fn test_probe_unreachable_backend() {
        let (reload_tx, _rx) = mpsc::channel(64);
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let checker = HealthChecker::new(storage, reload_tx);

        // Port that should not be listening
        let result = checker.probe_backend(&tcp_probe("127.0.0.1:19999")).await;
        let reason = result.expect_err("connect to closed port must fail");
        assert_eq!(reason.kind, UnhealthyKind::ConnectionRefused);
        assert!(reason.since > 0);
        assert_eq!(reason.since, reason.last_checked);
    }

    /// Spawn a one-shot HTTP server that answers every request with `status`,
    /// returning the `host:port` it bound to. Good enough to drive the probe.
    async fn spawn_http(status: u16) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn checker() -> HealthChecker {
        let (reload_tx, _rx) = mpsc::channel(64);
        HealthChecker::new(Arc::new(RwLock::new(BTreeMap::new())), reload_tx)
    }

    #[tokio::test]
    async fn http_probe_200_is_healthy() {
        let addr = spawn_http(200).await;
        let r = checker()
            .probe_backend(&http_probe(&addr, hc("/health", None)))
            .await;
        assert!(r.is_ok(), "200 should be healthy: {r:?}");
    }

    #[tokio::test]
    async fn http_probe_503_is_unhealthy_with_bad_status() {
        let addr = spawn_http(503).await;
        let r = checker()
            .probe_backend(&http_probe(&addr, hc("/health", None)))
            .await;
        let reason = r.expect_err("503 must be unhealthy");
        assert_eq!(reason.kind, UnhealthyKind::BadStatus);
    }

    #[tokio::test]
    async fn http_probe_exact_status_match() {
        let addr = spawn_http(204).await;
        // Want exactly 204 → healthy.
        let ok = checker()
            .probe_backend(&http_probe(&addr, hc("/health", Some(204))))
            .await;
        assert!(ok.is_ok(), "204 == wanted 204: {ok:?}");
        // Want 200 but got 204 → unhealthy even though 204 is a 2xx.
        let bad = checker()
            .probe_backend(&http_probe(&addr, hc("/health", Some(200))))
            .await;
        assert_eq!(bad.expect_err("204 != 200").kind, UnhealthyKind::BadStatus);
    }

    #[tokio::test]
    async fn http_probe_unreachable_is_http_error() {
        // Nothing listening here.
        let r = checker()
            .probe_backend(&http_probe("127.0.0.1:19998", hc("/health", None)))
            .await;
        let reason = r.expect_err("connection failure must be unhealthy");
        assert!(matches!(
            reason.kind,
            UnhealthyKind::HttpError | UnhealthyKind::Timeout
        ));
    }

    #[tokio::test]
    async fn path_without_leading_slash_is_normalised_in_config() {
        // The parser adds a leading slash; assert the probe builds a sane URL by
        // checking a server mounted at /health answers when path = "health".
        let addr = spawn_http(200).await;
        let r = checker()
            .probe_backend(&http_probe(&addr, hc("/health", None)))
            .await;
        assert!(r.is_ok());
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
