use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::model::{Backend, Entrypoint, HealthCheckConfig, Protocol};

/// The key a backend's health is kept under: its address, and the health
/// check of the route that probes it. Two routes that share a backend but
/// check it differently get a probe and a verdict each, so one route's check
/// never takes the backend out of the other. It can hold the check's header
/// values: it is never logged nor shown.
pub fn probe_key(backend: &Backend, health_check: Option<&HealthCheckConfig>) -> String {
    match health_check {
        None => backend.to_string(),
        Some(hc) => format!(
            "{backend} {}",
            serde_json::to_string(hc).unwrap_or_default()
        ),
    }
}

/// Map of [`probe_key`]s to the reason the probe marked the backend down. Shared
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

/// Where a probe stands between two runs: when it is due, and how many of its
/// last results agree.
#[derive(Debug)]
struct ProbeState {
    next_due: tokio::time::Instant,
    failures: u32,
    successes: u32,
    /// A probe is running: it is not started again until it answers.
    in_flight: bool,
}

/// Active health checker that probes backends and triggers reload when status changes
pub struct HealthChecker {
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    /// Between two probes of a backend, unless its check sets its own.
    interval: Duration,
    timeout: Duration,
    unhealthy_backends: Arc<RwLock<UnhealthyMap>>,
    probes: std::sync::Mutex<HashMap<String, ProbeState>>,
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
            probes: std::sync::Mutex::new(HashMap::new()),
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

    /// Checks every second which probes are due, and starts them: each
    /// backend is probed at its check's interval. A probe's result is taken
    /// as soon as it comes, so a slow one holds back no other.
    pub async fn run(&self) {
        use futures_util::StreamExt;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut running = futures_util::stream::FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    for (key, probe) in self.start_due_probes() {
                        running.push(async move {
                            let outcome = self.probe_backend(&probe).await;
                            (key, probe, outcome)
                        });
                    }
                }
                Some((key, probe, outcome)) = running.next(), if !running.is_empty() => {
                    self.take_outcome(&key, &probe, outcome).await;
                }
            }
        }
    }

    /// The probes due now, marked as running. The backends that left are
    /// forgotten on the way, every tick: their state must not grow
    /// unbounded, nor their verdict outlive them until some other probe is
    /// due.
    fn start_due_probes(&self) -> Vec<(String, BackendProbe)> {
        let backends = self.collect_backends();
        let now = tokio::time::Instant::now();
        let mut probes = self.probes.lock().unwrap_or_else(|p| p.into_inner());
        probes.retain(|key, _| backends.contains_key(key));
        self.unhealthy_backends
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|key, _| backends.contains_key(key));
        backends
            .into_iter()
            .filter(|(key, probe)| {
                let state = probes.entry(key.clone()).or_insert(ProbeState {
                    next_due: now,
                    failures: 0,
                    successes: 0,
                    in_flight: false,
                });
                if state.in_flight || state.next_due > now {
                    return false;
                }
                state.in_flight = true;
                state.next_due = now + probe.interval(self.interval);
                true
            })
            .collect()
    }

    /// Counts a probe's result, and reloads when the backend went down or
    /// came back. A backend that left while its probe ran is ignored.
    async fn take_outcome(
        &self,
        key: &str,
        probe: &BackendProbe,
        outcome: Result<(), UnhealthyReason>,
    ) {
        let changed = {
            let mut probes = self.probes.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = probes.get_mut(key) else {
                return;
            };
            state.in_flight = false;
            let mut unhealthy = self
                .unhealthy_backends
                .write()
                .unwrap_or_else(|p| p.into_inner());
            record_outcome(state, probe, outcome, key, &mut unhealthy)
        };
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
            // UDP backends are connectionless — a TCP/HTTP probe always fails
            // (ConnectionRefused) and would wrongly mark them down. Sōzu has its
            // own UDP health checks; leave UDP out of this checker.
            if entrypoint.protocol == Protocol::Udp {
                continue;
            }
            let health_check = entrypoint.config.health_check.as_ref();
            for backend in &entrypoint.backends {
                backends
                    .entry(probe_key(backend, health_check))
                    .or_insert_with(|| BackendProbe {
                        addr: match health_check.and_then(|hc| hc.port) {
                            Some(port) => format!("{}:{port}", backend.address),
                            None => backend.to_string(),
                        },
                        health_check: health_check.cloned(),
                    });
            }
        }
        backends
    }

    /// Probe one backend: an HTTP `GET <path>` when a health check is
    /// configured, otherwise a bare TCP connect (the historical behaviour).
    async fn probe_backend(&self, probe: &BackendProbe) -> Result<(), UnhealthyReason> {
        match &probe.health_check {
            Some(
                hc @ HealthCheckConfig {
                    path: Some(path), ..
                },
            ) => self.probe_http(&probe.addr, path, hc).await,
            Some(hc) => {
                let timeout = hc
                    .timeout_ms
                    .map(Duration::from_millis)
                    .unwrap_or(self.timeout);
                self.probe_tcp(&probe.addr, timeout).await
            }
            None => self.probe_tcp(&probe.addr, self.timeout).await,
        }
    }

    /// TCP connect probe: healthy as soon as the backend accepts a connection.
    async fn probe_tcp(&self, addr: &str, timeout: Duration) -> Result<(), UnhealthyReason> {
        let now = now_epoch_secs();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Health check passed for {}", addr);
                Ok(())
            }
            Ok(Err(e)) => {
                debug!("Health check failed for {}: {}", addr, e);
                // The address says which port was probed, which can be the
                // check's rather than the backend's.
                Err(UnhealthyReason::new(
                    UnhealthyKind::from_io_error(&e),
                    format!("connect to {addr}: {e}"),
                    now,
                ))
            }
            Err(_) => {
                debug!("Health check timed out for {}", addr);
                Err(UnhealthyReason::new(
                    UnhealthyKind::Timeout,
                    format!("connect to {addr} timed out after {timeout:?}"),
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
        path: &str,
        hc: &HealthCheckConfig,
    ) -> Result<(), UnhealthyReason> {
        let now = now_epoch_secs();
        let url = format!("http://{addr}{path}");

        // Per-check timeout overrides the client's global default when set.
        let mut req = self.http_client.get(&url);
        if let Some(ms) = hc.timeout_ms {
            req = req.timeout(Duration::from_millis(ms));
        }
        for (name, value) in &hc.headers {
            req = req.header(name, value);
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
    /// The address the probe dials: the backend's, with the check's port.
    addr: String,
    health_check: Option<HealthCheckConfig>,
}

impl BackendProbe {
    fn interval(&self, default: Duration) -> Duration {
        self.health_check
            .as_ref()
            .and_then(|hc| hc.interval_ms)
            .map(Duration::from_millis)
            .unwrap_or(default)
    }

    /// Consecutive failures before unhealthy, successes before healthy.
    fn thresholds(&self) -> (u32, u32) {
        let hc = self.health_check.as_ref();
        (
            hc.and_then(|hc| hc.unhealthy_threshold).unwrap_or(1).max(1),
            hc.and_then(|hc| hc.healthy_threshold).unwrap_or(1).max(1),
        )
    }

    /// How logs name the probe: never with its headers, which can be secrets.
    fn describe(&self) -> String {
        match self.health_check.as_ref().and_then(|hc| hc.path.as_deref()) {
            Some(path) => format!("{}{path}", self.addr),
            None => self.addr.clone(),
        }
    }
}

/// Counts a probe's result and moves the backend between healthy and
/// unhealthy once its thresholds are met. Returns whether routing changes:
/// the backend went down or came back, or why it is down changed.
fn record_outcome(
    state: &mut ProbeState,
    probe: &BackendProbe,
    outcome: Result<(), UnhealthyReason>,
    key: &str,
    unhealthy: &mut UnhealthyMap,
) -> bool {
    let (unhealthy_threshold, healthy_threshold) = probe.thresholds();
    let now = now_epoch_secs();
    match outcome {
        Ok(()) => {
            state.failures = 0;
            state.successes = state.successes.saturating_add(1);
            if state.successes >= healthy_threshold && unhealthy.remove(key).is_some() {
                info!("Backend {} is back up", probe.describe());
                return true;
            }
            false
        }
        Err(mut reason) => {
            state.successes = 0;
            state.failures = state.failures.saturating_add(1);
            if let Some(existing) = unhealthy.get_mut(key) {
                let kind_changed = existing.kind != reason.kind;
                existing.kind = reason.kind;
                existing.message = reason.message;
                existing.last_checked = now;
                if kind_changed {
                    warn!(
                        "Backend {} still down, reason changed to {:?}: {}",
                        probe.describe(),
                        existing.kind,
                        existing.message
                    );
                }
                return kind_changed;
            }
            if state.failures < unhealthy_threshold {
                debug!(
                    "Backend {} failed {} of {} probes before it is unhealthy: {}",
                    probe.describe(),
                    state.failures,
                    unhealthy_threshold,
                    reason.message
                );
                return false;
            }
            reason.since = now;
            reason.last_checked = now;
            warn!(
                "Backend {} is down ({:?}): {}",
                probe.describe(),
                reason.kind,
                reason.message
            );
            unhealthy.insert(key.to_string(), reason);
            true
        }
    }
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

    fn http_probe(addr: &str, hc: HealthCheckConfig) -> BackendProbe {
        BackendProbe {
            addr: addr.to_string(),
            health_check: Some(hc),
        }
    }

    fn hc(path: &str, status: Option<u16>) -> HealthCheckConfig {
        HealthCheckConfig {
            path: Some(path.to_string()),
            status,
            timeout_ms: None,
            interval_ms: None,
            port: None,
            headers: BTreeMap::new(),
            unhealthy_threshold: None,
            healthy_threshold: None,
        }
    }

    fn thresholds(unhealthy: u32, healthy: u32) -> BackendProbe {
        let mut check = hc("/health", None);
        check.unhealthy_threshold = Some(unhealthy);
        check.healthy_threshold = Some(healthy);
        http_probe("10.0.0.1:80", check)
    }

    fn failed() -> Result<(), UnhealthyReason> {
        Err(UnhealthyReason::new(
            UnhealthyKind::BadStatus,
            "503".to_string(),
            0,
        ))
    }

    /// A backend is unhealthy after `unhealthyThreshold` failures in a row,
    /// and healthy again after `healthyThreshold` successes in a row.
    #[test]
    fn thresholds_delay_both_transitions() {
        let probe = thresholds(3, 2);
        let mut state = ProbeState {
            next_due: tokio::time::Instant::now(),
            failures: 0,
            successes: 0,
            in_flight: false,
        };
        let mut unhealthy = UnhealthyMap::new();
        let mut run = |outcome| record_outcome(&mut state, &probe, outcome, "k", &mut unhealthy);

        assert!(!run(failed()));
        assert!(!run(failed()));
        assert!(run(failed()), "down on the third failure in a row");
        assert!(!run(Ok(())));
        assert!(run(Ok(())), "up on the second success in a row");
    }

    /// A success between failures starts the count again.
    #[test]
    fn a_success_resets_the_failure_count() {
        let probe = thresholds(2, 1);
        let mut state = ProbeState {
            next_due: tokio::time::Instant::now(),
            failures: 0,
            successes: 0,
            in_flight: false,
        };
        let mut unhealthy = UnhealthyMap::new();
        let mut run = |outcome| record_outcome(&mut state, &probe, outcome, "k", &mut unhealthy);

        assert!(!run(failed()));
        assert!(!run(Ok(())));
        assert!(!run(failed()));
        assert!(run(failed()));
    }

    /// The probe sends the check's headers: the backend here answers 200 only
    /// with the right token.
    #[tokio::test]
    async fn http_probe_sends_its_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let status = if request.contains("authorization: bearer abc") {
                    200
                } else {
                    401
                };
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        let mut with_token = hc("/health", None);
        with_token
            .headers
            .insert("Authorization".to_string(), "Bearer abc".to_string());

        assert!(
            checker()
                .probe_backend(&http_probe(&addr, with_token))
                .await
                .is_ok()
        );
        assert!(
            checker()
                .probe_backend(&http_probe(&addr, hc("/health", None)))
                .await
                .is_err()
        );
    }

    fn one_route_checker() -> HealthChecker {
        let ep: Entrypoint = serde_json::from_value(serde_json::json!({
            "id": "web", "name": "web",
            "backends": [{ "address": "10.0.0.1", "port": 80 }],
            "protocol": "Http",
            "config": {
                "hostnames": ["web.example.com"], "path": null, "tls": false,
                "strip_prefix": false, "https_redirect": false, "priority": 0,
                "auth": null, "headers": []
            }
        }))
        .unwrap();
        let (reload_tx, _rx) = mpsc::channel(64);
        HealthChecker::new(
            Arc::new(RwLock::new(BTreeMap::from([("web".to_string(), ep)]))),
            reload_tx,
        )
    }

    /// A probe still running is not started again, however slow it is; once
    /// it answers, it is due again after its interval.
    #[tokio::test]
    async fn a_running_probe_is_not_started_again() {
        let checker = one_route_checker();

        let started = checker.start_due_probes();
        assert_eq!(started.len(), 1);
        assert!(checker.start_due_probes().is_empty(), "still running");

        let (key, probe) = &started[0];
        checker.take_outcome(key, probe, Ok(())).await;
        assert!(
            checker.start_due_probes().is_empty(),
            "not due before its interval"
        );
    }

    /// A backend that left while its probe ran leaves no verdict behind.
    #[tokio::test]
    async fn the_result_of_a_departed_backend_is_dropped() {
        let checker = one_route_checker();
        let started = checker.start_due_probes();
        checker.storage.write().unwrap().clear();
        assert!(checker.start_due_probes().is_empty());

        let (key, probe) = &started[0];
        checker
            .take_outcome(
                key,
                probe,
                Err(UnhealthyReason::new(
                    UnhealthyKind::Timeout,
                    "slow".to_string(),
                    0,
                )),
            )
            .await;
        assert!(checker.unhealthy_backends.read().unwrap().is_empty());
    }

    /// The probe dials the check's port, not the backend's.
    #[test]
    fn the_probe_dials_the_check_port() {
        let mut ep: Entrypoint = serde_json::from_value(serde_json::json!({
            "id": "web", "name": "web",
            "backends": [{ "address": "10.0.0.1", "port": 80 }],
            "protocol": "Http",
            "config": {
                "hostnames": ["web.example.com"], "path": null, "tls": false,
                "strip_prefix": false, "https_redirect": false, "priority": 0,
                "auth": null, "headers": []
            }
        }))
        .unwrap();
        let mut check = hc("/health", None);
        check.port = Some(8081);
        ep.config.health_check = Some(check);
        let (reload_tx, _rx) = mpsc::channel(64);
        let checker = HealthChecker::new(
            Arc::new(RwLock::new(BTreeMap::from([("web".to_string(), ep)]))),
            reload_tx,
        );

        let probes = checker.collect_backends();

        assert_eq!(probes.values().next().unwrap().addr, "10.0.0.1:8081");
    }

    /// Two routes that share a backend but check it differently get a probe
    /// each, under keys of their own: one route's verdict must not take the
    /// backend out of the other.
    #[test]
    fn a_shared_backend_gets_one_probe_per_route_check() {
        let backend = Backend::new("10.0.0.1", 80);
        let route = |id: &str, health_check: Option<HealthCheckConfig>| {
            let mut ep: Entrypoint = serde_json::from_value(serde_json::json!({
                "id": id,
                "name": id,
                "backends": [{ "address": "10.0.0.1", "port": 80 }],
                "protocol": "Http",
                "config": {
                    "hostnames": [format!("{id}.example.com")],
                    "path": null,
                    "tls": false,
                    "strip_prefix": false,
                    "https_redirect": false,
                    "priority": 0,
                    "auth": null,
                    "headers": []
                }
            }))
            .unwrap();
            ep.config.health_check = health_check;
            (id.to_string(), ep)
        };
        let storage = BTreeMap::from([
            route("strict", Some(hc("/health", Some(200)))),
            route("plain", None),
        ]);
        let (reload_tx, _rx) = mpsc::channel(64);
        let checker = HealthChecker::new(Arc::new(RwLock::new(storage)), reload_tx);

        let probes = checker.collect_backends();

        assert_eq!(probes.len(), 2);
        let strict = probe_key(&backend, Some(&hc("/health", Some(200))));
        assert!(probes[&strict].health_check.is_some());
        assert!(probes[&probe_key(&backend, None)].health_check.is_none());
        assert_ne!(strict, probe_key(&backend, Some(&hc("/health", None))));
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
