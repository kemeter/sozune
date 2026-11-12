use crate::config::ConsulConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
use crate::model::Entrypoint;
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const PROVIDER_NAME: &str = crate::provider::CONSUL;
const NETWORK_NAME: &str = "consul";
/// Moves when a service registers or goes, not when its health changes.
const CATALOG_PATH: &str = "/v1/catalog/services";
/// Moves when a check changes state.
const HEALTH_PATH: &str = "/v1/health/state/any";
/// How long changes gather before a discovery: each one fetches every service,
/// and the health index moves for any check of the datacenter.
const CHANGE_COALESCE: Duration = Duration::from_secs(1);
/// How long before a discovery that failed is tried again.
const POLL_RETRY: Duration = Duration::from_secs(2);
/// How long a request Consul answers at once may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ConsulProvider {
    config: ConsulConfig,
    client: reqwest::Client,
}

#[async_trait]
impl Provider for ConsulProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        // Trait callers don't share the runtime store; use a throwaway so
        // diagnostics are at least logged.
        let throwaway = diagnostics::new_store();
        self.provide_into(&throwaway).await
    }
}

impl ConsulProvider {
    /// Same as `provide()` but writes diagnostics into the supplied store.
    async fn provide_into(
        &self,
        diagnostics: &DiagnosticsStore,
    ) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let candidates = self.collect().await?;
        let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();
        for candidate in candidates {
            let result = diagnostics::parse_and_store(diagnostics, &candidate);
            log_diagnostics(&candidate, &result.diagnostics);
            for (key, mut entrypoint) in result.entrypoints {
                let Some(backend) = entrypoint.backends.first().cloned() else {
                    continue;
                };
                if let Some(existing) = entrypoints.get_mut(&key) {
                    existing.add_candidates(&entrypoint.candidates);
                    if !existing.backends.iter().any(|b| b.same_address(&backend)) {
                        existing.backends.push(backend);
                    }
                } else {
                    entrypoint.source = Some(PROVIDER_NAME.to_string());
                    entrypoints.insert(key, entrypoint);
                }
            }
        }
        // The replicas of a workload share its weight.
        for entrypoint in entrypoints.values_mut() {
            crate::model::split_service_weights(&mut entrypoint.backends);
        }
        Ok(entrypoints)
    }
}

#[async_trait]
impl LabelSource for ConsulProvider {
    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        let services = self.list_services().await?;
        let mut candidates = Vec::new();
        for service_name in services {
            match self.fetch_instances(&service_name).await {
                Ok(instances) => {
                    for instance in instances {
                        candidates.push(instance.into_candidate(self.config.expose_by_default));
                    }
                }
                Err(e) => warn!("Consul: failed to fetch instances for {service_name}: {e}"),
            }
        }
        Ok(candidates)
    }
}

impl ConsulProvider {
    pub fn new(config: ConsulConfig) -> anyhow::Result<Self> {
        let client = crate::util::http_client::builder()
            .build()
            .context("Failed to build Consul HTTP client")?;
        Ok(Self { config, client })
    }

    fn build_url(&self, path: &str, index: Option<u64>) -> String {
        let base = self.config.endpoint.trim_end_matches('/');
        let mut url = format!("{base}{path}");
        let mut params: Vec<String> = Vec::new();
        if !self.config.datacenter.is_empty() {
            params.push(format!("dc={}", self.config.datacenter));
        }
        if let Some(idx) = index {
            params.push(format!("index={idx}"));
            params.push(format!("wait={}s", self.config.poll_interval));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        url
    }

    /// Issue a Consul API call. Returns the decoded payload along with the
    /// `X-Consul-Index` header value, which the caller passes back as `index`
    /// on the next call to enable Consul's blocking-query mechanism.
    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: String,
    ) -> anyhow::Result<(T, u64)> {
        self.get_json_within(url, REQUEST_TIMEOUT).await
    }

    async fn get_json_within<T: for<'de> Deserialize<'de>>(
        &self,
        url: String,
        timeout: Duration,
    ) -> anyhow::Result<(T, u64)> {
        let mut req = self.client.get(&url).timeout(timeout);
        if !self.config.token.is_empty() {
            req = req.header("X-Consul-Token", &self.config.token);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("Consul request to {url} failed"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Consul returned status {} for {}", resp.status(), url);
        }
        let new_index = resp
            .headers()
            .get("X-Consul-Index")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("Failed to read Consul response from {url}"))?;
        let body: T = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to decode Consul response from {url}"))?;
        Ok((body, new_index))
    }

    /// List registered service names in the configured datacenter (or the
    /// agent default). `GET /v1/catalog/services` returns a map of
    /// `service name → tags`; we only need the keys here.
    async fn list_services(&self) -> anyhow::Result<Vec<String>> {
        let url = self.build_url(CATALOG_PATH, None);
        let (payload, _) = self.get_json::<HashMap<String, Vec<String>>>(url).await?;
        // Drop Consul's built-in "consul" service — it's the agents
        // themselves, never a routable backend.
        let names = payload
            .into_keys()
            .filter(|name| name != "consul")
            .collect();
        Ok(names)
    }

    /// Fetch the healthy instances of one service via the health endpoint,
    /// which carries each instance's checks. Instances whose aggregate
    /// health is not in `strict_checks` are dropped. Not a blocking query:
    /// the services-list watcher already wakes us on catalog changes.
    async fn fetch_instances(&self, service_name: &str) -> anyhow::Result<Vec<ServiceInstance>> {
        let url = self.build_url(&format!("/v1/health/service/{service_name}"), None);
        let (payload, _) = self.get_json::<Vec<RawHealthEntry>>(url).await?;
        Ok(payload
            .into_iter()
            .filter(|entry| self.entry_is_allowed(entry))
            .map(|entry| ServiceInstance::from_raw(service_name, entry))
            .collect())
    }

    /// Whether an instance's aggregate health is allowed to take traffic.
    /// The effective status is the worst of its checks (`critical` >
    /// `warning` > `passing`); an instance is kept only if that status is
    /// listed in `strict_checks`. An instance with no checks is treated as
    /// `passing`.
    fn entry_is_allowed(&self, entry: &RawHealthEntry) -> bool {
        let status = aggregate_status(&entry.checks);
        self.config.strict_checks.iter().any(|s| s == status)
    }

    /// Pull entrypoints once and merge them into storage with
    /// `source = "consul"`. On any change vs the previous Consul-sourced
    /// entries, push a reload.
    async fn poll_once(
        &self,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
        diagnostics: &DiagnosticsStore,
    ) -> bool {
        let new_entrypoints = match self.provide_into(diagnostics).await {
            Ok(map) => map,
            Err(e) => {
                warn!("Consul poll failed: {e}");
                return false;
            }
        };

        let needs_update = {
            let storage_read = match storage.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
                    return false;
                }
            };

            let old_ids: HashSet<&String> = storage_read
                .iter()
                .filter(|(_, ep)| ep.source.as_deref() == Some(PROVIDER_NAME))
                .map(|(id, _)| id)
                .collect();
            let new_ids: HashSet<&String> = new_entrypoints.keys().collect();

            old_ids != new_ids
                || new_entrypoints
                    .iter()
                    .any(|(id, ep)| storage_read.get(id).is_none_or(|existing| existing != ep))
        };

        if !needs_update {
            return true;
        }

        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
                    return false;
                }
            };
            storage_write.retain(|_, ep| ep.source.as_deref() != Some(PROVIDER_NAME));
            for (id, entrypoint) in new_entrypoints {
                debug!(
                    "Consul entrypoint: {id} ({} backend(s))",
                    entrypoint.backends.len()
                );
                storage_write.insert(id, entrypoint);
            }
        }

        info!("Consul provider config changed, triggering reload");
        if let Err(e) = reload_tx.send(()).await {
            warn!("could not apply configuration update; will retry on next change: {e}");
        }
        // Notify ACME unconditionally on any storage change: the manager
        // checks for missing/expiring certs before re-issuing, so the extra
        // notification is cheap and keeps the contract identical across
        // providers (Docker, Swarm, Kubernetes, Nomad do the same).
        acme_notify.notify_one();
        true
    }

    /// The current `X-Consul-Index` of `path`, 0 when it cannot be read: the
    /// first blocking query then answers at once, and reports a change.
    async fn current_index(&self, path: &str) -> u64 {
        let url = self.build_url(path, None);
        match self.get_json::<IgnoredAny>(url).await {
            Ok((_, index)) => index,
            Err(e) => {
                warn!("Consul request failed: {e}");
                0
            }
        }
    }

    /// Hold blocking queries on `path`, and wake `changed` when its index
    /// moves. Consul holds each one until then, or `poll_interval` elapses.
    async fn watch_index(&self, path: &str, mut index: u64, changed: &Notify) {
        // Consul adds up to `wait / 16` of jitter to the wait.
        let wait = Duration::from_secs(self.config.poll_interval);
        let timeout = wait + wait / 16 + REQUEST_TIMEOUT;
        loop {
            let url = self.build_url(path, Some(index));
            match self.get_json_within::<IgnoredAny>(url, timeout).await {
                Ok((_, new_index)) if new_index != index => {
                    index = new_index;
                    changed.notify_one();
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Consul blocking query failed, backing off 1s: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Consul provider against {} (datacenter={}, strict_checks={:?}, expose_by_default={}, blocking-wait={}s)",
            self.config.endpoint,
            if self.config.datacenter.is_empty() {
                "<default>"
            } else {
                self.config.datacenter.as_str()
            },
            self.config.strict_checks,
            self.config.expose_by_default,
            self.config.poll_interval,
        );

        // Read before the first pull: a change made during it is then seen.
        let catalog = self.current_index(CATALOG_PATH).await;
        let health = self.current_index(HEALTH_PATH).await;
        self.poll_once(&storage, &reload_tx, &acme_notify, &diagnostics)
            .await;

        let changed = Notify::new();
        let apply = async {
            loop {
                changed.notified().await;
                tokio::time::sleep(CHANGE_COALESCE).await;
                // The index has moved on: nothing would report this change again.
                while !self
                    .poll_once(&storage, &reload_tx, &acme_notify, &diagnostics)
                    .await
                {
                    tokio::time::sleep(POLL_RETRY).await;
                }
            }
        };
        tokio::join!(
            self.watch_index(CATALOG_PATH, catalog, &changed),
            self.watch_index(HEALTH_PATH, health, &changed),
            apply,
        );
        Ok(())
    }
}

/// Worst-case status across an instance's checks. Consul check states, from
/// best to worst: `passing`, `warning`, `critical` (plus `maintenance`,
/// which we treat as the worst — an instance in maintenance should not take
/// traffic). No checks → `passing`.
fn aggregate_status(checks: &[RawCheck]) -> &'static str {
    let mut worst = 0u8;
    for check in checks {
        let rank = match check.status.as_str() {
            "passing" => 0,
            "warning" => 1,
            "critical" => 2,
            _ => 3, // maintenance / unknown: treat as worse than critical
        };
        worst = worst.max(rank);
    }
    match worst {
        0 => "passing",
        1 => "warning",
        2 => "critical",
        _ => "maintenance",
    }
}

/// Raw `GET /v1/health/service/<name>` entry: one registered instance with
/// its node, service definition, and health checks.
#[derive(Debug, Deserialize)]
struct RawHealthEntry {
    #[serde(rename = "Node")]
    node: RawNode,
    #[serde(rename = "Service")]
    service: RawService,
    #[serde(default, rename = "Checks")]
    checks: Vec<RawCheck>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    #[serde(default, rename = "Address")]
    address: String,
}

#[derive(Debug, Deserialize)]
struct RawService {
    #[serde(rename = "ID")]
    id: String,
    #[serde(default, rename = "Service")]
    service: String,
    #[serde(default, rename = "Address")]
    address: String,
    #[serde(default, rename = "Port")]
    port: u16,
    #[serde(default, rename = "Tags")]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawCheck {
    #[serde(default, rename = "Status")]
    status: String,
}

/// One service instance, ready to be turned into a `Candidate`.
struct ServiceInstance {
    id: String,
    display_name: String,
    address: String,
    port: u16,
    labels: HashMap<String, String>,
}

impl ServiceInstance {
    fn from_raw(service_name: &str, entry: RawHealthEntry) -> Self {
        let labels = parse_tags(&entry.service.tags);
        // Consul: the service may register its own address; if empty, the
        // instance is reachable at the node's address. Missing this fallback
        // yields backends with no IP.
        let address = if entry.service.address.is_empty() {
            entry.node.address
        } else {
            entry.service.address
        };
        // Prefer the service's own name; fall back to the queried name.
        let display_name = if entry.service.service.is_empty() {
            service_name.to_string()
        } else {
            entry.service.service
        };
        Self {
            id: entry.service.id,
            display_name,
            address,
            port: entry.service.port,
            labels,
        }
    }

    fn into_candidate(mut self, expose_by_default: bool) -> Candidate {
        self.synthesize_port_labels();

        let networks = if self.address.is_empty() {
            Vec::new()
        } else {
            vec![NetworkInfo {
                name: NETWORK_NAME.to_string(),
                ip: Some(self.address),
            }]
        };

        Candidate {
            provider: PROVIDER_NAME,
            id: self.id,
            display_name: self.display_name,
            labels: self.labels,
            networks,
            enabled_default: expose_by_default,
            health: None,
        }
    }

    /// For every `sozune.<proto>.<svc>.host` declared, inject the
    /// Consul-registered `Port` as `sozune.<proto>.<svc>.port` if the user
    /// hasn't already set one. Explicit user ports win.
    fn synthesize_port_labels(&mut self) {
        if self.port == 0 {
            return;
        }
        let port_str = self.port.to_string();
        let prefixes: Vec<String> = self
            .labels
            .keys()
            .filter_map(|k| {
                k.strip_suffix(".host")
                    .filter(|p| p.starts_with("sozune."))
                    .map(|p| p.to_string())
            })
            .collect();
        for prefix in prefixes {
            let key = format!("{prefix}.port");
            self.labels.entry(key).or_insert_with(|| port_str.clone());
        }
    }
}

/// Tags shaped `key=value` become labels; bare tags become flag labels with
/// an empty value (so `sozune.enable` works as a tag too).
fn parse_tags(tags: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for tag in tags {
        match tag.split_once('=') {
            Some((k, v)) => {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
            None => {
                out.insert(tag.trim().to_string(), String::new());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Consul whose catalog never moves: only `/v1/health/state/any` tells
    /// that the instance went critical. Answers blocking queries as Consul
    /// does, holding them until the index moves or the wait elapses.
    async fn fake_consul(
        status: Arc<RwLock<&'static str>>,
        health_index: Arc<Notify>,
        catalog_down: Arc<std::sync::atomic::AtomicBool>,
    ) -> u16 {
        use axum::extract::{Query, State};
        use axum::http::header::HeaderMap;
        use axum::routing::get;

        type Params = Query<HashMap<String, String>>;
        #[derive(Clone)]
        struct Fake {
            status: Arc<RwLock<&'static str>>,
            flipped: Arc<Notify>,
            index: Arc<std::sync::atomic::AtomicU64>,
            catalog_down: Arc<std::sync::atomic::AtomicBool>,
        }
        fn indexed(index: u64) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert("X-Consul-Index", index.to_string().parse().unwrap());
            headers
        }
        async fn catalog(
            State(fake): State<Fake>,
            Query(params): Params,
        ) -> (axum::http::StatusCode, HeaderMap, &'static str) {
            use std::sync::atomic::Ordering::SeqCst;
            if params.contains_key("index") {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let status = if fake.catalog_down.load(SeqCst) {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            } else {
                axum::http::StatusCode::OK
            };
            (status, indexed(7), r#"{"web":[]}"#)
        }
        async fn states(
            State(fake): State<Fake>,
            Query(params): Params,
        ) -> (HeaderMap, &'static str) {
            use std::sync::atomic::Ordering::SeqCst;
            if params.contains_key("index") {
                let _ = tokio::time::timeout(Duration::from_secs(1), fake.flipped.notified()).await;
            }
            let moved = *fake.status.read().unwrap() == "critical";
            let index = fake.index.load(SeqCst) + u64::from(moved);
            (indexed(index), "[]")
        }
        async fn instances(State(fake): State<Fake>) -> (HeaderMap, String) {
            let status = *fake.status.read().unwrap();
            let body = serde_json::json!([{
                "Node": {"Address": "10.0.0.1"},
                "Service": {"ID": "web1", "Service": "web", "Address": "10.0.0.1", "Port": 80,
                    "Tags": ["sozune.enable=true", "sozune.http.web.host=web.test"]},
                "Checks": [{"Status": status}],
            }]);
            (indexed(7), body.to_string())
        }

        let app = axum::Router::new()
            .route("/v1/catalog/services", get(catalog))
            .route("/v1/health/state/any", get(states))
            .route("/v1/health/service/web", get(instances))
            .with_state(Fake {
                status,
                flipped: health_index,
                index: Arc::new(std::sync::atomic::AtomicU64::new(5)),
                catalog_down,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        port
    }

    /// A check going critical leaves the catalog index alone: the instance
    /// must still lose its traffic, even when the discovery it triggers fails
    /// at first.
    #[tokio::test]
    async fn a_health_flip_removes_the_instance_without_a_catalog_change() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

        let status = Arc::new(RwLock::new("passing"));
        let flipped = Arc::new(Notify::new());
        let catalog_down = Arc::new(AtomicBool::new(false));
        let port = fake_consul(status.clone(), flipped.clone(), catalog_down.clone()).await;

        let mut config = cfg();
        config.endpoint = format!("http://127.0.0.1:{port}");
        config.poll_interval = 1;
        let provider = ConsulProvider::new(config).unwrap();
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let (reload_tx, mut reload_rx) = mpsc::channel(8);
        let watcher = {
            let storage = storage.clone();
            tokio::spawn(async move {
                provider
                    .start_polling(
                        storage,
                        reload_tx,
                        Arc::new(Notify::new()),
                        diagnostics::new_store(),
                    )
                    .await
            })
        };

        tokio::time::timeout(Duration::from_secs(5), reload_rx.recv())
            .await
            .expect("the first pull finds the instance")
            .unwrap();
        assert_eq!(storage.read().unwrap().len(), 1);

        catalog_down.store(true, SeqCst);
        *status.write().unwrap() = "critical";
        flipped.notify_waiters();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            storage.read().unwrap().len(),
            1,
            "the failed pull changes nothing"
        );
        catalog_down.store(false, SeqCst);

        tokio::time::timeout(Duration::from_secs(8), reload_rx.recv())
            .await
            .expect("the flip is seen with no catalog change, once discovery works again")
            .unwrap();
        assert!(storage.read().unwrap().is_empty());
        watcher.abort();
    }

    /// A blocking query may be held longer than a plain request may take.
    #[tokio::test]
    async fn a_blocking_query_outlasts_the_request_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                "[]"
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = ConsulProvider::new(cfg()).unwrap();
        let url = format!("http://127.0.0.1:{port}/slow");
        assert!(
            provider
                .get_json_within::<IgnoredAny>(url.clone(), Duration::from_millis(5))
                .await
                .is_err(),
            "the timeout is the one given"
        );
        assert!(
            provider
                .get_json_within::<IgnoredAny>(url, Duration::from_secs(5))
                .await
                .is_ok()
        );
    }

    fn cfg() -> ConsulConfig {
        ConsulConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:8500".to_string(),
            token: String::new(),
            datacenter: String::new(),
            poll_interval: 15,
            strict_checks: vec!["passing".to_string(), "warning".to_string()],
            expose_by_default: false,
        }
    }

    fn check(status: &str) -> RawCheck {
        RawCheck {
            status: status.to_string(),
        }
    }

    #[test]
    fn parse_tags_supports_key_value_and_flag() {
        let tags = vec![
            "sozune.enable=true".to_string(),
            "sozune.http.web.host=example.com".to_string(),
            "tier-frontend".to_string(),
        ];
        let labels = parse_tags(&tags);
        assert_eq!(
            labels.get("sozune.enable").map(|s| s.as_str()),
            Some("true")
        );
        assert_eq!(
            labels.get("sozune.http.web.host").map(|s| s.as_str()),
            Some("example.com")
        );
        assert_eq!(labels.get("tier-frontend").map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn aggregate_status_picks_the_worst_check() {
        assert_eq!(aggregate_status(&[]), "passing");
        assert_eq!(aggregate_status(&[check("passing")]), "passing");
        assert_eq!(
            aggregate_status(&[check("passing"), check("warning")]),
            "warning"
        );
        assert_eq!(
            aggregate_status(&[check("passing"), check("critical"), check("warning")]),
            "critical"
        );
        assert_eq!(aggregate_status(&[check("maintenance")]), "maintenance");
    }

    #[test]
    fn strict_checks_default_allows_passing_and_warning_but_not_critical() {
        let provider = ConsulProvider::new(cfg()).unwrap();
        let passing = RawHealthEntry {
            node: RawNode {
                address: "10.0.0.1".into(),
            },
            service: RawService {
                id: "s1".into(),
                service: "web".into(),
                address: "10.0.0.5".into(),
                port: 80,
                tags: vec![],
            },
            checks: vec![check("passing")],
        };
        let warning = RawHealthEntry {
            checks: vec![check("warning")],
            ..raw_like(&passing)
        };
        let critical = RawHealthEntry {
            checks: vec![check("critical")],
            ..raw_like(&passing)
        };
        assert!(provider.entry_is_allowed(&passing));
        assert!(provider.entry_is_allowed(&warning));
        assert!(!provider.entry_is_allowed(&critical));
    }

    #[test]
    fn strict_checks_passing_only_excludes_warning() {
        let mut config = cfg();
        config.strict_checks = vec!["passing".to_string()];
        let provider = ConsulProvider::new(config).unwrap();
        let warning = RawHealthEntry {
            node: RawNode {
                address: "10.0.0.1".into(),
            },
            service: RawService {
                id: "s1".into(),
                service: "web".into(),
                address: "10.0.0.5".into(),
                port: 80,
                tags: vec![],
            },
            checks: vec![check("warning")],
        };
        assert!(!provider.entry_is_allowed(&warning));
    }

    #[test]
    fn from_raw_falls_back_to_node_address_when_service_address_empty() {
        let entry = RawHealthEntry {
            node: RawNode {
                address: "10.0.0.99".into(),
            },
            service: RawService {
                id: "s1".into(),
                service: "web".into(),
                address: String::new(),
                port: 8080,
                tags: vec![],
            },
            checks: vec![],
        };
        let instance = ServiceInstance::from_raw("web", entry);
        assert_eq!(instance.address, "10.0.0.99");
    }

    #[test]
    fn from_raw_prefers_service_address() {
        let entry = RawHealthEntry {
            node: RawNode {
                address: "10.0.0.99".into(),
            },
            service: RawService {
                id: "s1".into(),
                service: "web".into(),
                address: "10.0.0.5".into(),
                port: 8080,
                tags: vec![],
            },
            checks: vec![],
        };
        let instance = ServiceInstance::from_raw("web", entry);
        assert_eq!(instance.address, "10.0.0.5");
    }

    #[test]
    fn synthesize_port_only_fills_missing_port_labels() {
        let mut instance = ServiceInstance {
            id: "s1".into(),
            display_name: "web".into(),
            address: "10.0.0.5".into(),
            port: 8080,
            labels: HashMap::from([
                (
                    "sozune.http.web.host".to_string(),
                    "example.com".to_string(),
                ),
                (
                    "sozune.http.api.host".to_string(),
                    "api.example.com".to_string(),
                ),
                ("sozune.http.api.port".to_string(), "9000".to_string()),
            ]),
        };
        instance.synthesize_port_labels();
        assert_eq!(
            instance
                .labels
                .get("sozune.http.web.port")
                .map(|s| s.as_str()),
            Some("8080"),
            "missing port should be filled from Consul registration"
        );
        assert_eq!(
            instance
                .labels
                .get("sozune.http.api.port")
                .map(|s| s.as_str()),
            Some("9000"),
            "user-provided port must be preserved"
        );
    }

    #[test]
    fn into_candidate_exposes_address_as_consul_network() {
        let instance = ServiceInstance {
            id: "s1".into(),
            display_name: "web".into(),
            address: "10.0.0.5".into(),
            port: 8080,
            labels: HashMap::from([(
                "sozune.http.web.host".to_string(),
                "example.com".to_string(),
            )]),
        };
        let candidate = instance.into_candidate(false);
        assert_eq!(candidate.provider, PROVIDER_NAME);
        assert_eq!(candidate.networks.len(), 1);
        assert_eq!(candidate.networks[0].name, NETWORK_NAME);
        assert_eq!(candidate.networks[0].ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn build_url_appends_datacenter_when_set() {
        let mut config = cfg();
        config.datacenter = "dc1".to_string();
        let provider = ConsulProvider::new(config).unwrap();
        let url = provider.build_url("/v1/catalog/services", None);
        assert_eq!(url, "http://127.0.0.1:8500/v1/catalog/services?dc=dc1");
    }

    #[test]
    fn build_url_omits_datacenter_when_empty() {
        let provider = ConsulProvider::new(cfg()).unwrap();
        let url = provider.build_url("/v1/catalog/services", None);
        assert_eq!(url, "http://127.0.0.1:8500/v1/catalog/services");
    }

    #[test]
    fn build_url_includes_blocking_query_params_when_index_set() {
        let provider = ConsulProvider::new(cfg()).unwrap();
        let url = provider.build_url("/v1/catalog/services", Some(42));
        assert_eq!(
            url,
            "http://127.0.0.1:8500/v1/catalog/services?index=42&wait=15s"
        );
    }

    #[test]
    fn build_url_combines_datacenter_and_index() {
        let mut config = cfg();
        config.datacenter = "dc1".to_string();
        let provider = ConsulProvider::new(config).unwrap();
        let url = provider.build_url("/v1/catalog/services", Some(42));
        assert_eq!(
            url,
            "http://127.0.0.1:8500/v1/catalog/services?dc=dc1&index=42&wait=15s"
        );
    }

    /// Build a fresh `RawHealthEntry` mirroring `base`'s node/service so
    /// tests can vary just the checks via struct update syntax.
    fn raw_like(base: &RawHealthEntry) -> RawHealthEntry {
        RawHealthEntry {
            node: RawNode {
                address: base.node.address.clone(),
            },
            service: RawService {
                id: base.service.id.clone(),
                service: base.service.service.clone(),
                address: base.service.address.clone(),
                port: base.service.port,
                tags: base.service.tags.clone(),
            },
            checks: vec![],
        }
    }
}
