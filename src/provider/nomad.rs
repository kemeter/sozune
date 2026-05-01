use crate::config::NomadConfig;
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::labels::source::LabelSource;
use crate::labels::{self};
use crate::model::Entrypoint;
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const PROVIDER_NAME: &str = "nomad";
const NETWORK_NAME: &str = "nomad";

pub struct NomadProvider {
    config: NomadConfig,
    client: reqwest::Client,
}

#[async_trait]
impl Provider for NomadProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let candidates = self.collect().await?;
        let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();
        for candidate in candidates {
            let result = labels::parse(&candidate);
            log_diagnostics(&candidate, &result.diagnostics);
            for (key, mut entrypoint) in result.entrypoints {
                let Some(backend) = entrypoint.backends.first().cloned() else {
                    continue;
                };
                if let Some(existing) = entrypoints.get_mut(&key) {
                    if !existing.backends.contains(&backend) {
                        existing.backends.push(backend);
                    }
                } else {
                    entrypoint.source = Some(PROVIDER_NAME.to_string());
                    entrypoints.insert(key, entrypoint);
                }
            }
        }
        Ok(entrypoints)
    }

    fn name(&self) -> &'static str {
        PROVIDER_NAME
    }
}

#[async_trait]
impl LabelSource for NomadProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        let (services, _) = self.list_services(None).await?;
        let mut candidates = Vec::new();
        for service_name in services {
            match self.fetch_instances(&service_name).await {
                Ok(instances) => {
                    for instance in instances {
                        candidates.push(instance.into_candidate(self.config.expose_by_default));
                    }
                }
                Err(e) => warn!("Nomad: failed to fetch instances for {service_name}: {e}"),
            }
        }
        Ok(candidates)
    }
}

impl NomadProvider {
    pub fn new(config: NomadConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build Nomad HTTP client")?;
        Ok(Self { config, client })
    }

    fn build_url(&self, path: &str, index: Option<u64>) -> String {
        let base = self.config.endpoint.trim_end_matches('/');
        let mut url = format!("{base}{path}");
        let mut params: Vec<String> = Vec::new();
        if !self.config.namespace.is_empty() {
            params.push(format!("namespace={}", self.config.namespace));
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

    /// Issue a Nomad API call. Returns the decoded payload along with the
    /// `X-Nomad-Index` header value, which the caller passes back as `index`
    /// on the next call to enable Nomad's blocking-query mechanism.
    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: String,
    ) -> anyhow::Result<(T, u64)> {
        let mut req = self.client.get(&url);
        if !self.config.token.is_empty() {
            req = req.header("X-Nomad-Token", &self.config.token);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("Nomad request to {url} failed"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Nomad returned status {} for {}", resp.status(), url);
        }
        let new_index = resp
            .headers()
            .get("X-Nomad-Index")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("Failed to read Nomad response from {url}"))?;
        let body: T = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to decode Nomad response from {url}"))?;
        Ok((body, new_index))
    }

    /// List service names visible in the configured namespace (or all of them).
    /// Uses a Nomad blocking query when `index` is `Some` — Nomad will hold
    /// the response until the services list changes (or `poll_interval`
    /// elapses), giving us near-real-time updates without polling spam.
    async fn list_services(&self, index: Option<u64>) -> anyhow::Result<(Vec<String>, u64)> {
        let url = self.build_url("/v1/services", index);
        let (payload, new_index) = self.get_json::<Vec<NamespaceServices>>(url).await?;
        let mut names = Vec::new();
        for ns in payload {
            for svc in ns.services {
                names.push(svc.service_name);
            }
        }
        Ok((names, new_index))
    }

    /// Fetch the registered instances of one service. Not a blocking query:
    /// the per-service endpoint changes far less often and we already get
    /// woken up by the services-list watcher.
    async fn fetch_instances(&self, service_name: &str) -> anyhow::Result<Vec<ServiceInstance>> {
        let url = self.build_url(&format!("/v1/service/{service_name}"), None);
        let (payload, _) = self.get_json::<Vec<RawInstance>>(url).await?;
        Ok(payload
            .into_iter()
            .map(|raw| ServiceInstance::from_raw(service_name, raw))
            .collect())
    }

    /// Pull entrypoints once and merge them into storage with `source = "nomad"`.
    /// On any change vs the previous Nomad-sourced entries, push a reload.
    async fn poll_once(
        &self,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
    ) {
        let new_entrypoints = match self.provide().await {
            Ok(map) => map,
            Err(e) => {
                warn!("Nomad poll failed: {e}");
                return;
            }
        };

        let needs_update = {
            let storage_read = match storage.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Storage lock poisoned in Nomad provider: {e}");
                    return;
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
            return;
        }

        let mut tls_added = false;
        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Storage lock poisoned in Nomad provider: {e}");
                    return;
                }
            };
            storage_write.retain(|_, ep| ep.source.as_deref() != Some(PROVIDER_NAME));
            for (id, entrypoint) in new_entrypoints {
                if entrypoint.config.tls {
                    tls_added = true;
                }
                debug!(
                    "Nomad entrypoint: {id} ({} backend(s))",
                    entrypoint.backends.len()
                );
                storage_write.insert(id, entrypoint);
            }
        }

        info!("Nomad provider config changed, triggering reload");
        if let Err(e) = reload_tx.send(()).await {
            warn!("Failed to send reload signal: {e}");
        }
        if tls_added {
            acme_notify.notify_one();
        }
    }

    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Nomad provider against {} (namespace={}, expose_by_default={}, blocking-wait={}s)",
            self.config.endpoint,
            if self.config.namespace.is_empty() {
                "<all>"
            } else {
                self.config.namespace.as_str()
            },
            self.config.expose_by_default,
            self.config.poll_interval,
        );

        // Initial pull (`index = None` → immediate response).
        self.poll_once(&storage, &reload_tx, &acme_notify).await;
        let mut last_index = self
            .list_services(None)
            .await
            .map(|(_, idx)| idx)
            .unwrap_or(0);

        loop {
            // Blocking query: Nomad holds the connection until the services
            // list changes or the configured wait elapses.
            match self.list_services(Some(last_index)).await {
                Ok((_, new_index)) => {
                    if new_index != last_index {
                        last_index = new_index;
                        self.poll_once(&storage, &reload_tx, &acme_notify).await;
                    }
                    // Same index = wait timed out with no change. Loop right
                    // back into another blocking call — no sleep needed.
                }
                Err(e) => {
                    warn!("Nomad blocking query failed, backing off 1s: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

/// Raw payload returned by `GET /v1/services` — list of namespaces, each with
/// a list of services.
#[derive(Debug, Deserialize)]
struct NamespaceServices {
    #[serde(default, rename = "Services")]
    services: Vec<NamespaceService>,
}

#[derive(Debug, Deserialize)]
struct NamespaceService {
    #[serde(rename = "ServiceName")]
    service_name: String,
}

/// Raw payload returned by `GET /v1/service/<name>` — one entry per healthy
/// allocation registered for that service.
#[derive(Debug, Deserialize)]
struct RawInstance {
    #[serde(rename = "ID")]
    id: String,
    #[serde(default, rename = "Address")]
    address: String,
    #[serde(default, rename = "Port")]
    port: u16,
    #[serde(default, rename = "Tags")]
    tags: Vec<String>,
}

/// One service allocation, ready to be turned into a `Candidate`.
struct ServiceInstance {
    id: String,
    display_name: String,
    address: String,
    port: u16,
    labels: HashMap<String, String>,
}

impl ServiceInstance {
    fn from_raw(service_name: &str, raw: RawInstance) -> Self {
        let labels = parse_tags(&raw.tags);
        Self {
            id: raw.id,
            display_name: service_name.to_string(),
            address: raw.address,
            port: raw.port,
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
        }
    }

    /// For every `sozune.<proto>.<svc>.host` declared, inject the
    /// Nomad-allocated `Port` as `sozune.<proto>.<svc>.port` if the user
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

fn log_diagnostics(candidate: &Candidate, diagnostics: &[Diagnostic]) {
    for d in diagnostics {
        let target = format!("{}/{}", candidate.provider, candidate.display_name);
        match d.severity() {
            Severity::Error => error!(
                "[{}] {}: {} (label={})",
                target,
                d.code.as_str(),
                d.message,
                d.label.as_deref().unwrap_or("-")
            ),
            Severity::Warn => warn!(
                "[{}] {}: {} (label={}, value={:?})",
                target,
                d.code.as_str(),
                d.message,
                d.label.as_deref().unwrap_or("-"),
                d.value.as_deref().unwrap_or("")
            ),
            Severity::Info => debug!("[{}] {}: {}", target, d.code.as_str(), d.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NomadConfig {
        NomadConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:4646".to_string(),
            token: String::new(),
            namespace: String::new(),
            poll_interval: 15,
            expose_by_default: false,
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
    fn synthesize_port_only_fills_missing_port_labels() {
        let mut instance = ServiceInstance {
            id: "alloc-1".into(),
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
            "missing port should be filled from Nomad allocation"
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
    fn synthesize_port_skips_when_no_allocation() {
        let mut instance = ServiceInstance {
            id: "alloc-2".into(),
            display_name: "web".into(),
            address: String::new(),
            port: 0,
            labels: HashMap::from([(
                "sozune.http.web.host".to_string(),
                "example.com".to_string(),
            )]),
        };
        instance.synthesize_port_labels();
        assert!(!instance.labels.contains_key("sozune.http.web.port"));
    }

    #[test]
    fn into_candidate_exposes_address_as_nomad_network() {
        let instance = ServiceInstance {
            id: "alloc-3".into(),
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
    fn build_url_appends_namespace_when_set() {
        let mut config = cfg();
        config.namespace = "team-a".to_string();
        let provider = NomadProvider::new(config).unwrap();
        let url = provider.build_url("/v1/services", None);
        assert_eq!(url, "http://127.0.0.1:4646/v1/services?namespace=team-a");
    }

    #[test]
    fn build_url_omits_namespace_when_empty() {
        let provider = NomadProvider::new(cfg()).unwrap();
        let url = provider.build_url("/v1/services", None);
        assert_eq!(url, "http://127.0.0.1:4646/v1/services");
    }

    #[test]
    fn build_url_includes_blocking_query_params_when_index_set() {
        let provider = NomadProvider::new(cfg()).unwrap();
        let url = provider.build_url("/v1/services", Some(42));
        assert_eq!(url, "http://127.0.0.1:4646/v1/services?index=42&wait=15s");
    }

    #[test]
    fn build_url_combines_namespace_and_index() {
        let mut config = cfg();
        config.namespace = "team-a".to_string();
        let provider = NomadProvider::new(config).unwrap();
        let url = provider.build_url("/v1/services", Some(42));
        assert_eq!(
            url,
            "http://127.0.0.1:4646/v1/services?namespace=team-a&index=42&wait=15s"
        );
    }
}
