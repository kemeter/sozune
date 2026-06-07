//! Ring provider — service discovery from a Ring cluster.
//!
//! Ring (https://github.com/kemeter/ring) is a lightweight orchestrator that
//! runs workloads as containers or microVMs (Firecracker / Cloud Hypervisor).
//! Like the Docker/Nomad/Consul providers, sōzune *observes* Ring: it reads the
//! deployment list over Ring's HTTP API and turns each running instance into a
//! routing candidate. Ring never needs to know sōzune exists.
//!
//! One `GET /deployments` returns everything we need per deployment: the
//! `sozune.*` labels (set by whoever created the deployment) and the running
//! `instances`, each carrying its routable guest `address`. That single call is
//! the whole discovery surface — no per-service second round-trip like Nomad.
//!
//! Auth mirrors Nomad/Consul: an optional token sent on every request, here as
//! the standard `Authorization: Bearer <token>` Ring expects (a PAT scoped to
//! `deployments:read`).

use crate::config::RingConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
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

const PROVIDER_NAME: &str = crate::provider::RING;
const NETWORK_NAME: &str = "ring";

pub struct RingProvider {
    config: RingConfig,
    client: reqwest::Client,
}

#[async_trait]
impl Provider for RingProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let throwaway = diagnostics::new_store();
        self.provide_into(&throwaway).await
    }
}

impl RingProvider {
    pub fn new(config: RingConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build Ring HTTP client")?;
        Ok(Self { config, client })
    }

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

    fn build_url(&self, path: &str) -> String {
        let base = self.config.endpoint.trim_end_matches('/');
        format!("{base}{path}")
    }

    /// Fetch every deployment Ring knows about. The token (a PAT scoped to
    /// `deployments:read`) is sent as a Bearer header when configured.
    async fn list_deployments(&self) -> anyhow::Result<Vec<RawDeployment>> {
        let url = self.build_url("/deployments");
        let mut req = self.client.get(&url).header("Accept", "application/json");
        if !self.config.token.is_empty() {
            req = req.bearer_auth(&self.config.token);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("Ring request to {url} failed"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Ring returned status {} for {}", resp.status(), url);
        }
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("Failed to read Ring response from {url}"))?;
        let body: Vec<RawDeployment> = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to decode Ring response from {url}"))?;
        Ok(body)
    }

    /// Pull entrypoints once and merge them into storage with `source = "ring"`.
    /// On any change vs the previous Ring-sourced entries, push a reload.
    async fn poll_once(
        &self,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
        diagnostics: &DiagnosticsStore,
    ) {
        let new_entrypoints = match self.provide_into(diagnostics).await {
            Ok(map) => map,
            Err(e) => {
                warn!("Ring poll failed: {e}");
                return;
            }
        };

        let needs_update = {
            let storage_read = match storage.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
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

        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
                    return;
                }
            };
            storage_write.retain(|_, ep| ep.source.as_deref() != Some(PROVIDER_NAME));
            for (id, entrypoint) in new_entrypoints {
                debug!(
                    "Ring entrypoint: {id} ({} backend(s))",
                    entrypoint.backends.len()
                );
                storage_write.insert(id, entrypoint);
            }
        }

        info!("Ring provider config changed, triggering reload");
        if let Err(e) = reload_tx.send(()).await {
            warn!("could not apply configuration update; will retry on next change: {e}");
        }
        acme_notify.notify_one();
    }

    /// Ring has no blocking-query mechanism, so we poll at a fixed interval.
    /// `poll_once` only triggers a reload when the Ring-sourced view actually
    /// changes, so a short interval is cheap.
    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Ring provider against {} (poll={}s, expose_by_default={})",
            self.config.endpoint, self.config.poll_interval, self.config.expose_by_default,
        );
        loop {
            self.poll_once(&storage, &reload_tx, &acme_notify, &diagnostics)
                .await;
            tokio::time::sleep(Duration::from_secs(self.config.poll_interval)).await;
        }
    }
}

#[async_trait]
impl LabelSource for RingProvider {
    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        let deployments = self.list_deployments().await?;
        let mut candidates = Vec::new();
        for deployment in deployments {
            // Only running deployments can serve traffic.
            if deployment.status != "running" {
                continue;
            }
            // For every `sozune.<proto>.<svc>.host`, inject the container's
            // target port as `sozune.<proto>.<svc>.port` unless the user set one.
            // Computed once per deployment and shared by all its instances.
            let labels = synthesize_port_labels(deployment.labels.clone(), &deployment.ports);
            // One candidate per running instance: each carries its own guest
            // address, so a multi-replica deployment fans out to N backends —
            // the same host+labels, different IPs (Nomad/Consul model).
            for instance in &deployment.instances {
                let Some(address) = instance.address.clone() else {
                    continue; // instance not yet addressable (starting up, or runtime inspect failed)
                };
                candidates.push(Candidate {
                    provider: PROVIDER_NAME,
                    id: instance.id.clone(),
                    display_name: deployment.name.clone(),
                    labels: labels.clone(),
                    networks: vec![NetworkInfo {
                        name: NETWORK_NAME.to_string(),
                        ip: Some(address),
                    }],
                    enabled_default: self.config.expose_by_default,
                    health: None,
                });
            }
        }
        Ok(candidates)
    }
}

/// Subset of Ring's `GET /deployments` response we care about.
#[derive(Debug, Deserialize)]
struct RawDeployment {
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    ports: Vec<RawPort>,
    #[serde(default)]
    instances: Vec<RawInstance>,
}

/// One port, as exposed by Ring's `DeploymentPort` DTO. We route to each
/// instance's guest `address` directly, so the reachable port is `target` (the
/// container's internal port) — not `published`, which is a host-side mapping
/// that Ring forbids entirely once `replicas > 1`.
#[derive(Debug, Deserialize)]
struct RawPort {
    #[serde(default)]
    target: u16,
}

/// One running instance, as exposed by Ring's `DeploymentInstance` DTO.
#[derive(Debug, Deserialize)]
struct RawInstance {
    #[serde(default)]
    id: String,
    #[serde(default)]
    address: Option<String>,
}

/// For every `sozune.<proto>.<svc>.host` declared, inject the first Ring port's
/// `target` as `sozune.<proto>.<svc>.port` unless the user already set one.
/// Explicit user ports win. Without this, a backend with no port label falls
/// back to `:80`. We use `target` (the in-container port) because we route to
/// the instance's guest IP, not a host-published port.
fn synthesize_port_labels(
    mut labels: HashMap<String, String>,
    ports: &[RawPort],
) -> HashMap<String, String> {
    let Some(target) = ports.iter().map(|p| p.target).find(|&p| p != 0) else {
        return labels;
    };
    let port_str = target.to_string();
    let prefixes: Vec<String> = labels
        .keys()
        .filter_map(|k| {
            k.strip_suffix(".host")
                .filter(|p| p.starts_with("sozune."))
                .map(|p| p.to_string())
        })
        .collect();
    for prefix in prefixes {
        labels
            .entry(format!("{prefix}.port"))
            .or_insert_with(|| port_str.clone());
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RingConfig {
        RingConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:3030".to_string(),
            token: String::new(),
            poll_interval: 10,
            expose_by_default: false,
        }
    }

    fn provider() -> RingProvider {
        RingProvider::new(cfg()).unwrap()
    }

    #[test]
    fn build_url_joins_endpoint_and_path() {
        assert_eq!(
            provider().build_url("/deployments"),
            "http://127.0.0.1:3030/deployments"
        );
    }

    #[test]
    fn build_url_trims_trailing_slash() {
        let mut c = cfg();
        c.endpoint = "http://127.0.0.1:3030/".to_string();
        let p = RingProvider::new(c).unwrap();
        assert_eq!(
            p.build_url("/deployments"),
            "http://127.0.0.1:3030/deployments"
        );
    }

    /// Builds candidates from a fixed deployment list, exercising the SAME
    /// per-deployment/per-instance logic as `collect()` (status gate, port
    /// synthesis, address skip, fan-out) without the HTTP round-trip.
    fn candidates_from(deployments: Vec<RawDeployment>, expose_by_default: bool) -> Vec<Candidate> {
        let mut out = Vec::new();
        for deployment in deployments {
            if deployment.status != "running" {
                continue;
            }
            let labels = synthesize_port_labels(deployment.labels.clone(), &deployment.ports);
            for instance in &deployment.instances {
                let Some(address) = instance.address.clone() else {
                    continue;
                };
                out.push(Candidate {
                    provider: PROVIDER_NAME,
                    id: instance.id.clone(),
                    display_name: deployment.name.clone(),
                    labels: labels.clone(),
                    networks: vec![NetworkInfo {
                        name: NETWORK_NAME.to_string(),
                        ip: Some(address),
                    }],
                    enabled_default: expose_by_default,
                    health: None,
                });
            }
        }
        out
    }

    /// A real Ring `GET /deployments` payload must deserialize into our DTO.
    /// This is the test that guards the contract with Ring's `DeploymentOutput`:
    /// `instances` is `[{id, address}]` and `ports` is `[{published, target, ...}]`.
    #[test]
    fn deserializes_real_ring_payload() {
        let body = r#"[
          {
            "id": "dep-1",
            "name": "web",
            "status": "running",
            "labels": { "sozune.http.web.host": "example.com" },
            "ports": [ { "published": 8080, "target": 80, "protocol": "tcp" } ],
            "instances": [
              { "id": "dep-1-a", "address": "10.42.0.2" },
              { "id": "dep-1-b", "address": null }
            ]
          }
        ]"#;
        let parsed: Vec<RawDeployment> =
            serde_json::from_str(body).expect("real Ring payload must deserialize");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ports[0].target, 80);
        assert_eq!(parsed[0].instances.len(), 2);
        assert_eq!(parsed[0].instances[0].address.as_deref(), Some("10.42.0.2"));
        assert_eq!(parsed[0].instances[1].address, None);
    }

    #[test]
    fn running_instance_with_address_becomes_candidate() {
        let d = RawDeployment {
            name: "web".into(),
            status: "running".into(),
            labels: HashMap::from([(
                "sozune.http.web.host".to_string(),
                "example.com".to_string(),
            )]),
            ports: vec![],
            instances: vec![RawInstance {
                id: "dep-1-abc".into(),
                address: Some("10.42.0.2".into()),
            }],
        };
        let c = candidates_from(vec![d], false);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].display_name, "web");
        assert_eq!(c[0].networks[0].ip.as_deref(), Some("10.42.0.2"));
        assert_eq!(
            c[0].labels.get("sozune.http.web.host").map(|s| s.as_str()),
            Some("example.com")
        );
    }

    #[test]
    fn non_running_deployment_is_skipped() {
        let d = RawDeployment {
            name: "web".into(),
            status: "pending".into(),
            labels: HashMap::new(),
            ports: vec![],
            instances: vec![RawInstance {
                id: "dep-1-abc".into(),
                address: Some("10.42.0.2".into()),
            }],
        };
        assert!(candidates_from(vec![d], false).is_empty());
    }

    #[test]
    fn instance_without_address_is_skipped() {
        let d = RawDeployment {
            name: "web".into(),
            status: "running".into(),
            labels: HashMap::new(),
            ports: vec![],
            instances: vec![RawInstance {
                id: "dep-1-abc".into(),
                address: None,
            }],
        };
        assert!(candidates_from(vec![d], false).is_empty());
    }

    #[test]
    fn multi_replica_fans_out_to_one_candidate_per_instance() {
        let d = RawDeployment {
            name: "web".into(),
            status: "running".into(),
            labels: HashMap::from([(
                "sozune.http.web.host".to_string(),
                "example.com".to_string(),
            )]),
            ports: vec![],
            instances: vec![
                RawInstance {
                    id: "dep-1-a".into(),
                    address: Some("10.42.0.2".into()),
                },
                RawInstance {
                    id: "dep-1-b".into(),
                    address: Some("10.42.0.6".into()),
                },
            ],
        };
        let c = candidates_from(vec![d], false);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn target_port_synthesizes_missing_port_label() {
        let labels = HashMap::from([(
            "sozune.http.web.host".to_string(),
            "example.com".to_string(),
        )]);
        let ports = vec![RawPort { target: 80 }];
        let out = synthesize_port_labels(labels, &ports);
        assert_eq!(
            out.get("sozune.http.web.port").map(|s| s.as_str()),
            Some("80"),
            "missing port should be filled from the Ring port's target"
        );
    }

    #[test]
    fn explicit_port_label_is_preserved() {
        let labels = HashMap::from([
            (
                "sozune.http.web.host".to_string(),
                "example.com".to_string(),
            ),
            ("sozune.http.web.port".to_string(), "9000".to_string()),
        ]);
        let ports = vec![RawPort { target: 80 }];
        let out = synthesize_port_labels(labels, &ports);
        assert_eq!(
            out.get("sozune.http.web.port").map(|s| s.as_str()),
            Some("9000"),
            "user-provided port must win over the target port"
        );
    }

    #[test]
    fn no_port_leaves_labels_untouched() {
        let labels = HashMap::from([(
            "sozune.http.web.host".to_string(),
            "example.com".to_string(),
        )]);
        let out = synthesize_port_labels(labels, &[]);
        assert!(!out.contains_key("sozune.http.web.port"));
    }
}
