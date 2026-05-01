use crate::config::KubernetesConfig;
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::labels::source::LabelSource;
use crate::labels::{self};
use crate::model::Entrypoint;
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Service};
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, Config, Resource};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const PROVIDER_NAME: &str = "kubernetes";

pub struct KubernetesProvider {
    config: KubernetesConfig,
    name: &'static str,
}

#[async_trait]
impl Provider for KubernetesProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let candidates = self.collect().await?;
        let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();
        for candidate in candidates {
            let result = labels::parse(&candidate);
            log_diagnostics(&candidate, &result.diagnostics);
            for (key, entrypoint) in result.entrypoints {
                entrypoints.insert(key, entrypoint);
            }
        }
        Ok(entrypoints)
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

#[async_trait]
impl LabelSource for KubernetesProvider {
    fn provider_name(&self) -> &'static str {
        self.name
    }

    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        let client = self.build_client().await?;
        let services: Api<Service> = self.scoped_api(&client);
        let list = services
            .list(&ListParams::default())
            .await
            .context("Failed to list Kubernetes services")?;

        let mut out = Vec::new();
        for svc in list.items {
            if let Some(candidate) = self.service_to_candidate(&svc) {
                out.push(candidate);
            }
        }
        Ok(out)
    }
}

impl KubernetesProvider {
    pub fn new(config: KubernetesConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            name: PROVIDER_NAME,
        })
    }

    async fn build_client(&self) -> anyhow::Result<Client> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        if self.config.kubeconfig.is_empty() {
            Client::try_default()
                .await
                .context("Failed to build Kubernetes client from default config")
        } else {
            let kubeconfig = Kubeconfig::read_from(&self.config.kubeconfig).with_context(|| {
                format!("Failed to read kubeconfig at {}", self.config.kubeconfig)
            })?;
            let kube_config =
                Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                    .await
                    .context("Failed to build kube Config from kubeconfig")?;
            Client::try_from(kube_config).context("Failed to build Kubernetes client from Config")
        }
    }

    /// Build a namespaced or cluster-wide Api handle depending on config.
    fn scoped_api<K>(&self, client: &Client) -> Api<K>
    where
        K: Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        <K as Resource>::DynamicType: Default,
    {
        if self.config.namespace.is_empty() {
            Api::all(client.clone())
        } else {
            Api::namespaced(client.clone(), &self.config.namespace)
        }
    }

    /// Convert a Service into a `Candidate`. Returns `None` for Services that
    /// have no `sozune.*` annotation and are not opted-in via `expose_by_default`.
    fn service_to_candidate(&self, svc: &Service) -> Option<Candidate> {
        let metadata = &svc.metadata;
        let namespace = metadata.namespace.as_deref().unwrap_or("default");
        let name = metadata.name.as_deref()?;

        let annotations: HashMap<String, String> = metadata
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let has_sozune_annotation = annotations.keys().any(|k| k.starts_with("sozune."));
        if !has_sozune_annotation && !self.config.expose_by_default {
            return None;
        }

        let cluster_ip = svc
            .spec
            .as_ref()
            .and_then(|s| s.cluster_ip.clone())
            .filter(|ip| !ip.is_empty() && ip != "None");

        let networks = match cluster_ip {
            Some(ip) => vec![NetworkInfo {
                name: "cluster".to_string(),
                ip: Some(ip),
            }],
            None => Vec::new(),
        };

        let id = format!("{namespace}/{name}");
        Some(Candidate {
            provider: self.name,
            id: id.clone(),
            display_name: id,
            labels: annotations,
            networks,
            enabled_default: self.config.expose_by_default,
        })
    }

    pub async fn start_service(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Kubernetes provider (namespace={}, ingress_class={}, expose_by_default={})",
            if self.config.namespace.is_empty() {
                "<all>"
            } else {
                self.config.namespace.as_str()
            },
            self.config.ingress_class,
            self.config.expose_by_default,
        );

        let client = self.build_client().await?;

        let version = client
            .apiserver_version()
            .await
            .context("Failed to query Kubernetes API server")?;
        info!(
            "Connected to Kubernetes cluster (version {}.{}, git {})",
            version.major, version.minor, version.git_version
        );

        let ns_api: Api<Namespace> = Api::all(client.clone());
        let ns_list = ns_api
            .list(&ListParams::default())
            .await
            .context("Failed to list namespaces")?;
        info!(
            "Kubernetes auth OK: {} namespace(s) visible to ServiceAccount",
            ns_list.items.len()
        );

        self.watch_services(client, storage, reload_tx, acme_notify)
            .await
    }

    async fn watch_services(
        &self,
        client: Client,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
    ) -> anyhow::Result<()> {
        let services: Api<Service> = self.scoped_api(&client);
        let stream = watcher::watcher(services, watcher::Config::default());
        tokio::pin!(stream);

        info!("Kubernetes Service watcher started");

        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(svc)) | Ok(Event::InitApply(svc)) => {
                    self.upsert_service(&svc, &storage, &reload_tx, &acme_notify)
                        .await;
                }
                Ok(Event::Delete(svc)) => {
                    self.remove_service(&svc, &storage, &reload_tx).await;
                }
                Ok(Event::Init) => {
                    debug!("Service watcher restart: reinitialising");
                }
                Ok(Event::InitDone) => {
                    debug!("Service watcher initial sync complete");
                }
                Err(e) => {
                    error!("Service watcher error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        warn!("Kubernetes Service watcher stopped");
        Ok(())
    }

    async fn upsert_service(
        &self,
        svc: &Service,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
    ) {
        let Some(candidate) = self.service_to_candidate(svc) else {
            return;
        };

        let result = labels::parse(&candidate);
        log_diagnostics(&candidate, &result.diagnostics);

        if result.entrypoints.is_empty() {
            return;
        }

        let mut storage_changed = false;
        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Storage lock poisoned in Kubernetes upsert: {}", e);
                    return;
                }
            };

            for (key, mut entrypoint) in result.entrypoints {
                entrypoint.source = Some(self.name.to_string());
                info!(
                    "Kubernetes upsert {} from service {}",
                    key, candidate.display_name
                );
                storage_write.insert(key, entrypoint);
                storage_changed = true;
            }
        }

        if storage_changed {
            if let Err(e) = reload_tx.send(()).await {
                error!(
                    "Failed to send reload signal after Kubernetes upsert: {}",
                    e
                );
            }
            acme_notify.notify_one();
        }
    }

    async fn remove_service(
        &self,
        svc: &Service,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
    ) {
        let Some(candidate) = self.service_to_candidate(svc) else {
            return;
        };

        let result = labels::parse(&candidate);
        if result.entrypoints.is_empty() {
            return;
        }

        let mut storage_changed = false;
        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Storage lock poisoned in Kubernetes remove: {}", e);
                    return;
                }
            };

            for key in result.entrypoints.keys() {
                if storage_write.remove(key).is_some() {
                    info!(
                        "Kubernetes remove {} from service {}",
                        key, candidate.display_name
                    );
                    storage_changed = true;
                }
            }
        }

        if storage_changed && let Err(e) = reload_tx.send(()).await {
            error!(
                "Failed to send reload signal after Kubernetes remove: {}",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_provider(expose_by_default: bool) -> KubernetesProvider {
        KubernetesProvider {
            config: KubernetesConfig {
                enabled: true,
                kubeconfig: String::new(),
                namespace: String::new(),
                ingress_class: "sozune".to_string(),
                expose_by_default,
            },
            name: PROVIDER_NAME,
        }
    }

    fn make_service(
        name: &str,
        namespace: &str,
        annotations: &[(&str, &str)],
        cluster_ip: Option<&str>,
    ) -> Service {
        let mut anns = BTreeMap::new();
        for (k, v) in annotations {
            anns.insert((*k).to_string(), (*v).to_string());
        }
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                annotations: if anns.is_empty() { None } else { Some(anns) },
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: cluster_ip.map(|s| s.to_string()),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn service_without_sozune_annotation_is_skipped() {
        let provider = make_provider(false);
        let svc = make_service("api", "default", &[("app", "api")], Some("10.0.0.1"));
        assert!(provider.service_to_candidate(&svc).is_none());
    }

    #[test]
    fn service_with_sozune_annotation_becomes_candidate() {
        let provider = make_provider(false);
        let svc = make_service(
            "api",
            "default",
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "x.test"),
            ],
            Some("10.0.0.1"),
        );
        let candidate = provider.service_to_candidate(&svc).expect("candidate");
        assert_eq!(candidate.id, "default/api");
        assert_eq!(candidate.networks.len(), 1);
        assert_eq!(candidate.networks[0].name, "cluster");
        assert_eq!(candidate.networks[0].ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn expose_by_default_picks_up_unannotated_service() {
        let provider = make_provider(true);
        let svc = make_service("api", "default", &[], Some("10.0.0.1"));
        assert!(provider.service_to_candidate(&svc).is_some());
    }

    #[test]
    fn headless_service_has_no_network() {
        let provider = make_provider(true);
        let svc = make_service("headless", "default", &[], Some("None"));
        let candidate = provider.service_to_candidate(&svc).expect("candidate");
        assert!(candidate.networks.is_empty());
    }
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
