use crate::config::KubernetesConfig;
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::labels::source::LabelSource;
use crate::labels::{self};
use crate::model::{Backend, Entrypoint};
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, Config, Resource};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const PROVIDER_NAME: &str = "kubernetes";
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// Maps `namespace/service` → (slice name → ready pod IPs from that slice).
/// We track per-slice attribution so an Apply that shrinks a slice (e.g.
/// scale-down) correctly drops the IPs that left, instead of accumulating
/// stale endpoints across events.
type EndpointsCache = Arc<RwLock<HashMap<String, HashMap<String, Vec<String>>>>>;

pub struct KubernetesProvider {
    config: KubernetesConfig,
    name: &'static str,
    endpoints: EndpointsCache,
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
            endpoints: Arc::new(RwLock::new(HashMap::new())),
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
    ///
    /// The candidate carries a single representative network IP (first ready
    /// pod IP if available, otherwise `Service.spec.clusterIP`) to satisfy the
    /// label parser. Multiple backends are injected by `upsert_service` after
    /// parsing — the parser produces only one backend per candidate by design.
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

        let id = format!("{namespace}/{name}");

        let pod_ips = self.pod_ips_for(&id);
        let representative_ip = pod_ips.first().cloned().or_else(|| {
            svc.spec
                .as_ref()
                .and_then(|s| s.cluster_ip.clone())
                .filter(|ip| !ip.is_empty() && ip != "None")
        });

        let networks = match representative_ip {
            Some(ip) => vec![NetworkInfo {
                name: "cluster".to_string(),
                ip: Some(ip),
            }],
            None => Vec::new(),
        };

        Some(Candidate {
            provider: self.name,
            id: id.clone(),
            display_name: id,
            labels: annotations,
            networks,
            enabled_default: self.config.expose_by_default,
        })
    }

    /// Read all ready pod IPs known for a `namespace/service`, flattened
    /// across every EndpointSlice attached to that service. IPs are
    /// deduplicated to avoid double-listing if two slices overlap (rare but
    /// permitted by the API).
    fn pod_ips_for(&self, svc_id: &str) -> Vec<String> {
        let Ok(cache) = self.endpoints.read() else {
            return Vec::new();
        };
        let Some(slices) = cache.get(svc_id) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for ips in slices.values() {
            for ip in ips {
                if !out.contains(ip) {
                    out.push(ip.clone());
                }
            }
        }
        out.sort();
        out
    }

    pub async fn start_service(
        self: Arc<Self>,
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

        let svc_provider = Arc::clone(&self);
        let svc_storage = Arc::clone(&storage);
        let svc_reload = reload_tx.clone();
        let svc_acme = Arc::clone(&acme_notify);
        let svc_client = client.clone();
        let svc_handle = tokio::spawn(async move {
            if let Err(e) = svc_provider
                .watch_services(svc_client, svc_storage, svc_reload, svc_acme)
                .await
            {
                error!("Kubernetes Service watcher failed: {}", e);
            }
        });

        let ep_provider = Arc::clone(&self);
        let ep_storage = Arc::clone(&storage);
        let ep_reload = reload_tx.clone();
        let ep_acme = Arc::clone(&acme_notify);
        let ep_client = client.clone();
        let ep_handle = tokio::spawn(async move {
            if let Err(e) = ep_provider
                .watch_endpoint_slices(ep_client, ep_storage, ep_reload, ep_acme)
                .await
            {
                error!("Kubernetes EndpointSlice watcher failed: {}", e);
            }
        });

        let _ = tokio::try_join!(svc_handle, ep_handle);
        warn!("Kubernetes watchers stopped");
        Ok(())
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

    async fn watch_endpoint_slices(
        &self,
        client: Client,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
    ) -> anyhow::Result<()> {
        let slices: Api<EndpointSlice> = self.scoped_api(&client);
        let stream = watcher::watcher(slices, watcher::Config::default());
        tokio::pin!(stream);

        info!("Kubernetes EndpointSlice watcher started");

        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(slice)) | Ok(Event::InitApply(slice)) => {
                    if let Some(svc_id) = self.apply_slice(&slice) {
                        self.refresh_service(&client, &svc_id, &storage, &reload_tx, &acme_notify)
                            .await;
                    }
                }
                Ok(Event::Delete(slice)) => {
                    if let Some(svc_id) = self.remove_slice(&slice) {
                        self.refresh_service(&client, &svc_id, &storage, &reload_tx, &acme_notify)
                            .await;
                    }
                }
                Ok(Event::Init) | Ok(Event::InitDone) => {}
                Err(e) => {
                    error!("EndpointSlice watcher error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        warn!("Kubernetes EndpointSlice watcher stopped");
        Ok(())
    }

    /// Update the endpoints cache from a slice. Returns `Some(namespace/service)`
    /// when the slice belongs to a service we can resolve, `None` otherwise.
    fn apply_slice(&self, slice: &EndpointSlice) -> Option<String> {
        let namespace = slice.metadata.namespace.as_deref()?;
        let service_name = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))?;

        let svc_id = format!("{namespace}/{service_name}");

        let ips: Vec<String> = slice
            .endpoints
            .iter()
            .filter(|ep| ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true))
            .flat_map(|ep| ep.addresses.iter().cloned())
            .filter(|ip| !ip.is_empty())
            .collect();

        let slice_name = slice.metadata.name.as_deref()?.to_string();

        let mut cache = match self.endpoints.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Endpoints cache poisoned: {}", e);
                return None;
            }
        };

        let slices = cache.entry(svc_id.clone()).or_default();
        let total_after = if ips.is_empty() {
            slices.remove(&slice_name);
            slices.values().map(|v| v.len()).sum::<usize>()
        } else {
            let count = ips.len();
            slices.insert(slice_name.clone(), ips);
            count
                + slices
                    .iter()
                    .filter_map(|(k, v)| {
                        if k != &slice_name {
                            Some(v.len())
                        } else {
                            None
                        }
                    })
                    .sum::<usize>()
        };

        debug!(
            "EndpointSlice {} applied: {} ready endpoint(s) for {} (total across slices: {})",
            slice_name,
            slices.get(&slice_name).map(|v| v.len()).unwrap_or(0),
            svc_id,
            total_after
        );

        Some(svc_id)
    }

    /// Drop a slice's contribution from the cache. Surviving slices for the
    /// same service stay intact — their attribution is keyed by slice name.
    fn remove_slice(&self, slice: &EndpointSlice) -> Option<String> {
        let namespace = slice.metadata.namespace.as_deref()?;
        let service_name = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))?;
        let slice_name = slice.metadata.name.as_deref()?;

        let svc_id = format!("{namespace}/{service_name}");

        if let Ok(mut cache) = self.endpoints.write()
            && let Some(slices) = cache.get_mut(&svc_id)
        {
            slices.remove(slice_name);
            if slices.is_empty() {
                cache.remove(&svc_id);
            }
        }

        Some(svc_id)
    }

    /// Re-fetch a Service and re-run the upsert path so its entrypoint picks
    /// up the freshest backend list from the endpoints cache.
    async fn refresh_service(
        &self,
        client: &Client,
        svc_id: &str,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
    ) {
        let Some((namespace, name)) = svc_id.split_once('/') else {
            return;
        };
        let api: Api<Service> = Api::namespaced(client.clone(), namespace);
        match api.get(name).await {
            Ok(svc) => {
                self.upsert_service(&svc, storage, reload_tx, acme_notify)
                    .await;
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                debug!(
                    "Service {} not found during endpoint refresh (likely deleted)",
                    svc_id
                );
            }
            Err(e) => {
                warn!(
                    "Failed to refresh service {} after endpoint change: {}",
                    svc_id, e
                );
            }
        }
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

        // Replace the parser's single-IP backend list with every ready pod IP
        // known for this service. When the cache is empty we keep the parser's
        // backend (clusterIP fallback or 127.0.0.1).
        let pod_ips = self.pod_ips_for(&candidate.id);

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
                // Replace the parser's single-pod placeholder with one
                // Backend per ready pod IP, all targeting the same port the
                // parser resolved from the labels.
                if !pod_ips.is_empty() {
                    let port = entrypoint
                        .backends
                        .first()
                        .map(|b| b.port)
                        .unwrap_or_default();
                    entrypoint.backends = pod_ips
                        .iter()
                        .map(|ip| Backend::new(ip.clone(), port))
                        .collect();
                }
                let backends = entrypoint.backends.len();
                let existing_changed = match storage_write.get(&key) {
                    Some(existing) => existing != &entrypoint,
                    None => true,
                };
                if existing_changed {
                    info!(
                        "Kubernetes upsert {} from service {} ({} backend(s))",
                        key, candidate.display_name, backends
                    );
                    storage_write.insert(key, entrypoint);
                    storage_changed = true;
                }
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
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};
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
            endpoints: Arc::new(RwLock::new(HashMap::new())),
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

    fn make_slice(
        slice_name: &str,
        namespace: &str,
        service_name: &str,
        endpoints: Vec<(Vec<&str>, Option<bool>)>,
    ) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert(SERVICE_NAME_LABEL.to_string(), service_name.to_string());
        EndpointSlice {
            address_type: "IPv4".to_string(),
            metadata: ObjectMeta {
                name: Some(slice_name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            endpoints: endpoints
                .into_iter()
                .map(|(addrs, ready)| Endpoint {
                    addresses: addrs.into_iter().map(|s| s.to_string()).collect(),
                    conditions: ready.map(|r| EndpointConditions {
                        ready: Some(r),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
            ports: None,
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

    #[test]
    fn endpoint_slice_populates_pod_ips() {
        let provider = make_provider(true);
        let slice = make_slice(
            "api-abc",
            "default",
            "api",
            vec![
                (vec!["10.244.0.5"], Some(true)),
                (vec!["10.244.0.6"], Some(true)),
            ],
        );
        assert_eq!(provider.apply_slice(&slice).as_deref(), Some("default/api"));
        assert_eq!(
            provider.pod_ips_for("default/api"),
            vec!["10.244.0.5".to_string(), "10.244.0.6".to_string()]
        );
    }

    #[test]
    fn not_ready_endpoints_are_excluded() {
        let provider = make_provider(true);
        let slice = make_slice(
            "api-abc",
            "default",
            "api",
            vec![
                (vec!["10.244.0.5"], Some(true)),
                (vec!["10.244.0.6"], Some(false)),
            ],
        );
        provider.apply_slice(&slice);
        assert_eq!(
            provider.pod_ips_for("default/api"),
            vec!["10.244.0.5".to_string()]
        );
    }

    #[test]
    fn candidate_uses_first_pod_ip_as_representative() {
        let provider = make_provider(true);
        let slice = make_slice(
            "api-abc",
            "default",
            "api",
            vec![
                (vec!["10.244.0.5"], Some(true)),
                (vec!["10.244.0.6"], Some(true)),
            ],
        );
        provider.apply_slice(&slice);
        let svc = make_service(
            "api",
            "default",
            &[("sozune.enable", "true")],
            Some("10.0.0.1"),
        );
        let candidate = provider.service_to_candidate(&svc).expect("candidate");
        assert_eq!(candidate.networks.len(), 1);
        assert_eq!(candidate.networks[0].ip.as_deref(), Some("10.244.0.5"));
    }

    #[test]
    fn endpoints_fall_back_to_cluster_ip_when_cache_empty() {
        let provider = make_provider(true);
        let svc = make_service(
            "api",
            "default",
            &[("sozune.enable", "true")],
            Some("10.0.0.1"),
        );
        let candidate = provider.service_to_candidate(&svc).expect("candidate");
        assert_eq!(candidate.networks.len(), 1);
        assert_eq!(candidate.networks[0].ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn remove_slice_clears_service_bucket() {
        let provider = make_provider(true);
        let slice = make_slice(
            "api-abc",
            "default",
            "api",
            vec![(vec!["10.244.0.5"], Some(true))],
        );
        provider.apply_slice(&slice);
        assert!(
            provider
                .endpoints
                .read()
                .unwrap()
                .contains_key("default/api")
        );
        provider.remove_slice(&slice);
        assert!(
            !provider
                .endpoints
                .read()
                .unwrap()
                .contains_key("default/api")
        );
    }

    #[test]
    fn shrinking_slice_drops_stale_ips() {
        let provider = make_provider(true);
        let initial = make_slice(
            "api-abc",
            "default",
            "api",
            vec![
                (vec!["10.244.0.5"], Some(true)),
                (vec!["10.244.0.6"], Some(true)),
                (vec!["10.244.0.7"], Some(true)),
            ],
        );
        provider.apply_slice(&initial);
        assert_eq!(provider.pod_ips_for("default/api").len(), 3);

        let shrunk = make_slice(
            "api-abc",
            "default",
            "api",
            vec![(vec!["10.244.0.5"], Some(true))],
        );
        provider.apply_slice(&shrunk);
        assert_eq!(
            provider.pod_ips_for("default/api"),
            vec!["10.244.0.5".to_string()]
        );
    }

    #[test]
    fn multiple_slices_for_same_service_are_merged() {
        let provider = make_provider(true);
        let slice_a = make_slice(
            "api-aaa",
            "default",
            "api",
            vec![(vec!["10.244.0.5"], Some(true))],
        );
        let slice_b = make_slice(
            "api-bbb",
            "default",
            "api",
            vec![(vec!["10.244.0.6"], Some(true))],
        );
        provider.apply_slice(&slice_a);
        provider.apply_slice(&slice_b);
        assert_eq!(
            provider.pod_ips_for("default/api"),
            vec!["10.244.0.5".to_string(), "10.244.0.6".to_string()]
        );

        provider.remove_slice(&slice_a);
        assert_eq!(
            provider.pod_ips_for("default/api"),
            vec!["10.244.0.6".to_string()]
        );
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
