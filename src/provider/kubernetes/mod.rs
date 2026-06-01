pub mod gateway;
pub mod gateway_filters;

use crate::config::KubernetesConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
use crate::model::{Backend, Entrypoint, EntrypointConfig, PathConfig, PathRuleType, Protocol};
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{HTTPIngressPath, Ingress, IngressBackend};
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, Config, Resource};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const PROVIDER_NAME: &str = crate::provider::KUBERNETES;
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// Maps `namespace/service` → (slice name → ready pod IPs from that slice).
/// We track per-slice attribution so an Apply that shrinks a slice (e.g.
/// scale-down) correctly drops the IPs that left, instead of accumulating
/// stale endpoints across events.
type EndpointsCache = Arc<RwLock<HashMap<String, HashMap<String, Vec<String>>>>>;

/// Maps `namespace/ingress` → set of entrypoint keys it owns. Lets us remove
/// only the entrypoints belonging to a deleted/updated Ingress without
/// touching what other Ingresses or annotated Services produced.
type IngressOwnership = Arc<RwLock<HashMap<String, HashSet<String>>>>;

/// References to the four shared values every watcher needs: the storage,
/// the reload channel, the ACME notifier, and the diagnostics store. Borrowed
/// so the same context can be threaded through nested helpers without forcing
/// an `Arc::clone` at every call site.
struct WatchCtx<'a> {
    storage: &'a Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: &'a mpsc::Sender<()>,
    acme_notify: &'a Arc<Notify>,
    diagnostics: &'a DiagnosticsStore,
}

pub struct KubernetesProvider {
    config: KubernetesConfig,
    name: &'static str,
    endpoints: EndpointsCache,
    ingress_keys: IngressOwnership,
}

#[async_trait]
impl Provider for KubernetesProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        // Trait callers don't share the runtime store; use a throwaway so
        // diagnostics are at least logged.
        let throwaway = diagnostics::new_store();
        let candidates = self.collect().await?;
        let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();
        for candidate in candidates {
            let result = diagnostics::parse_and_store(&throwaway, &candidate);
            log_diagnostics(&candidate, &result.diagnostics);
            for (key, entrypoint) in result.entrypoints {
                entrypoints.insert(key, entrypoint);
            }
        }
        Ok(entrypoints)
    }
}

#[async_trait]
impl LabelSource for KubernetesProvider {
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
            ingress_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn build_client(&self) -> anyhow::Result<Client> {
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
            health: None,
        })
    }

    /// Read all ready pod IPs known for a `namespace/service`, flattened
    /// across every EndpointSlice attached to that service. IPs are
    /// deduplicated to avoid double-listing if two slices overlap (rare but
    /// permitted by the API).
    pub fn pod_ips_for(&self, svc_id: &str) -> Vec<String> {
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
        diagnostics: DiagnosticsStore,
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
        let svc_diagnostics = Arc::clone(&diagnostics);
        let svc_handle = tokio::spawn(async move {
            if let Err(e) = svc_provider
                .watch_services(
                    svc_client,
                    svc_storage,
                    svc_reload,
                    svc_acme,
                    svc_diagnostics,
                )
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
        let ep_diagnostics = Arc::clone(&diagnostics);
        let ep_handle = tokio::spawn(async move {
            if let Err(e) = ep_provider
                .watch_endpoint_slices(ep_client, ep_storage, ep_reload, ep_acme, ep_diagnostics)
                .await
            {
                error!("Kubernetes EndpointSlice watcher failed: {}", e);
            }
        });

        let ing_provider = Arc::clone(&self);
        let ing_storage = Arc::clone(&storage);
        let ing_reload = reload_tx.clone();
        let ing_acme = Arc::clone(&acme_notify);
        let ing_client = client.clone();
        let ing_diagnostics = Arc::clone(&diagnostics);
        let ing_handle = tokio::spawn(async move {
            if let Err(e) = ing_provider
                .watch_ingresses(
                    ing_client,
                    ing_storage,
                    ing_reload,
                    ing_acme,
                    ing_diagnostics,
                )
                .await
            {
                error!("Kubernetes Ingress watcher failed: {}", e);
            }
        });

        let _ = tokio::try_join!(svc_handle, ep_handle, ing_handle);
        warn!("Kubernetes watchers stopped");
        Ok(())
    }

    async fn watch_services(
        &self,
        client: Client,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        let services: Api<Service> = self.scoped_api(&client);
        let stream = watcher::watcher(services, watcher::Config::default());
        tokio::pin!(stream);

        info!("Kubernetes Service watcher started");

        let ctx = WatchCtx {
            storage: &storage,
            reload_tx: &reload_tx,
            acme_notify: &acme_notify,
            diagnostics: &diagnostics,
        };

        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(svc)) | Ok(Event::InitApply(svc)) => {
                    self.upsert_service(&svc, &ctx).await;
                }
                Ok(Event::Delete(svc)) => {
                    self.remove_service(&svc, &ctx).await;
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
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        let slices: Api<EndpointSlice> = self.scoped_api(&client);
        let stream = watcher::watcher(slices, watcher::Config::default());
        tokio::pin!(stream);

        info!("Kubernetes EndpointSlice watcher started");

        let ctx = WatchCtx {
            storage: &storage,
            reload_tx: &reload_tx,
            acme_notify: &acme_notify,
            diagnostics: &diagnostics,
        };

        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(slice)) | Ok(Event::InitApply(slice)) => {
                    if let Some(svc_id) = self.apply_slice(&slice) {
                        self.refresh_service(&client, &svc_id, &ctx).await;
                    }
                }
                Ok(Event::Delete(slice)) => {
                    if let Some(svc_id) = self.remove_slice(&slice) {
                        self.refresh_service(&client, &svc_id, &ctx).await;
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
                error!(
                    "internal state corrupted (configuration store), restart required: {}",
                    e
                );
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
    async fn refresh_service(&self, client: &Client, svc_id: &str, ctx: &WatchCtx<'_>) {
        let Some((namespace, name)) = svc_id.split_once('/') else {
            return;
        };
        let api: Api<Service> = Api::namespaced(client.clone(), namespace);
        match api.get(name).await {
            Ok(svc) => {
                self.upsert_service(&svc, ctx).await;
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

        self.refresh_ingresses_for_service(client, namespace, name, ctx)
            .await;
    }

    /// Re-apply every Ingress in `namespace` whose backend references `svc_name`.
    /// Called when an EndpointSlice changes so that Ingress entrypoints pick up
    /// the freshest pod IPs the same way Service entrypoints do.
    async fn refresh_ingresses_for_service(
        &self,
        client: &Client,
        namespace: &str,
        svc_name: &str,
        ctx: &WatchCtx<'_>,
    ) {
        let api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
        let list = match api.list(&ListParams::default()).await {
            Ok(l) => l,
            Err(e) => {
                debug!(
                    "Failed to list ingresses in {} during endpoint refresh: {}",
                    namespace, e
                );
                return;
            }
        };

        for ing in list.items {
            if !ingress_references_service(&ing, svc_name) {
                continue;
            }
            self.apply_ingress(&ing, ctx).await;
        }
    }

    async fn upsert_service(&self, svc: &Service, ctx: &WatchCtx<'_>) {
        let Some(candidate) = self.service_to_candidate(svc) else {
            return;
        };

        let result = diagnostics::parse_and_store(ctx.diagnostics, &candidate);
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
            let mut storage_write = match ctx.storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
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
            if let Err(e) = ctx.reload_tx.send(()).await {
                error!(
                    "could not apply configuration update; will retry on next change: {}",
                    e
                );
            }
            ctx.acme_notify.notify_one();
        }
    }

    async fn remove_service(&self, svc: &Service, ctx: &WatchCtx<'_>) {
        let Some(candidate) = self.service_to_candidate(svc) else {
            return;
        };

        // Service is gone — drop its diagnostics. We still need to know which
        // entrypoint keys it produced, so re-parse without writing to the store.
        let result = crate::labels::parse(&candidate);
        diagnostics::remove(ctx.diagnostics, &candidate.id);
        if result.entrypoints.is_empty() {
            return;
        }

        let mut storage_changed = false;
        {
            let mut storage_write = match ctx.storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
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

        if storage_changed && let Err(e) = ctx.reload_tx.send(()).await {
            error!(
                "could not apply configuration update; will retry on next change: {}",
                e
            );
        }
    }

    async fn watch_ingresses(
        &self,
        client: Client,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        let ingresses: Api<Ingress> = self.scoped_api(&client);
        let stream = watcher::watcher(ingresses, watcher::Config::default());
        tokio::pin!(stream);

        info!(
            "Kubernetes Ingress watcher started (class={})",
            self.config.ingress_class
        );

        let ctx = WatchCtx {
            storage: &storage,
            reload_tx: &reload_tx,
            acme_notify: &acme_notify,
            diagnostics: &diagnostics,
        };

        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(ing)) | Ok(Event::InitApply(ing)) => {
                    self.apply_ingress(&ing, &ctx).await;
                }
                Ok(Event::Delete(ing)) => {
                    self.remove_ingress(&ing, &ctx).await;
                }
                Ok(Event::Init) | Ok(Event::InitDone) => {}
                Err(e) => {
                    error!("Ingress watcher error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        warn!("Kubernetes Ingress watcher stopped");
        Ok(())
    }

    async fn apply_ingress(&self, ing: &Ingress, ctx: &WatchCtx<'_>) {
        let Some(ing_id) = ingress_id(ing) else {
            return;
        };

        // Filter by ingressClassName. An Ingress without a class (or with a
        // different class) is ignored — and if we used to own it, drop it.
        let class_match = ing
            .spec
            .as_ref()
            .and_then(|s| s.ingress_class_name.as_deref())
            .map(|c| c == self.config.ingress_class)
            .unwrap_or(false);
        if !class_match {
            self.remove_ingress(ing, ctx).await;
            return;
        }

        let new_entries = self.ingress_to_entrypoints(ing);
        let new_keys: HashSet<String> = new_entries.iter().map(|(k, _)| k.clone()).collect();

        let old_keys = self
            .ingress_keys
            .read()
            .ok()
            .and_then(|m| m.get(&ing_id).cloned())
            .unwrap_or_default();

        let mut storage_changed = false;
        let mut tls_added = false;
        {
            let mut storage_write = match ctx.storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
                    return;
                }
            };

            // Remove keys this Ingress used to own that aren't there anymore.
            for stale in old_keys.difference(&new_keys) {
                if storage_write.remove(stale).is_some() {
                    info!("Ingress {} drops stale entrypoint {}", ing_id, stale);
                    storage_changed = true;
                }
            }

            // Upsert the current set.
            for (key, mut entrypoint) in new_entries {
                entrypoint.source = Some(self.name.to_string());
                let changed = match storage_write.get(&key) {
                    Some(existing) => existing != &entrypoint,
                    None => true,
                };
                if changed {
                    info!(
                        "Ingress {} upsert entrypoint {} ({} backend(s))",
                        ing_id,
                        key,
                        entrypoint.backends.len()
                    );
                    if entrypoint.config.tls {
                        tls_added = true;
                    }
                    storage_write.insert(key, entrypoint);
                    storage_changed = true;
                }
            }
        }

        if let Ok(mut owned) = self.ingress_keys.write() {
            owned.insert(ing_id, new_keys);
        }

        if storage_changed {
            if let Err(e) = ctx.reload_tx.send(()).await {
                error!(
                    "could not apply configuration update; will retry on next change: {}",
                    e
                );
            }
            if tls_added {
                ctx.acme_notify.notify_one();
            }
        }
    }

    async fn remove_ingress(&self, ing: &Ingress, ctx: &WatchCtx<'_>) {
        let Some(ing_id) = ingress_id(ing) else {
            return;
        };

        let keys = match self.ingress_keys.write() {
            Ok(mut owned) => owned.remove(&ing_id).unwrap_or_default(),
            Err(e) => {
                error!(
                    "internal state corrupted (ingress tracking), restart required: {}",
                    e
                );
                return;
            }
        };

        if keys.is_empty() {
            return;
        }

        let mut storage_changed = false;
        {
            let mut storage_write = match ctx.storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
                    return;
                }
            };
            for key in &keys {
                if storage_write.remove(key).is_some() {
                    info!("Ingress {} remove entrypoint {}", ing_id, key);
                    storage_changed = true;
                }
            }
        }

        if storage_changed && let Err(e) = ctx.reload_tx.send(()).await {
            error!(
                "could not apply configuration update; will retry on next change: {}",
                e
            );
        }
    }

    /// Convert an Ingress into entrypoints. Each (rule, path) becomes one
    /// entrypoint; `defaultBackend` becomes a catch-all entrypoint with no
    /// hostname filter. Backend pod IPs are read from the EndpointSlice cache;
    /// if none are known yet the entrypoint is registered with an empty
    /// backend list and a later EndpointSlice event will populate it.
    fn ingress_to_entrypoints(&self, ing: &Ingress) -> Vec<(String, Entrypoint)> {
        let Some(ing_id) = ingress_id(ing) else {
            return Vec::new();
        };
        let namespace = ing.metadata.namespace.as_deref().unwrap_or("default");
        let Some(spec) = ing.spec.as_ref() else {
            return Vec::new();
        };

        // Hosts that should get TLS termination via ACME.
        let tls_hosts: HashSet<String> = spec
            .tls
            .as_ref()
            .map(|tls_list| {
                tls_list
                    .iter()
                    .flat_map(|t| t.hosts.clone().unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default();

        let ctx = IngressParseCtx {
            provider: self,
            ing_id: &ing_id,
            namespace,
            tls_hosts: &tls_hosts,
        };

        let mut entries: Vec<(String, Entrypoint)> = Vec::new();

        if let Some(rules) = spec.rules.as_ref() {
            for (rule_idx, rule) in rules.iter().enumerate() {
                let host = rule.host.clone();
                let Some(http) = rule.http.as_ref() else {
                    continue;
                };
                for (path_idx, path) in http.paths.iter().enumerate() {
                    if let Some(entry) =
                        ctx.path_to_entrypoint(rule_idx, path_idx, host.as_deref(), path)
                    {
                        entries.push(entry);
                    }
                }
            }
        }

        if let Some(default) = spec.default_backend.as_ref()
            && let Some(entry) = ctx.backend_to_entrypoint("default", None, None, default, false)
        {
            entries.push(entry);
        }

        entries
    }
}

/// Identity + pre-computed state carried through every helper that parses one
/// Ingress into entrypoints. Lifted out of `path_to_entrypoint` /
/// `backend_to_entrypoint` so they're not dragging the same 4 contextual
/// values through their signatures.
struct IngressParseCtx<'a> {
    provider: &'a KubernetesProvider,
    ing_id: &'a str,
    namespace: &'a str,
    tls_hosts: &'a HashSet<String>,
}

impl IngressParseCtx<'_> {
    fn path_to_entrypoint(
        &self,
        rule_idx: usize,
        path_idx: usize,
        host: Option<&str>,
        path: &HTTPIngressPath,
    ) -> Option<(String, Entrypoint)> {
        let suffix = format!("r{rule_idx}p{path_idx}");
        let tls = host.map(|h| self.tls_hosts.contains(h)).unwrap_or(false);

        let path_config = match path.path.as_deref() {
            Some(p) if !p.is_empty() => Some(PathConfig {
                rule_type: match path.path_type.as_str() {
                    "Exact" => PathRuleType::Exact,
                    // Both `Prefix` and `ImplementationSpecific` map to Prefix:
                    // K8s lets implementations choose for the latter.
                    _ => PathRuleType::Prefix,
                },
                value: p.to_string(),
            }),
            _ => None,
        };

        self.backend_to_entrypoint(&suffix, host, path_config, &path.backend, tls)
    }

    fn backend_to_entrypoint(
        &self,
        suffix: &str,
        host: Option<&str>,
        path: Option<PathConfig>,
        backend: &IngressBackend,
        tls: bool,
    ) -> Option<(String, Entrypoint)> {
        let svc_ref = backend.service.as_ref()?;
        let port = match svc_ref.port.as_ref() {
            Some(p) => p.number.unwrap_or(80) as u16,
            None => 80,
        };
        let svc_id = format!("{}/{}", self.namespace, svc_ref.name);

        let pod_ips = self.provider.pod_ips_for(&svc_id);
        let backends: Vec<Backend> = if pod_ips.is_empty() {
            warn!(
                "Ingress {} references service {} but no ready endpoints are known yet",
                self.ing_id, svc_id
            );
            Vec::new()
        } else {
            pod_ips
                .into_iter()
                .map(|ip| Backend::new(ip, port))
                .collect()
        };

        let key = format!("ingress_{}_{}", sanitise(self.ing_id), suffix);
        let hostnames = host.map(|h| vec![h.to_string()]).unwrap_or_default();

        let entrypoint = Entrypoint {
            id: key.clone(),
            backends,
            name: key.clone(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames,
                path,
                tls,
                strip_prefix: false,
                add_prefix: None,
                https_redirect: false,
                https_redirect_port: None,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                rewrite_host: None,
                rewrite_path: None,
                rewrite_port: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                health_check: None,
                rate_limit: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                error_pages: std::collections::BTreeMap::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                ip_allow_list: Vec::new(),
            },
            source: Some(self.provider.name.to_string()),
        };

        Some((key, entrypoint))
    }
}

fn ingress_id(ing: &Ingress) -> Option<String> {
    let ns = ing.metadata.namespace.as_deref()?;
    let name = ing.metadata.name.as_deref()?;
    Some(format!("{ns}/{name}"))
}

/// Make an Ingress id safe to use inside an entrypoint key (which is also a
/// Sōzu cluster id). Replace `/` and `.` with `-`.
fn sanitise(id: &str) -> String {
    id.replace(['/', '.'], "-")
}

/// Whether any rule path or `defaultBackend` of `ing` points at the given
/// in-namespace service. Used to know which Ingresses to re-apply when an
/// EndpointSlice for that service changes.
fn ingress_references_service(ing: &Ingress, svc_name: &str) -> bool {
    let Some(spec) = ing.spec.as_ref() else {
        return false;
    };

    if let Some(default) = spec.default_backend.as_ref()
        && let Some(svc) = default.service.as_ref()
        && svc.name == svc_name
    {
        return true;
    }

    let Some(rules) = spec.rules.as_ref() else {
        return false;
    };
    for rule in rules {
        let Some(http) = rule.http.as_ref() else {
            continue;
        };
        for path in &http.paths {
            if let Some(svc) = path.backend.service.as_ref()
                && svc.name == svc_name
            {
                return true;
            }
        }
    }
    false
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
            ingress_keys: Arc::new(RwLock::new(HashMap::new())),
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

    fn make_ingress(
        name: &str,
        namespace: &str,
        class: Option<&str>,
        rules: Vec<(Option<&str>, Vec<(&str, &str, &str, i32)>)>,
        tls_hosts: Vec<&str>,
    ) -> Ingress {
        use k8s_openapi::api::networking::v1::{
            HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressSpec,
            IngressTLS, ServiceBackendPort,
        };

        let rule_objs: Vec<IngressRule> = rules
            .into_iter()
            .map(|(host, paths)| IngressRule {
                host: host.map(|s| s.to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: paths
                        .into_iter()
                        .map(|(path, path_type, svc, port)| HTTPIngressPath {
                            path: Some(path.to_string()),
                            path_type: path_type.to_string(),
                            backend: IngressBackend {
                                service: Some(
                                    k8s_openapi::api::networking::v1::IngressServiceBackend {
                                        name: svc.to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(port),
                                            name: None,
                                        }),
                                    },
                                ),
                                resource: None,
                            },
                        })
                        .collect(),
                }),
            })
            .collect();

        let tls = if tls_hosts.is_empty() {
            None
        } else {
            Some(vec![IngressTLS {
                hosts: Some(tls_hosts.into_iter().map(|s| s.to_string()).collect()),
                secret_name: None,
            }])
        };

        Ingress {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: class.map(|s| s.to_string()),
                rules: Some(rule_objs),
                tls,
                default_backend: None,
            }),
            status: None,
        }
    }

    #[test]
    fn ingress_with_wrong_class_is_filtered_out() {
        let provider = make_provider(false);
        let ing = make_ingress(
            "web",
            "default",
            Some("nginx"),
            vec![(Some("api.test"), vec![("/", "Prefix", "api", 80)])],
            vec![],
        );
        // ingress_to_entrypoints itself doesn't filter — the class check
        // lives in apply_ingress. We verify the predicate logic the way
        // apply_ingress evaluates it.
        let class_match = ing
            .spec
            .as_ref()
            .and_then(|s| s.ingress_class_name.as_deref())
            .map(|c| c == provider.config.ingress_class)
            .unwrap_or(false);
        assert!(!class_match);
    }

    #[test]
    fn ingress_converts_rules_to_entrypoints() {
        let provider = make_provider(false);
        provider.apply_slice(&make_slice(
            "api-abc",
            "default",
            "api",
            vec![
                (vec!["10.244.0.5"], Some(true)),
                (vec!["10.244.0.6"], Some(true)),
            ],
        ));

        let ing = make_ingress(
            "web",
            "default",
            Some("sozune"),
            vec![(
                Some("api.test"),
                vec![
                    ("/api", "Prefix", "api", 80),
                    ("/exact", "Exact", "api", 80),
                ],
            )],
            vec![],
        );

        let entries = provider.ingress_to_entrypoints(&ing);
        assert_eq!(entries.len(), 2);

        let prefix_entry = entries.iter().find(|(k, _)| k.ends_with("r0p0")).unwrap();
        assert_eq!(prefix_entry.1.config.hostnames, vec!["api.test"]);
        assert_eq!(
            prefix_entry.1.config.path.as_ref().unwrap().rule_type,
            PathRuleType::Prefix
        );
        assert_eq!(prefix_entry.1.config.path.as_ref().unwrap().value, "/api");
        assert_eq!(prefix_entry.1.backends.len(), 2);
        assert!(prefix_entry.1.backends.iter().all(|b| b.port == 80));
        assert!(!prefix_entry.1.config.tls);

        let exact_entry = entries.iter().find(|(k, _)| k.ends_with("r0p1")).unwrap();
        assert_eq!(
            exact_entry.1.config.path.as_ref().unwrap().rule_type,
            PathRuleType::Exact
        );
    }

    #[test]
    fn ingress_tls_block_enables_tls_on_matching_hosts() {
        let provider = make_provider(false);
        let ing = make_ingress(
            "web",
            "default",
            Some("sozune"),
            vec![
                (Some("api.test"), vec![("/", "Prefix", "api", 80)]),
                (Some("public.test"), vec![("/", "Prefix", "api", 80)]),
            ],
            vec!["api.test"],
        );

        let entries = provider.ingress_to_entrypoints(&ing);
        let api_entry = entries
            .iter()
            .find(|(_, e)| e.config.hostnames == vec!["api.test"])
            .unwrap();
        let public_entry = entries
            .iter()
            .find(|(_, e)| e.config.hostnames == vec!["public.test"])
            .unwrap();
        assert!(api_entry.1.config.tls);
        assert!(!public_entry.1.config.tls);
    }

    #[test]
    fn ingress_implementation_specific_path_falls_back_to_prefix() {
        let provider = make_provider(false);
        let ing = make_ingress(
            "web",
            "default",
            Some("sozune"),
            vec![(
                Some("api.test"),
                vec![("/", "ImplementationSpecific", "api", 80)],
            )],
            vec![],
        );
        let entries = provider.ingress_to_entrypoints(&ing);
        assert_eq!(
            entries[0].1.config.path.as_ref().unwrap().rule_type,
            PathRuleType::Prefix
        );
    }

    #[test]
    fn ingress_keys_are_unique_per_rule_and_path() {
        let provider = make_provider(false);
        let ing = make_ingress(
            "web",
            "default",
            Some("sozune"),
            vec![
                (Some("a.test"), vec![("/", "Prefix", "api", 80)]),
                (Some("b.test"), vec![("/", "Prefix", "api", 80)]),
            ],
            vec![],
        );
        let entries = provider.ingress_to_entrypoints(&ing);
        let keys: HashSet<String> = entries.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn ingress_without_known_endpoints_registers_with_empty_backends() {
        let provider = make_provider(false);
        // No EndpointSlice applied for this Service — the entry is still
        // produced so that a later EndpointSlice apply can populate it.
        let ing = make_ingress(
            "web",
            "default",
            Some("sozune"),
            vec![(Some("api.test"), vec![("/", "Prefix", "missing", 80)])],
            vec![],
        );
        let entries = provider.ingress_to_entrypoints(&ing);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].1.backends.is_empty());
    }

    #[test]
    fn sanitise_replaces_path_separators() {
        assert_eq!(sanitise("default/web"), "default-web");
        assert_eq!(sanitise("ns.test/web.app"), "ns-test-web-app");
    }
}
