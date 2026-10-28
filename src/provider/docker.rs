use crate::config::DockerConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, HealthStatus, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
use crate::model::{Backend, Entrypoint};
use crate::provider::Provider;
use async_trait::async_trait;
use bollard::models::HealthStatusEnum;
use bollard::{
    Docker,
    query_parameters::{EventsOptions, InspectContainerOptions, ListContainersOptions},
};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct DockerProvider {
    docker: Docker,
    config: DockerConfig,
    name: &'static str,
    /// Tracks container_id -> the backends it contributed, so cleanup can drop
    /// exactly those when it stops. Stopped containers no longer expose their
    /// network IP via inspect, and the address alone is not enough to tell two
    /// containers apart: host-network ones all resolve to `127.0.0.1`, and
    /// Docker recycles addresses.
    container_ips: std::sync::Mutex<HashMap<String, Vec<Backend>>>,
    /// What each container serving routes declares, by route key: a route is
    /// rebuilt from its remaining containers when one leaves, so it takes
    /// what they declare, not what the one that left did.
    declared: std::sync::Mutex<HashMap<String, HashMap<String, Entrypoint>>>,
}

#[async_trait]
impl Provider for DockerProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        // Throwaway store: trait callers (CLI, validate) don't share the
        // runtime store; diagnostics get logged either way.
        let throwaway = diagnostics::new_store();
        let hashmap = self
            .get_entrypoints_from_containers(&throwaway)
            .await
            .map_err(anyhow::Error::new)?;
        Ok(hashmap.into_iter().collect())
    }
}

#[async_trait]
impl LabelSource for DockerProvider {
    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: false,
                ..Default::default()
            }))
            .await?;

        let mut candidates = Vec::with_capacity(containers.len());
        for container in containers {
            let Some(labels) = container.labels else {
                continue;
            };
            let id = container.id.unwrap_or_default();
            let display_name = container
                .names
                .as_ref()
                .and_then(|names| names.first().cloned())
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| id.clone());
            let (networks, health) = self.inspect_for_routing(&id).await;
            candidates.push(Candidate {
                provider: self.name,
                id,
                display_name,
                labels,
                networks,
                enabled_default: self.config.expose_by_default,
                health,
            });
        }
        Ok(candidates)
    }
}

impl DockerProvider {
    pub fn new(config: DockerConfig) -> Result<Self, bollard::errors::Error> {
        Self::new_named(config, crate::provider::DOCKER)
    }

    pub fn new_named(
        config: DockerConfig,
        name: &'static str,
    ) -> Result<Self, bollard::errors::Error> {
        let docker = if config.endpoint.starts_with("unix://") {
            Docker::connect_with_socket(&config.endpoint, 120, bollard::API_DEFAULT_VERSION)?
        } else if config.endpoint.starts_with("/") {
            Docker::connect_with_socket(
                &format!("unix://{}", config.endpoint),
                120,
                bollard::API_DEFAULT_VERSION,
            )?
        } else {
            Docker::connect_with_local_defaults()?
        };
        Ok(Self {
            docker,
            config,
            name,
            container_ips: std::sync::Mutex::new(HashMap::new()),
            declared: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Start Docker service: initial scan + event listening
    pub async fn start_service(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<tokio::sync::Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!("Starting Docker service");

        // Initial scan of existing containers
        info!("Performing initial scan of running containers");
        match self.get_entrypoints_from_containers(&diagnostics).await {
            Ok(initial_entrypoints) => {
                if !initial_entrypoints.is_empty() {
                    let storage_changed = {
                        let mut changed = false;
                        let mut storage_write = match storage.write() {
                            Ok(guard) => guard,
                            Err(e) => {
                                error!(
                                    "internal state corrupted (configuration store), restart required: {}",
                                    e
                                );
                                return Ok(());
                            }
                        };

                        for (key, entrypoint) in initial_entrypoints {
                            // The container that declared it, like the event path
                            // uses: a redirect has no backend to name it by.
                            let source_id = entrypoint
                                .candidates
                                .first()
                                .cloned()
                                .or_else(|| entrypoint.backends.first().map(|b| b.address.clone()))
                                .unwrap_or_default();
                            info!("Loading container entrypoint: {}", key);
                            merge_or_insert_entrypoint_btree(
                                &mut storage_write,
                                key,
                                entrypoint,
                                &source_id,
                                self.name,
                            );
                            changed = true;
                        }
                        changed
                    };

                    // Only trigger reload if configuration actually changed
                    if storage_changed {
                        if let Err(e) = reload_tx.send(()).await {
                            warn!(
                                "could not apply configuration update; will retry on next change: {}",
                                e
                            );
                        } else {
                            info!("Initial configuration loaded from running containers");
                        }
                        acme_notify.notify_one();
                    } else {
                        info!("No new container entrypoints found, configuration unchanged");
                    }
                } else {
                    info!("No running containers with Sozune labels found");
                }
            }
            Err(e) => {
                error!("Failed to scan running containers: {}", e);
            }
        }

        // Start event listener
        self.start_event_listener(storage, reload_tx, acme_notify, diagnostics)
            .await
    }

    /// Start listening for Docker events and update storage directly
    async fn start_event_listener(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<tokio::sync::Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!("Starting Docker event listener");

        let mut filters = std::collections::HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "event".to_string(),
            vec![
                "start".to_string(),
                "stop".to_string(),
                "die".to_string(),
                "destroy".to_string(),
                "update".to_string(),
                // HEALTHCHECK transitions — Docker emits these as
                // `health_status: healthy` / `health_status: unhealthy` (the
                // space after the colon is part of the action string).
                "health_status: healthy".to_string(),
                "health_status: unhealthy".to_string(),
            ],
        );

        let mut events = self.docker.events(Some(EventsOptions {
            since: None,
            until: None,
            filters: Some(filters),
        }));

        while let Some(event_result) = events.next().await {
            match event_result {
                Ok(event) => {
                    if let Some(action) = &event.action
                        && let Some(actor) = &event.actor
                        && let Some(container_id) = &actor.id
                    {
                        info!("Docker event: {} for container {}", action, container_id);

                        let mut storage_changed = false;

                        let action_str = action.as_str();
                        match action_str {
                            "start" | "health_status: healthy" => {
                                if let Ok(entrypoints) = self
                                    .get_container_entrypoints(container_id, &diagnostics)
                                    .await
                                    && !entrypoints.is_empty()
                                {
                                    // Remember exactly what this container
                                    // contributes, so its stop takes those and
                                    // nothing a neighbour shares an address with.
                                    if let Ok(mut ips) = self.container_ips.lock() {
                                        ips.insert(
                                            container_id.to_string(),
                                            endpoints_of(entrypoints.values()),
                                        );
                                    }
                                    self.remember(container_id, &entrypoints);
                                    let mut storage_write = match storage.write() {
                                        Ok(guard) => guard,
                                        Err(e) => {
                                            error!(
                                                "internal state corrupted (configuration store), restart required: {}",
                                                e
                                            );
                                            continue;
                                        }
                                    };
                                    for (key, entrypoint) in entrypoints {
                                        info!(
                                            "Adding entrypoint from {} container: {}",
                                            if action_str == "start" {
                                                "started"
                                            } else {
                                                "healthy"
                                            },
                                            key
                                        );
                                        merge_or_insert_entrypoint_btree(
                                            &mut storage_write,
                                            key,
                                            entrypoint,
                                            container_id,
                                            self.name,
                                        );
                                    }
                                    storage_changed = true;
                                }
                            }
                            "health_status: unhealthy" => {
                                // Container went unhealthy: remove from the
                                // backend pool but keep the IP tracking so a
                                // later recovery to healthy can re-add it
                                // without a fresh container start/inspect race.
                                let container_ip = self
                                    .container_ips
                                    .lock()
                                    .ok()
                                    .and_then(|ips| ips.get(container_id.as_str()).cloned());
                                let Some(container_ip) = container_ip else {
                                    debug!(
                                        "Container {} went unhealthy but had no tracked IP; nothing to remove",
                                        container_id
                                    );
                                    continue;
                                };
                                let mut storage_write = match storage.write() {
                                    Ok(guard) => guard,
                                    Err(e) => {
                                        error!(
                                            "internal state corrupted (configuration store), restart required: {}",
                                            e
                                        );
                                        continue;
                                    }
                                };
                                self.forget(container_id);
                                self.take_off(&mut storage_write, container_id, &container_ip);
                                storage_changed = true;
                            }
                            "stop" | "die" | "destroy" => {
                                // Drop any cached diagnostics for this container — it's gone.
                                diagnostics::remove(&diagnostics, container_id);
                                // A stopped container no longer reports what it served, so
                                // we read the endpoints recorded when it started. With no
                                // entry — the event arrived before we ever saw the container —
                                // there is nothing safe to remove: guessing an address and
                                // sweeping on it would take every host-network backend with
                                // it. The provider only watches events after its initial
                                // scan, so those routes do stay until a restart; a stale
                                // route beats deleting live ones.
                                let Some(container_ip) = self
                                    .container_ips
                                    .lock()
                                    .ok()
                                    .and_then(|mut ips| ips.remove(container_id.as_str()))
                                else {
                                    warn!(
                                        "container {} stopped but we never recorded what it served; its routes stay until sozune restarts",
                                        container_id
                                    );
                                    continue;
                                };
                                let mut storage_write = match storage.write() {
                                    Ok(guard) => guard,
                                    Err(e) => {
                                        error!(
                                            "internal state corrupted (configuration store), restart required: {}",
                                            e
                                        );
                                        continue;
                                    }
                                };

                                self.forget(container_id);
                                self.take_off(&mut storage_write, container_id, &container_ip);
                                storage_changed = true;
                            }
                            "update" => {
                                // For updates, remove old and add new
                                if let Ok(entrypoints) = self
                                    .get_container_entrypoints(container_id, &diagnostics)
                                    .await
                                {
                                    // What this container contributed before
                                    // the update, so the old endpoints go and a
                                    // neighbour sharing an address keeps its
                                    // own. Guessing 127.0.0.1 on a failed
                                    // lookup would sweep every host-network
                                    // backend instead.
                                    let previous = self
                                        .container_ips
                                        .lock()
                                        .ok()
                                        .and_then(|ips| ips.get(container_id).cloned())
                                        .unwrap_or_default();
                                    let mut storage_write = match storage.write() {
                                        Ok(guard) => guard,
                                        Err(e) => {
                                            error!(
                                                "internal state corrupted (configuration store), restart required: {}",
                                                e
                                            );
                                            continue;
                                        }
                                    };

                                    // Remove old entries for this container
                                    self.forget(container_id);
                                    self.take_off(&mut storage_write, container_id, &previous);

                                    // Add new entries, and remember them: a
                                    // later stop has to drop what the container
                                    // contributes now, not what it did before
                                    // this update.
                                    if let Ok(mut ips) = self.container_ips.lock() {
                                        ips.insert(
                                            container_id.to_string(),
                                            endpoints_of(entrypoints.values()),
                                        );
                                    }
                                    self.remember(container_id, &entrypoints);
                                    for (key, entrypoint) in entrypoints {
                                        merge_or_insert_entrypoint_btree(
                                            &mut storage_write,
                                            key,
                                            entrypoint,
                                            container_id,
                                            self.name,
                                        );
                                    }
                                    storage_changed = true;
                                }
                            }
                            _ => {
                                // Other events we don't care about
                            }
                        }

                        if storage_changed {
                            info!("Storage updated, triggering reload");
                            if let Err(e) = reload_tx.send(()).await {
                                error!(
                                    "could not apply configuration update; will retry on next change: {}",
                                    e
                                );
                                break;
                            }
                            acme_notify.notify_one();
                        }
                    }
                }
                Err(e) => {
                    error!("Docker event error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        warn!("Docker event listener stopped");
        Ok(())
    }

    /// Get entrypoints for a specific container.
    ///
    /// When the container declares a Docker `HEALTHCHECK` and the current
    /// status is `starting` or `unhealthy`, returns an empty map: Sōzune treats
    /// the healthcheck as a readiness probe and refuses to route traffic until
    /// the probe reports `healthy`. Containers without a healthcheck are not
    /// gated.
    async fn get_container_entrypoints(
        &self,
        container_id: &str,
        diagnostics: &DiagnosticsStore,
    ) -> Result<HashMap<String, Entrypoint>, bollard::errors::Error> {
        let candidate = match self.inspect_to_candidate(container_id).await? {
            Some(c) => c,
            None => return Ok(HashMap::new()),
        };

        let result = diagnostics::parse_and_store(diagnostics, &candidate);
        log_diagnostics(&candidate, &result.diagnostics);

        if is_gated(candidate.health) {
            debug!(
                "Gating container {}: HEALTHCHECK status is {:?}",
                container_id, candidate.health
            );
            return Ok(HashMap::new());
        }

        Ok(result.entrypoints)
    }

    async fn get_entrypoints_from_containers(
        &self,
        diagnostics: &DiagnosticsStore,
    ) -> Result<HashMap<String, Entrypoint>, bollard::errors::Error> {
        let mut entrypoints: HashMap<String, Entrypoint> = HashMap::new();

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: false,
                ..Default::default()
            }))
            .await?;

        for container in containers {
            let Some(container_labels) = container.labels else {
                continue;
            };
            let container_id = container.id.unwrap_or_default();

            // Network info and health status are only available via inspect,
            // not list (before API v1.52) — fetch both in one call.
            let (networks, health) = self.inspect_for_routing(&container_id).await;
            let candidate =
                self.build_candidate(container_id.clone(), container_labels, networks, health);

            let result = diagnostics::parse_and_store(diagnostics, &candidate);
            log_diagnostics(&candidate, &result.diagnostics);

            if result.entrypoints.is_empty() {
                continue;
            }

            // Track the resolved backend IP for cleanup on stop, even when the
            // container is currently gated by its healthcheck — we need the
            // mapping so a later health_status: unhealthy event can locate the
            // backend, and a healthy → unhealthy → healthy cycle stays cheap.
            if let Ok(mut ips) = self.container_ips.lock() {
                ips.insert(
                    container_id.clone(),
                    endpoints_of(result.entrypoints.values()),
                );
            }

            if is_gated(candidate.health) {
                debug!(
                    "Skipping container {} on initial scan: HEALTHCHECK status is {:?}",
                    container_id, candidate.health
                );
                continue;
            }

            let serving: HashMap<String, Entrypoint> = result
                .entrypoints
                .into_iter()
                .filter(|(_, entrypoint)| {
                    !entrypoint.backends.is_empty() || entrypoint.answers_without_backend()
                })
                .collect();
            self.remember(&container_id, &serving);
            for (key, entrypoint) in serving {
                merge_or_insert_entrypoint(&mut entrypoints, key, entrypoint, &container_id);
            }
        }

        Ok(entrypoints)
    }

    /// Inspect a container and turn it into a `Candidate`. Returns `None` when
    /// the container has no labels at all (sozune cannot route it either way).
    async fn inspect_to_candidate(
        &self,
        container_id: &str,
    ) -> Result<Option<Candidate>, bollard::errors::Error> {
        let container = self
            .docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await?;

        let display_name = container
            .name
            .clone()
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| container_id.to_string());

        let health = container
            .state
            .as_ref()
            .and_then(|s| s.health.as_ref())
            .and_then(|h| h.status)
            .and_then(map_health_status);

        let Some(config) = container.config else {
            return Ok(None);
        };
        let Some(labels) = config.labels else {
            return Ok(None);
        };

        let networks = container
            .network_settings
            .and_then(|s| s.networks)
            .map(|nets| {
                nets.into_iter()
                    .map(|(name, n)| NetworkInfo {
                        name,
                        ip: n.ip_address.filter(|ip| !ip.is_empty()),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(Candidate {
            provider: self.name,
            id: container_id.to_string(),
            display_name,
            labels,
            networks,
            enabled_default: self.config.expose_by_default,
            health,
        }))
    }

    /// Build a `Candidate` from labels already obtained via list_containers
    /// (which omits network_settings and health). Caller supplies them via a
    /// separate inspect.
    fn build_candidate(
        &self,
        container_id: String,
        labels: HashMap<String, String>,
        networks: Vec<NetworkInfo>,
        health: Option<HealthStatus>,
    ) -> Candidate {
        Candidate {
            provider: self.name,
            display_name: container_id.clone(),
            id: container_id,
            labels,
            networks,
            enabled_default: self.config.expose_by_default,
            health,
        }
    }

    /// Record what `container_id` declares, replacing what it did before.
    fn remember(&self, container_id: &str, entrypoints: &HashMap<String, Entrypoint>) {
        if let Ok(mut declared) = self.declared.lock() {
            if entrypoints.is_empty() {
                declared.remove(container_id);
            } else {
                declared.insert(container_id.to_string(), entrypoints.clone());
            }
        }
    }

    fn forget(&self, container_id: &str) {
        if let Ok(mut declared) = self.declared.lock() {
            declared.remove(container_id);
        }
    }

    /// Take `container_id` off the routes it serves: see [`take_off`].
    fn take_off(
        &self,
        storage: &mut BTreeMap<String, Entrypoint>,
        container_id: &str,
        departing: &[Backend],
    ) {
        let declared = self.declared.lock().map(|d| d.clone()).unwrap_or_default();
        take_off(storage, container_id, departing, self.name, &declared);
    }

    /// Fetch network information AND health status for a container via inspect.
    /// One inspect call serves both needs — list_containers exposes neither
    /// before API v1.52.
    async fn inspect_for_routing(
        &self,
        container_id: &str,
    ) -> (Vec<NetworkInfo>, Option<HealthStatus>) {
        let container = match self
            .docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                debug!(
                    "Could not inspect container {} for routing info: {}",
                    container_id, e
                );
                return (Vec::new(), None);
            }
        };

        let health = container
            .state
            .as_ref()
            .and_then(|s| s.health.as_ref())
            .and_then(|h| h.status)
            .and_then(map_health_status);

        let networks = container
            .network_settings
            .and_then(|s| s.networks)
            .map(|nets| {
                nets.into_iter()
                    .map(|(name, n)| NetworkInfo {
                        name,
                        ip: n.ip_address.filter(|ip| !ip.is_empty()),
                    })
                    .collect()
            })
            .unwrap_or_default();

        (networks, health)
    }
}

/// Map bollard's `HealthStatusEnum` to our provider-agnostic `HealthStatus`.
/// Returns `None` for `EMPTY` (no `State.Health` block) and `NONE` (Docker's
/// "no healthcheck configured" sentinel) — both mean "container did not opt
/// into a readiness contract, route as soon as running".
fn map_health_status(status: HealthStatusEnum) -> Option<HealthStatus> {
    match status {
        HealthStatusEnum::EMPTY | HealthStatusEnum::NONE => None,
        HealthStatusEnum::STARTING => Some(HealthStatus::Starting),
        HealthStatusEnum::HEALTHY => Some(HealthStatus::Healthy),
        HealthStatusEnum::UNHEALTHY => Some(HealthStatus::Unhealthy),
    }
}

/// Gating rule: a container is gated (excluded from routing) when it declared
/// a healthcheck and the current status is anything other than `healthy`.
/// `None` (no healthcheck) and `Some(Healthy)` both pass.
fn is_gated(health: Option<HealthStatus>) -> bool {
    matches!(health, Some(s) if !s.is_routable())
}

/// Decide whether two entrypoints sharing the same key (`<protocol>_<service>`)
/// are actually the same route (i.e. legitimate replicas of the same service).
/// Two entrypoints are compatible when they expose the **same routing surface**
/// — same set of hostnames and same path rule. Other fields (headers, auth,
/// rate limits, …) are ignored on purpose: containers in a deployment may
/// drift on those for a short time during a rolling update, and refusing the
/// merge there would create transient W018 collisions on every push.
fn entrypoints_are_replicas(a: &Entrypoint, b: &Entrypoint) -> bool {
    let mut a_hosts = a.config.hostnames.clone();
    let mut b_hosts = b.config.hostnames.clone();
    a_hosts.sort();
    b_hosts.sort();
    // Mirrors of different routes share no backends, though both serve no
    // host.
    a_hosts == b_hosts && a.config.path == b.config.path && a.config.mirror_of == b.config.mirror_of
}

/// Merge `incoming`, a replica of `existing`'s route, into it: its candidates
/// and backends. The route keeps the configuration of the first replica,
/// except that one that forwards wins over one that answers without a
/// backend (a redirect): during a rollout from one to the other, the route
/// forwards while any container serves it, and redirects once the last one
/// is gone. A route of another provider (`same_provider` false) keeps its
/// own: this provider's cleanup could not restore it.
fn merge_replica(existing: &mut Entrypoint, incoming: Entrypoint, same_provider: bool) {
    if same_provider && existing.answers_without_backend() != incoming.answers_without_backend() {
        warn!(
            "containers of route `{}` disagree: some redirect, some forward to a backend; it forwards while any of them serves it",
            existing.id
        );
        if existing.answers_without_backend() {
            existing.config = incoming.config.clone();
        }
    }
    existing.add_candidates(&incoming.candidates);
    for backend in incoming.backends {
        if !existing.backends.contains(&backend) {
            existing.backends.push(backend);
        }
    }
}

/// The route `current`, stored under `key`, as the containers `candidates`
/// declare it, merged in their order, from what each one declared
/// (`declared`). `None` when one of them declared nothing for it: the route
/// cannot be rebuilt.
fn rebuild_route(
    key: &str,
    current: &Entrypoint,
    candidates: &[String],
    declared: &HashMap<String, HashMap<String, Entrypoint>>,
) -> Option<Entrypoint> {
    let mut route: Option<Entrypoint> = None;
    for candidate in candidates {
        let parts = declared.get(candidate)?;
        // A route that collided with another is stored under `<key>_<id>`,
        // and declared under `<key>`.
        let part = parts
            .get(key)
            .or_else(|| {
                parts.iter().find_map(|(declared_key, part)| {
                    let suffixed = key
                        .strip_prefix(declared_key.as_str())
                        .is_some_and(|rest| rest.starts_with('_'));
                    (suffixed && entrypoints_are_replicas(part, current)).then_some(part)
                })
            })?
            .clone();
        match &mut route {
            None => route = Some(part),
            Some(route) => merge_replica(route, part, true),
        }
    }
    route
}

/// Take `container_id` off the routes of `provider` it serves, `departing`
/// its endpoints. A route other containers still serve is rebuilt from what
/// they declare (`declared`); one nobody serves any more, or left with no
/// backend to forward to, goes.
fn take_off(
    storage: &mut BTreeMap<String, Entrypoint>,
    container_id: &str,
    departing: &[Backend],
    provider: &str,
    declared: &HashMap<String, HashMap<String, Entrypoint>>,
) {
    let mut keys_to_remove = Vec::new();
    for (key, entrypoint) in storage.iter_mut() {
        let served = entrypoint.candidates.iter().any(|id| id == container_id);
        let mut gone = drop_backends_of(entrypoint, container_id, departing, provider);
        if served
            && entrypoint.source.as_deref() == Some(provider)
            && let Some(rebuilt) = rebuild_route(key, entrypoint, &entrypoint.candidates, declared)
        {
            *entrypoint = Entrypoint {
                id: entrypoint.id.clone(),
                source: entrypoint.source.clone(),
                ..rebuilt
            };
            gone = entrypoint.backends.is_empty() && !entrypoint.answers_without_backend();
        }
        if gone {
            keys_to_remove.push(key.clone());
        }
    }
    for key in &keys_to_remove {
        info!("Removing entrypoint with no backends: {}", key);
        storage.remove(key);
    }
}

/// Insert `incoming` under `key` in `dest`, or merge backends into the existing
/// entry when both entrypoints look like replicas of the same service.
///
/// When the incoming entrypoint shares a key with an existing one but its
/// routing surface differs (different hostnames or path), this is an
/// **accidental collision** — two unrelated workloads happen to share a
/// `<protocol>.<service-name>` segment. We keep the first one in place under
/// the canonical key and re-insert the loser under a disambiguated key
/// (`<key>_<short-source>`) so it stays visible to the rest of the system
/// (W018 will surface the resulting host+path collision if any).
///
/// `source_id` is the candidate id (container id for Docker) used to build the
/// disambiguated key.
fn merge_or_insert_entrypoint(
    dest: &mut HashMap<String, Entrypoint>,
    key: String,
    incoming: Entrypoint,
    source_id: &str,
) {
    let Some(existing) = dest.get_mut(&key) else {
        dest.insert(key, incoming);
        return;
    };

    if entrypoints_are_replicas(existing, &incoming) {
        merge_replica(existing, incoming, true);
        return;
    }

    let suffix: String = source_id.chars().take(12).collect();
    let alt_key = format!("{key}_{suffix}");
    warn!(
        "service-name collision on `{key}`: existing entrypoint exposes {:?} {:?}, incoming exposes {:?} {:?}; storing the new one as `{alt_key}` to keep both visible — rename the `sozune.<protocol>.<service-name>` segment to silence this",
        existing.config.hostnames,
        existing.config.path,
        incoming.config.hostnames,
        incoming.config.path,
    );
    // The id names the route everywhere the key does — API, route resolver,
    // dashboard links — so it follows the key.
    let entrypoint = Entrypoint {
        id: alt_key.clone(),
        ..incoming
    };
    dest.insert(alt_key, entrypoint);
}

/// Same as `merge_or_insert_entrypoint` but operates on a `BTreeMap` (the
/// runtime storage) instead of a `HashMap` (used during the initial scan).
fn merge_or_insert_entrypoint_btree(
    dest: &mut BTreeMap<String, Entrypoint>,
    key: String,
    incoming: Entrypoint,
    source_id: &str,
    source_label: &str,
) {
    let Some(existing) = dest.get_mut(&key) else {
        let mut entrypoint = incoming;
        entrypoint.source = Some(source_label.to_string());
        dest.insert(key, entrypoint);
        return;
    };

    if entrypoints_are_replicas(existing, &incoming) {
        let same_provider = existing.source.as_deref() == Some(source_label);
        merge_replica(existing, incoming, same_provider);
        return;
    }

    let suffix: String = source_id.chars().take(12).collect();
    let alt_key = format!("{key}_{suffix}");
    warn!(
        "service-name collision on `{key}`: existing entrypoint exposes {:?} {:?}, incoming exposes {:?} {:?}; storing the new one as `{alt_key}` to keep both visible — rename the `sozune.<protocol>.<service-name>` segment to silence this",
        existing.config.hostnames,
        existing.config.path,
        incoming.config.hostnames,
        incoming.config.path,
    );
    let mut entrypoint = incoming;
    entrypoint.id = alt_key.clone();
    entrypoint.source = Some(source_label.to_string());
    dest.insert(alt_key, entrypoint);
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn no_healthcheck_is_not_gated() {
        assert!(!is_gated(None));
    }

    #[test]
    fn healthy_is_not_gated() {
        assert!(!is_gated(Some(HealthStatus::Healthy)));
    }

    #[test]
    fn starting_is_gated() {
        assert!(is_gated(Some(HealthStatus::Starting)));
    }

    #[test]
    fn unhealthy_is_gated() {
        assert!(is_gated(Some(HealthStatus::Unhealthy)));
    }

    #[test]
    fn maps_bollard_empty_and_none_to_no_healthcheck() {
        assert_eq!(map_health_status(HealthStatusEnum::EMPTY), None);
        assert_eq!(map_health_status(HealthStatusEnum::NONE), None);
    }

    #[test]
    fn maps_bollard_states_to_our_enum() {
        assert_eq!(
            map_health_status(HealthStatusEnum::STARTING),
            Some(HealthStatus::Starting)
        );
        assert_eq!(
            map_health_status(HealthStatusEnum::HEALTHY),
            Some(HealthStatus::Healthy)
        );
        assert_eq!(
            map_health_status(HealthStatusEnum::UNHEALTHY),
            Some(HealthStatus::Unhealthy)
        );
    }
}

/// Drop the backends a departing container contributed to one entrypoint.
///
/// Scoped to entrypoints this provider owns: matching on the address alone
/// reached across providers, so a Docker container stopping stripped backends
/// from file, consul or API entrypoints that happened to share the address --
/// `127.0.0.1` most of all, which is what a host-network container resolves to.
/// The endpoints a container contributes, across all the entrypoints its
/// labels declare. Tracked at start so cleanup can drop exactly those: a
/// stopped container no longer reports its address, and the address alone
/// cannot tell two containers apart.
fn endpoints_of<'a>(entrypoints: impl Iterator<Item = &'a Entrypoint>) -> Vec<Backend> {
    let mut endpoints: Vec<Backend> = Vec::new();
    for entrypoint in entrypoints {
        for backend in &entrypoint.backends {
            if !endpoints
                .iter()
                .any(|e| e.address == backend.address && e.port == backend.port)
            {
                endpoints.push(backend.clone());
            }
        }
    }
    endpoints
}

/// Take a departing container out of a route: its endpoints and its id among
/// the route's candidates. A container that still serves the route after an
/// update is merged back in afterwards.
/// Take a departing container's backends and candidacy off a route this
/// provider owns. Returns whether the route has to go: no container declares
/// it any more, or it needs a backend and has none left. A route that answers
/// without a backend (a redirect) has none to begin with, so its backends say
/// nothing about it; and a route of another provider is never touched.
fn drop_backends_of(
    entrypoint: &mut Entrypoint,
    container_id: &str,
    departing: &[Backend],
    provider: &str,
) -> bool {
    if entrypoint.source.as_deref() != Some(provider) {
        return false;
    }
    entrypoint.candidates.retain(|id| id != container_id);
    entrypoint.backends.retain(|b| {
        !departing
            .iter()
            .any(|d| d.address == b.address && d.port == b.port)
    });
    entrypoint.candidates.is_empty()
        || (entrypoint.backends.is_empty() && !entrypoint.answers_without_backend())
}

#[cfg(test)]
pub(super) mod merge_tests {
    use super::*;
    use crate::model::{
        Backend, EntrypointConfig, LoadBalancer, PathConfig, PathRuleType, Protocol,
    };

    pub(super) fn ep(host: &str, path: Option<&str>, ip: &str) -> Entrypoint {
        Entrypoint {
            id: "x".into(),
            backends: vec![Backend::new(ip, 80)],
            name: "svc".into(),
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.into()],
                path: path.map(|p| PathConfig {
                    rule_type: PathRuleType::Prefix,
                    value: p.into(),
                }),
                tls: false,
                strip_prefix: false,
                add_prefix: None,
                https_redirect: false,
                https_redirect_port: None,
                https_only: false,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                rewrite_host: None,
                rewrite_path: None,
                rewrite: None,
                rewrite_port: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                request_timeout: None,
                health_check: None,
                load_balancer: LoadBalancer::default(),
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                sni: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: std::collections::BTreeMap::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                answer: None,
                mirrors: Vec::new(),
                mirror_of: None,
                failing_shares: None,
                ip_allow_list: Vec::new(),
            },
            source: None,
            candidates: Vec::new(),
        }
    }

    #[test]
    fn replicas_with_same_route_are_merged() {
        let mut map: HashMap<String, Entrypoint> = HashMap::new();
        merge_or_insert_entrypoint(
            &mut map,
            "http_web".into(),
            ep("app.example.com", Some("/"), "10.0.0.1"),
            "container-aaaa",
        );
        merge_or_insert_entrypoint(
            &mut map,
            "http_web".into(),
            ep("app.example.com", Some("/"), "10.0.0.2"),
            "container-bbbb",
        );
        assert_eq!(map.len(), 1);
        let merged = &map["http_web"];
        assert_eq!(merged.backends.len(), 2);
    }

    #[test]
    fn merged_replicas_keep_every_candidate() {
        let with_candidate = |ip: &str, id: &str| Entrypoint {
            candidates: vec![id.to_string()],
            ..ep("app.example.com", Some("/"), ip)
        };
        let mut map: HashMap<String, Entrypoint> = HashMap::new();
        merge_or_insert_entrypoint(
            &mut map,
            "http_web".into(),
            with_candidate("10.0.0.1", "container-aaaa"),
            "container-aaaa",
        );
        merge_or_insert_entrypoint(
            &mut map,
            "http_web".into(),
            with_candidate("10.0.0.2", "container-bbbb"),
            "container-bbbb",
        );
        assert_eq!(
            map["http_web"].candidates,
            vec!["container-aaaa", "container-bbbb"]
        );
    }

    #[test]
    fn a_route_renamed_at_runtime_takes_its_key_as_id() {
        let mut storage: BTreeMap<String, Entrypoint> = BTreeMap::new();
        merge_or_insert_entrypoint_btree(
            &mut storage,
            "http_api".into(),
            ep("a.example.com", None, "10.0.0.1"),
            "container-aaaa",
            "docker",
        );
        merge_or_insert_entrypoint_btree(
            &mut storage,
            "http_api".into(),
            ep("b.example.com", None, "10.0.0.2"),
            "container-bbbb",
            "docker",
        );
        assert_eq!(storage["http_api_container-bb"].id, "http_api_container-bb");
    }

    #[test]
    fn collision_on_hostnames_creates_disambiguated_key() {
        let mut map: HashMap<String, Entrypoint> = HashMap::new();
        merge_or_insert_entrypoint(
            &mut map,
            "http_api".into(),
            ep("app1.example.com", None, "10.0.0.1"),
            "container-aaaa-very-long",
        );
        merge_or_insert_entrypoint(
            &mut map,
            "http_api".into(),
            ep("app2.example.com", None, "10.0.0.2"),
            "container-bbbb-very-long",
        );
        assert_eq!(map.len(), 2, "incompatible configs must not be merged");
        assert!(map.contains_key("http_api"));
        assert!(map.contains_key("http_api_container-bb"));
        // The renamed route answers to its own id, not the first one's.
        assert_eq!(map["http_api_container-bb"].id, "http_api_container-bb");
    }

    #[test]
    fn collision_on_path_creates_disambiguated_key() {
        let mut map: HashMap<String, Entrypoint> = HashMap::new();
        merge_or_insert_entrypoint(
            &mut map,
            "http_api".into(),
            ep("app.example.com", Some("/v1"), "10.0.0.1"),
            "container-aaaa",
        );
        merge_or_insert_entrypoint(
            &mut map,
            "http_api".into(),
            ep("app.example.com", Some("/v2"), "10.0.0.2"),
            "container-bbbb",
        );
        assert_eq!(map.len(), 2);
    }
}

#[cfg(test)]
mod stop_cleanup_tests {
    use super::*;
    use crate::model::Backend;

    fn with(source: Option<&str>, backends: Vec<Backend>) -> Entrypoint {
        let mut entrypoint = super::merge_tests::ep("app.example.com", None, "10.0.0.1");
        entrypoint.backends = backends;
        entrypoint.source = source.map(str::to_string);
        entrypoint
    }

    /// Two containers can share an address — host-network ones all resolve to
    /// `127.0.0.1`, and Docker recycles addresses. Matching on the address
    /// alone made one stopping take the other's backends with it, so a service
    /// that never moved lost its route.
    ///
    /// The port is what tells them apart, and the tracker has it.
    #[test]
    fn a_container_sharing_an_address_keeps_its_own_backends() {
        let mut entrypoint = with(
            Some("docker"),
            vec![
                Backend::new("127.0.0.1", 8080),
                Backend::new("127.0.0.1", 9090),
            ],
        );

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("127.0.0.1", 8080)],
            "docker",
        );

        assert_eq!(
            entrypoint.backends,
            vec![Backend::new("127.0.0.1", 9090)],
            "only the departing container's endpoint goes"
        );
    }

    fn redirect_of(source: Option<&str>, candidates: &[&str]) -> Entrypoint {
        let mut entrypoint = with(source, Vec::new());
        entrypoint.config.redirect = Some(crate::model::RedirectPolicy::Permanent);
        entrypoint.candidates = candidates.iter().map(|c| c.to_string()).collect();
        entrypoint
    }

    /// A redirect has no backend, which used to read as "nothing left": any
    /// container stopping took every redirect route in the store with it.
    #[test]
    fn a_redirect_stays_when_another_container_stops() {
        let mut entrypoint = redirect_of(Some("docker"), &["container-a"]);
        let goes = drop_backends_of(
            &mut entrypoint,
            "container-b",
            &[Backend::new("10.0.0.2", 80)],
            "docker",
        );
        assert!(!goes);
    }

    #[test]
    fn a_redirect_goes_with_the_container_that_declares_it() {
        let mut entrypoint = redirect_of(Some("docker"), &["container-a"]);
        let goes = drop_backends_of(&mut entrypoint, "container-a", &[], "docker");
        assert!(goes);
    }

    /// A route from another provider is never this provider's to remove.
    #[test]
    fn a_route_of_another_provider_is_left_alone() {
        let mut entrypoint = redirect_of(Some("http"), &[]);
        let goes = drop_backends_of(&mut entrypoint, "container-a", &[], "docker");
        assert!(!goes);
    }

    #[test]
    fn a_route_stays_while_a_replica_still_serves_it() {
        let mut entrypoint = with(
            Some("docker"),
            vec![Backend::new("10.0.0.1", 80), Backend::new("10.0.0.2", 80)],
        );
        entrypoint.candidates = vec!["container-a".into(), "container-b".into()];
        let goes = drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("10.0.0.1", 80)],
            "docker",
        );
        assert!(!goes);
        assert_eq!(entrypoint.backends, vec![Backend::new("10.0.0.2", 80)]);
    }

    /// A container exposing several ports takes all of them with it.
    #[test]
    fn a_container_takes_every_endpoint_it_contributed() {
        let mut entrypoint = with(
            Some("docker"),
            vec![
                Backend::new("10.0.0.1", 8080),
                Backend::new("10.0.0.1", 9090),
                Backend::new("10.0.0.2", 8080),
            ],
        );

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[
                Backend::new("10.0.0.1", 8080),
                Backend::new("10.0.0.1", 9090),
            ],
            "docker",
        );

        assert_eq!(entrypoint.backends, vec![Backend::new("10.0.0.2", 8080)]);
    }

    /// A stopped container must take its own backends with it and nothing
    /// else. Matching on the address alone removed every backend that happened
    /// to share the IP, across every entrypoint in the store.
    #[test]
    fn only_the_stopped_container_s_backends_go() {
        let mut entrypoint = with(
            Some("docker"),
            vec![Backend::new("10.0.0.1", 80), Backend::new("10.0.0.2", 80)],
        );

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("10.0.0.1", 80)],
            "docker",
        );

        assert_eq!(entrypoint.backends, vec![Backend::new("10.0.0.2", 80)]);
    }

    /// Entrypoints from another provider are not ours to prune. A Docker
    /// container stopping used to strip backends from file, consul or API
    /// entrypoints that shared the address — `127.0.0.1` above all.
    #[test]
    fn another_provider_s_entrypoint_is_left_alone() {
        let mut entrypoint = with(Some("file"), vec![Backend::new("127.0.0.1", 80)]);

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("127.0.0.1", 80)],
            "docker",
        );

        assert_eq!(entrypoint.backends, vec![Backend::new("127.0.0.1", 80)]);
    }

    /// An entrypoint with no source is not attributable to Docker either.
    #[test]
    fn an_unsourced_entrypoint_is_left_alone() {
        let mut entrypoint = with(None, vec![Backend::new("10.0.0.1", 80)]);

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("10.0.0.1", 80)],
            "docker",
        );

        assert_eq!(entrypoint.backends, vec![Backend::new("10.0.0.1", 80)]);
    }

    /// The container leaves the route's candidates with its endpoints, so its
    /// diagnostics stop showing on a route it no longer serves.
    #[test]
    fn the_departing_container_leaves_the_candidates() {
        let mut entrypoint = with(
            Some("docker"),
            vec![Backend::new("10.0.0.1", 80), Backend::new("10.0.0.2", 80)],
        );
        entrypoint.candidates = vec!["container-a".into(), "container-b".into()];

        drop_backends_of(
            &mut entrypoint,
            "container-a",
            &[Backend::new("10.0.0.1", 80)],
            "docker",
        );

        assert_eq!(entrypoint.candidates, vec!["container-b"]);
    }
}

#[cfg(test)]
mod rollout_tests {
    use super::*;
    use crate::model::RedirectPolicy;

    /// What container `id` declares for route `web`: a forward to `ip`, or a
    /// redirect.
    fn declares(id: &str, ip: Option<&str>) -> Entrypoint {
        let mut entrypoint = super::merge_tests::ep("app.example.com", None, ip.unwrap_or("-"));
        entrypoint.id = "web".into();
        entrypoint.source = Some("docker".into());
        entrypoint.candidates = vec![id.to_string()];
        if ip.is_none() {
            entrypoint.backends.clear();
            entrypoint.config.redirect = Some(RedirectPolicy::Permanent);
        }
        entrypoint
    }

    /// The store and what each container declares, after `containers` start
    /// in this order.
    fn started(
        containers: &[Entrypoint],
    ) -> (
        BTreeMap<String, Entrypoint>,
        HashMap<String, HashMap<String, Entrypoint>>,
    ) {
        let mut storage = BTreeMap::new();
        let mut declared = HashMap::new();
        for entrypoint in containers {
            let id = entrypoint.candidates[0].clone();
            declared.insert(
                id.clone(),
                HashMap::from([("web".to_string(), entrypoint.clone())]),
            );
            merge_or_insert_entrypoint_btree(
                &mut storage,
                "web".into(),
                entrypoint.clone(),
                &id,
                "docker",
            );
        }
        (storage, declared)
    }

    fn stop(
        storage: &mut BTreeMap<String, Entrypoint>,
        declared: &mut HashMap<String, HashMap<String, Entrypoint>>,
        id: &str,
        endpoints: &[Backend],
    ) {
        declared.remove(id);
        take_off(storage, id, endpoints, "docker", declared);
    }

    /// From a forward to a redirect: the route forwards while the old
    /// container serves it, and redirects once it stops. It used to go with
    /// the last forwarding container, the redirect with it.
    #[test]
    fn a_rollout_to_a_redirect_redirects_once_the_last_backend_goes() {
        let (mut storage, mut declared) =
            started(&[declares("old", Some("10.0.0.1")), declares("new", None)]);
        assert!(!storage["web"].answers_without_backend());

        stop(
            &mut storage,
            &mut declared,
            "old",
            &[Backend::new("10.0.0.1", 80)],
        );

        let route = &storage["web"];
        assert!(route.answers_without_backend());
        assert_eq!(route.candidates, ["new"]);
    }

    /// From a redirect to a forward: the new container forwards as soon as it
    /// starts. The redirect used to keep the route, even after it stopped.
    #[test]
    fn a_rollout_to_a_forward_forwards_from_the_first_backend() {
        let (mut storage, mut declared) =
            started(&[declares("old", None), declares("new", Some("10.0.0.2"))]);
        assert!(!storage["web"].answers_without_backend());
        assert_eq!(storage["web"].backends, [Backend::new("10.0.0.2", 80)]);

        stop(&mut storage, &mut declared, "old", &[]);
        assert!(!storage["web"].answers_without_backend());

        // And the route goes with the last container.
        stop(
            &mut storage,
            &mut declared,
            "new",
            &[Backend::new("10.0.0.2", 80)],
        );
        assert!(storage.is_empty());
    }

    /// A route stored under another key, after a collision, is rebuilt
    /// from what its containers declared under theirs.
    #[test]
    fn a_disambiguated_route_is_rebuilt_too() {
        let (mut storage, mut declared) =
            started(&[declares("old", Some("10.0.0.1")), declares("new", None)]);
        let route = storage.remove("web").unwrap();
        storage.insert(
            "web_abc".into(),
            Entrypoint {
                id: "web_abc".into(),
                ..route
            },
        );

        stop(
            &mut storage,
            &mut declared,
            "old",
            &[Backend::new("10.0.0.1", 80)],
        );

        assert!(storage["web_abc"].answers_without_backend());
        assert_eq!(storage["web_abc"].id, "web_abc");
    }

    /// The route takes what its remaining containers declare, not what the
    /// one that left did.
    #[test]
    fn a_route_takes_the_settings_of_the_containers_left() {
        let mut old = declares("old", Some("10.0.0.1"));
        old.config.priority = 1;
        let mut new = declares("new", Some("10.0.0.2"));
        new.config.priority = 2;
        let (mut storage, mut declared) = started(&[old, new]);
        assert_eq!(storage["web"].config.priority, 1);

        stop(
            &mut storage,
            &mut declared,
            "old",
            &[Backend::new("10.0.0.1", 80)],
        );

        assert_eq!(storage["web"].config.priority, 2);
        assert_eq!(storage["web"].backends, [Backend::new("10.0.0.2", 80)]);
    }
}
