use crate::config::DockerConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, HealthStatus, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
use crate::labels::{self};
use crate::model::Entrypoint;
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
    /// Tracks container_id -> IP so we can clean up when the container stops
    /// (stopped containers no longer expose their network IP via inspect)
    container_ips: std::sync::Mutex<HashMap<String, String>>,
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
                            let source_id = entrypoint
                                .backends
                                .first()
                                .map(|b| b.address.clone())
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
                                // Track the container IP for later cleanup
                                if let Some(ip) = self.get_container_ip(container_id).await
                                    && let Ok(mut ips) = self.container_ips.lock()
                                {
                                    ips.insert(container_id.to_string(), ip);
                                }

                                if let Ok(entrypoints) = self
                                    .get_container_entrypoints(container_id, &diagnostics)
                                    .await
                                    && !entrypoints.is_empty()
                                {
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
                                let mut keys_to_remove = Vec::new();
                                for (key, entrypoint) in storage_write.iter_mut() {
                                    entrypoint.backends.retain(|b| b.address != container_ip);
                                    if entrypoint.backends.is_empty() {
                                        keys_to_remove.push(key.clone());
                                    }
                                }
                                for key in &keys_to_remove {
                                    info!(
                                        "Removing entrypoint with no backends after unhealthy: {}",
                                        key
                                    );
                                    storage_write.remove(key);
                                }
                                storage_changed = true;
                            }
                            "stop" | "die" | "destroy" => {
                                // Drop any cached diagnostics for this container — it's gone.
                                diagnostics::remove(&diagnostics, container_id);
                                // Stopped containers lose their network IP, so we read from
                                // the per-container tracker populated at `start` time. If the
                                // tracker has no entry (event arrived before we ever saw it),
                                // fall back to 127.0.0.1 so the cleanup pass at least runs —
                                // the warn! makes the partial cleanup visible in the logs.
                                let container_ip = self
                                    .container_ips
                                    .lock()
                                    .ok()
                                    .and_then(|mut ips| ips.remove(container_id.as_str()))
                                    .unwrap_or_else(|| {
                                        warn!(
                                            "No tracked IP for stopped container {}, cleanup may be incomplete",
                                            container_id
                                        );
                                        "127.0.0.1".to_string()
                                    });
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

                                let mut keys_to_remove = Vec::new();
                                for (key, entrypoint) in storage_write.iter_mut() {
                                    // Remove this container's IP from backends
                                    entrypoint.backends.retain(|b| b.address != container_ip);

                                    // If no backends left, mark for removal
                                    if entrypoint.backends.is_empty() {
                                        keys_to_remove.push(key.clone());
                                    }
                                }

                                for key in &keys_to_remove {
                                    info!("Removing entrypoint with no backends: {}", key);
                                    storage_write.remove(key);
                                }

                                storage_changed = true;
                            }
                            "update" => {
                                // For updates, remove old and add new
                                if let Ok(entrypoints) = self
                                    .get_container_entrypoints(container_id, &diagnostics)
                                    .await
                                {
                                    let container_ip = self
                                        .get_container_ip(container_id)
                                        .await
                                        .unwrap_or_else(|| "127.0.0.1".to_string());
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
                                    let mut keys_to_remove = Vec::new();
                                    for (key, entrypoint) in storage_write.iter_mut() {
                                        entrypoint.backends.retain(|b| b.address != container_ip);
                                        if entrypoint.backends.is_empty() {
                                            keys_to_remove.push(key.clone());
                                        }
                                    }
                                    for key in keys_to_remove {
                                        storage_write.remove(&key);
                                    }

                                    // Add new entries
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
            if let Some(first) = result.entrypoints.values().next()
                && let Some(backend) = first.backends.first()
                && let Ok(mut ips) = self.container_ips.lock()
            {
                ips.insert(container_id.clone(), backend.address.clone());
            }

            if is_gated(candidate.health) {
                debug!(
                    "Skipping container {} on initial scan: HEALTHCHECK status is {:?}",
                    container_id, candidate.health
                );
                continue;
            }

            for (key, entrypoint) in result.entrypoints {
                if entrypoint.backends.is_empty() {
                    continue;
                }
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

    /// Resolve a container's backend IP using the shared label parser.
    /// Used by the event listener to track backends for cleanup on stop.
    async fn get_container_ip(&self, container_id: &str) -> Option<String> {
        let candidate = self
            .inspect_to_candidate(container_id)
            .await
            .ok()
            .flatten()?;
        let mut throwaway = Vec::new();
        let ip = labels::network::resolve_ip(&candidate, &mut throwaway);
        if ip == "127.0.0.1" { None } else { Some(ip) }
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
    a_hosts == b_hosts && a.config.path == b.config.path
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
        for backend in incoming.backends {
            if !existing.backends.contains(&backend) {
                existing.backends.push(backend);
            }
        }
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
    dest.insert(alt_key, incoming);
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
        for backend in incoming.backends {
            if !existing.backends.contains(&backend) {
                existing.backends.push(backend);
            }
        }
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

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::model::{
        Backend, EntrypointConfig, LoadBalancer, PathConfig, PathRuleType, Protocol,
    };

    fn ep(host: &str, path: Option<&str>, ip: &str) -> Entrypoint {
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
                health_check: None,
                load_balancer: LoadBalancer::default(),
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
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
            source: None,
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
