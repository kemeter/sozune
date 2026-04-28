use crate::config::DockerConfig;
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::labels::{self};
use crate::model::Entrypoint;
use crate::provider::Provider;
use async_trait::async_trait;
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
    /// Tracks container_id -> IP so we can clean up when the container stops
    /// (stopped containers no longer expose their network IP via inspect)
    container_ips: std::sync::Mutex<HashMap<String, String>>,
}

#[async_trait]
impl Provider for DockerProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let hashmap = self
            .get_entrypoints_from_containers()
            .await
            .map_err(|e| anyhow::Error::new(e))?;
        Ok(hashmap.into_iter().collect())
    }

    fn name(&self) -> &'static str {
        "docker"
    }
}

impl DockerProvider {
    pub fn new(config: DockerConfig) -> Result<Self, bollard::errors::Error> {
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
            container_ips: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Start Docker service: initial scan + event listening
    pub async fn start_service(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<tokio::sync::Notify>,
    ) -> anyhow::Result<()> {
        info!("Starting Docker service");

        // Initial scan of existing containers
        info!("Performing initial scan of running containers");
        match self.get_entrypoints_from_containers().await {
            Ok(initial_entrypoints) => {
                if !initial_entrypoints.is_empty() {
                    let storage_changed = {
                        let mut changed = false;
                        let mut storage_write = match storage.write() {
                            Ok(guard) => guard,
                            Err(e) => {
                                error!("Storage lock poisoned during initial scan: {}", e);
                                return Ok(());
                            }
                        };

                        for (key, mut entrypoint) in initial_entrypoints {
                            entrypoint.source = Some("docker".to_string());

                            if !storage_write.contains_key(&key) {
                                info!("Found new container entrypoint: {}", key);
                                storage_write.insert(key, entrypoint);
                                changed = true;
                            } else {
                                info!(
                                    "Container entrypoint {} already exists in storage",
                                    key
                                );
                            }
                        }
                        changed
                    };

                    // Only trigger reload if configuration actually changed
                    if storage_changed {
                        if let Err(e) = reload_tx.send(()).await {
                            warn!("Failed to send initial reload signal: {}", e);
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
        self.start_event_listener(storage, reload_tx, acme_notify).await
    }

    /// Start listening for Docker events and update storage directly
    pub async fn start_event_listener(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<tokio::sync::Notify>,
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
                    if let Some(action) = &event.action {
                        if let Some(actor) = &event.actor {
                            if let Some(container_id) = &actor.id {
                                info!("Docker event: {} for container {}", action, container_id);

                                let mut storage_changed = false;

                                match action.as_str() {
                                    "start" => {
                                        // Track the container IP for later cleanup
                                        if let Some(ip) = self.get_container_ip(container_id).await
                                        {
                                            if let Ok(mut ips) = self.container_ips.lock() {
                                                ips.insert(container_id.to_string(), ip);
                                            }
                                        }

                                        if let Ok(entrypoints) =
                                            self.get_container_entrypoints(container_id).await
                                        {
                                            if !entrypoints.is_empty() {
                                                let mut storage_write = match storage.write() {
                                                    Ok(guard) => guard,
                                                    Err(e) => {
                                                        error!(
                                                            "Storage lock poisoned on container start: {}",
                                                            e
                                                        );
                                                        continue;
                                                    }
                                                };
                                                for (key, entrypoint) in entrypoints {
                                                    info!(
                                                        "Adding entrypoint from started container: {}",
                                                        key
                                                    );
                                                    if let Some(existing) =
                                                        storage_write.get_mut(&key)
                                                    {
                                                        // Merge backends
                                                        for backend in entrypoint.backends {
                                                            if !existing.backends.contains(&backend)
                                                            {
                                                                existing.backends.push(backend);
                                                            }
                                                        }
                                                    } else {
                                                        let mut entrypoint = entrypoint;
                                                        entrypoint.source =
                                                            Some("docker".to_string());
                                                        storage_write.insert(key, entrypoint);
                                                    }
                                                }
                                                storage_changed = true;
                                            }
                                        }
                                    }
                                    "stop" | "die" | "destroy" => {
                                        // Use tracked IP (stopped containers lose their network IP)
                                        let container_ip = self.container_ips.lock().ok()
                                            .and_then(|mut ips| ips.remove(container_id.as_str()))
                                            .or_else(|| {
                                                // Fallback: try inspect (may work for "stop" before network teardown)
                                                None
                                            })
                                            .unwrap_or_else(|| {
                                                warn!("No tracked IP for stopped container {}, cleanup may be incomplete", container_id);
                                                "127.0.0.1".to_string()
                                            });
                                        let mut storage_write = match storage.write() {
                                            Ok(guard) => guard,
                                            Err(e) => {
                                                error!(
                                                    "Storage lock poisoned on container stop: {}",
                                                    e
                                                );
                                                continue;
                                            }
                                        };

                                        let mut keys_to_remove = Vec::new();
                                        for (key, entrypoint) in storage_write.iter_mut() {
                                            // Remove this container's IP from backends
                                            entrypoint.backends.retain(|ip| ip != &container_ip);

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
                                        if let Ok(entrypoints) =
                                            self.get_container_entrypoints(container_id).await
                                        {
                                            let container_ip = self
                                                .get_container_ip(container_id)
                                                .await
                                                .unwrap_or_else(|| "127.0.0.1".to_string());
                                            let mut storage_write = match storage.write() {
                                                Ok(guard) => guard,
                                                Err(e) => {
                                                    error!(
                                                        "Storage lock poisoned on container update: {}",
                                                        e
                                                    );
                                                    continue;
                                                }
                                            };

                                            // Remove old entries for this container
                                            let mut keys_to_remove = Vec::new();
                                            for (key, entrypoint) in storage_write.iter_mut() {
                                                entrypoint
                                                    .backends
                                                    .retain(|ip| ip != &container_ip);
                                                if entrypoint.backends.is_empty() {
                                                    keys_to_remove.push(key.clone());
                                                }
                                            }
                                            for key in keys_to_remove {
                                                storage_write.remove(&key);
                                            }

                                            // Add new entries
                                            for (key, entrypoint) in entrypoints {
                                                if let Some(existing) = storage_write.get_mut(&key)
                                                {
                                                    for backend in entrypoint.backends {
                                                        if !existing.backends.contains(&backend) {
                                                            existing.backends.push(backend);
                                                        }
                                                    }
                                                } else {
                                                    let mut entrypoint = entrypoint;
                                                    entrypoint.source = Some("docker".to_string());
                                                    storage_write.insert(key, entrypoint);
                                                }
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
                                        error!("Failed to send reload signal: {}", e);
                                        break;
                                    }
                                    acme_notify.notify_one();
                                }
                            }
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
    async fn get_container_entrypoints(
        &self,
        container_id: &str,
    ) -> Result<HashMap<String, Entrypoint>, bollard::errors::Error> {
        let candidate = match self.inspect_to_candidate(container_id).await? {
            Some(c) => c,
            None => return Ok(HashMap::new()),
        };

        let result = labels::parse(&candidate);
        log_diagnostics(&candidate, &result.diagnostics);
        Ok(result.entrypoints)
    }

    pub async fn get_entrypoints_from_containers(
        &self,
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

            // Network info is only available via inspect, not list — fetch it.
            let networks = self.extract_networks(&container_id).await;
            let candidate = self.build_candidate(
                container_id.clone(),
                container_labels,
                networks,
            );

            let result = labels::parse(&candidate);
            log_diagnostics(&candidate, &result.diagnostics);

            if result.entrypoints.is_empty() {
                continue;
            }

            // Track the resolved backend IP for cleanup on stop. Every
            // entrypoint produced by a single candidate carries the same
            // backend list, so peek at the first.
            if let Some(first) = result.entrypoints.values().next() {
                if let Some(ip) = first.backends.first() {
                    if let Ok(mut ips) = self.container_ips.lock() {
                        ips.insert(container_id.clone(), ip.clone());
                    }
                }
            }

            for (key, entrypoint) in result.entrypoints {
                let backend_ip = entrypoint.backends.first().cloned().unwrap_or_default();
                if let Some(existing) = entrypoints.get_mut(&key) {
                    if !existing.backends.contains(&backend_ip) {
                        existing.backends.push(backend_ip.clone());
                        info!("Added backend {} to existing entrypoint {}", backend_ip, key);
                    }
                } else {
                    entrypoints.insert(key.clone(), entrypoint);
                    info!("Created new entrypoint {}", key);
                }
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
            provider: "docker",
            id: container_id.to_string(),
            display_name,
            labels,
            networks,
            enabled_default: self.config.expose_by_default,
        }))
    }

    /// Build a `Candidate` from labels already obtained via list_containers
    /// (which omits network_settings). Caller supplies `networks` separately.
    fn build_candidate(
        &self,
        container_id: String,
        labels: HashMap<String, String>,
        networks: Vec<NetworkInfo>,
    ) -> Candidate {
        Candidate {
            provider: "docker",
            display_name: container_id.clone(),
            id: container_id,
            labels,
            networks,
            enabled_default: self.config.expose_by_default,
        }
    }

    /// Fetch network information for a container via inspect.
    async fn extract_networks(&self, container_id: &str) -> Vec<NetworkInfo> {
        let container = match self
            .docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                debug!(
                    "Could not inspect container {} for networks: {}",
                    container_id, e
                );
                return Vec::new();
            }
        };

        container
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
            .unwrap_or_default()
    }

    /// Resolve a container's backend IP using the shared label parser.
    /// Used by the event listener to track backends for cleanup on stop.
    async fn get_container_ip(&self, container_id: &str) -> Option<String> {
        let candidate = self.inspect_to_candidate(container_id).await.ok().flatten()?;
        let mut throwaway = Vec::new();
        let ip = labels::network::resolve_ip(&candidate, &mut throwaway);
        if ip == "127.0.0.1" { None } else { Some(ip) }
    }
}

/// Emit each diagnostic at the appropriate tracing level so the runtime logs
/// match what `sozune validate` would report.
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
            Severity::Info => debug!(
                "[{}] {}: {}",
                target,
                d.code.as_str(),
                d.message
            ),
        }
    }
}

