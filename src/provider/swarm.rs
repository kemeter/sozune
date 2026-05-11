use crate::config::SwarmConfig;
use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::labels::source::LabelSource;
use crate::model::Entrypoint;
use crate::provider::Provider;
use async_trait::async_trait;
use bollard::Docker;
use bollard::models::{EndpointSpecModeEnum, LocalNodeState};
use bollard::query_parameters::{EventsOptions, ListNetworksOptions, ListServicesOptions};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

const SOURCE: &str = "swarm";

pub struct SwarmProvider {
    docker: Docker,
    config: SwarmConfig,
}

impl SwarmProvider {
    pub fn new(config: SwarmConfig) -> Result<Self, bollard::errors::Error> {
        let docker = if config.endpoint.starts_with("unix://") {
            Docker::connect_with_socket(&config.endpoint, 120, bollard::API_DEFAULT_VERSION)?
        } else if config.endpoint.starts_with('/') {
            Docker::connect_with_socket(
                &format!("unix://{}", config.endpoint),
                120,
                bollard::API_DEFAULT_VERSION,
            )?
        } else {
            Docker::connect_with_local_defaults()?
        };
        Ok(Self { docker, config })
    }

    /// Build the network_id -> network_name map (cluster-scoped).
    /// Used to translate VIP NetworkID into the human name `sozune.network` matches against.
    async fn network_id_to_name(&self) -> HashMap<String, String> {
        match self.docker.list_networks(None::<ListNetworksOptions>).await {
            Ok(networks) => networks
                .into_iter()
                .filter_map(|n| Some((n.id?, n.name?)))
                .collect(),
            Err(e) => {
                warn!("swarm: failed to list networks for VIP resolution: {}", e);
                HashMap::new()
            }
        }
    }

    async fn build_candidates(&self) -> Result<Vec<Candidate>, bollard::errors::Error> {
        let services = self
            .docker
            .list_services(None::<ListServicesOptions>)
            .await?;

        let net_map = self.network_id_to_name().await;

        let mut candidates = Vec::with_capacity(services.len());
        for service in services {
            let id = service.id.clone().unwrap_or_default();
            let spec = match service.spec {
                Some(s) => s,
                None => continue,
            };
            let display_name = spec.name.clone().unwrap_or_else(|| id.clone());
            let labels = spec.labels.unwrap_or_default();

            // bollard 0.20 does not expose per-task NetworkAttachments, so we
            // cannot resolve individual task IPs in dnsrr mode. The Swarm VIP
            // (when present) still works because Docker keeps load-balancing
            // behind it. Warn loudly so misconfigured services are visible.
            if let Some(endpoint_spec) = spec.endpoint_spec.as_ref()
                && matches!(endpoint_spec.mode, Some(EndpointSpecModeEnum::DNSRR))
            {
                warn!(
                    "swarm: service '{}' uses dnsrr endpoint mode; sozune cannot enumerate individual task IPs and will fall back to the VIP if available",
                    display_name
                );
            }

            let networks = service
                .endpoint
                .as_ref()
                .and_then(|e| e.virtual_ips.as_ref())
                .map(|vips| {
                    vips.iter()
                        .filter_map(|vip| {
                            let nid = vip.network_id.clone()?;
                            let name = net_map.get(&nid).cloned().unwrap_or(nid);
                            // Honour the optional network filter from config: drop VIPs
                            // outside the configured overlay so they cannot be picked up
                            // by `resolve_ip` as a fallback.
                            if !self.config.network.is_empty() && name != self.config.network {
                                return None;
                            }
                            let ip = vip.addr.as_ref().map(|a| strip_cidr(a).to_string());
                            Some(NetworkInfo { name, ip })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            candidates.push(Candidate {
                provider: SOURCE,
                id,
                display_name,
                labels,
                networks,
                enabled_default: self.config.expose_by_default,
                health: None,
            });
        }
        Ok(candidates)
    }

    /// Verify the configured endpoint points to an active Swarm manager.
    /// Returns a descriptive error when the daemon is not in Swarm mode or
    /// when this node is a worker — both surface as cryptic 503s on every
    /// list_services call otherwise.
    async fn verify_swarm_manager(&self) -> anyhow::Result<()> {
        let info = self.docker.info().await.map_err(|e| {
            anyhow::anyhow!("docker info failed on '{}': {}", self.config.endpoint, e)
        })?;
        let swarm = info
            .swarm
            .ok_or_else(|| anyhow::anyhow!("docker info returned no Swarm section"))?;

        match swarm.local_node_state {
            Some(LocalNodeState::ACTIVE) => {}
            other => anyhow::bail!(
                "endpoint '{}' is not in Swarm mode (LocalNodeState={:?}); run `docker swarm init` or point endpoint to a manager",
                self.config.endpoint,
                other
            ),
        }

        if swarm.control_available != Some(true) {
            anyhow::bail!(
                "endpoint '{}' is a Swarm worker, not a manager; the swarm provider must talk to a manager node",
                self.config.endpoint
            );
        }
        Ok(())
    }

    /// Start the Swarm provider: initial sync, then run the event stream and
    /// the periodic poll concurrently. The poll catches up on anything the
    /// event stream may have dropped (reconnections, missed messages).
    pub async fn start_service(
        self: Arc<Self>,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        if let Err(e) = self.verify_swarm_manager().await {
            error!("Swarm provider disabled: {}", e);
            return Ok(());
        }

        // Initial sync: run one poll iteration's worth of work synchronously
        // before kicking off the loops, so storage is populated by the time
        // start_services() returns.
        if let Err(e) = self
            .sync_once(&storage, &reload_tx, &acme_notify, &diagnostics, true)
            .await
        {
            warn!("Swarm provider initial sync failed: {}", e);
        }

        let poll = {
            let provider = Arc::clone(&self);
            let storage = Arc::clone(&storage);
            let reload_tx = reload_tx.clone();
            let acme_notify = Arc::clone(&acme_notify);
            let diagnostics = Arc::clone(&diagnostics);
            tokio::spawn(async move {
                if let Err(e) = provider
                    .start_polling(storage, reload_tx, acme_notify, diagnostics)
                    .await
                {
                    error!("Swarm polling loop failed: {}", e);
                }
            })
        };

        let events = {
            let provider = Arc::clone(&self);
            let storage = Arc::clone(&storage);
            let reload_tx = reload_tx.clone();
            let acme_notify = Arc::clone(&acme_notify);
            let diagnostics = Arc::clone(&diagnostics);
            tokio::spawn(async move {
                if let Err(e) = provider
                    .start_event_listener(storage, reload_tx, acme_notify, diagnostics)
                    .await
                {
                    error!("Swarm event listener failed: {}", e);
                }
            })
        };

        let _ = tokio::try_join!(poll, events);
        Ok(())
    }

    /// One synchronous diff-and-apply pass against the API. Returns true if
    /// storage was modified. Used by both the initial sync and the event
    /// stream (debounced through the poll loop's regular cadence).
    async fn sync_once(
        &self,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
        diagnostics: &DiagnosticsStore,
        log_when_idle: bool,
    ) -> anyhow::Result<bool> {
        let new_entrypoints = self.provide_into(diagnostics).await?;

        let needs_update = {
            let storage_read = match storage.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
                    return Ok(false);
                }
            };

            let old_ids: std::collections::HashSet<&String> = storage_read
                .iter()
                .filter(|(_, ep)| ep.source.as_deref() == Some(SOURCE))
                .map(|(id, _)| id)
                .collect();

            let new_ids: std::collections::HashSet<&String> = new_entrypoints.keys().collect();

            old_ids != new_ids
                || new_entrypoints.iter().any(|(id, ep)| {
                    storage_read.get(id).is_none_or(|existing| {
                        existing.backends != ep.backends
                            || existing.config.hostnames != ep.config.hostnames
                    })
                })
        };

        if !needs_update {
            if log_when_idle {
                info!("No Swarm services with sozune labels found on initial scan");
            }
            return Ok(false);
        }

        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        "internal state corrupted (configuration store), restart required: {}",
                        e
                    );
                    return Ok(false);
                }
            };
            storage_write.retain(|_, ep| ep.source.as_deref() != Some(SOURCE));
            for (id, mut entrypoint) in new_entrypoints {
                entrypoint.source = Some(SOURCE.to_string());
                debug!("Swarm provider entrypoint: {}", id);
                storage_write.insert(id, entrypoint);
            }
        }

        info!("Swarm provider config changed, triggering reload");
        if let Err(e) = reload_tx.send(()).await {
            warn!(
                "could not apply configuration update; will retry on next change: {}",
                e
            );
        }
        acme_notify.notify_one();
        Ok(true)
    }

    /// Subscribe to Docker events filtered on `type=service`. Each event
    /// triggers a sync_once. We do not try to be clever about which event
    /// means what — Swarm service create/update/remove all warrant a re-diff.
    pub async fn start_event_listener(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!("Starting Swarm event listener");

        loop {
            let mut filters = HashMap::new();
            filters.insert("type".to_string(), vec!["service".to_string()]);

            let mut events = self.docker.events(Some(EventsOptions {
                since: None,
                until: None,
                filters: Some(filters),
            }));

            while let Some(event_result) = events.next().await {
                match event_result {
                    Ok(event) => {
                        if let Some(action) = &event.action {
                            debug!("Swarm event: {} (actor={:?})", action, event.actor);
                            if let Err(e) = self
                                .sync_once(&storage, &reload_tx, &acme_notify, &diagnostics, false)
                                .await
                            {
                                warn!("Swarm sync after event failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Swarm event stream error: {}, reconnecting in 5s", e);
                        break;
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Periodic poll: rebuild the full set of `swarm`-sourced entrypoints from
    /// the API, diff against storage, and replace-all on change. Mirrors the
    /// HTTP provider strategy and acts as a safety net even once the event
    /// stream is wired up.
    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Swarm provider polling on {} every {}s",
            self.config.endpoint, self.config.refresh_interval
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.refresh_interval));

        loop {
            interval.tick().await;

            if let Err(e) = self
                .sync_once(&storage, &reload_tx, &acme_notify, &diagnostics, false)
                .await
            {
                warn!("Swarm provider poll failed: {}", e);
            }
        }
    }
}

#[async_trait]
impl Provider for SwarmProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        // Trait callers don't share the runtime store; use a throwaway so
        // diagnostics are at least logged.
        let throwaway = diagnostics::new_store();
        self.provide_into(&throwaway).await
    }

    fn name(&self) -> &'static str {
        SOURCE
    }
}

impl SwarmProvider {
    /// Same as `provide()` but writes diagnostics into the supplied store.
    async fn provide_into(
        &self,
        diagnostics: &DiagnosticsStore,
    ) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let candidates = self.build_candidates().await.map_err(anyhow::Error::new)?;
        let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();

        for candidate in candidates {
            let result = diagnostics::parse_and_store(diagnostics, &candidate);
            log_diagnostics(&candidate, &result.diagnostics);

            for (key, entrypoint) in result.entrypoints {
                let Some(backend) = entrypoint.backends.first().cloned() else {
                    continue;
                };
                if let Some(existing) = entrypoints.get_mut(&key) {
                    if !existing.backends.contains(&backend) {
                        existing.backends.push(backend);
                    }
                } else {
                    entrypoints.insert(key, entrypoint);
                }
            }
        }

        Ok(entrypoints)
    }
}

#[async_trait]
impl LabelSource for SwarmProvider {
    fn provider_name(&self) -> &'static str {
        SOURCE
    }

    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        self.build_candidates().await.map_err(anyhow::Error::new)
    }
}

/// Swarm reports VIPs as `10.0.0.5/24`. The `/CIDR` is metadata, not part of
/// the routable IP — strip it.
fn strip_cidr(addr: &str) -> &str {
    addr.split('/').next().unwrap_or(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_cidr_removes_suffix() {
        assert_eq!(strip_cidr("10.0.0.5/24"), "10.0.0.5");
        assert_eq!(strip_cidr("10.0.0.5"), "10.0.0.5");
        assert_eq!(strip_cidr(""), "");
        assert_eq!(strip_cidr("fd00::1/64"), "fd00::1");
    }
}
