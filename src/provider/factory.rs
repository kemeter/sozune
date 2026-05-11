use crate::config::AppConfig;
use crate::diagnostics::DiagnosticsStore;
use crate::model::Entrypoint;
use crate::provider::{
    Provider,
    config::ConfigProvider,
    docker::DockerProvider,
    http::HttpProvider,
    kubernetes::{KubernetesProvider, gateway},
    nomad::NomadProvider,
    podman::PodmanProvider,
    swarm::SwarmProvider,
};
use anyhow::Context;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{error, info, warn};

pub async fn start_services(
    config: &AppConfig,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    acme_notify: Arc<Notify>,
    diagnostics: DiagnosticsStore,
) -> anyhow::Result<()> {
    info!("Loading initial entrypoints and starting provider services");

    // Load initial entrypoints from config file provider and start watcher if enabled
    if let Some(config_file) = &config.providers.config_file
        && config_file.enabled
    {
        info!("Loading initial entrypoints from config file provider");
        let config_provider = ConfigProvider::new(&config_file.path);

        match config_provider.provide().await {
            Ok(entrypoints) => {
                let loaded = entrypoints.len();
                {
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
                    for (id, mut entrypoint) in entrypoints {
                        if storage_write.contains_key(&id) {
                            warn!("Duplicate entrypoint ID {} from config file provider", id);
                        }
                        entrypoint.source = Some("config".to_string());
                        info!("Loaded entrypoint from config: {}", id);
                        storage_write.insert(id, entrypoint);
                    }
                }
                if loaded > 0
                    && let Err(e) = reload_tx.send(()).await
                {
                    warn!("Failed to signal reload after config file load: {}", e);
                }
            }
            Err(e) => {
                warn!("Config file provider failed: {}", e);
            }
        }

        // Start file watcher if watch is enabled
        if config_file.watch {
            info!("Starting file watcher for config file");
            let config_provider_watcher = ConfigProvider::new(&config_file.path);
            let storage_watcher = Arc::clone(&storage);
            let reload_tx_watcher = reload_tx.clone();

            tokio::spawn(async move {
                if let Err(e) = config_provider_watcher
                    .start_file_watcher(storage_watcher, reload_tx_watcher)
                    .await
                {
                    error!("Config file watcher failed: {}", e);
                }
            });
        }
    }

    // Start Docker service if enabled (includes initial scan)
    if let Some(docker_config) = &config.providers.docker
        && docker_config.enabled
    {
        info!("Starting Docker service");
        let docker_provider = DockerProvider::new(docker_config.clone())
            .context("Failed to create Docker provider")?;
        let storage_docker = Arc::clone(&storage);
        let reload_tx_docker = reload_tx.clone();
        let acme_notify_docker = Arc::clone(&acme_notify);
        let diagnostics_docker = Arc::clone(&diagnostics);

        tokio::spawn(async move {
            if let Err(e) = docker_provider
                .start_service(
                    storage_docker,
                    reload_tx_docker,
                    acme_notify_docker,
                    diagnostics_docker,
                )
                .await
            {
                error!("Docker service failed: {}", e);
            }
        });
    }

    // Start Podman service if enabled (Docker API-compatible socket)
    if let Some(podman_config) = &config.providers.podman
        && podman_config.enabled
    {
        info!("Starting Podman service");
        let podman_provider = PodmanProvider::new(podman_config.clone())
            .context("Failed to create Podman provider")?;
        let storage_podman = Arc::clone(&storage);
        let reload_tx_podman = reload_tx.clone();
        let acme_notify_podman = Arc::clone(&acme_notify);
        let diagnostics_podman = Arc::clone(&diagnostics);

        tokio::spawn(async move {
            if let Err(e) = podman_provider
                .start_service(
                    storage_podman,
                    reload_tx_podman,
                    acme_notify_podman,
                    diagnostics_podman,
                )
                .await
            {
                error!("Podman service failed: {}", e);
            }
        });
    }

    // Start Swarm service if enabled
    if let Some(swarm_config) = &config.providers.swarm
        && swarm_config.enabled
    {
        info!("Starting Swarm service");
        let swarm_provider = Arc::new(
            SwarmProvider::new(swarm_config.clone()).context("Failed to create Swarm provider")?,
        );
        let storage_swarm = Arc::clone(&storage);
        let reload_tx_swarm = reload_tx.clone();
        let acme_notify_swarm = Arc::clone(&acme_notify);
        let diagnostics_swarm = Arc::clone(&diagnostics);

        tokio::spawn(async move {
            if let Err(e) = swarm_provider
                .start_service(
                    storage_swarm,
                    reload_tx_swarm,
                    acme_notify_swarm,
                    diagnostics_swarm,
                )
                .await
            {
                error!("Swarm service failed: {}", e);
            }
        });
    }

    // Start Kubernetes service if enabled
    if let Some(kubernetes_config) = &config.providers.kubernetes
        && kubernetes_config.enabled
    {
        info!("Starting Kubernetes service");
        let kubernetes_provider = Arc::new(
            KubernetesProvider::new(kubernetes_config.clone())
                .context("Failed to create Kubernetes provider")?,
        );
        let storage_kubernetes = Arc::clone(&storage);
        let reload_tx_kubernetes = reload_tx.clone();
        let acme_notify_kubernetes = Arc::clone(&acme_notify);
        let diagnostics_kubernetes = Arc::clone(&diagnostics);

        let kubernetes_provider_for_gateway = Arc::clone(&kubernetes_provider);
        let storage_for_gateway = Arc::clone(&storage);
        let reload_tx_for_gateway = reload_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = kubernetes_provider
                .start_service(
                    storage_kubernetes,
                    reload_tx_kubernetes,
                    acme_notify_kubernetes,
                    diagnostics_kubernetes,
                )
                .await
            {
                error!("Kubernetes service failed: {}", e);
            }
        });

        // Try to bring up the Gateway API watchers alongside the legacy
        // Ingress provider. If the cluster does not have the CRDs
        // installed we log and move on — Ingress alone is enough.
        //
        // Three watchers run side by side, sharing a single
        // `GatewayScope`:
        //   - GatewayClass watcher — accepts classes whose
        //     controllerName matches sōzune's identity
        //   - Gateway watcher     — accepts Gateways whose class is owned
        //   - HTTPRoute watcher   — accepts routes whose parentRefs
        //                            point to an accepted Gateway
        // Mutations to the scope notify the HTTPRoute watcher, which
        // re-resolves every tracked route so changes propagate without
        // waiting for the periodic tick.
        tokio::spawn(async move {
            let client = match kubernetes_provider_for_gateway.build_client().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Gateway API: failed to build kube client: {}", e);
                    return;
                }
            };
            if !gateway::httproute_crd_installed(&client).await {
                info!(
                    "Gateway API: HTTPRoute CRD not installed (or unreachable), skipping Gateway watchers"
                );
                return;
            }

            let scope = gateway::GatewayScope::new();
            let resolver: Arc<dyn gateway::ServiceResolver> =
                kubernetes_provider_for_gateway.clone();

            let gc_client = client.clone();
            let gc_scope = scope.clone();
            tokio::spawn(async move {
                if let Err(e) = gateway::run_gatewayclass_watcher(gc_client, gc_scope).await {
                    error!("Gateway API: GatewayClass watcher failed: {}", e);
                }
            });

            let gw_client = client.clone();
            let gw_scope = scope.clone();
            tokio::spawn(async move {
                if let Err(e) = gateway::run_gateway_watcher(gw_client, gw_scope).await {
                    error!("Gateway API: Gateway watcher failed: {}", e);
                }
            });

            if let Err(e) = gateway::run_httproute_watcher(
                client,
                storage_for_gateway,
                reload_tx_for_gateway,
                resolver,
                scope,
            )
            .await
            {
                error!("Gateway API: HTTPRoute watcher failed: {}", e);
            }
        });
    }

    // Start Nomad provider if enabled
    if let Some(nomad_config) = &config.providers.nomad
        && nomad_config.enabled
    {
        info!("Starting Nomad provider");
        let nomad_provider =
            NomadProvider::new(nomad_config.clone()).context("Failed to create Nomad provider")?;
        let storage_nomad = Arc::clone(&storage);
        let reload_tx_nomad = reload_tx.clone();
        let acme_notify_nomad = Arc::clone(&acme_notify);
        let diagnostics_nomad = Arc::clone(&diagnostics);

        tokio::spawn(async move {
            if let Err(e) = nomad_provider
                .start_polling(
                    storage_nomad,
                    reload_tx_nomad,
                    acme_notify_nomad,
                    diagnostics_nomad,
                )
                .await
            {
                error!("Nomad provider failed: {}", e);
            }
        });
    }

    // Start HTTP provider if enabled
    if let Some(http_config) = &config.providers.http
        && http_config.enabled
    {
        info!("Starting HTTP provider");
        let http_provider = HttpProvider::new(http_config.clone());
        let storage_http = Arc::clone(&storage);
        let reload_tx_http = reload_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = http_provider
                .start_polling(storage_http, reload_tx_http)
                .await
            {
                error!("HTTP provider failed: {}", e);
            }
        });
    }

    Ok(())
}
