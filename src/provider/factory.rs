use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use crate::config::AppConfig;
use crate::provider::{Provider, config::ConfigProvider, docker::DockerProvider};
use crate::model::Entrypoint;
use anyhow::Context;
use tracing::{error, info, warn};

pub async fn start_services(
    config: &AppConfig,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::UnboundedSender<()>
) -> anyhow::Result<()> {
    info!("Loading initial entrypoints and starting provider services");
    
    // Load initial entrypoints from config file provider and start watcher if enabled
    if let Some(config_file) = &config.providers.config_file {
        if config_file.enabled {
            info!("Loading initial entrypoints from config file provider");
            let config_provider = ConfigProvider::new(&config_file.path);
            
            match config_provider.provide().await {
                Ok(entrypoints) => {
                    let mut storage_write = storage.write().unwrap();
                    for (id, mut entrypoint) in entrypoints {
                        if storage_write.contains_key(&id) {
                            warn!("Duplicate entrypoint ID {} from config file provider", id);
                        }
                        entrypoint.source = Some("config".to_string());
                        info!("Loaded entrypoint from config: {}", id);
                        storage_write.insert(id, entrypoint);
                    }
                    drop(storage_write);
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
                    if let Err(e) = config_provider_watcher.start_file_watcher(storage_watcher, reload_tx_watcher).await {
                        error!("Config file watcher failed: {}", e);
                    }
                });
            }
        }
    }
    
    // Start Docker service if enabled (includes initial scan)
    if let Some(docker_config) = &config.providers.docker {
        if docker_config.enabled {
            info!("Starting Docker service");
            let docker_provider = DockerProvider::new(docker_config.clone())
                .context("Failed to create Docker provider")?;
            
            if let Err(e) = docker_provider.start_service(storage, reload_tx.clone()).await {
                error!("Docker service failed: {}", e);
            }
        }
    }
    
    // TODO: Add file watcher for config file provider if enabled
    
    Ok(())
}