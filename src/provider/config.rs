use super::Provider;
use crate::model::Entrypoint;
use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use tracing::{info, warn, error};

#[derive(Deserialize)]
pub struct ConfigFile {
    pub entrypoints: Vec<Entrypoint>,
}

pub struct ConfigProvider {
    config_path: String,
}

impl ConfigProvider {
    pub fn new(config_path: impl Into<String>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }
}

#[async_trait]
impl Provider for ConfigProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let content = tokio::fs::read_to_string(&self.config_path).await
            .context("Failed to read config file")?;

        let config: ConfigFile = serde_yaml::from_str(&content)
            .context("Failed to parse config file")?;

        Ok(config.entrypoints
            .into_iter()
            .map(|ep| (ep.id.clone(), ep))
            .collect())
    }

    fn name(&self) -> &'static str {
        "config"
    }
}

impl ConfigProvider {
    /// Start file watcher for config file changes
    pub async fn start_file_watcher(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::UnboundedSender<()>
    ) -> anyhow::Result<()> {
        let config_path = self.config_path.clone();
        let storage_clone = Arc::clone(&storage);
        
        info!("Starting file watcher for config file: {}", config_path);
        
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Create file watcher
        let mut watcher = notify::recommended_watcher(move |result: Result<Event, notify::Error>| {
            match result {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        if let Err(e) = tx.send(()) {
                            error!("Failed to send file change notification: {}", e);
                        }
                    }
                }
                Err(e) => error!("File watcher error: {}", e),
            }
        })?;
        
        // Watch the config file directory (not the file directly, to handle renames/recreates)
        let watch_path = std::path::Path::new(&config_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        
        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;
        
        // Handle file change events
        while let Some(_) = rx.recv().await {
            info!("Config file changed, reloading entrypoints");
            
            match self.provide().await {
                Ok(new_entrypoints) => {
                    // Replace config entrypoints in storage
                    {
                        let mut storage_write = storage_clone.write().unwrap();
                        
                        // Remove existing config entrypoints
                        storage_write.retain(|_, entrypoint| {
                            !entrypoint.source.as_ref().map_or(false, |s| s == "config")
                        });
                        
                        // Add new config entrypoints  
                        for (id, mut entrypoint) in new_entrypoints {
                            entrypoint.source = Some("config".to_string());
                            info!("Reloaded config entrypoint: {}", id);
                            storage_write.insert(id, entrypoint);
                        }
                    }
                    
                    // Trigger proxy reload
                    if let Err(e) = reload_tx.send(()) {
                        warn!("Failed to send a reload signal: {}", e);
                    } else {
                        info!("Config entrypoints reloaded successfully");
                    }
                }
                Err(e) => {
                    error!("Failed to reload config entrypoints: {}", e);
                }
            }
        }
        
        Ok(())
    }
}