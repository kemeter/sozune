use super::Provider;
use crate::model::Entrypoint;
use anyhow::Context;
use async_trait::async_trait;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

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
        let content = tokio::fs::read_to_string(&self.config_path)
            .await
            .context("Failed to read config file")?;

        let config: ConfigFile =
            serde_yaml::from_str(&content).context("Failed to parse config file")?;

        Ok(config
            .entrypoints
            .into_iter()
            .map(|ep| (ep.id.clone(), ep))
            .collect())
    }
}

impl ConfigProvider {
    /// Start file watcher for config file changes
    pub async fn start_file_watcher(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
    ) -> anyhow::Result<()> {
        let config_path = self.config_path.clone();
        let storage_clone = Arc::clone(&storage);

        info!("Starting file watcher for config file: {}", config_path);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Canonicalize the watched file so we can match it against event paths,
        // which the OS reports as canonical (resolved symlinks, no `.`/`..`).
        let watched_file = tokio::fs::canonicalize(&config_path)
            .await
            .unwrap_or_else(|_| std::path::PathBuf::from(&config_path));

        // Create file watcher
        let mut watcher = notify::recommended_watcher({
            let watched_file = watched_file.clone();
            move |result: Result<Event, notify::Error>| match result {
                Ok(event) => {
                    if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        return;
                    }
                    if !event.paths.iter().any(|p| p == &watched_file) {
                        return;
                    }
                    if let Err(e) = tx.send(()) {
                        error!("Failed to send file change notification: {}", e);
                    }
                }
                Err(e) => error!("File watcher error: {}", e),
            }
        })?;

        // Watch the config file directory (not the file directly, to handle renames/recreates).
        // Events for unrelated files in the same directory are filtered out above.
        let watch_path = watched_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;

        // Handle file change events
        while rx.recv().await.is_some() {
            info!("Config file changed, reloading entrypoints");

            match self.provide().await {
                Ok(new_entrypoints) => {
                    // Replace config entrypoints in storage
                    {
                        let mut storage_write = match storage_clone.write() {
                            Ok(guard) => guard,
                            Err(e) => {
                                error!(
                                    "internal state corrupted (configuration store), restart required: {}",
                                    e
                                );
                                continue;
                            }
                        };

                        // Remove existing config entrypoints
                        storage_write.retain(|_, entrypoint| {
                            entrypoint
                                .source
                                .as_ref()
                                .is_none_or(|s| s != crate::provider::CONFIG)
                        });

                        // Add new config entrypoints
                        for (id, mut entrypoint) in new_entrypoints {
                            entrypoint.source = Some(crate::provider::CONFIG.to_string());
                            info!("Reloaded config entrypoint: {}", id);
                            storage_write.insert(id, entrypoint);
                        }
                    }

                    // Trigger proxy reload
                    if let Err(e) = reload_tx.send(()).await {
                        warn!(
                            "could not apply configuration update; will retry on next change: {}",
                            e
                        );
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
