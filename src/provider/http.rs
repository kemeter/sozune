use crate::config::HttpProviderConfig;
use crate::model::Entrypoint;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct HttpProvider {
    config: HttpProviderConfig,
}

impl HttpProvider {
    pub fn new(config: HttpProviderConfig) -> Self {
        Self { config }
    }

    async fn fetch_entrypoints(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let response = reqwest::get(&self.config.url).await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "HTTP provider returned status {}",
                response.status()
            );
        }

        let body = response.text().await?;

        let entrypoints: Vec<Entrypoint> = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("Failed to parse HTTP provider response: {}", e))?;

        Ok(entrypoints
            .into_iter()
            .map(|ep| (ep.id.clone(), ep))
            .collect())
    }

    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting HTTP provider polling {} every {}s",
            self.config.url, self.config.poll_interval
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.poll_interval));

        loop {
            interval.tick().await;

            match self.fetch_entrypoints().await {
                Ok(new_entrypoints) => {
                    let changed = {
                        let mut storage_write = match storage.write() {
                            Ok(guard) => guard,
                            Err(e) => {
                                error!("Storage lock poisoned in HTTP provider: {}", e);
                                continue;
                            }
                        };

                        // Collect current HTTP provider entrypoint IDs
                        let old_ids: Vec<String> = storage_write
                            .iter()
                            .filter(|(_, ep)| ep.source.as_deref() == Some("http"))
                            .map(|(id, _)| id.clone())
                            .collect();

                        let new_ids: Vec<String> = new_entrypoints.keys().cloned().collect();

                        let changed = old_ids != new_ids
                            || new_entrypoints.iter().any(|(id, ep)| {
                                storage_write
                                    .get(id)
                                    .map_or(true, |existing| {
                                        existing.backends != ep.backends
                                            || existing.config.hostnames != ep.config.hostnames
                                            || existing.config.port != ep.config.port
                                    })
                            });

                        if changed {
                            // Remove old HTTP provider entrypoints
                            storage_write
                                .retain(|_, ep| ep.source.as_deref() != Some("http"));

                            // Add new ones
                            for (id, mut entrypoint) in new_entrypoints {
                                entrypoint.source = Some("http".to_string());
                                debug!("HTTP provider entrypoint: {}", id);
                                storage_write.insert(id, entrypoint);
                            }
                        }

                        changed
                    };

                    if changed {
                        info!("HTTP provider config changed, triggering reload");
                        if let Err(e) = reload_tx.send(()).await {
                            warn!("Failed to send reload signal: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("HTTP provider fetch failed: {}", e);
                }
            }
        }
    }
}
