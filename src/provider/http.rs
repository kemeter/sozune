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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::collections::HashMap;
    use crate::model::{EntrypointConfig, Protocol};

    fn sample_entrypoints_json() -> String {
        serde_json::to_string(&vec![
            Entrypoint {
                id: "web".to_string(),
                name: "web".to_string(),
                backends: vec!["127.0.0.1:3000".to_string()],
                protocol: Protocol::Http,
                config: EntrypointConfig {
                    hostnames: vec!["example.com".to_string()],
                    port: 80,
                    path: None,
                    tls: false,
                    strip_prefix: false,
                    https_redirect: false,
                    https_redirect_port: None,
                    redirect: None,
                    redirect_scheme: None,
                    redirect_template: None,
                    www_authenticate: None,
                    priority: 0,
                    auth: None,
                    headers: HashMap::new(),
                    backend_timeout: None,
                    rate_limit: None,
                    sticky_session: false,
                    compress: false,
                },
                source: None,
                backend_weights: HashMap::new(),
            },
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn test_fetch_entrypoints() {
        let json = sample_entrypoints_json();
        let app = Router::new().route("/config", get(move || {
            let json = json.clone();
            async move { json }
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 30,
        });

        let result = provider.fetch_entrypoints().await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("web"));
        assert_eq!(result["web"].config.hostnames, vec!["example.com"]);
    }

    #[tokio::test]
    async fn test_polling_updates_storage() {
        let json = sample_entrypoints_json();
        let app = Router::new().route("/config", get(move || {
            let json = json.clone();
            async move { json }
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 1,
        });

        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let (reload_tx, mut reload_rx) = mpsc::channel(64);

        let storage_clone = Arc::clone(&storage);
        let handle = tokio::spawn(async move {
            provider.start_polling(storage_clone, reload_tx).await.unwrap();
        });

        // Wait for first poll to trigger reload
        tokio::time::timeout(Duration::from_secs(5), reload_rx.recv())
            .await
            .expect("timeout waiting for reload")
            .expect("channel closed");

        handle.abort();

        let storage_read = storage.read().unwrap();
        assert_eq!(storage_read.len(), 1);
        let ep = storage_read.get("web").unwrap();
        assert_eq!(ep.source.as_deref(), Some("http"));
        assert_eq!(ep.config.hostnames, vec!["example.com"]);
    }

    #[tokio::test]
    async fn test_fetch_error_on_404() {
        let app = Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/missing", addr),
            poll_interval: 30,
        });

        let result = provider.fetch_entrypoints().await;
        assert!(result.is_err());
    }
}
