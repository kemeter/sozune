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
        let mut request = reqwest::Client::new().get(&self.config.url);
        if !self.config.auth_header.is_empty() && !self.config.auth_value.is_empty() {
            request = request.header(&self.config.auth_header, &self.config.auth_value);
        }
        let response = request.send().await?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP provider returned status {}", response.status());
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
                    // Compare under a read lock first; the API server also
                    // takes read locks on this storage and would otherwise
                    // contend with our write lock on every poll.
                    let needs_update = {
                        let storage_read = match storage.read() {
                            Ok(guard) => guard,
                            Err(e) => {
                                error!(
                                    "internal state corrupted (configuration store), restart required: {}",
                                    e
                                );
                                continue;
                            }
                        };

                        let old_ids: std::collections::HashSet<&String> = storage_read
                            .iter()
                            .filter(|(_, ep)| ep.source.as_deref() == Some("http"))
                            .map(|(id, _)| id)
                            .collect();

                        let new_ids: std::collections::HashSet<&String> =
                            new_entrypoints.keys().collect();

                        old_ids != new_ids
                            || new_entrypoints.iter().any(|(id, ep)| {
                                storage_read.get(id).is_none_or(|existing| {
                                    existing.backends != ep.backends
                                        || existing.config.hostnames != ep.config.hostnames
                                })
                            })
                    };

                    if !needs_update {
                        continue;
                    }

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
                        storage_write.retain(|_, ep| ep.source.as_deref() != Some("http"));
                        for (id, mut entrypoint) in new_entrypoints {
                            entrypoint.source = Some("http".to_string());
                            debug!("HTTP provider entrypoint: {}", id);
                            storage_write.insert(id, entrypoint);
                        }
                    }

                    info!("HTTP provider config changed, triggering reload");
                    if let Err(e) = reload_tx.send(()).await {
                        warn!(
                            "could not apply configuration update; will retry on next change: {}",
                            e
                        );
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
    use crate::model::{Backend, EntrypointConfig, Protocol};
    use axum::{Router, routing::get};

    fn sample_entrypoints_json() -> String {
        serde_json::to_string(&vec![Entrypoint {
            id: "web".to_string(),
            name: "web".to_string(),
            backends: vec![Backend::new("127.0.0.1", 3000)],
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec!["example.com".to_string()],
                path: None,
                tls: false,
                strip_prefix: false,
                add_prefix: None,
                https_redirect: false,
                https_redirect_port: None,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                rate_limit: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                methods: Vec::new(),
            },
            source: None,
        }])
        .unwrap()
    }

    #[tokio::test]
    async fn test_fetch_entrypoints() {
        let json = sample_entrypoints_json();
        let app = Router::new().route(
            "/config",
            get(move || {
                let json = json.clone();
                async move { json }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 30,
            auth_header: String::new(),
            auth_value: String::new(),
        });

        let result = provider.fetch_entrypoints().await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("web"));
        assert_eq!(result["web"].config.hostnames, vec!["example.com"]);
    }

    #[tokio::test]
    async fn test_polling_updates_storage() {
        let json = sample_entrypoints_json();
        let app = Router::new().route(
            "/config",
            get(move || {
                let json = json.clone();
                async move { json }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 1,
            auth_header: String::new(),
            auth_value: String::new(),
        });

        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let (reload_tx, mut reload_rx) = mpsc::channel(64);

        let storage_clone = Arc::clone(&storage);
        let handle = tokio::spawn(async move {
            provider
                .start_polling(storage_clone, reload_tx)
                .await
                .unwrap();
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
            auth_header: String::new(),
            auth_value: String::new(),
        });

        let result = provider.fetch_entrypoints().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_sends_auth_header_when_configured() {
        use axum::extract::Request;
        use std::sync::Mutex;

        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);
        let json = sample_entrypoints_json();
        let app = Router::new().route(
            "/config",
            get(move |req: Request| {
                let json = json.clone();
                let captured = Arc::clone(&captured_clone);
                async move {
                    let value = req
                        .headers()
                        .get("X-Sozune-Token")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    *captured.lock().unwrap() = value;
                    json
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 30,
            auth_header: "X-Sozune-Token".to_string(),
            auth_value: "secret-123".to_string(),
        });

        provider.fetch_entrypoints().await.unwrap();

        let header = captured.lock().unwrap().clone();
        assert_eq!(header.as_deref(), Some("secret-123"));
    }

    #[tokio::test]
    async fn test_fetch_omits_auth_header_when_value_is_empty() {
        use axum::extract::Request;
        use std::sync::Mutex;

        let saw_header: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let saw_header_clone = Arc::clone(&saw_header);
        let json = sample_entrypoints_json();
        let app = Router::new().route(
            "/config",
            get(move |req: Request| {
                let json = json.clone();
                let saw = Arc::clone(&saw_header_clone);
                async move {
                    if req.headers().contains_key("X-Sozune-Token") {
                        *saw.lock().unwrap() = true;
                    }
                    json
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = HttpProvider::new(HttpProviderConfig {
            enabled: true,
            url: format!("http://{}/config", addr),
            poll_interval: 30,
            auth_header: "X-Sozune-Token".to_string(),
            auth_value: String::new(),
        });

        provider.fetch_entrypoints().await.unwrap();
        assert!(!*saw_header.lock().unwrap());
    }
}
