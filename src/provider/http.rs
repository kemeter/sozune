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

        // Same gate the label path applies: a name holding `/` is a regex to
        // Sozu and a bare `*` matches every host, so an entrypoint from an
        // upstream control plane could otherwise claim the whole proxy.
        Ok(entrypoints
            .into_iter()
            .filter(|ep| {
                let bad = ep
                    .config
                    .hostnames
                    .iter()
                    .find(|h| !crate::labels::fields::host::is_routable_hostname(h));
                if let Some(bad) = bad {
                    warn!(
                        "dropping entrypoint `{}` from the HTTP provider: `{}` is not a hostname",
                        ep.id, bad
                    );
                    return false;
                }
                // Served without it, the route would take more requests
                // than it asks for.
                if let Some(bad) = ep.config.invalid_match_regex() {
                    warn!(
                        "dropping entrypoint `{}` from the HTTP provider: the regex of `{}` does not compile",
                        ep.id, bad.key
                    );
                    return false;
                }
                true
            })
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
                Ok(mut new_entrypoints) => {
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

                        drop_taken_ids(&storage_read, &mut new_entrypoints);
                        http_entrypoints_changed(&storage_read, &new_entrypoints)
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
                        storage_write
                            .retain(|_, ep| ep.source.as_deref() != Some(crate::provider::HTTP));
                        // Another provider may have taken one since the read lock.
                        drop_taken_ids(&storage_write, &mut new_entrypoints);
                        for (id, mut entrypoint) in new_entrypoints {
                            entrypoint.source = Some(crate::provider::HTTP.to_string());
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

/// Leaves out the fetched entrypoints whose id another source already uses:
/// inserted, they would replace that source's route.
fn drop_taken_ids(
    stored: &BTreeMap<String, Entrypoint>,
    fetched: &mut BTreeMap<String, Entrypoint>,
) {
    fetched.retain(|id, _| match stored.get(id) {
        Some(existing) if existing.source.as_deref() != Some(crate::provider::HTTP) => {
            warn!(
                "HTTP provider entrypoint `{}` ignored: this id is already used by {}",
                id,
                existing.source.as_deref().unwrap_or("another source")
            );
            false
        }
        _ => true,
    });
}

/// Whether the entrypoints the HTTP provider fetched (`fetched`) differ from
/// those it put in `stored`: one more or one fewer, or any change to one, not
/// just its backends and hostnames. The stored copies carry the source the
/// provider gave them.
fn http_entrypoints_changed(
    stored: &BTreeMap<String, Entrypoint>,
    fetched: &BTreeMap<String, Entrypoint>,
) -> bool {
    let ours = |ep: &Entrypoint| ep.source.as_deref() == Some(crate::provider::HTTP);
    let old_ids: std::collections::HashSet<&String> = stored
        .iter()
        .filter(|(_, ep)| ours(ep))
        .map(|(id, _)| id)
        .collect();
    let new_ids: std::collections::HashSet<&String> = fetched.keys().collect();
    old_ids != new_ids
        || fetched.iter().any(|(id, ep)| {
            stored.get(id).is_none_or(|existing| {
                !ours(existing)
                    || Entrypoint {
                        source: existing.source.clone(),
                        ..ep.clone()
                    } != *existing
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Backend, EntrypointConfig, LoadBalancer, Protocol};
    use axum::{Router, routing::get};

    /// A change the provider makes to a route, a match condition among
    /// others, is applied; an unchanged fetch is not.
    #[test]
    fn any_change_to_a_fetched_entrypoint_is_seen() {
        let fetched: Vec<Entrypoint> = serde_json::from_str(&sample_entrypoints_json()).unwrap();
        let fetched: BTreeMap<String, Entrypoint> =
            fetched.into_iter().map(|ep| (ep.id.clone(), ep)).collect();
        let stored: BTreeMap<String, Entrypoint> = fetched
            .iter()
            .map(|(id, ep)| {
                let mut ep = ep.clone();
                ep.source = Some(crate::provider::HTTP.to_string());
                (id.clone(), ep)
            })
            .collect();
        assert!(!http_entrypoints_changed(&stored, &fetched));

        let mut changed = fetched.clone();
        changed.get_mut("web").unwrap().config.match_headers = vec![crate::model::MatchCondition {
            key: "x-version".into(),
            value: "v[0-9]+".into(),
            regex: true,
        }];
        assert!(http_entrypoints_changed(&stored, &changed));
    }

    #[test]
    fn an_id_another_source_uses_is_left_out() {
        let entrypoint = |source: Option<&str>| Entrypoint {
            source: source.map(str::to_string),
            ..serde_json::from_str::<Vec<Entrypoint>>(&sample_entrypoints_json()).unwrap()[0]
                .clone()
        };
        let stored = BTreeMap::from([("docker_web".to_string(), entrypoint(Some("docker")))]);
        let mut fetched = BTreeMap::from([
            ("docker_web".to_string(), entrypoint(None)),
            ("web".to_string(), entrypoint(None)),
        ]);
        drop_taken_ids(&stored, &mut fetched);
        assert_eq!(fetched.keys().collect::<Vec<_>>(), vec!["web"]);
        // Nothing to do on the next poll for the id left out.
        fetched.remove("web");
        assert!(!http_entrypoints_changed(&stored, &fetched));
    }

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
                https_only: false,
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
                request_timeout: None,
                health_check: None,
                load_balancer: LoadBalancer::default(),
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                sni: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: std::collections::BTreeMap::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                answer: None,
                mirrors: Vec::new(),
                mirror_of: None,
                failing_shares: None,
                cors: None,
                ip_allow_list: Vec::new(),
            },
            source: None,
            candidates: Vec::new(),
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
        assert_eq!(ep.source.as_deref(), Some(crate::provider::HTTP));
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
