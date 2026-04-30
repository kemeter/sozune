use crate::config::{DockerConfig, PodmanConfig};
use crate::labels::candidate::Candidate;
use crate::labels::source::LabelSource;
use crate::model::Entrypoint;
use crate::provider::Provider;
use crate::provider::docker::DockerProvider;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

pub struct PodmanProvider {
    inner: DockerProvider,
}

impl PodmanProvider {
    pub fn new(config: PodmanConfig) -> Result<Self, bollard::errors::Error> {
        let docker_config = DockerConfig {
            enabled: config.enabled,
            endpoint: config.endpoint,
            expose_by_default: config.expose_by_default,
        };
        Ok(Self {
            inner: DockerProvider::new_named(docker_config, "podman")?,
        })
    }

    pub async fn start_service(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<tokio::sync::Notify>,
    ) -> anyhow::Result<()> {
        self.inner
            .start_service(storage, reload_tx, acme_notify)
            .await
    }
}

#[async_trait]
impl Provider for PodmanProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        self.inner.provide().await
    }

    fn name(&self) -> &'static str {
        "podman"
    }
}

#[async_trait]
impl LabelSource for PodmanProvider {
    fn provider_name(&self) -> &'static str {
        "podman"
    }

    async fn collect(&self) -> anyhow::Result<Vec<Candidate>> {
        self.inner.collect().await
    }
}
