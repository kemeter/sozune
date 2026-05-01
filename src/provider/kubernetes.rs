use crate::config::KubernetesConfig;
use crate::model::Entrypoint;
use crate::provider::Provider;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{info, warn};

pub struct KubernetesProvider {
    config: KubernetesConfig,
    name: &'static str,
}

#[async_trait]
impl Provider for KubernetesProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        Ok(BTreeMap::new())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

impl KubernetesProvider {
    pub fn new(config: KubernetesConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            name: "kubernetes",
        })
    }

    pub async fn start_service(
        &self,
        _storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        _reload_tx: mpsc::Sender<()>,
        _acme_notify: Arc<Notify>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Kubernetes provider (namespace={}, ingress_class={}, expose_by_default={})",
            if self.config.namespace.is_empty() {
                "<all>"
            } else {
                self.config.namespace.as_str()
            },
            self.config.ingress_class,
            self.config.expose_by_default,
        );

        warn!(
            "Kubernetes provider is a stub: discovery is not implemented yet (see .prd/kubernetes-provider.md)"
        );

        Ok(())
    }
}
