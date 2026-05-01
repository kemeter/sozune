use crate::config::KubernetesConfig;
use crate::model::Entrypoint;
use crate::provider::Provider;
use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config};
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

    /// Build a Kubernetes client.
    ///
    /// - empty `kubeconfig` → in-cluster ServiceAccount or auto-discovered
    ///   kubeconfig (`$KUBECONFIG` / `~/.kube/config`) via `Client::try_default`.
    /// - non-empty `kubeconfig` → load that exact file.
    async fn build_client(&self) -> anyhow::Result<Client> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        if self.config.kubeconfig.is_empty() {
            Client::try_default()
                .await
                .context("Failed to build Kubernetes client from default config")
        } else {
            let kubeconfig = Kubeconfig::read_from(&self.config.kubeconfig).with_context(|| {
                format!("Failed to read kubeconfig at {}", self.config.kubeconfig)
            })?;
            let kube_config =
                Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                    .await
                    .context("Failed to build kube Config from kubeconfig")?;
            Client::try_from(kube_config).context("Failed to build Kubernetes client from Config")
        }
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

        let client = self.build_client().await?;

        match client.apiserver_version().await {
            Ok(version) => info!(
                "Connected to Kubernetes cluster (version {}.{}, git {})",
                version.major, version.minor, version.git_version
            ),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to query Kubernetes API server: {}",
                    e
                ));
            }
        }

        let ns_api: Api<Namespace> = Api::all(client.clone());
        match ns_api.list(&ListParams::default()).await {
            Ok(list) => info!(
                "Kubernetes auth OK: {} namespace(s) visible to ServiceAccount",
                list.items.len()
            ),
            Err(e) => return Err(anyhow::anyhow!("Failed to list namespaces: {}", e)),
        }

        warn!("Kubernetes provider discovery is not implemented yet");

        Ok(())
    }
}
