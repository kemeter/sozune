use crate::acme::CertCommand;
use crate::config::ProxyConfig;
use crate::middleware::{MiddlewareState, PluginRegistry};
use crate::model::Entrypoint;
use crate::proxy;
use crate::proxy::metrics_snapshot::MetricsSnapshotStore;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Bundle of channels and state the proxy needs to wire up. Grouped here so
/// every caller and forward (main.rs → init_proxy → start_sozu_proxy) only
/// has to pass one value instead of nine — the inner fields are deliberately
/// public so the sozu reload thread can take direct ownership of each.
pub struct ProxyInputs {
    pub storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    pub shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    pub reload_rx: mpsc::Receiver<()>,
    pub cert_rx: mpsc::Receiver<CertCommand>,
    pub metrics_poll_rx: mpsc::Receiver<()>,
    pub metrics_store: MetricsSnapshotStore,
    pub acme_challenge_port: Option<u16>,
    pub middleware_state: MiddlewareState,
    pub middleware_port: u16,
    /// Compiled WASM plugins, keyed by declared name. Built once at startup.
    pub plugins: PluginRegistry,
    pub handle: tokio::runtime::Handle,
}

pub fn init_proxy(inputs: ProxyInputs, config: &ProxyConfig) -> anyhow::Result<()> {
    proxy::sozu::start_sozu_proxy(inputs, config)
}
