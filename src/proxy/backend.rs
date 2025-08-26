use crate::config::ProxyConfig;
use crate::model::Entrypoint;
use crate::proxy;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

pub fn init_proxy(
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    config: &ProxyConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    reload_rx: mpsc::UnboundedReceiver<()>
) -> anyhow::Result<()> {
    proxy::sozu::start_sozu_proxy(storage, config, shutdown_rx, reload_rx)
}