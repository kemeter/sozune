use crate::acme::CertCommand;
use crate::config::ProxyConfig;
use crate::middleware::MiddlewareState;
use crate::model::Entrypoint;
use crate::proxy;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

pub fn init_proxy(
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    config: &ProxyConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    reload_rx: mpsc::UnboundedReceiver<()>,
    cert_rx: mpsc::UnboundedReceiver<CertCommand>,
    acme_challenge_port: Option<u16>,
    middleware_state: MiddlewareState,
    middleware_port: u16,
) -> anyhow::Result<()> {
    proxy::sozu::start_sozu_proxy(storage, config, shutdown_rx, reload_rx, cert_rx, acme_challenge_port, middleware_state, middleware_port)
}