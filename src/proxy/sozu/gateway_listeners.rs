//! Listeners opened for Kubernetes Gateways on the ports of
//! `proxy.gateway_ports`.
//!
//! A Gateway route served on such a port refers to its listener by a name
//! carrying the port (see [`crate::config::gateway_tcp_listener`]). Each reload
//! opens the listeners its routes refer to and closes those no route uses any
//! more, so a port stays open only while a route is served on it.

use super::{
    Channels, L4Channels, RoutingSnapshot, WorkerSettings, serve_tcp_forwarder, spawn_tcp_worker,
    spawn_udp_worker, stop_worker,
};
use crate::config::{GatewayPortsConfig, TcpListenerConfig, gateway_tcp_port, gateway_udp_port};
use crate::model::Protocol;
use crate::provider::kubernetes::gateway::is_gateway_route;
use crate::proxy::backend::UnopenedGatewayPorts;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tracing::{error, info, warn};

/// The listeners opened on `proxy.gateway_ports`.
pub(super) struct GatewayListeners {
    ports: GatewayPortsConfig,
    settings: WorkerSettings,
    /// Each TCP listener opened here, with the forwarder owning its public
    /// port.
    tcp: HashMap<String, Forwarder>,
    udp: HashSet<String>,
    /// Where the ports that could not be opened are published, for the
    /// Gateway listener status.
    unopened: watch::Sender<UnopenedGatewayPorts>,
}

impl GatewayListeners {
    pub(super) fn new(
        ports: GatewayPortsConfig,
        settings: WorkerSettings,
        unopened: watch::Sender<UnopenedGatewayPorts>,
    ) -> Self {
        Self {
            ports,
            settings,
            tcp: HashMap::new(),
            udp: HashSet::new(),
            unopened,
        }
    }
}

/// The Gateway listeners routes are served on, by name, with their port.
pub(super) struct Referenced {
    tcp: BTreeMap<String, u16>,
    udp: BTreeMap<String, u16>,
}

/// The Gateway listeners the Gateway routes of `snapshot` are served on. A
/// route of another provider naming such a listener opens nothing.
fn referenced(snapshot: &RoutingSnapshot) -> Referenced {
    let mut tcp = BTreeMap::new();
    let mut udp = BTreeMap::new();
    for entrypoint in snapshot.values().filter(|ep| is_gateway_route(ep)) {
        let Some(name) = entrypoint.config.entrypoint.as_deref() else {
            continue;
        };
        match entrypoint.protocol {
            Protocol::Tcp => {
                if let Some(port) = gateway_tcp_port(name) {
                    tcp.insert(name.to_string(), port);
                }
            }
            Protocol::Udp => {
                if let Some(port) = gateway_udp_port(name) {
                    udp.insert(name.to_string(), port);
                }
            }
            Protocol::Http => {}
        }
    }
    Referenced { tcp, udp }
}

/// Open every Gateway listener a route of `snapshot` is served on and that is
/// not open yet. One that cannot be opened is reported, in the logs and to the
/// Gateway listener status, and its routes are refused until a later reload
/// opens it. Returns the listeners the routes want, for
/// [`close_unused_gateway_listeners`] once they are installed.
pub(super) fn open_gateway_listeners(
    channels: &mut Channels,
    snapshot: &RoutingSnapshot,
) -> Referenced {
    let Channels {
        tcp, udp, gateway, ..
    } = channels;
    let wanted = referenced(snapshot);
    let mut unopened = UnopenedGatewayPorts::default();
    for (name, &port) in &wanted.tcp {
        if tcp.contains_key(name) {
            continue;
        }
        match open_tcp(gateway, tcp, name, port) {
            Ok(()) => info!("Opened TCP port {} for Gateway listener `{}`", port, name),
            Err(e) => {
                error!("Could not open Gateway listener `{}`: {:#}", name, e);
                unopened.tcp.insert(port, format!("{e:#}"));
            }
        }
    }
    for (name, &port) in &wanted.udp {
        if udp.contains_key(name) {
            continue;
        }
        match open_udp(gateway, udp, name, port) {
            Ok(()) => info!("Opened UDP port {} for Gateway listener `{}`", port, name),
            Err(e) => {
                error!("Could not open Gateway listener `{}`: {:#}", name, e);
                unopened.udp.insert(port, format!("{e:#}"));
            }
        }
    }
    gateway.unopened.send_if_modified(|published| {
        let changed = *published != unopened;
        *published = unopened;
        changed
    });
    wanted
}

/// The task forwarding a public TCP port, and how to learn it let go of it.
struct Forwarder {
    task: AbortHandle,
    released: std::sync::mpsc::Receiver<()>,
}

/// A public port held by a forwarder task. Dropped with the task, aborted or
/// not, it closes the port before saying so.
struct PublicPort {
    listener: Option<tokio::net::TcpListener>,
    released: std::sync::mpsc::Sender<()>,
}

impl Drop for PublicPort {
    fn drop(&mut self) {
        self.listener.take();
        let _ = self.released.send(());
    }
}

/// How long a stopping forwarder may take to close its port. A reopening
/// within that time would otherwise find the port still taken.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(2);

fn open_tcp(
    gateway: &mut GatewayListeners,
    tcp: &mut L4Channels,
    name: &str,
    port: u16,
) -> anyhow::Result<()> {
    if !gateway.ports.allows_tcp(port) {
        anyhow::bail!("port {} is not in proxy.gateway_ports.tcp", port);
    }
    let runtime = tokio::runtime::Handle::try_current()?;
    let _entered = runtime.enter();
    // Bound before the worker starts, so a port already taken fails here with
    // nothing to undo.
    let public = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
    public.set_nonblocking(true)?;
    let public = tokio::net::TcpListener::from_std(public)?;

    let config = TcpListenerConfig {
        name: name.to_string(),
        listen: port,
        ip_allow_list: Vec::new(),
        rate_limit: None,
        sni_preread_timeout: None,
        sni_preread_max_bytes: None,
        idle_timeout: None,
    };
    // The worker thread stops when its listener is closed; nothing joins it.
    let (channel, _worker, forwarder) = spawn_tcp_worker(&config, gateway.settings)?;
    let (released_tx, released) = std::sync::mpsc::channel();
    let port_guard = PublicPort {
        listener: Some(public),
        released: released_tx,
    };
    let task = runtime.spawn(async move {
        let port_guard = port_guard;
        if let Some(listener) = &port_guard.listener {
            serve_tcp_forwarder(forwarder, listener).await;
        }
    });
    gateway.tcp.insert(
        name.to_string(),
        Forwarder {
            task: task.abort_handle(),
            released,
        },
    );
    tcp.insert(name.to_string(), channel);
    Ok(())
}

fn open_udp(
    gateway: &mut GatewayListeners,
    udp: &mut L4Channels,
    name: &str,
    port: u16,
) -> anyhow::Result<()> {
    if !gateway.ports.allows_udp(port) {
        anyhow::bail!("port {} is not in proxy.gateway_ports.udp", port);
    }
    // The worker thread stops when its listener is closed; nothing joins it.
    let (channel, _worker) = spawn_udp_worker(name, port, gateway.settings)?;
    gateway.udp.insert(name.to_string());
    udp.insert(name.to_string(), channel);
    Ok(())
}

/// Close every Gateway listener no route wants any more. `wanted` comes from
/// the routes the reload set out to serve, not those it managed to install:
/// a reload failing on another route must not take a live listener down.
pub(super) fn close_unused_gateway_listeners(channels: &mut Channels, wanted: &Referenced) {
    let Channels {
        tcp, udp, gateway, ..
    } = channels;

    let unused: Vec<String> = gateway
        .tcp
        .keys()
        .filter(|name| !wanted.tcp.contains_key(*name))
        .cloned()
        .collect();
    for name in unused {
        // The public port first, so no connection arrives for a worker that
        // is stopping.
        if let Some(forwarder) = gateway.tcp.remove(&name) {
            forwarder.task.abort();
            if forwarder.released.recv_timeout(RELEASE_TIMEOUT)
                == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                warn!("Gateway listener `{}` still holds its port", name);
            }
        }
        if let Some(mut listener) = tcp.remove(&name) {
            stop_worker(&mut listener.channel, &name);
        }
        info!(
            "Closed Gateway listener `{}`: no route is served on it",
            name
        );
    }

    let unused: Vec<String> = gateway
        .udp
        .iter()
        .filter(|name| !wanted.udp.contains_key(*name))
        .cloned()
        .collect();
    for name in unused {
        gateway.udp.remove(&name);
        if let Some(mut listener) = udp.remove(&name) {
            stop_worker(&mut listener.channel, &name);
        }
        info!(
            "Closed Gateway listener `{}`: no route is served on it",
            name
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{gateway_tcp_listener, gateway_udp_listener};
    use crate::model::Entrypoint;

    fn entrypoint(id: &str, protocol: Protocol, listener: &str) -> (String, Entrypoint) {
        let mut ep = super::super::tests::tcp_ep(id, listener, None);
        ep.protocol = protocol;
        ep.source = Some(format!("k8s-gateway-tcp/default/{id}"));
        (id.into(), ep)
    }

    /// An aborted forwarder closes its port before saying so, so the port
    /// can be bound again at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_forwarder_releases_its_port() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (released_tx, released) = std::sync::mpsc::channel();
        let guard = PublicPort {
            listener: Some(listener),
            released: released_tx,
        };
        let task = tokio::spawn(async move {
            let guard = guard;
            if let Some(listener) = &guard.listener {
                let _ = listener.accept().await;
            }
        });

        task.abort();
        released.recv_timeout(RELEASE_TIMEOUT).unwrap();
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[test]
    fn only_gateway_listeners_are_referenced() {
        let snapshot: RoutingSnapshot = [
            entrypoint("a", Protocol::Tcp, &gateway_tcp_listener(9000)),
            entrypoint("b", Protocol::Tcp, &gateway_tcp_listener(9000)),
            entrypoint("c", Protocol::Tcp, "postgres"),
            entrypoint("d", Protocol::Udp, &gateway_udp_listener(5353)),
            // A UDP name on a TCP route opens nothing.
            entrypoint("e", Protocol::Tcp, &gateway_udp_listener(5354)),
            // Only a Gateway route opens a port.
            {
                let (id, mut ep) = entrypoint("f", Protocol::Tcp, &gateway_tcp_listener(9001));
                ep.source = Some("docker".into());
                (id, ep)
            },
        ]
        .into_iter()
        .collect();

        let Referenced { tcp, udp } = referenced(&snapshot);
        assert_eq!(
            tcp.into_iter().collect::<Vec<_>>(),
            vec![(gateway_tcp_listener(9000), 9000)]
        );
        assert_eq!(
            udp.into_iter().collect::<Vec<_>>(),
            vec![(gateway_udp_listener(5353), 5353)]
        );
    }
}
