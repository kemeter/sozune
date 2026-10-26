//! Listeners opened for Kubernetes Gateways on the ports of
//! `proxy.gateway_ports`.
//!
//! A Gateway route served on such a port refers to its listener by a name
//! carrying the port (see [`crate::config::gateway_tcp_listener`]). Each reload
//! opens the listeners its routes refer to and closes those no route uses any
//! more, so a port stays open only while a route is served on it.

use super::{
    Channels, L4Channels, RoutingSnapshot, WorkerSettings, send_to_worker, serve_tcp_forwarder,
    spawn_tcp_worker, spawn_udp_worker, stop_worker,
};
use crate::config::{
    GatewayPortsConfig, TcpListenerConfig, gateway_http_port, gateway_tcp_port, gateway_udp_port,
};
use crate::model::Protocol;
use crate::provider::kubernetes::gateway::is_gateway_route;
use crate::proxy::backend::UnopenedGatewayPorts;
use sozu_command_lib::channel::Channel;
use sozu_command_lib::proto::command::{
    ActivateListener, DeactivateListener, HttpListenerConfig, ListenerType, RemoveListener,
    SocketAddress, WorkerRequest, WorkerResponse, request::RequestType,
};
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
    /// The HTTP listeners opened on the HTTP worker, by name, with their
    /// port.
    http: BTreeMap<String, u16>,
    /// What those are built from: the main HTTP listener's settings.
    http_template: HttpListenerConfig,
    /// Where the ports that could not be opened are published, for the
    /// Gateway listener status.
    unopened: watch::Sender<UnopenedGatewayPorts>,
}

impl GatewayListeners {
    pub(super) fn new(
        ports: GatewayPortsConfig,
        settings: WorkerSettings,
        unopened: watch::Sender<UnopenedGatewayPorts>,
        http_template: HttpListenerConfig,
    ) -> Self {
        Self {
            ports,
            settings,
            tcp: HashMap::new(),
            udp: HashSet::new(),
            http: BTreeMap::new(),
            http_template,
            unopened,
        }
    }

    /// Whether the Gateway HTTP listener `name` is open.
    pub(super) fn http_open(&self, name: &str) -> bool {
        self.http.contains_key(name)
    }
}

/// The Gateway listeners routes are served on, by name, with their port.
pub(super) struct Referenced {
    http: BTreeMap<String, u16>,
    tcp: BTreeMap<String, u16>,
    udp: BTreeMap<String, u16>,
}

/// The Gateway listeners the Gateway routes of `snapshot` are served on. A
/// route of another provider naming such a listener opens nothing.
pub(super) fn referenced(snapshot: &RoutingSnapshot) -> Referenced {
    let mut http = BTreeMap::new();
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
            Protocol::Http => {
                if let Some(port) = gateway_http_port(name) {
                    http.insert(name.to_string(), port);
                }
            }
        }
    }
    Referenced { http, tcp, udp }
}

/// Open every Gateway listener of `wanted` (see [`referenced`]) that is not
/// open yet. One that cannot be opened is reported, in the logs and to the
/// Gateway listener status, and its routes are refused until a later reload
/// opens it.
pub(super) fn open_gateway_listeners(channels: &mut Channels, wanted: &Referenced) {
    let Channels {
        http,
        tcp,
        udp,
        gateway,
        ..
    } = channels;
    let mut unopened = UnopenedGatewayPorts::default();
    for (name, &port) in &wanted.http {
        if gateway.http.contains_key(name) {
            continue;
        }
        match open_http(gateway, http, name, port) {
            Ok(()) => info!("Opened HTTP port {} for Gateway listener `{}`", port, name),
            Err(e) => {
                error!("Could not open Gateway listener `{}`: {:#}", name, e);
                unopened.http.insert(port, format!("{e:#}"));
            }
        }
    }
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

/// Add an HTTP listener on `port` to the HTTP worker, with the main one's
/// settings. One worker serves every HTTP port.
fn open_http(
    gateway: &mut GatewayListeners,
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    name: &str,
    port: u16,
) -> anyhow::Result<()> {
    if !gateway.ports.allows_http(port) {
        anyhow::bail!("port {} is not in proxy.gateway_ports.http", port);
    }
    let address = SocketAddress::new_v4(0, 0, 0, 0, port);
    let config = HttpListenerConfig {
        address,
        ..gateway.http_template.clone()
    };
    if let Err(e) = send_to_worker(
        channel,
        format!("add-http-listener-{name}"),
        RequestType::AddHttpListener(config),
    ) {
        // An answer lost, unlike a refusal, may hide a listener added all the
        // same: take it back, so the next reload does not meet it as a
        // duplicate. Removing one never added would upset the worker.
        if e.downcast_ref::<super::channel::WorkerRejected>().is_none() {
            let _ = remove_http(channel, name, port);
        }
        anyhow::bail!("could not add the HTTP listener: {e}");
    }
    if let Err(e) = send_to_worker(
        channel,
        format!("activate-http-listener-{name}"),
        RequestType::ActivateListener(ActivateListener {
            address,
            proxy: ListenerType::Http.into(),
            from_scm: false,
            interface: None,
        }),
    ) {
        // Nothing listens: take the listener back rather than leave it.
        let _ = remove_http(channel, name, port);
        anyhow::bail!("could not bind port {port}: {e}");
    }
    gateway.http.insert(name.to_string(), port);
    Ok(())
}

/// Close an HTTP listener `open_http` added: unbind its port, then forget it.
/// Send it once per listener: the worker counts a removal even of a listener
/// it does not have.
fn remove_http(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    name: &str,
    port: u16,
) -> anyhow::Result<()> {
    let address = SocketAddress::new_v4(0, 0, 0, 0, port);
    let _ = send_to_worker(
        channel,
        format!("deactivate-http-listener-{name}"),
        RequestType::DeactivateListener(DeactivateListener {
            address,
            proxy: ListenerType::Http.into(),
            to_scm: false,
            interface: None,
        }),
    );
    send_to_worker(
        channel,
        format!("remove-http-listener-{name}"),
        RequestType::RemoveListener(RemoveListener {
            address,
            proxy: ListenerType::Http.into(),
            interface: None,
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
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
/// the routes the reload sets out to serve, not those it manages to install:
/// a reload failing on another route must not take a live listener down.
/// Called once the departed routes are removed and before
/// [`open_gateway_listeners`], so a port a listener of another protocol leaves
/// is free for the one taking it.
pub(super) fn close_unused_gateway_listeners(channels: &mut Channels, wanted: &Referenced) {
    let Channels {
        http,
        tcp,
        udp,
        gateway,
        ..
    } = channels;

    let unused: Vec<(String, u16)> = gateway
        .http
        .iter()
        .filter(|(name, _)| !wanted.http.contains_key(*name))
        .map(|(name, port)| (name.clone(), *port))
        .collect();
    for (name, port) in unused {
        // Forgotten whatever the answer: removing a listener the worker no
        // longer has would upset its accounting, so a removal is never sent
        // twice, even when its answer is lost.
        if let Err(e) = remove_http(http, &name, port) {
            warn!("Could not close Gateway listener `{}`: {}", name, e);
        }
        gateway.http.remove(&name);
        info!(
            "Closed Gateway listener `{}`: no route is served on it",
            name
        );
    }

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
    use crate::config::{gateway_http_listener, gateway_tcp_listener, gateway_udp_listener};
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
            entrypoint("g", Protocol::Http, &gateway_http_listener(8080)),
            // An HTTP name on a TCP route opens nothing.
            entrypoint("h", Protocol::Tcp, &gateway_http_listener(8081)),
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

        let Referenced { http, tcp, udp } = referenced(&snapshot);
        assert_eq!(
            http.into_iter().collect::<Vec<_>>(),
            vec![(gateway_http_listener(8080), 8080)]
        );
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
