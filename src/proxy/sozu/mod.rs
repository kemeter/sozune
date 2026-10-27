mod acme;
mod addr;
mod builders;
mod channel;
mod gateway_listeners;
mod worker;

use crate::acme::{CertAction, CertCommand};
use crate::config::{ProxyConfig, ProxyTimeouts, TcpRateLimit};
use crate::middleware::ip_allow_list::IpAllowList;
use crate::middleware::rate_limit::{RateLimitResult, RateLimiter};
use crate::middleware::{self, MiddlewareState};
use crate::model::{Backend, Entrypoint, HeaderConfig, HeaderDirection, LoadBalancer, Protocol};
use crate::proxy::backend::ProxyInputs;
use crate::proxy::health::{UnhealthyMap, probe_key};
use crate::proxy::metrics_snapshot;
use crate::proxy::tls_gate;
use acme::{
    add_certificate, register_acme_challenge_cluster, remove_certificate, replace_certificate,
};
use addr::{l4_backend_id, parse_backend_address};
use builders::{
    build_authorized_hashes, build_frontend_headers, build_header_predicates,
    build_path_and_rewrite, map_redirect_policy, map_redirect_scheme, methods_for_frontend,
};
pub(crate) use builders::{header_predicate, routes_on_query};
use channel::{send_to_worker, wait_for_worker_ready, with_reload_budget};
use gateway_listeners::{GatewayListeners, close_unused_gateway_listeners, open_gateway_listeners};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        ActivateListener, AddBackend, CloseSessions, Cluster, HardStop, ListenerType,
        LoadBalancingAlgorithms, LoadBalancingParams, PathRule, QueryMetricsOptions, RemoveBackend,
        Request, RequestHttpFrontend, RequestTcpFrontend, RequestUdpFrontend, ResponseStatus,
        RulePosition, SocketAddress, TlsVersion, UdpClusterConfig, WorkerRequest, WorkerResponse,
        request::RequestType, response_content::ContentType,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Map Sōzune's [`LoadBalancer`](crate::model::LoadBalancer) to the Sōzu
/// worker's `LoadBalancingAlgorithms` discriminant.
fn lb_algorithm(lb: LoadBalancer) -> LoadBalancingAlgorithms {
    match lb {
        LoadBalancer::RoundRobin => LoadBalancingAlgorithms::RoundRobin,
        LoadBalancer::Random => LoadBalancingAlgorithms::Random,
        LoadBalancer::PowerOfTwo => LoadBalancingAlgorithms::PowerOfTwo,
        LoadBalancer::LeastConnections => LoadBalancingAlgorithms::LeastLoaded,
        LoadBalancer::Hrw => LoadBalancingAlgorithms::Hrw,
        LoadBalancer::Maglev => LoadBalancingAlgorithms::Maglev,
    }
}

/// Snapshot of the storage at the moment of the last successful reload, keyed
/// by `cluster_id`. Used to compute the diff between two reloads.
///
/// We keep the full `Entrypoint` (not a derived subset) so that any change to
/// the entrypoint — including middleware fields like `headers`, `redirect`,
/// `auth` — triggers the diff. A subset snapshot has caused silent regressions
/// before: a new middleware field was added but the snapshot was not updated,
/// so changes to that field never produced a `RemoveHttpFrontend` and the
/// subsequent `AddHttpFrontend` was rejected by Sōzu as a duplicate, leaving
/// the old config in the worker. Full-equality on `Entrypoint` makes that
/// class of bug impossible.
type RoutingSnapshot = BTreeMap<String, Entrypoint>;

/// Whether every frontend an entrypoint declares actually landed in Sōzu.
///
/// A rolling deploy briefly runs the old and the new container under the same
/// hostname, and Sōzu answers the second `AddHttpFrontend` with "already
/// exists". Recording such an entrypoint as live is what strands a route: the
/// next reload finds it unchanged in the snapshot, skips it, and never retries
/// the add — so once the old cluster departs the hostname keeps a backend with
/// no frontend of its own. Reporting the rejection keeps the entrypoint out of
/// the snapshot, exactly like a SNI clash, so the following reload installs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrontendOutcome {
    Installed,
    Rejected,
}

/// A reload that gave up partway, carrying the entrypoints it had applied
/// before the error so the caller can keep the rest out of the snapshot. The
/// alternative — returning the error alone — is what let unsent entrypoints be
/// recorded as live and skipped by every later reload.
struct ReloadFailure {
    error: anyhow::Error,
    applied: BTreeSet<String>,
}

/// Drop from the snapshot every entrypoint a reload did not apply, so the next
/// one retries them instead of judging them unchanged and skipping them for
/// good.
fn retain_applied(snapshot: &mut RoutingSnapshot, applied: &BTreeSet<String>) {
    snapshot.retain(|cluster_id, _| applied.contains(cluster_id));
}

/// The id Sozu knows a backend by.
///
/// Sozu keys a backend on the id it was added under, so the add and the later
/// removal have to agree. Deriving it from address and port rather than from
/// the position in the list keeps that true when a rescale reorders or removes
/// entries: a backend that moves from index 2 to index 1 is still the same
/// backend, and one that leaves takes its own id with it.
///
/// `index` is accepted so callers can keep their loop variable, but it is
/// deliberately unused - it is what the old positional scheme keyed on, and
/// taking it here makes that impossible to reintroduce by accident.
fn backend_id(cluster_id: &str, _index: usize, backend: &Backend) -> String {
    format!("{cluster_id}-backend-{}-{}", backend.address, backend.port)
}

/// A backend's weight and backup flag as Sōzu takes them. Sōzu counts a
/// weight of 0 as 1 under every policy but `random`, so such a backend is sent
/// as a backup instead: it serves only when no other backend can.
fn sozu_weight(backend: &Backend) -> (Option<LoadBalancingParams>, Option<bool>) {
    if backend.weight == 0 {
        return (Some(LoadBalancingParams { weight: 1 }), Some(true));
    }
    let weight = i32::try_from(backend.weight).unwrap_or(i32::MAX);
    (Some(LoadBalancingParams { weight }), None)
}

/// Whether a cluster's backends leave it able to serve.
///
/// A frontend is all-or-nothing, but backends are not: losing one of three
/// still leaves somewhere to send traffic, and retrying the entrypoint over it
/// would re-send frontends Sōzu already accepted and refuse them as duplicates.
/// Losing every one is different — the route survives with nothing behind it
/// and answers 503 until something retries the adds.
fn backend_outcome(attempted: usize, rejected: usize) -> FrontendOutcome {
    if attempted > 0 && rejected == attempted {
        FrontendOutcome::Rejected
    } else {
        FrontendOutcome::Installed
    }
}

/// Record a rejected entrypoint so it is left out of the snapshot, which is
/// what gets its frontend retried on the next reload. Never clears an existing
/// skip: a cluster held back for another reason stays held back.
fn note_frontend_outcome(
    cluster_id: &str,
    outcome: FrontendOutcome,
    skipped: &mut BTreeSet<String>,
) {
    if outcome == FrontendOutcome::Rejected {
        warn!(
            "Frontend rejected for cluster {}: retrying on the next reload",
            cluster_id
        );
        skipped.insert(cluster_id.to_string());
    }
}

/// Command channel for a single Sōzu L4 (TCP or UDP) worker, paired with the
/// port it binds. We need the port at routing time to build the
/// `RequestTcpFrontend` / `RequestUdpFrontend`. TCP and UDP share the same shape
/// — one worker binds one listener — so they share this type.
struct L4ListenerChannel {
    port: u16,
    channel: Channel<WorkerRequest, WorkerResponse>,
}

/// L4 workers keyed by listener name (matches `proxy.tcp[].name` /
/// `proxy.udp[].name`). One worker = one listener.
type L4Channels = HashMap<String, L4ListenerChannel>;

/// Bundle of every Sōzu worker channel a reload needs to talk to, plus the
/// ports they're bound on. Grouped together because every function in the
/// reload path already has to pass all of them — this turns a 6-parameter
/// drag into one `&mut Channels`.
struct Channels {
    http: Channel<WorkerRequest, WorkerResponse>,
    https: Channel<WorkerRequest, WorkerResponse>,
    tcp: L4Channels,
    udp: L4Channels,
    http_port: u16,
    https_port: u16,
    /// Octets of the IP the HTTPS worker listens on. `0.0.0.0` normally, but
    /// `127.0.0.1` when the TLS gate fronts 443 and the worker moved to
    /// loopback. HTTPS frontends and certificates must attach to this exact
    /// address, or Sōzu rejects them ("found no listener with address …").
    https_ip: [u8; 4],
    /// Loopback port serving the ACME HTTP-01 challenge responder, when
    /// ACME is enabled. `None` disables every ACME-specific code path.
    acme_challenge_port: Option<u16>,
    /// Loopback port of the middleware server, the only backend of a route
    /// that goes through it.
    middleware_port: u16,
    /// The TCP and UDP listeners opened for Gateways, whose workers are in
    /// `tcp` and `udp` alongside the declared ones.
    gateway: GatewayListeners,
    /// How many senders added each certificate the HTTPS worker holds, by
    /// fingerprint. The worker keeps one copy however many add it, so it is
    /// only taken back when the last of them removes it.
    certificate_holders: HashMap<String, usize>,
    /// The certificates the HTTPS worker holds, by fingerprint.
    certificates: BTreeMap<String, HeldCertificate>,
}

impl Channels {
    /// The address the HTTPS worker's listener is bound to. HTTPS frontends and
    /// certificates must attach here — using `0.0.0.0` when the worker is on
    /// loopback (behind the TLS gate) makes Sōzu reject them.
    fn https_addr(&self) -> SocketAddress {
        let [a, b, c, d] = self.https_ip;
        SocketAddress::new_v4(a, b, c, d, self.https_port)
    }
}

fn snapshot_from_storage(storage: &BTreeMap<String, Entrypoint>) -> RoutingSnapshot {
    storage
        .iter()
        .filter(|(_, ep)| matches!(ep.protocol, Protocol::Http | Protocol::Tcp | Protocol::Udp))
        .map(|(id, ep)| (id.clone(), ep.clone()))
        .collect()
}

/// One pre-accept TCP forwarder to spawn: bind the public port, gate the peer
/// IP at `accept()`, and forward accepted connections to the loopback port the
/// Sōzu worker bound. Carries the raw allow-list CIDRs (compiled once in the
/// forwarder task).
struct TcpForwarderSpec {
    name: String,
    public_port: u16,
    loopback_port: u16,
    allow_list: Vec<String>,
    rate_limit: Option<TcpRateLimit>,
}

/// Grab a free loopback port by binding `127.0.0.1:0` and reading the assigned
/// port, then releasing it so the Sōzu worker can bind it. There is a tiny race
/// between release and the worker's bind; if lost, the worker's `to_tcp()` fails
/// loudly at startup rather than corrupting state — acceptable.
fn pick_loopback_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Accept loop for one TCP listener: bind the public port, drop connections
/// whose peer IP is not in the allow-list (empty list = allow all), and splice
/// accepted ones to the loopback Sōzu worker with `copy_bidirectional`.
async fn run_tcp_forwarder(spec: TcpForwarderSpec) {
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, spec.public_port)).await {
        Ok(l) => l,
        Err(e) => {
            error!(
                "TCP forwarder `{}` failed to bind 0.0.0.0:{}: {}",
                spec.name, spec.public_port, e
            );
            return;
        }
    };
    serve_tcp_forwarder(spec, &listener).await;
}

/// The accept loop of [`run_tcp_forwarder`], on a public port already bound.
async fn serve_tcp_forwarder(spec: TcpForwarderSpec, listener: &TcpListener) {
    let allow = IpAllowList::new(&spec.allow_list);
    // Anti-flood: a token-bucket conn-rate limiter, plus an exempt list of
    // source ranges that are never limited (e.g. internal Docker ranges that
    // open startup bursts). Both are None/empty when no rate_limit is set.
    let (limiter, exempt) = match &spec.rate_limit {
        Some(rl) => (
            Some(RateLimiter::with_rate(rl.max_conns, rl.per_seconds)),
            IpAllowList::new(&rl.exempt),
        ),
        None => (None, IpAllowList::new(&[])),
    };
    info!(
        "TCP forwarder `{}` listening on 0.0.0.0:{} → 127.0.0.1:{}",
        spec.name, spec.public_port, spec.loopback_port
    );
    let loopback = (Ipv4Addr::LOCALHOST, spec.loopback_port);

    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TCP forwarder `{}` accept error: {}", spec.name, e);
                continue;
            }
        };
        // Empty allow-list = allow all (never black-hole the listener).
        if !allow.is_empty() && !allow.allows(peer.ip()) {
            debug!(
                "TCP forwarder `{}` denied connection from {}",
                spec.name,
                peer.ip()
            );
            continue; // `inbound` dropped here → connection closed
        }
        // Anti-flood: drop if the source exceeds its conn-rate, unless exempt.
        if let Some(limiter) = &limiter
            && !exempt.allows(peer.ip())
            && matches!(
                limiter.check(&peer.ip().to_string()),
                RateLimitResult::Limited
            )
        {
            debug!(
                "TCP forwarder `{}` rate-limited connection from {}",
                spec.name,
                peer.ip()
            );
            continue;
        }
        let name = spec.name.clone();
        tokio::spawn(async move {
            let mut inbound = inbound;
            let mut outbound = match TcpStream::connect(loopback).await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "TCP forwarder `{}` could not reach loopback worker: {}",
                        name, e
                    );
                    return;
                }
            };
            if let Err(e) = copy_bidirectional(&mut inbound, &mut outbound).await {
                debug!("TCP forwarder `{}` connection closed: {}", name, e);
            }
        });
    }
}

/// What starting one more L4 worker takes, at startup or when a Gateway opens
/// a port of `proxy.gateway_ports`.
#[derive(Clone, Copy)]
struct WorkerSettings {
    max_buffers: usize,
    buffer_size: usize,
    startup_timeout: Duration,
    command_buffer_max_bytes: u64,
}

impl WorkerSettings {
    fn from_config(config: &ProxyConfig) -> Self {
        Self {
            max_buffers: config.max_buffers,
            buffer_size: config.buffer_size,
            startup_timeout: Duration::from_millis(config.startup_delay_ms),
            command_buffer_max_bytes: config.command_buffer_max_bytes,
        }
    }
}

fn spawn_tcp_workers(
    config: &ProxyConfig,
) -> anyhow::Result<(
    L4Channels,
    Vec<thread::JoinHandle<()>>,
    Vec<TcpForwarderSpec>,
)> {
    let mut channels: L4Channels = HashMap::new();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut forwarders: Vec<TcpForwarderSpec> = Vec::new();
    let settings = WorkerSettings::from_config(config);

    for tcp_cfg in &config.tcp {
        if channels.contains_key(&tcp_cfg.name) {
            anyhow::bail!(
                "duplicate TCP listener name `{}` in proxy.tcp",
                tcp_cfg.name
            );
        }
        if crate::config::gateway_tcp_port(&tcp_cfg.name).is_some() {
            anyhow::bail!(
                "TCP listener name `{}` in proxy.tcp is reserved for the listeners Gateways open",
                tcp_cfg.name
            );
        }
        if tcp_cfg.name == crate::config::HTTPS_PASSTHROUGH_LISTENER {
            anyhow::bail!(
                "TCP listener name `{}` in proxy.tcp is reserved for the passthrough routes of proxy.https",
                tcp_cfg.name
            );
        }
        let (channel, handle, forwarder) = spawn_tcp_worker(tcp_cfg, settings)?;
        channels.insert(tcp_cfg.name.clone(), channel);
        forwarders.push(forwarder);
        handles.push(handle);
    }

    Ok((channels, handles, forwarders))
}

/// Start the Sōzu worker of one TCP listener, on a loopback port. The returned
/// forwarder spec is what owns the public port once spawned.
fn spawn_tcp_worker(
    tcp_cfg: &crate::config::TcpListenerConfig,
    settings: WorkerSettings,
) -> anyhow::Result<(L4ListenerChannel, thread::JoinHandle<()>, TcpForwarderSpec)> {
    // Sōzu binds a private loopback port; Sōzune owns the public port via
    // the pre-accept forwarder. The TCP frontend therefore targets the
    // loopback port — stored as `L4ListenerChannel.port`, which
    // configure_tcp_entrypoint already uses to build the frontend address.
    let loopback_port = pick_loopback_port()?;
    let mut builder = ListenerBuilder::new_tcp(SocketAddress::new_v4(127, 0, 0, 1, loopback_port));
    // Bounds on the SNI preread, only consulted once an SNI-scoped frontend
    // targets this listener. Set directly: `ListenerBuilder` exposes these
    // as public fields with no `with_…` methods. `None` leaves Sōzu's
    // defaults (5s / 16 KiB) in place.
    builder.sni_preread_timeout = tcp_cfg.sni_preread_timeout;
    builder.sni_preread_max_bytes = tcp_cfg.sni_preread_max_bytes;
    apply_tcp_listener_idle_timeout(&mut builder, tcp_cfg.idle_timeout)
        .map_err(|e| anyhow::anyhow!("TCP listener `{}`: {}", tcp_cfg.name, e))?;
    let listener_config = builder.to_tcp(None).map_err(|e| {
        anyhow::anyhow!(
            "Could not create TCP listener `{}` on 127.0.0.1:{}: {}",
            tcp_cfg.name,
            loopback_port,
            e
        )
    })?;

    let (mut command, proxy_chan) = Channel::generate(1000, settings.command_buffer_max_bytes)
        .map_err(|e| {
            anyhow::anyhow!("Could not create TCP channel for `{}`: {}", tcp_cfg.name, e)
        })?;

    let listener_name = tcp_cfg.name.clone();
    let WorkerSettings {
        max_buffers,
        buffer_size,
        ..
    } = settings;
    let handle = thread::spawn(move || {
        if let Err(e) =
            worker::start_tcp_worker(listener_config, max_buffers, buffer_size, proxy_chan)
        {
            error!("TCP worker `{}` failed: {}", listener_name, e);
        }
    });

    wait_for_worker_ready(
        &mut command,
        &format!("TCP[{}]", tcp_cfg.name),
        settings.startup_timeout,
    )?;
    info!(
        "Sōzu TCP worker `{}` running on 127.0.0.1:{} (public :{})",
        tcp_cfg.name, loopback_port, tcp_cfg.listen
    );

    Ok((
        L4ListenerChannel {
            port: loopback_port,
            channel: command,
        },
        handle,
        TcpForwarderSpec {
            name: tcp_cfg.name.clone(),
            public_port: tcp_cfg.listen,
            loopback_port,
            allow_list: tcp_cfg.ip_allow_list.clone(),
            rate_limit: tcp_cfg.rate_limit.clone(),
        },
    ))
}

fn spawn_udp_workers(
    config: &ProxyConfig,
) -> anyhow::Result<(L4Channels, Vec<thread::JoinHandle<()>>)> {
    let mut channels: L4Channels = HashMap::new();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let settings = WorkerSettings::from_config(config);

    for udp_cfg in &config.udp {
        if channels.contains_key(&udp_cfg.name) {
            anyhow::bail!(
                "duplicate UDP listener name `{}` in proxy.udp",
                udp_cfg.name
            );
        }
        if crate::config::gateway_udp_port(&udp_cfg.name).is_some() {
            anyhow::bail!(
                "UDP listener name `{}` in proxy.udp is reserved for the listeners Gateways open",
                udp_cfg.name
            );
        }
        let (channel, handle) = spawn_udp_worker(&udp_cfg.name, udp_cfg.listen, settings)?;
        channels.insert(udp_cfg.name.clone(), channel);
        handles.push(handle);
    }

    Ok((channels, handles))
}

/// Start the Sōzu worker of one UDP listener, bound to `port` on every
/// interface. A worker whose listener cannot be bound is stopped again.
fn spawn_udp_worker(
    name: &str,
    port: u16,
    settings: WorkerSettings,
) -> anyhow::Result<(L4ListenerChannel, thread::JoinHandle<()>)> {
    // Build the listener config up front so a bad address fails before we
    // spawn the worker thread.
    let listener_config = ListenerBuilder::new_udp(SocketAddress::new_v4(0, 0, 0, 0, port))
        .to_udp(None)
        .map_err(|e| {
            anyhow::anyhow!(
                "Could not create UDP listener `{}` on :{}: {}",
                name,
                port,
                e
            )
        })?;

    let (mut command, proxy_chan) = Channel::generate(1000, settings.command_buffer_max_bytes)
        .map_err(|e| anyhow::anyhow!("Could not create UDP channel for `{}`: {}", name, e))?;

    let listener_name = name.to_string();
    let WorkerSettings {
        max_buffers,
        buffer_size,
        ..
    } = settings;
    // Unlike TCP/HTTP/HTTPS, `start_udp_worker` takes no listener to
    // pre-activate (Sōzu builds the `UdpProxy` internally). The bare worker
    // starts here; we install the listener over the channel below.
    let handle = thread::spawn(move || {
        if let Err(e) = worker::start_udp_worker(proxy_chan, max_buffers, buffer_size) {
            error!("UDP worker `{}` failed: {}", listener_name, e);
        }
    });

    wait_for_worker_ready(
        &mut command,
        &format!("UDP[{}]", name),
        settings.startup_timeout,
    )?;

    // Register then bind the listener (AddUdpListener records it, the socket
    // is bound by ActivateListener), the same two-step Sōzu uses natively.
    let address = SocketAddress::new_v4(0, 0, 0, 0, port);
    let installed = send_to_worker(
        &mut command,
        format!("add-udp-listener-{}", name),
        RequestType::AddUdpListener(listener_config),
    )
    .map_err(|e| anyhow::anyhow!("Failed to add UDP listener `{}`: {}", name, e))
    .and_then(|()| {
        send_to_worker(
            &mut command,
            format!("activate-udp-listener-{}", name),
            RequestType::ActivateListener(ActivateListener {
                address,
                proxy: ListenerType::Udp.into(),
                from_scm: false,
                interface: None,
            }),
        )
        .map_err(|e| anyhow::anyhow!("Failed to activate UDP listener `{}`: {}", name, e))
    });
    if let Err(e) = installed {
        // The worker runs with nothing to serve: stop it rather than leave a
        // thread behind.
        stop_worker(&mut command, name);
        return Err(e);
    }

    info!("Sōzu UDP worker `{}` running on 0.0.0.0:{}", name, port);

    Ok((
        L4ListenerChannel {
            port,
            channel: command,
        },
        handle,
    ))
}

/// Stop a worker for good: it answers, then leaves its event loop, closing its
/// listener.
fn stop_worker(channel: &mut Channel<WorkerRequest, WorkerResponse>, name: &str) {
    if let Err(e) = send_to_worker(
        channel,
        format!("stop-{}", name),
        RequestType::HardStop(HardStop {}),
    ) {
        warn!("Could not stop the worker of listener `{}`: {}", name, e);
    }
}

/// Stop every worker, on shutdown. Dropping their command channels is not
/// enough: a worker reading the close as an error on its channel, rather than
/// as a close, keeps running, and its thread is never joined.
fn stop_workers(channels: &mut Channels) {
    stop_worker(&mut channels.http, "http");
    stop_worker(&mut channels.https, "https");
    for (name, listener) in channels.tcp.iter_mut().chain(channels.udp.iter_mut()) {
        stop_worker(&mut listener.channel, name);
    }
}

pub fn start_sozu_proxy(inputs: ProxyInputs, config: &ProxyConfig) -> anyhow::Result<()> {
    let ProxyInputs {
        storage,
        shutdown_rx,
        mut reload_rx,
        mut cert_rx,
        mut metrics_poll_rx,
        metrics_store,
        acme_challenge_port,
        tls_alpn_responder_port,
        middleware_state,
        middleware_port,
        live_routes,
        unhealthy_backends,
        unopened_gateway_ports,
        plugins,
        handle,
    } = inputs;

    info!("Starting Sōzu HTTP and HTTPS workers");

    // Copy values needed for threads
    let max_buffers = config.max_buffers;
    let buffer_size = config.buffer_size;
    // Compile the trusted-proxies CIDR list once at boot; it's read by every
    // middleware-route rebuild via `handle_reload`. Shared across threads.
    let trusted_proxies = Arc::new(middleware::ip_allow_list::TrustedProxies::new(
        &config.trusted_proxies,
    ));

    // HTTP Listener
    let mut http_builder = ListenerBuilder::new_http(SocketAddress::new_v4(
        0,
        0,
        0,
        0,
        config.http.listen_address,
    ));
    apply_listener_error_pages(&mut http_builder, &config.http.error_pages, "HTTP");
    apply_listener_timeouts(&mut http_builder, &config.timeouts)?;
    let http_listener = http_builder
        .to_http(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTP listener: {}", e))?;
    // What a Gateway HTTP listener on a port of its own is built from.
    let http_listener_template = http_listener.clone();

    // With the TLS gate active (TLS-ALPN-01, or passthrough on the HTTPS
    // port), the HTTPS worker steps off the public 443 onto loopback and the
    // gate owns 443, prereading each connection's ClientHello. Bound to
    // 127.0.0.1 so nothing but the gate can reach it. Without the gate, the
    // worker binds the public 443 directly — the unchanged default.
    let gated = tls_alpn_responder_port.is_some() || config.https.passthrough;
    let (https_bind_ip, https_bind_port) = if gated {
        (Ipv4Addr::LOCALHOST, pick_loopback_port()?)
    } else {
        (Ipv4Addr::UNSPECIFIED, config.https.listen_address)
    };
    let https_bind = https_bind_ip.octets();
    let mut https_builder = ListenerBuilder::new_https(SocketAddress::new_v4(
        https_bind[0],
        https_bind[1],
        https_bind[2],
        https_bind[3],
        https_bind_port,
    ));
    apply_listener_error_pages(&mut https_builder, &config.https.error_pages, "HTTPS");
    apply_listener_timeouts(&mut https_builder, &config.timeouts)?;
    apply_listener_http2(&mut https_builder, &config.https.http2);
    apply_listener_tls_options(&mut https_builder, &config.https.tls)
        .map_err(|e| anyhow::anyhow!("Invalid HTTPS TLS options: {e}"))?;
    // Behind the gate the worker only ever sees loopback connections, losing the
    // real client IP. So the gate prepends a PROXY-v2 header carrying the true
    // peer, and the worker is told to expect it — otherwise client-IP matching,
    // allow-lists and access logs would all read 127.0.0.1.
    if gated {
        https_builder.with_expect_proxy(true);
    }
    let https_listener = https_builder
        .to_tls(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTPS listener: {}", e))?;
    check_client_crls_current(&https_listener, unix_now())?;
    // What a Gateway HTTPS listener on a port of its own is built from. It
    // binds its port itself, never behind the gate.
    let https_listener_template = sozu_command_lib::proto::command::HttpsListenerConfig {
        expect_proxy: false,
        ..https_listener.clone()
    };

    // Create communication channels
    let command_buffer_max_bytes = config.command_buffer_max_bytes;
    let (mut command_channel, proxy_channel) = Channel::generate(1000, command_buffer_max_bytes)
        .map_err(|e| anyhow::anyhow!("Could not create HTTP channel: {}", e))?;
    let (mut command_channel_https, proxy_channel_https) =
        Channel::generate(1000, command_buffer_max_bytes)
            .map_err(|e| anyhow::anyhow!("Could not create HTTPS channel: {}", e))?;

    let worker_http_handle = thread::spawn(move || {
        if let Err(e) =
            worker::start_http_worker(http_listener, proxy_channel, max_buffers, buffer_size)
        {
            error!("HTTP server failed: {:#}", e);
        }
    });

    let worker_https_handle = thread::spawn(move || {
        if let Err(e) = worker::start_https_worker(
            https_listener,
            proxy_channel_https,
            max_buffers,
            buffer_size,
        ) {
            error!("HTTPS server failed: {:#}", e);
        }
    });

    // Wait for workers to be ready by sending a Status probe
    let timeout = Duration::from_millis(config.startup_delay_ms);
    wait_for_worker_ready(&mut command_channel, "HTTP", timeout)?;
    wait_for_worker_ready(&mut command_channel_https, "HTTPS", timeout)?;

    // Spawn one Sōzu TCP worker per declared listener.
    let (mut tcp_channels, mut tcp_worker_handles, tcp_forwarders) = spawn_tcp_workers(config)?;
    // The passthrough routes of the HTTPS port: a TCP listener the gate
    // splices to, with no public port of its own.
    let passthrough = if config.https.passthrough {
        // A ClientHello the gate read whole, the worker reads too: up to its
        // buffer, which bounds its preread whatever the setting.
        let max_hello_bytes = tls_gate::PREREAD_MAX_BYTES.min(config.buffer_size);
        let listener = crate::config::TcpListenerConfig {
            name: crate::config::HTTPS_PASSTHROUGH_LISTENER.to_string(),
            listen: config.https.listen_address,
            ip_allow_list: Vec::new(),
            rate_limit: None,
            sni_preread_timeout: None,
            sni_preread_max_bytes: u32::try_from(max_hello_bytes).ok(),
            idle_timeout: None,
        };
        let (channel, handle, forwarder) =
            spawn_tcp_worker(&listener, WorkerSettings::from_config(config))?;
        tcp_channels.insert(listener.name, channel);
        tcp_worker_handles.push(handle);
        Some(tls_gate::Passthrough {
            loopback_port: forwarder.loopback_port,
            max_hello_bytes,
            hosts: Arc::new(RwLock::new(Vec::new())),
        })
    } else {
        None
    };
    let (udp_channels, udp_worker_handles) = spawn_udp_workers(config)?;

    // Spawn one pre-accept forwarder per TCP listener: it owns the public port,
    // gates the peer IP against the listener's allow-list, and forwards to the
    // loopback Sōzu worker. Done here, before `handle` is moved into the reload
    // thread below.
    for spec in tcp_forwarders {
        handle.spawn(run_tcp_forwarder(spec));
    }

    // Initial configuration will be handled by provider reload signals
    info!("Waiting for providers to populate configuration");

    info!(
        "Sōzu HTTP worker running on 0.0.0.0:{}",
        config.http.listen_address
    );
    if gated {
        info!(
            "Sōzu HTTPS worker running on 127.0.0.1:{https_bind_port} (behind the TLS gate on :{})",
            config.https.listen_address
        );
    } else {
        info!(
            "Sōzu HTTPS worker running on 0.0.0.0:{}",
            config.https.listen_address
        );
    }

    // Front 443 with the TLS gate: `acme-tls/1` handshakes go to the
    // responder, those naming a passthrough route to its listener, everything
    // else to the HTTPS worker now on `https_bind_port`. Bind synchronously so
    // a taken 443 fails startup here — the worker has already moved to
    // loopback, so a silent gate failure would leave 443 unserved.
    if gated {
        let public_port = config.https.listen_address;
        let listener = handle.block_on(tls_gate::bind(public_port))?;
        let backends = tls_gate::GateBackends {
            https_loopback_port: https_bind_port,
            responder_port: tls_alpn_responder_port,
            passthrough: passthrough.clone(),
        };
        handle.spawn(async move {
            tls_gate::run(listener, public_port, backends).await;
        });
    }

    // Register ACME challenge cluster if enabled (routes added per-hostname during reload)
    if let Some(challenge_port) = acme_challenge_port
        && let Err(e) = register_acme_challenge_cluster(&mut command_channel, challenge_port)
    {
        error!("Failed to register ACME challenge cluster: {}", e);
    }

    // Start configuration reload handler
    let storage_reload = Arc::clone(&storage);
    let trusted_proxies_reload = Arc::clone(&trusted_proxies);
    let client_certificate_redirect = client_certificate_redirect_port(config);
    let http_port = config.http.listen_address;
    // The port the HTTPS worker actually listens on: the loopback port behind
    // the gate, or the public 443. Certificates and HTTPS frontends attach to
    // this listener, so they must use the worker's real port, not the public
    // one the gate fronts.
    let https_port = https_bind_port;
    let cluster_setup_delay_ms = config.cluster_setup_delay_ms;
    let reload_debounce = Duration::from_millis(config.reload_debounce_ms);
    let metrics_poll_timeout = Duration::from_millis(config.metrics_poll_timeout_ms);

    // Now that every worker is up and the static ACME cluster has been
    // registered, fold the three command channels into a single `Channels`
    // and hand it to the reload thread by value. Splitting them again here
    // would just push the 6-parameter mess further down.
    let mut channels = Channels {
        http: command_channel,
        https: command_channel_https,
        tcp: tcp_channels,
        udp: udp_channels,
        http_port,
        https_port,
        https_ip: https_bind_ip.octets(),
        acme_challenge_port,
        middleware_port,
        gateway: GatewayListeners::new(
            config.gateway_ports.clone(),
            WorkerSettings::from_config(config),
            unopened_gateway_ports,
            http_listener_template,
            https_listener_template,
        ),
        certificate_holders: HashMap::new(),
        certificates: BTreeMap::new(),
    };

    let reload_handle = thread::spawn(move || {
        handle.block_on(async {
            let mut shutdown_rx = shutdown_rx;
            let mut cert_rx_open = true;
            let mut previous_snapshot: RoutingSnapshot = BTreeMap::new();

            // Debounce-then-apply loop. A burst of reload signals (e.g. from
            // `docker compose up` starting many containers at once) is
            // coalesced into a single `handle_reload` call once the channel
            // has been silent for `reload_debounce`. Each new signal during
            // the window resets the silence timer, so we only ever read the
            // storage snapshot when it has stopped changing. Mirrors
            // Traefik's `providersThrottleDuration` semantics.
            //
            // Cert commands take the same path: applying the cert immediately
            // (so the HTTPS worker has the material) and then folding the
            // follow-up reload into the same debounce window.
            'outer: loop {
                // Wait for the first event of a new burst.
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        info!("Shutdown signal received in reload handler");
                        break 'outer;
                    }
                    reload = reload_rx.recv() => match reload {
                        Some(()) => {}
                        None => {
                            debug!("Reload channel closed");
                            break 'outer;
                        }
                    },
                    cert_cmd = cert_rx.recv(), if cert_rx_open => match cert_cmd {
                        Some(cmd) => {
                            if !apply_certificate(&mut channels, cmd) {
                                continue 'outer;
                            }
                        }
                        None => {
                            debug!("Cert channel closed, falling back to reload-only mode");
                            cert_rx_open = false;
                            continue 'outer;
                        }
                    },
                    poll = metrics_poll_rx.recv() => match poll {
                        Some(()) => {
                            // Drain coalesced pings so we only run one query
                            // per wakeup even if the poller fires fast.
                            while metrics_poll_rx.try_recv().is_ok() {}

                            let mut merged = std::collections::BTreeMap::new();
                            for (proxy_metrics, name) in [
                                (
                                    poll_worker_metrics(
                                        &mut channels.http,
                                        "HTTP",
                                        metrics_poll_timeout,
                                    ),
                                    "HTTP",
                                ),
                                (
                                    poll_worker_metrics(
                                        &mut channels.https,
                                        "HTTPS",
                                        metrics_poll_timeout,
                                    ),
                                    "HTTPS",
                                ),
                            ] {
                                debug!("metrics: {} worker returned {} keys", name, proxy_metrics.len());
                                for (k, v) in proxy_metrics {
                                    if let Some(value) = metrics_snapshot::convert(&v) {
                                        metrics_snapshot::merge_into(&mut merged, k, value);
                                    }
                                }
                            }

                            match metrics_store.write() {
                                Ok(mut snap) => {
                                    snap.proxy = merged;
                                    snap.last_poll_unix = metrics_snapshot::now_unix();
                                }
                                Err(e) => error!("metrics: snapshot lock poisoned: {}", e),
                            }

                            continue 'outer;
                        }
                        None => {
                            debug!("Metrics poll channel closed");
                            continue 'outer;
                        }
                    },
                }

                // Drain anything else already queued, then enter the silence
                // wait. `try_recv` collapses an in-flight burst without an
                // extra wakeup per signal.
                while reload_rx.try_recv().is_ok() {}
                let mut coalesced: usize = 1;
                let mut deadline = tokio::time::Instant::now() + reload_debounce;

                if !reload_debounce.is_zero() {
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut shutdown_rx => {
                                info!("Shutdown signal received in reload handler");
                                break 'outer;
                            }
                            _ = tokio::time::sleep_until(deadline) => break,
                            reload = reload_rx.recv() => match reload {
                                Some(()) => {
                                    coalesced += 1;
                                    while reload_rx.try_recv().is_ok() {
                                        coalesced += 1;
                                    }
                                    deadline = tokio::time::Instant::now() + reload_debounce;
                                }
                                None => break,
                            },
                            cert_cmd = cert_rx.recv(), if cert_rx_open => match cert_cmd {
                                Some(cmd) => {
                                    apply_certificate(&mut channels, cmd);
                                    deadline = tokio::time::Instant::now() + reload_debounce;
                                }
                                None => {
                                    debug!("Cert channel closed, falling back to reload-only mode");
                                    cert_rx_open = false;
                                }
                            },
                        }
                    }
                }

                if coalesced > 1 {
                    debug!("Coalesced {} reload signals into a single apply", coalesced);
                }

                previous_snapshot = handle_reload(
                    &storage_reload,
                    &mut channels,
                    cluster_setup_delay_ms,
                    &previous_snapshot,
                    &middleware_state,
                    middleware_port,
                    &plugins,
                    &trusted_proxies_reload,
                    client_certificate_redirect,
                    &unhealthy_backends,
                );
                match live_routes.write() {
                    Ok(mut live) => *live = previous_snapshot.clone(),
                    Err(e) => error!(
                        "internal state corrupted (live routes), restart required: {}",
                        e
                    ),
                }
                if let Some(passthrough) = &passthrough {
                    match passthrough.hosts.write() {
                        Ok(mut hosts) => *hosts = passthrough_hosts(&previous_snapshot),
                        Err(e) => error!(
                            "internal state corrupted (passthrough hosts), restart required: {}",
                            e
                        ),
                    }
                }
            }
            stop_workers(&mut channels);
        });
    });

    // Wait for worker threads with error handling
    if let Err(e) = worker_http_handle.join() {
        error!("HTTP worker thread panicked: {:?}", e);
        return Err(anyhow::anyhow!("HTTP worker failed"));
    }

    if let Err(e) = worker_https_handle.join() {
        error!("HTTPS worker thread panicked: {:?}", e);
        return Err(anyhow::anyhow!("HTTPS worker failed"));
    }

    for handle in tcp_worker_handles {
        if let Err(e) = handle.join() {
            error!("TCP worker thread panicked: {:?}", e);
        }
    }

    for handle in udp_worker_handles {
        if let Err(e) = handle.join() {
            error!("UDP worker thread panicked: {:?}", e);
        }
    }

    if let Err(e) = reload_handle.join() {
        error!("Reload handler thread panicked: {:?}", e);
    }

    info!("All Sōzu workers stopped gracefully");
    Ok(())
}

/// A certificate the HTTPS worker holds, as it was handed over: what a
/// Gateway HTTPS listener opened later is given too.
pub(super) struct HeldCertificate {
    pub(super) names: Vec<String>,
    cert_pem: String,
    chain: Vec<String>,
    key_pem: String,
}

impl HeldCertificate {
    /// Hand it to the HTTPS listener at `address`.
    pub(super) fn add(
        &self,
        channel: &mut Channel<WorkerRequest, WorkerResponse>,
        address: SocketAddress,
    ) -> anyhow::Result<()> {
        add_certificate(
            channel,
            address,
            &self.cert_pem,
            &self.chain,
            &self.key_pem,
            &self.names,
        )
    }

    /// Take it back from the HTTPS listener at `address`.
    pub(super) fn remove(
        &self,
        channel: &mut Channel<WorkerRequest, WorkerResponse>,
        address: SocketAddress,
    ) -> anyhow::Result<()> {
        remove_certificate(channel, address, &self.cert_pem)
    }
}

/// The SNI patterns of the live routes on the passthrough listener of the
/// HTTPS port, which the TLS gate sends there.
fn passthrough_hosts(live: &RoutingSnapshot) -> Vec<String> {
    let mut hosts: Vec<String> = live
        .values()
        .filter(|ep| {
            ep.protocol == Protocol::Tcp
                && ep.config.entrypoint.as_deref()
                    == Some(crate::config::HTTPS_PASSTHROUGH_LISTENER)
        })
        .filter_map(|ep| ep.config.sni.as_deref().map(str::to_ascii_lowercase))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Hand a certificate to the HTTPS worker, or take one back. Returns whether
/// the worker did it on the main HTTPS listener; the Gateway HTTPS listeners
/// follow it.
fn apply_certificate(channels: &mut Channels, cmd: CertCommand) -> bool {
    let https_addr = channels.https_addr();
    let gateway_addrs = channels.gateway.https_addresses();
    let names = cmd.names.join(", ");
    let held = HeldCertificate {
        names: cmd.names.clone(),
        cert_pem: cmd.cert_pem.clone(),
        chain: cmd.chain.clone(),
        key_pem: cmd.key_pem.clone(),
    };
    let fingerprint = crate::acme::certificate_fingerprint(&cmd.cert_pem).ok();
    let applied = match cmd.action {
        CertAction::Add => {
            info!("Adding certificate for {}", names);
            // Every listener, or the sender tries again: adding a
            // certificate a listener holds already is a no-op.
            let mut added = held.add(&mut channels.https, https_addr);
            if added.is_ok() {
                for address in gateway_addrs {
                    if let Err(e) = held.add(&mut channels.https, address) {
                        added = Err(e.context(format!("on port {}", address.port)));
                    }
                }
            }
            added
        }
        CertAction::Replace => {
            info!("Replacing certificate for {}", names);
            let mut replaced = replace_certificate(
                &mut channels.https,
                https_addr,
                &cmd.cert_pem,
                &cmd.chain,
                &cmd.key_pem,
                &cmd.names,
            );
            if replaced.is_ok() {
                for address in gateway_addrs {
                    if let Err(e) = replace_certificate(
                        &mut channels.https,
                        address,
                        &cmd.cert_pem,
                        &cmd.chain,
                        &cmd.key_pem,
                        &cmd.names,
                    ) {
                        replaced = Err(e.context(format!("on port {}", address.port)));
                    }
                }
            }
            replaced
        }
        CertAction::Remove => {
            if fingerprint
                .as_deref()
                .is_some_and(|f| !release_certificate(&mut channels.certificate_holders, f))
            {
                debug!("Certificate for {} is still added by another sender", names);
                Ok(())
            } else {
                info!("Removing certificate for {}", names);
                // From every listener before its last holder lets go: a
                // removal retried after a failure must still find it held,
                // and removing one a listener no longer has is a no-op.
                let mut removed =
                    remove_certificate(&mut channels.https, https_addr, &cmd.cert_pem);
                if removed.is_ok() {
                    for address in gateway_addrs {
                        if let Err(e) =
                            remove_certificate(&mut channels.https, address, &cmd.cert_pem)
                        {
                            removed = Err(e.context(format!("on port {}", address.port)));
                        }
                    }
                }
                if removed.is_ok()
                    && let Some(fingerprint) = &fingerprint
                {
                    channels.certificate_holders.remove(fingerprint);
                    channels.certificates.remove(fingerprint);
                }
                removed
            }
        }
    };
    if applied.is_ok()
        && cmd.action != CertAction::Remove
        && let Some(fingerprint) = fingerprint
    {
        if cmd.action == CertAction::Add {
            *channels
                .certificate_holders
                .entry(fingerprint.clone())
                .or_default() += 1;
            // The worker keeps the first material added for a leaf: another
            // chain for it only lands through a replacement.
            channels.certificates.entry(fingerprint).or_insert(held);
        } else {
            channels.certificates.insert(fingerprint, held);
        }
    }

    // The sender wrote the certificate to disk before handing it over, so
    // only this answer tells it whether the hostname can actually serve TLS.
    if let Some(accepted) = cmd.accepted {
        let _ = accepted.send(applied.is_ok());
    }
    if let Err(e) = &applied {
        let action = match cmd.action {
            CertAction::Add => "add",
            CertAction::Replace => "replace",
            CertAction::Remove => "remove",
        };
        error!("Failed to {} certificate for {}: {}", action, names, e);
    }
    applied.is_ok()
}

/// Count one sender fewer for the certificate `fingerprint`, unless it is
/// the last one. Returns whether it is, so the worker should drop it — also
/// when none was counted. The last holder stays counted until the worker
/// confirms.
fn release_certificate(holders: &mut HashMap<String, usize>, fingerprint: &str) -> bool {
    match holders.get_mut(fingerprint) {
        Some(count) if *count > 1 => {
            *count -= 1;
            false
        }
        _ => true,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_reload(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    channels: &mut Channels,
    cluster_setup_delay_ms: u64,
    previous_snapshot: &RoutingSnapshot,
    middleware_state: &MiddlewareState,
    middleware_port: u16,
    plugins: &middleware::PluginRegistry,
    trusted_proxies: &middleware::ip_allow_list::TrustedProxies,
    client_certificate_redirect: Option<u16>,
    unhealthy: &RwLock<UnhealthyMap>,
) -> RoutingSnapshot {
    info!("Received configuration reload request");
    // A poisoned lock leaves every backend in rotation, as before health
    // checks took any out.
    let unhealthy = unhealthy.read().map(|u| u.clone()).unwrap_or_default();
    let storage_read = match storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!(
                "internal state corrupted (configuration store), restart required: {}",
                e
            );
            return previous_snapshot.clone();
        }
    };

    let (storage_read, _) =
        routes_as_applied(&storage_read, client_certificate_redirect, &unhealthy);
    let mut current_snapshot = snapshot_from_storage(&storage_read);
    let wanted_gateway_listeners = gateway_listeners::referenced(&current_snapshot);

    // Run the reload under a shared consecutive-timeout counter. A worker that
    // goes silent is given up on after a few failed acks, so it can't stall the
    // event loop for PER_COMMAND_TIMEOUT × (number of commands). A healthy reload
    // of hundreds of entrypoints is unaffected: every ack resets the counter, so
    // only a genuinely unresponsive worker trips the short-circuit.
    with_reload_budget(|| {
        let departed = apply_routing_diff(previous_snapshot, &current_snapshot, channels);
        // Once the departed routes are off them, and before any route is
        // installed: the listeners no route wants let their ports go, so one
        // of another protocol can take them.
        close_unused_gateway_listeners(channels, &wanted_gateway_listeners);
        open_gateway_listeners(channels, &wanted_gateway_listeners);

        // Update middleware route table
        update_middleware_routes(&storage_read, middleware_state, plugins, trusted_proxies);

        let outcome = configure_sozu_routing(
            channels,
            &storage_read,
            previous_snapshot,
            cluster_setup_delay_ms,
            middleware_port,
        );
        // Once the changed routes are back, so a client that reconnects at
        // once reaches them instead of a route being reinstalled. A route the
        // reload did not install keeps its sessions: they are all it has left.
        close_departed_sessions(channels, &reinstalled_only(departed, &outcome));
        match outcome {
            Ok(skipped) => {
                // Entrypoints we chose not to send must not be recorded as
                // live, or the next reload would see them unchanged and never
                // apply them — leaving the route dead even after the operator
                // fixes what blocked it.
                for cluster_id in &skipped {
                    current_snapshot.remove(cluster_id);
                }
                info!("Configuration reloaded successfully");
            }
            Err(ReloadFailure { error, applied }) => {
                // The reload stopped partway. Only what it got through was
                // sent to a worker; recording the rest as live would hide it
                // from every later reload, which is how one bad backend
                // address takes every lower-priority route down with it.
                let held_back = current_snapshot.len().saturating_sub(applied.len());
                retain_applied(&mut current_snapshot, &applied);
                error!(
                    "Failed to reload configuration: {}. {} entrypoint(s) were not applied and will be retried",
                    error, held_back
                );
            }
        }
    });

    current_snapshot
}

/// The public HTTPS port when client certificates are `required` on the
/// HTTPS listener, `None` otherwise.
pub(crate) fn client_certificate_redirect_port(config: &ProxyConfig) -> Option<u16> {
    let client_auth = config.https.tls.client_auth.as_ref()?;
    (client_auth.mode == crate::config::ClientAuthMode::Required)
        .then_some(config.https.listen_address)
}

/// With client certificates `required` on the HTTPS listener (`https_port` is
/// then its public port), a TLS route redirects its plain HTTP requests to
/// HTTPS: served on both listeners, it would hand its backend to any client
/// that skips the certificate by using port 80. A route that already
/// redirects keeps its own port; routes without TLS are not served over HTTPS
/// and stay as they are. The proxy and the route resolver both apply it, so
/// they compare the same routes.
pub(crate) fn require_https_for_client_certificates(
    storage: &BTreeMap<String, Entrypoint>,
    https_port: Option<u16>,
) -> std::borrow::Cow<'_, BTreeMap<String, Entrypoint>> {
    let Some(https_port) = https_port else {
        return std::borrow::Cow::Borrowed(storage);
    };
    let mut routes = storage.clone();
    for entrypoint in routes.values_mut() {
        if entrypoint.protocol == Protocol::Http
            && entrypoint.config.tls
            && !entrypoint.config.https_redirect
        {
            entrypoint.config.https_redirect = true;
            entrypoint.config.https_redirect_port = Some(https_port);
        }
    }
    std::borrow::Cow::Owned(routes)
}

/// The backends a health check took out of their routes, by route id.
pub(crate) type Evicted = BTreeMap<String, Vec<Backend>>;

/// `storage` without the backends the health checker found unhealthy, and
/// those backends by route. A route whose backends are all unhealthy keeps
/// them all: one with nothing left would refuse every request, and a probe
/// can be wrong. Backups (weight 0) stay when they are healthy, so they take
/// over primaries that are not.
pub(crate) fn without_unhealthy_backends(
    storage: &BTreeMap<String, Entrypoint>,
    unhealthy: &UnhealthyMap,
) -> (BTreeMap<String, Entrypoint>, Evicted) {
    let mut routes = storage.clone();
    let mut evicted = Evicted::new();
    if unhealthy.is_empty() {
        return (routes, evicted);
    }
    for (id, entrypoint) in routes.iter_mut() {
        let down = evicted_backends(entrypoint, unhealthy);
        if down.is_empty() {
            if entrypoint.backends.iter().any(|b| {
                unhealthy.contains_key(&probe_key(b, entrypoint.config.health_check.as_ref()))
            }) {
                warn!(
                    "every backend of route `{}` is failing its health check; keeping them all",
                    entrypoint.name
                );
            }
            continue;
        }
        entrypoint.backends.retain(|b| !down.contains(b));
        evicted.insert(id.clone(), down);
    }
    (routes, evicted)
}

/// The backends of `entrypoint` its health check takes out of rotation: the
/// unhealthy ones, unless every backend is (then none, see
/// [`without_unhealthy_backends`]). UDP backends are not probed.
pub(crate) fn evicted_backends(entrypoint: &Entrypoint, unhealthy: &UnhealthyMap) -> Vec<Backend> {
    if entrypoint.protocol == Protocol::Udp {
        return Vec::new();
    }
    let down: Vec<Backend> = entrypoint
        .backends
        .iter()
        .filter(|backend| {
            unhealthy.contains_key(&probe_key(backend, entrypoint.config.health_check.as_ref()))
        })
        .cloned()
        .collect();
    if down.len() == entrypoint.backends.len() {
        return Vec::new();
    }
    down
}

/// The backends of each live route that its stored version has and Sōzu was
/// not given: those the last reload took out of rotation. Read from what was
/// applied, not from the health checker, whose state can be newer.
pub(crate) fn evicted_from_live(
    stored: &BTreeMap<String, Entrypoint>,
    live: &BTreeMap<String, Entrypoint>,
) -> Evicted {
    live.iter()
        .filter_map(|(id, applied)| {
            let missing: Vec<Backend> = stored
                .get(id)?
                .backends
                .iter()
                // By address: a weight the reload has not applied yet is not
                // an eviction.
                .filter(|b| {
                    !applied
                        .backends
                        .iter()
                        .any(|a| a.address == b.address && a.port == b.port)
                })
                .cloned()
                .collect();
            (!missing.is_empty()).then(|| (id.clone(), missing))
        })
        .collect()
}

/// The routes as the proxy applies them: TLS routes redirected to HTTPS when
/// client certificates are required, without their unhealthy backends. The
/// reload and the route resolver both build them here, so they compare the
/// same routes.
pub(crate) fn routes_as_applied(
    storage: &BTreeMap<String, Entrypoint>,
    client_certificate_https_port: Option<u16>,
    unhealthy: &UnhealthyMap,
) -> (BTreeMap<String, Entrypoint>, Evicted) {
    without_unhealthy_backends(
        &require_https_for_client_certificates(storage, client_certificate_https_port),
        unhealthy,
    )
}

/// Rebuild the middleware route table from current storage
fn update_middleware_routes(
    storage: &BTreeMap<String, Entrypoint>,
    middleware_state: &MiddlewareState,
    plugins: &middleware::PluginRegistry,
    trusted_proxies: &middleware::ip_allow_list::TrustedProxies,
) {
    let mut table = match middleware_state.write() {
        Ok(guard) => guard,
        Err(e) => {
            error!(
                "internal state corrupted (middleware routing), restart required: {}",
                e
            );
            return;
        }
    };

    table.clear();
    fill_middleware_table(&mut table, storage, plugins, trusted_proxies);
}

/// Adds every HTTP route that goes through the middleware to `table`. Shared
/// by the reload and by the route resolver, which builds a table of its own to
/// see which route the middleware server would pick.
pub(crate) fn fill_middleware_table(
    table: &mut middleware::MiddlewareRouteTable,
    storage: &BTreeMap<String, Entrypoint>,
    plugins: &middleware::PluginRegistry,
    trusted_proxies: &middleware::ip_allow_list::TrustedProxies,
) {
    let forward_auth_client = middleware::build_forward_auth_client();

    // Same order as the frontends: a wildcard or regex hostname is resolved by
    // trying patterns in turn, and the first to match must be the route Sōzu
    // picked.
    for (cluster_id, entrypoint) in routing_order(storage) {
        if !matches!(entrypoint.protocol, Protocol::Http) {
            continue;
        }
        if middleware::needs_middleware(&entrypoint.config) {
            let route = middleware::build_middleware_route(
                cluster_id,
                &entrypoint.config,
                &entrypoint.backends,
                &forward_auth_client,
                plugins,
                trusted_proxies,
            );
            debug!(
                "Middleware route for {} (hosts: {:?}): {} middleware(s)",
                cluster_id,
                entrypoint.config.hostnames,
                route.middlewares.len(),
            );
            table.update_routes_for_entrypoint(
                &entrypoint.config.hostnames,
                entrypoint.config.path.as_ref(),
                route,
            );
        }
    }
}

/// Names of TCP entrypoints Sōzu would reject, grouped per listener.
///
/// Sōzu forbids a TCP listener from carrying both SNI-scoped and catch-all
/// frontends: the first shape wins and the rest are refused. It reports that
/// over the command socket, where `configure_tcp_entrypoint` can only log it
/// at `debug!` — invisible to the operator, who just sees a route that never
/// matches. So we catch the clash here, while we still have every entrypoint
/// in view, and name the offenders.
///
/// Returns, per listener, the entrypoints on the minority side — the ones to
/// change — as `(cluster_id, name)` pairs. Ties break toward reporting the
/// catch-all ones, since adding an `sni` label is the usual fix.
///
/// Callers must *skip* these entrypoints rather than merely warn: sending a
/// frontend Sōzu will refuse, while still recording it as applied, leaves the
/// route permanently unreachable — the next reload sees it unchanged against
/// the snapshot and never retries it, even once the clash is resolved.
fn tcp_sni_mode_clashes(
    storage: &BTreeMap<String, Entrypoint>,
) -> BTreeMap<String, Vec<(String, String)>> {
    type Side<'a> = Vec<(&'a str, &'a str)>;
    let mut per_listener: BTreeMap<&str, (Side, Side)> = BTreeMap::new();

    for (cluster_id, entrypoint) in storage {
        if !matches!(entrypoint.protocol, Protocol::Tcp) {
            continue;
        }
        let Some(listener) = entrypoint.config.entrypoint.as_deref() else {
            continue;
        };
        let (with_sni, without_sni) = per_listener.entry(listener).or_default();
        let side = match entrypoint.config.sni {
            Some(_) => with_sni,
            None => without_sni,
        };
        side.push((cluster_id.as_str(), entrypoint.name.as_str()));
    }

    per_listener
        .into_iter()
        .filter(|(_, (with, without))| !with.is_empty() && !without.is_empty())
        .map(|(listener, (with, without))| {
            let minority = if with.len() < without.len() {
                with
            } else {
                without
            };
            (
                listener.to_string(),
                minority
                    .into_iter()
                    .map(|(id, name)| (id.to_string(), name.to_string()))
                    .collect(),
            )
        })
        .collect()
}

/// Cluster IDs to leave out of this reload because their listener mixes
/// SNI-routed and catch-all frontends. Logs one line per affected listener.
fn skipped_on_sni_clash(storage: &BTreeMap<String, Entrypoint>) -> BTreeSet<String> {
    let mut skipped = BTreeSet::new();

    for (listener, offenders) in tcp_sni_mode_clashes(storage) {
        error!(
            "TCP listener `{}` mixes SNI-routed and catch-all entrypoints, which Sōzu refuses. \
             Skipping {} for now — give them an `sni` of their own, or move them to a \
             separate listener, and they will be applied on the next reload.",
            listener,
            offenders
                .iter()
                .map(|(_, name)| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        skipped.extend(offenders.into_iter().map(|(id, _)| id));
    }

    skipped
}

/// The order Sōzu matches routes in: priority descending, then the more
/// specific route first, then cluster id. Sōzu checks its Pre rules in
/// insertion order, first match wins, so this is both the order frontends are
/// sent in and the order anything reproducing Sōzu's choice has to try them
/// in.
pub(crate) fn routing_order(storage: &BTreeMap<String, Entrypoint>) -> Vec<(&String, &Entrypoint)> {
    let mut ordered: Vec<(&String, &Entrypoint)> = storage.iter().collect();
    // Stable sort over the BTreeMap's id order: ties keep their ids ascending.
    ordered.sort_by_key(|(_, ep)| (std::cmp::Reverse(ep.config.priority), specificity(ep)));
    ordered
}

/// A hostname's or a path's rank: its kind, then its length, the longest
/// first.
type Rank = (u8, std::cmp::Reverse<usize>);

/// How specific a route is, as [`specificity`] ranks it.
type Specificity = (
    Rank,
    bool,
    Rank,
    bool,
    std::cmp::Reverse<usize>,
    std::cmp::Reverse<usize>,
);

/// Whether `a` is tried before `b` for being more specific, their priority
/// being equal.
pub(crate) fn more_specific(a: &Entrypoint, b: &Entrypoint) -> bool {
    specificity(a) < specificity(b)
}

/// How specific a route is, the most specific first: by hostname, then path,
/// then a route on methods before one on any method, then the more header
/// conditions Sōzu routes on, then the more query conditions it routes on.
/// Conditions left to the middleware do not count: it answers `404` when they
/// fail, so trying such a route first would take the requests of a wider one.
fn specificity(ep: &Entrypoint) -> Specificity {
    let header_predicates = ep
        .config
        .match_headers
        .iter()
        .filter(|condition| header_predicate(condition).is_some())
        .count();
    (
        host_specificity(&ep.config.hostnames),
        // On its host, a route keeping it from a Gateway listener it is not
        // attached to comes after every route of that listener, whatever
        // their paths.
        ep.config.answer == Some(crate::model::FixedAnswer::OtherListener),
        path_specificity(ep.config.path.as_ref()),
        ep.config.methods.is_empty(),
        std::cmp::Reverse(header_predicates),
        std::cmp::Reverse(if routes_on_query(&ep.config) {
            ep.config.match_query.len()
        } else {
            0
        }),
    )
}

/// How specific a route's hostnames are, the most specific first: an exact
/// name, then a regex, then a wildcard (the longer, the more specific), then
/// any host (`*`, or no hostname at all). A route is as specific as its most
/// specific hostname.
fn host_specificity(hostnames: &[String]) -> Rank {
    hostnames
        .iter()
        .map(|h| {
            if let Some(suffix) = h.strip_prefix(crate::model::ANY_LABELS_PREFIX) {
                // Ranked as the `*.` wildcard it stands for.
                return (2, std::cmp::Reverse(suffix.len() + 2));
            }
            let rank = if h == "*" {
                3
            } else if h.starts_with("*.") {
                2
            } else if h.contains('/') {
                1
            } else {
                0
            };
            (rank, std::cmp::Reverse(h.len()))
        })
        .min()
        .unwrap_or((3, std::cmp::Reverse(0)))
}

/// How specific a route's path is, the most specific first: an exact path,
/// then a prefix, the longer first. A regex counts as the literal prefix it
/// starts with: its length says nothing of the paths it matches. No path is
/// the `/` prefix.
fn path_specificity(path: Option<&crate::model::PathConfig>) -> Rank {
    use crate::model::PathRuleType;
    match path {
        Some(p) if p.rule_type == PathRuleType::Exact => (0, std::cmp::Reverse(p.value.len())),
        // An alternative can match far wider than its first branch: such a
        // regex counts as `/`.
        Some(p) if p.rule_type == PathRuleType::Regex && p.value.contains('|') => {
            (1, std::cmp::Reverse(1))
        }
        Some(p) if p.rule_type == PathRuleType::Regex => (
            1,
            std::cmp::Reverse(regex_literal_prefix(&p.value).len().max(1)),
        ),
        Some(p) => (1, std::cmp::Reverse(p.value.len())),
        None => (1, std::cmp::Reverse(1)),
    }
}

/// The literal text a path regex starts with, up to its first construct:
/// `^/api/v[0-9]+` gives `/api/v`.
fn regex_literal_prefix(pattern: &str) -> &str {
    let pattern = pattern.strip_prefix('^').unwrap_or(pattern);
    let end = pattern
        .find(|c: char| ".*+?()[]{}|\\$".contains(c))
        .unwrap_or(pattern.len());
    &pattern[..end]
}

/// Applies `storage` to the workers. Returns the cluster IDs deliberately left
/// out, which the caller must also drop from the snapshot so they are retried
/// once whatever blocks them is fixed.
fn configure_sozu_routing(
    channels: &mut Channels,
    storage: &BTreeMap<String, Entrypoint>,
    previous: &RoutingSnapshot,
    cluster_setup_delay_ms: u64,
    middleware_port: u16,
) -> Result<BTreeSet<String>, ReloadFailure> {
    info!(
        "Applying Sōzu configuration for {} entrypoints",
        storage.len()
    );

    let mut skipped = skipped_on_sni_clash(storage);
    // Every entrypoint the loop gets through, so a mid-loop failure can still
    // tell the caller what actually reached a worker.
    let mut applied: BTreeSet<String> = BTreeSet::new();

    let sorted_entrypoints = routing_order(storage);

    // Sōzu appends every new frontend to its Pre rules, so a route installed
    // on this reload lands behind every route already live, whatever their
    // priorities. Once one is installed, each live HTTP route that sorts after
    // it is moved back behind it.
    let mut reorder_live_routes = false;

    for (cluster_id, entrypoint) in sorted_entrypoints {
        // Sending a frontend Sōzu is going to refuse would still mark it
        // applied, and the snapshot would then hide it from every later
        // reload. Leave it out entirely instead.
        if skipped.contains(cluster_id) {
            continue;
        }

        // Already live, unchanged or with only its backends changed (which
        // apply_routing_diff() updated in place): re-adding it would make Sōzu
        // reject the command as a duplicate. Its frontends only move when a
        // route installed earlier in this loop must pass in front of them.
        if let Some(old) = previous.get(cluster_id)
            && (old == entrypoint
                || is_backends_only_change(old, entrypoint)
                || is_middleware_only_change(old, entrypoint))
        {
            if reorder_live_routes && entrypoint.protocol == Protocol::Http {
                let outcome = reinstall_http_frontends(channels, cluster_id, old, entrypoint);
                note_frontend_outcome(cluster_id, outcome, &mut skipped);
            }
            continue;
        }

        // A Gateway HTTP or HTTPS listener that could not be opened: a later
        // reload opens it and retries the route.
        if let Some(name) = entrypoint.config.entrypoint.as_deref()
            && entrypoint.protocol == Protocol::Http
            && ((crate::config::gateway_http_port(name).is_some()
                && !channels.gateway.http_open(name))
                || (crate::config::gateway_https_port(name).is_some()
                    && !channels.gateway.https_open(name)))
        {
            warn!(
                "HTTP entrypoint `{}` is served on Gateway listener `{}`, which is not open, skipping",
                entrypoint.name, name
            );
            skipped.insert(cluster_id.clone());
            continue;
        }

        // Only process HTTP entrypoints for Sozu
        match entrypoint.protocol {
            Protocol::Http => {
                debug!("Configuring HTTP cluster: {}", entrypoint.name);

                // Register ACME challenge frontend BEFORE normal frontend
                // Pre rules are checked in insertion order, so the more specific
                // ACME path must be registered first to take priority over "/"
                if channels.acme_challenge_port.is_some() {
                    for hostname in acme_hostnames(&entrypoint.config.hostnames) {
                        let acme_front = build_acme_frontend(
                            hostname,
                            listener_http_port(entrypoint, channels.http_port),
                        );
                        if let Err(e) = send_to_worker(
                            &mut channels.http,
                            format!("add-frontend-acme-{}", hostname),
                            RequestType::AddHttpFrontend(acme_front),
                        ) {
                            debug!(
                                "Failed to add ACME frontend for {} (may already exist): {}",
                                hostname, e
                            );
                        }
                    }
                    for twin in build_acme_twins(entrypoint, channels.http_port) {
                        let hostname = twin.hostname.clone();
                        if let Err(e) = send_to_worker(
                            &mut channels.http,
                            format!("add-frontend-acme-headers-{}-{}", cluster_id, hostname),
                            RequestType::add_http_frontend(twin),
                        ) {
                            debug!(
                                "Failed to add ACME frontend with header predicates for {} (may already exist): {}",
                                hostname, e
                            );
                        }
                    }
                }

                let https_addr = channels.https_addr();
                let http_port = channels.http_port;
                let outcome = match configure_http_entrypoint(
                    &mut channels.http,
                    &mut channels.https,
                    cluster_id,
                    entrypoint,
                    http_port,
                    https_addr,
                    middleware_port,
                ) {
                    Ok(outcome) => outcome,
                    // Giving up here is fine, but the entrypoints the loop has
                    // not reached were never sent: hand back what did land so
                    // the rest stays out of the snapshot and is retried.
                    Err(error) => return Err(ReloadFailure { error, applied }),
                };

                if outcome == FrontendOutcome::Installed {
                    reorder_live_routes = true;
                }
                note_frontend_outcome(cluster_id, outcome, &mut skipped);
            }
            Protocol::Tcp => {
                let outcome = configure_tcp_entrypoint(&mut channels.tcp, cluster_id, entrypoint);
                note_frontend_outcome(cluster_id, outcome, &mut skipped);
            }
            Protocol::Udp => {
                let outcome = configure_udp_entrypoint(&mut channels.udp, cluster_id, entrypoint);
                note_frontend_outcome(cluster_id, outcome, &mut skipped);
            }
        }

        // A rejected route was not installed: left out, it stays out of the
        // snapshot when a later route fails the reload, and is retried.
        if !skipped.contains(cluster_id) {
            applied.insert(cluster_id.clone());
        }

        thread::sleep(std::time::Duration::from_millis(cluster_setup_delay_ms));
    }

    info!("Sōzu configuration applied successfully");
    Ok(skipped)
}

/// Moves a live route's frontends to the end of Sōzu's Pre rules, behind a
/// route installed earlier in the same reload. Its cluster and backends stay
/// as they are. `live` is what Sōzu currently holds, used for the removal.
///
/// A refusal on the way back leaves the route with no frontend, so it is torn
/// down completely: the caller keeps it out of the snapshot and the next
/// reload installs it from scratch rather than meeting its own leftovers.
fn reinstall_http_frontends(
    channels: &mut Channels,
    cluster_id: &str,
    live: &Entrypoint,
    entrypoint: &Entrypoint,
) -> FrontendOutcome {
    let https_addr = channels.https_addr();
    let http_port = channels.http_port;
    remove_http_frontends(
        &mut channels.http,
        &mut channels.https,
        cluster_id,
        live,
        http_port,
        https_addr,
    );
    let outcome = add_http_frontends(
        &mut channels.http,
        &mut channels.https,
        cluster_id,
        entrypoint,
        http_port,
        https_addr,
    );
    if outcome == FrontendOutcome::Rejected {
        remove_http_frontends(
            &mut channels.http,
            &mut channels.https,
            cluster_id,
            entrypoint,
            http_port,
            https_addr,
        );
        remove_backends(
            &mut channels.http,
            &mut channels.https,
            cluster_id,
            entrypoint,
            channels.middleware_port,
        );
        remove_cluster(&mut channels.http, &mut channels.https, cluster_id);
    }
    outcome
}

/// The cluster ACME HTTP-01 challenges are routed to.
pub(crate) const ACME_CHALLENGE_CLUSTER: &str = "acme-challenge";

/// The frontend sending `hostname`'s ACME HTTP-01 challenges to the challenge
/// server. It goes in just before the hostname's own frontends, so the more
/// specific challenge path wins over a route on `/`.
pub(crate) fn build_acme_frontend(hostname: &str, http_port: u16) -> RequestHttpFrontend {
    RequestHttpFrontend {
        cluster_id: Some(ACME_CHALLENGE_CLUSTER.to_string()),
        address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
        hostname: hostname.to_string(),
        path: PathRule {
            value: "/.well-known/acme-challenge/".to_string(),
            kind: 0, // Prefix
        },
        method: None,
        position: RulePosition::Pre as i32,
        tags: BTreeMap::new(),
        ..Default::default()
    }
}

/// The ACME challenge frontends a route with header conditions needs on top
/// of [`build_acme_frontend`]: Sōzu tries a frontend whose header predicates
/// hold before every frontend without any, so the route would take the
/// challenge requests that carry its headers. Each copy carries the route's
/// predicates and is installed before it, which keeps the challenge first.
pub(crate) fn build_acme_twins(
    entrypoint: &Entrypoint,
    http_port: u16,
) -> Vec<RequestHttpFrontend> {
    let header_predicates = build_header_predicates(&entrypoint.config.match_headers);
    if header_predicates.is_empty() {
        return Vec::new();
    }
    // On the route's own listener: challenges reach it there.
    let http_port = listener_http_port(entrypoint, http_port);
    acme_hostnames(&entrypoint.config.hostnames)
        .map(|hostname| RequestHttpFrontend {
            header_predicates: header_predicates.clone(),
            ..build_acme_frontend(hostname, http_port)
        })
        .collect()
}

/// The hostnames that get an ACME HTTP-01 challenge frontend: exact names
/// only. HTTP-01 validates no wildcard, and one for `*` or a pattern would
/// take the challenge path of hosts that never asked for a certificate.
fn acme_hostnames(hostnames: &[String]) -> impl Iterator<Item = &String> {
    hostnames
        .iter()
        .filter(|h| !h.starts_with('*') && !h.contains('/'))
}

/// The HTTP port an entrypoint's frontends go on: the port of the Gateway
/// listener it names (see [`crate::config::gateway_http_listener`]), or the
/// main HTTP port.
pub(crate) fn listener_http_port(entrypoint: &Entrypoint, http_port: u16) -> u16 {
    entrypoint
        .config
        .entrypoint
        .as_deref()
        .and_then(crate::config::gateway_http_port)
        .unwrap_or(http_port)
}

/// The address an entrypoint's HTTPS frontends go on: that of the Gateway
/// HTTPS listener it names (see [`crate::config::gateway_https_listener`]), or
/// the main HTTPS listener's, `https_addr`.
pub(crate) fn listener_https_addr(
    entrypoint: &Entrypoint,
    https_addr: SocketAddress,
) -> SocketAddress {
    match listener_https_port(entrypoint, 0) {
        0 => https_addr,
        port => SocketAddress::new_v4(0, 0, 0, 0, port),
    }
}

/// The HTTPS twin of [`listener_http_port`].
pub(crate) fn listener_https_port(entrypoint: &Entrypoint, https_port: u16) -> u16 {
    entrypoint
        .config
        .entrypoint
        .as_deref()
        .and_then(crate::config::gateway_https_port)
        .unwrap_or(https_port)
}

/// The listener a frontend is installed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FrontListener {
    Http,
    Https,
}

/// The frontends of an HTTP `entrypoint`, in the order they are sent: one per
/// hostname and method on the HTTP listener, plus its HTTPS twin when TLS is
/// on. Built once here so what reaches the workers and anything reproducing
/// Sōzu's routing (the route resolver) cannot drift apart.
pub(crate) fn build_http_frontends(
    cluster_id: &str,
    entrypoint: &Entrypoint,
    http_port: u16,
    https_addr: SocketAddress,
) -> Vec<(FrontListener, RequestHttpFrontend)> {
    let mut frontends = Vec::new();
    let frontend_required_auth = if build_authorized_hashes(&entrypoint.config.auth).is_empty() {
        None
    } else {
        Some(true)
    };
    for hostname in &entrypoint.config.hostnames {
        let (path_rule, frontend_rewrite_path) = build_path_and_rewrite(
            entrypoint.config.path.as_ref(),
            entrypoint.config.strip_prefix,
            entrypoint.config.add_prefix.as_deref(),
            entrypoint.config.rewrite.as_ref(),
            cluster_id,
        );
        let path_rule = builders::query_path_rule(&entrypoint.config).unwrap_or(path_rule);

        // `Sozune-Route` is reserved on requests: an edit of it could reach
        // the middleware ahead of the route it names. Its response side stays.
        let header_edits: Vec<HeaderConfig> = entrypoint
            .config
            .headers
            .iter()
            .filter_map(|edit| {
                if !edit.name.eq_ignore_ascii_case(middleware::ROUTE_HEADER) {
                    return Some(edit.clone());
                }
                match edit.direction {
                    HeaderDirection::Request => None,
                    HeaderDirection::Response | HeaderDirection::Both => Some(HeaderConfig {
                        direction: HeaderDirection::Response,
                        ..edit.clone()
                    }),
                }
            })
            .collect();
        let mut frontend_headers = build_frontend_headers(&header_edits);
        if middleware::needs_middleware(&entrypoint.config) {
            // Names the route for the middleware, which cannot tell it from
            // another one on the same host and path by itself.
            frontend_headers.extend(build_frontend_headers(&[HeaderConfig {
                name: middleware::ROUTE_HEADER.to_string(),
                value: cluster_id.to_string(),
                direction: HeaderDirection::Request,
                append: false,
            }]));
        }
        let frontend_redirect = entrypoint.config.redirect.map(map_redirect_policy);
        let frontend_redirect_scheme = entrypoint.config.redirect_scheme.map(map_redirect_scheme);
        let frontend_redirect_template = entrypoint.config.redirect_template.clone();
        // A redirect target's path rewrite wins over the prefix rewrite:
        // strip/add_prefix only make sense when the request reaches the
        // backend, which a permanent redirect never does.
        let frontend_rewrite_path = entrypoint
            .config
            .rewrite_path
            .clone()
            .or(frontend_rewrite_path);
        // A redirect's host. A urlRewrite hostname is applied by the
        // middleware instead (see `middleware::url_rewrite_host`).
        let frontend_rewrite_host = entrypoint.config.rewrite_host.clone();
        let frontend_rewrite_port = entrypoint.config.rewrite_port.map(|p| p as u32);
        let header_predicates = build_header_predicates(&entrypoint.config.match_headers);

        for method in methods_for_frontend(&entrypoint.config.methods) {
            let front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(
                    0,
                    0,
                    0,
                    0,
                    listener_http_port(entrypoint, http_port),
                ),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: method.clone(),
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
                headers: frontend_headers.clone(),
                required_auth: frontend_required_auth,
                rewrite_path: frontend_rewrite_path.clone(),
                rewrite_host: frontend_rewrite_host.clone(),
                rewrite_port: frontend_rewrite_port,
                redirect: frontend_redirect,
                redirect_scheme: frontend_redirect_scheme,
                redirect_template: frontend_redirect_template.clone(),
                header_predicates: header_predicates.clone(),
                ..Default::default()
            };
            if entrypoint.config.tls {
                let https_front = RequestHttpFrontend {
                    address: listener_https_addr(entrypoint, https_addr),
                    ..front.clone()
                };
                // Served over HTTPS alone: nothing on the HTTP listener.
                if !entrypoint.config.https_only {
                    frontends.push((FrontListener::Http, front));
                }
                frontends.push((FrontListener::Https, https_front));
            } else {
                frontends.push((FrontListener::Http, front));
            }
        }
    }
    frontends
}

/// Sends the HTTP (and, with TLS, HTTPS) frontends of `entrypoint`: one per
/// hostname and method. Sōzu appends each to its `Pre` rules, which it matches
/// in insertion order, so where a call lands in the reload decides precedence.
fn add_http_frontends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    http_port: u16,
    https_addr: SocketAddress,
) -> FrontendOutcome {
    let mut outcome = FrontendOutcome::Installed;
    for (listener, front) in build_http_frontends(cluster_id, entrypoint, http_port, https_addr) {
        let hostname = front.hostname.clone();
        let method_tag = front.method.clone().unwrap_or_else(|| "any".to_string());
        match listener {
            FrontListener::Http => {
                if let Err(e) = send_to_worker(
                    command_channel,
                    format!(
                        "add-frontend-http-{}-{}-{}",
                        cluster_id, hostname, method_tag
                    ),
                    RequestType::add_http_frontend(front),
                ) {
                    debug!(
                        "Failed to add HTTP frontend for {} [{}] (may already exist): {}",
                        hostname, method_tag, e
                    );
                    outcome = FrontendOutcome::Rejected;
                }
            }
            FrontListener::Https => {
                info!(
                    "Configuring HTTPS frontend for {} [{}] on cluster {}",
                    hostname, method_tag, cluster_id
                );
                match send_to_worker(
                    command_channel_https,
                    format!(
                        "add-frontend-https-{}-{}-{}",
                        cluster_id, hostname, method_tag
                    ),
                    RequestType::add_https_frontend(front),
                ) {
                    Ok(_) => info!("HTTPS frontend added for {} [{}]", hostname, method_tag),
                    Err(e) => {
                        error!(
                            "Failed to add HTTPS frontend for {} [{}]: {}",
                            hostname, method_tag, e
                        );
                        outcome = FrontendOutcome::Rejected;
                    }
                }
            }
        }
    }
    outcome
}

fn configure_http_entrypoint(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    http_port: u16,
    https_addr: SocketAddress,
    middleware_port: u16,
) -> anyhow::Result<FrontendOutcome> {
    // Add cluster for both HTTP and HTTPS
    let authorized_hashes = build_authorized_hashes(&entrypoint.config.auth);
    let cluster_answers = build_cluster_answers(&entrypoint.config.error_pages, cluster_id);
    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: entrypoint.config.sticky_session,
        https_redirect: entrypoint.config.https_redirect,
        proxy_protocol: None,
        load_balancing: lb_algorithm(entrypoint.config.load_balancer) as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        authorized_hashes,
        https_redirect_port: entrypoint.config.https_redirect_port.map(|p| p as u32),
        www_authenticate: entrypoint.config.www_authenticate.clone(),
        answers: cluster_answers,
        ..Default::default()
    };

    // Send to HTTP and HTTPS workers - ignore errors if cluster already exists
    if let Err(e) = send_to_worker(
        command_channel,
        format!("add-cluster-http-{}", cluster_id),
        RequestType::AddCluster(cluster.clone()),
    ) {
        debug!(
            "Failed to add HTTP cluster {} (may already exist): {}",
            cluster_id, e
        );
    }
    if let Err(e) = send_to_worker(
        command_channel_https,
        format!("add-cluster-https-{}", cluster_id),
        RequestType::AddCluster(cluster),
    ) {
        debug!(
            "Failed to add HTTPS cluster {} (may already exist): {}",
            cluster_id, e
        );
    }

    let mut outcome = add_http_frontends(
        command_channel,
        command_channel_https,
        cluster_id,
        entrypoint,
        http_port,
        https_addr,
    );

    // Sōzu refused at least one frontend. The entrypoint is about to be left
    // out of the snapshot so the next reload retries it, and anything installed
    // in the meantime has to go with it: a frontend the snapshot does not know
    // about is one `apply_routing_diff` will never remove, and on the retry it
    // would come back as a duplicate rejection of our own making, pinning the
    // entrypoint outside the snapshot for good.
    if outcome == FrontendOutcome::Rejected {
        remove_http_frontends(
            command_channel,
            command_channel_https,
            cluster_id,
            entrypoint,
            http_port,
            https_addr,
        );
        remove_cluster(command_channel, command_channel_https, cluster_id);
        return Ok(outcome);
    }

    // Add backends
    // If this entrypoint needs middleware, route through the middleware server instead
    let use_middleware = middleware::needs_middleware(&entrypoint.config);

    if use_middleware {
        debug!(
            "Routing {} through middleware server at 127.0.0.1:{}",
            entrypoint.name, middleware_port
        );
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: middleware_backend_id(cluster_id),
            address: SocketAddress::new_v4(127, 0, 0, 1, middleware_port),
            load_balancing_parameters: Some(LoadBalancingParams { weight: 100 }),
            sticky_id: None,
            backup: None,
            unix_path: None,
        };

        let mut rejected = 0usize;
        if let Err(e) = send_to_worker(
            command_channel,
            format!("add-backend-http-{}-0", cluster_id),
            RequestType::AddBackend(backend.clone()),
        ) {
            debug!(
                "Failed to add HTTP middleware backend {} (may already exist): {}",
                backend.backend_id, e
            );
            rejected += 1;
        }
        if entrypoint.config.tls
            && let Err(e) = send_to_worker(
                command_channel_https,
                format!("add-backend-https-{}-0", cluster_id),
                RequestType::AddBackend(backend),
            )
        {
            debug!(
                "Failed to add HTTPS middleware backend (may already exist): {}",
                e
            );
        }

        // The middleware path installs one synthetic backend pointing at the
        // middleware server, so losing it leaves the cluster with nothing.
        outcome = backend_outcome(1, rejected);
    } else {
        debug!(
            "Setting up {} backends for {}: {:?}",
            entrypoint.backends.len(),
            entrypoint.name,
            entrypoint.backends
        );
        let mut rejected = 0usize;
        for (backend_index, backend_entry) in entrypoint.backends.iter().enumerate() {
            let address = parse_backend_address(backend_entry)?;
            let (load_balancing_parameters, backup) = sozu_weight(backend_entry);

            let backend = AddBackend {
                cluster_id: cluster_id.to_string(),
                backend_id: backend_id(cluster_id, backend_index, backend_entry),
                address,
                load_balancing_parameters,
                sticky_id: None,
                backup,
                unix_path: None,
            };

            debug!("Adding backend {}: {}", backend.backend_id, backend_entry);
            if let Err(e) = send_to_worker(
                command_channel,
                format!("add-backend-http-{}-{}", cluster_id, backend_index),
                RequestType::AddBackend(backend.clone()),
            ) {
                debug!(
                    "Failed to add HTTP backend {} (may already exist): {}",
                    backend.backend_id, e
                );
                rejected += 1;
            }

            // HTTPS backend only if TLS is enabled
            if entrypoint.config.tls {
                let backend_id = backend.backend_id.clone();
                info!("Adding HTTPS backend {} -> {}", backend_id, backend_entry);
                match send_to_worker(
                    command_channel_https,
                    format!("add-backend-https-{}-{}", cluster_id, backend_index),
                    RequestType::AddBackend(backend),
                ) {
                    Ok(_) => info!("HTTPS backend {} added successfully", backend_id),
                    Err(e) => error!("Failed to add HTTPS backend {}: {}", backend_id, e),
                }
            }
        }

        // Judged on the HTTP adds: the HTTPS worker carries the same backend
        // set, so a cluster that kept none of them has nowhere to send traffic
        // and would answer 503 until a later reload retries the adds.
        outcome = backend_outcome(entrypoint.backends.len(), rejected);
    }

    Ok(outcome)
}

fn configure_tcp_entrypoint(
    tcp_channels: &mut L4Channels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) -> FrontendOutcome {
    debug!(
        "Configuring TCP cluster `{}` (backends: {:?})",
        entrypoint.name, entrypoint.backends
    );
    let listener_name = match entrypoint.config.entrypoint.as_deref() {
        Some(name) => name,
        None => {
            error!(
                "TCP entrypoint `{}` has no listener reference, skipping",
                entrypoint.name
            );
            // A missing listener is operator misconfiguration, not something
            // Sōzu would accept on a later reload: retrying it every time would
            // spin without ever converging.
            return FrontendOutcome::Installed;
        }
    };

    if crate::config::gateway_tcp_port(listener_name).is_some()
        && !crate::provider::kubernetes::gateway::is_gateway_route(entrypoint)
    {
        error!(
            "TCP entrypoint `{}` references listener `{}`, which is reserved for Gateway routes, skipping",
            entrypoint.name, listener_name
        );
        // Misconfiguration, as for an undeclared listener.
        return FrontendOutcome::Installed;
    }
    let listener = match tcp_channels.get_mut(listener_name) {
        Some(c) => c,
        // A Gateway listener that could not be opened: a later reload opens
        // it and retries the route.
        None if crate::config::gateway_tcp_port(listener_name).is_some() => {
            warn!(
                "TCP entrypoint `{}` is served on Gateway listener `{}`, which is not open, skipping",
                entrypoint.name, listener_name
            );
            return FrontendOutcome::Rejected;
        }
        None => {
            error!(
                "TCP entrypoint `{}` references undeclared listener `{}`, skipping. \
                 Declare it under `proxy.tcp` in the config.",
                entrypoint.name, listener_name
            );
            // Also misconfiguration: the listener has to be declared in the
            // config before any reload could apply this entrypoint.
            return FrontendOutcome::Installed;
        }
    };
    let listener_port = listener.port;
    let channel = &mut listener.channel;

    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: false,
        https_redirect: false,
        proxy_protocol: None,
        load_balancing: lb_algorithm(entrypoint.config.load_balancer) as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        authorized_hashes: Vec::new(),
        https_redirect_port: None,
        www_authenticate: None,
        ..Default::default()
    };

    if let Err(e) = send_to_worker(
        channel,
        format!("add-cluster-tcp-{}", cluster_id),
        RequestType::AddCluster(cluster),
    ) {
        debug!(
            "Failed to add TCP cluster {} on listener {} (may already exist): {}",
            cluster_id, listener_name, e
        );
    }

    let tcp_front = RequestTcpFrontend {
        cluster_id: cluster_id.to_string(),
        // The Sōzu TCP worker binds loopback (the public port is owned by the
        // pre-accept forwarder), so the frontend address must match: 127.0.0.1,
        // not 0.0.0.0. `listener_port` is the loopback port here.
        address: SocketAddress::new_v4(127, 0, 0, 1, listener_port),
        // `None` keeps the legacy catch-all frontend. `Some` makes the worker
        // preread the ClientHello and route on the name, without terminating
        // TLS. Sōzu keys a frontend on `(address, sni, alpn)`, so removal must
        // pass the identical value — see `remove_tcp_entrypoint`.
        sni: entrypoint.config.sni.clone(),
        ..Default::default()
    };

    let mut outcome = FrontendOutcome::Installed;

    if let Err(e) = send_to_worker(
        channel,
        format!("add-frontend-tcp-{}", cluster_id),
        RequestType::AddTcpFrontend(tcp_front),
    ) {
        debug!(
            "Failed to add TCP frontend for cluster {} on listener {}: {}",
            cluster_id, listener_name, e
        );
        outcome = FrontendOutcome::Rejected;
    }

    // Nothing routes without the frontend, and the entrypoint is about to be
    // held back from the snapshot so the next reload retries it. Leave the
    // cluster behind and the retry meets its own leftovers as a duplicate.
    if outcome == FrontendOutcome::Rejected {
        remove_l4_cluster(channel, cluster_id, "tcp");
        return outcome;
    }

    for backend_entry in &entrypoint.backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                error!(
                    "Invalid TCP backend address {} for {}: {}",
                    backend_entry, cluster_id, e
                );
                continue;
            }
        };
        let (load_balancing_parameters, backup) = sozu_weight(backend_entry);
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters,
            sticky_id: None,
            backup,
            unix_path: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-tcp-{backend_id}"),
            RequestType::AddBackend(backend),
        ) {
            debug!("Failed to add TCP backend {backend_id} (may already exist): {e}");
        }
    }

    outcome
}

fn configure_udp_entrypoint(
    udp_channels: &mut L4Channels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) -> FrontendOutcome {
    debug!(
        "Configuring UDP cluster `{}` (backends: {:?})",
        entrypoint.name, entrypoint.backends
    );
    let listener_name = match entrypoint.config.entrypoint.as_deref() {
        Some(name) => name,
        None => {
            error!(
                "UDP entrypoint `{}` has no listener reference, skipping",
                entrypoint.name
            );
            // A missing listener is operator misconfiguration, not something
            // Sōzu would accept on a later reload: retrying it every time would
            // spin without ever converging.
            return FrontendOutcome::Installed;
        }
    };

    if crate::config::gateway_udp_port(listener_name).is_some()
        && !crate::provider::kubernetes::gateway::is_gateway_route(entrypoint)
    {
        error!(
            "UDP entrypoint `{}` references listener `{}`, which is reserved for Gateway routes, skipping",
            entrypoint.name, listener_name
        );
        // Misconfiguration, as for an undeclared listener.
        return FrontendOutcome::Installed;
    }
    let listener = match udp_channels.get_mut(listener_name) {
        Some(c) => c,
        // A Gateway listener that could not be opened: a later reload opens
        // it and retries the route.
        None if crate::config::gateway_udp_port(listener_name).is_some() => {
            warn!(
                "UDP entrypoint `{}` is served on Gateway listener `{}`, which is not open, skipping",
                entrypoint.name, listener_name
            );
            return FrontendOutcome::Rejected;
        }
        None => {
            error!(
                "UDP entrypoint `{}` references undeclared listener `{}`, skipping. \
                 Declare it under `proxy.udp` in the config.",
                entrypoint.name, listener_name
            );
            // Also misconfiguration: the listener has to be declared in the
            // config before any reload could apply this entrypoint.
            return FrontendOutcome::Installed;
        }
    };
    let listener_port = listener.port;
    let channel = &mut listener.channel;

    // A `udp` block is required for Sōzu to treat this as a UDP cluster; we use
    // its defaults (source-IP flow affinity). HRW/Maglev, set via
    // `load_balancing`, are the flow-affine algorithms that key on that affinity.
    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: false,
        https_redirect: false,
        proxy_protocol: None,
        load_balancing: lb_algorithm(entrypoint.config.load_balancer) as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        authorized_hashes: Vec::new(),
        https_redirect_port: None,
        www_authenticate: None,
        udp: Some(UdpClusterConfig::default()),
        ..Default::default()
    };

    if let Err(e) = send_to_worker(
        channel,
        format!("add-cluster-udp-{}", cluster_id),
        RequestType::AddCluster(cluster),
    ) {
        debug!(
            "Failed to add UDP cluster {} on listener {} (may already exist): {}",
            cluster_id, listener_name, e
        );
    }

    let udp_front = RequestUdpFrontend {
        cluster_id: cluster_id.to_string(),
        address: SocketAddress::new_v4(0, 0, 0, 0, listener_port),
        ..Default::default()
    };

    let mut outcome = FrontendOutcome::Installed;

    if let Err(e) = send_to_worker(
        channel,
        format!("add-frontend-udp-{}", cluster_id),
        RequestType::AddUdpFrontend(udp_front),
    ) {
        debug!(
            "Failed to add UDP frontend for cluster {} on listener {}: {}",
            cluster_id, listener_name, e
        );
        outcome = FrontendOutcome::Rejected;
    }

    // Same reasoning as TCP: no frontend, no route, so take the cluster back
    // out rather than leave the retry a duplicate to trip over.
    if outcome == FrontendOutcome::Rejected {
        remove_l4_cluster(channel, cluster_id, "udp");
        return outcome;
    }

    for backend_entry in &entrypoint.backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                error!(
                    "Invalid UDP backend address {} for {}: {}",
                    backend_entry, cluster_id, e
                );
                continue;
            }
        };
        let (load_balancing_parameters, backup) = sozu_weight(backend_entry);
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters,
            sticky_id: None,
            backup,
            unix_path: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-udp-{backend_id}"),
            RequestType::AddBackend(backend),
        ) {
            debug!("Failed to add UDP backend {backend_id} (may already exist): {e}");
        }
    }

    outcome
}

/// Undo the cluster an L4 entrypoint installed before its frontend was refused.
fn remove_l4_cluster(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    proto: &str,
) {
    if let Err(e) = send_to_worker(
        channel,
        format!("rm-cluster-{proto}-{cluster_id}"),
        RequestType::RemoveCluster(cluster_id.to_string()),
    ) {
        debug!("Failed to remove {proto} cluster {cluster_id} after a rejected frontend: {e}");
    }
}

fn remove_udp_entrypoint(udp_channels: &mut L4Channels, cluster_id: &str, entrypoint: &Entrypoint) {
    let Some(listener_name) = entrypoint.config.entrypoint.as_deref() else {
        return;
    };
    let Some(listener) = udp_channels.get_mut(listener_name) else {
        return;
    };
    let listener_port = listener.port;
    let channel = &mut listener.channel;

    for backend_entry in &entrypoint.backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("rm-backend-udp-{backend_id}"),
            RequestType::RemoveBackend(remove),
        ) {
            debug!("Failed to remove UDP backend {backend_id}: {e}");
        }
    }

    let udp_front = RequestUdpFrontend {
        cluster_id: cluster_id.to_string(),
        address: SocketAddress::new_v4(0, 0, 0, 0, listener_port),
        ..Default::default()
    };
    if let Err(e) = send_to_worker(
        channel,
        format!("rm-frontend-udp-{}", cluster_id),
        RequestType::RemoveUdpFrontend(udp_front),
    ) {
        debug!("Failed to remove UDP frontend for {}: {}", cluster_id, e);
    }

    if let Err(e) = send_to_worker(
        channel,
        format!("rm-cluster-udp-{}", cluster_id),
        RequestType::RemoveCluster(cluster_id.to_string()),
    ) {
        debug!("Failed to remove UDP cluster {}: {}", cluster_id, e);
    }
}

/// Send `QueryMetrics` to a single worker and return the proxy-wide metric
/// map (worker counters/gauges, no per-cluster breakdown).
///
/// We request `no_clusters: true` to keep the response small — the API only
/// exposes proxy-wide aggregates today. Returns an empty map on any error;
/// callers log and move on (a transient worker hiccup must not poison the
/// snapshot).
fn poll_worker_metrics(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    name: &str,
    timeout: Duration,
) -> std::collections::BTreeMap<String, sozu_command_lib::proto::command::FilteredMetrics> {
    let id = format!("{}-metrics-{}", name, metrics_snapshot::now_unix());
    let request = WorkerRequest {
        id: id.clone(),
        content: Request {
            request_type: Some(RequestType::QueryMetrics(QueryMetricsOptions {
                list: false,
                cluster_ids: Vec::new(),
                backend_ids: Vec::new(),
                metric_names: Vec::new(),
                no_clusters: true,
                workers: false,
            })),
        },
    };

    if let Err(e) = channel.write_message(&request) {
        error!(
            "metrics: failed to write QueryMetrics to {} worker: {}",
            name, e
        );
        return Default::default();
    }

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            error!(
                "metrics: timeout waiting for {} worker QueryMetrics response",
                name
            );
            return Default::default();
        }
        match channel.read_message_blocking_timeout(Some(remaining)) {
            Ok(response) => {
                if response.id != id {
                    debug!(
                        "metrics: skipping unrelated response {} on {}",
                        response.id, name
                    );
                    continue;
                }
                if response.status == ResponseStatus::Failure as i32 {
                    error!(
                        "metrics: {} worker rejected QueryMetrics: {}",
                        name, response.message
                    );
                    return Default::default();
                }
                let Some(content) = response.content else {
                    return Default::default();
                };
                match content.content_type {
                    // Workers respond with WorkerMetrics (their own proxy +
                    // cluster maps). The aggregated form Metrics(AggregatedMetrics)
                    // only comes from the Sōzu main process, which we don't run.
                    Some(ContentType::WorkerMetrics(wm)) => return wm.proxy,
                    Some(ContentType::Metrics(agg)) => return agg.proxying,
                    // Content is not printed: Sōzu keeps `Debug` off it since
                    // 2.2.1, as some variants carry certificates and keys.
                    Some(_) => {
                        debug!("metrics: unexpected content type from {} worker", name);
                        return Default::default();
                    }
                    None => {
                        debug!("metrics: empty content from {} worker", name);
                        return Default::default();
                    }
                }
            }
            Err(e) => {
                error!("metrics: error reading {} worker QueryMetrics: {}", name, e);
                return Default::default();
            }
        }
    }
}

fn remove_http_frontends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    http_port: u16,
    https_addr: SocketAddress,
) {
    let (path_rule, _) = build_path_and_rewrite(
        entrypoint.config.path.as_ref(),
        entrypoint.config.strip_prefix,
        entrypoint.config.add_prefix.as_deref(),
        entrypoint.config.rewrite.as_ref(),
        cluster_id,
    );
    let path_rule = builders::query_path_rule(&entrypoint.config).unwrap_or(path_rule);

    let header_predicates = build_header_predicates(&entrypoint.config.match_headers);
    for hostname in &entrypoint.config.hostnames {
        for method in methods_for_frontend(&entrypoint.config.methods) {
            let method_tag = method.as_deref().unwrap_or("any");
            let http_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(
                    0,
                    0,
                    0,
                    0,
                    listener_http_port(entrypoint, http_port),
                ),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: method.clone(),
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
                header_predicates: header_predicates.clone(),
                ..Default::default()
            };

            if let Err(e) = send_to_worker(
                command_channel,
                format!(
                    "rm-frontend-http-{}-{}-{}",
                    cluster_id, hostname, method_tag
                ),
                RequestType::remove_http_frontend(http_front),
            ) {
                debug!(
                    "Failed to remove HTTP frontend for {} [{}]: {}",
                    hostname, method_tag, e
                );
            }

            if entrypoint.config.tls {
                let https_front = RequestHttpFrontend {
                    cluster_id: Some(cluster_id.to_string()),
                    address: listener_https_addr(entrypoint, https_addr),
                    hostname: hostname.clone(),
                    path: path_rule.clone(),
                    method: method.clone(),
                    position: RulePosition::Pre as i32,
                    tags: BTreeMap::new(),
                    header_predicates: header_predicates.clone(),
                    ..Default::default()
                };

                if let Err(e) = send_to_worker(
                    command_channel_https,
                    format!(
                        "rm-frontend-https-{}-{}-{}",
                        cluster_id, hostname, method_tag
                    ),
                    RequestType::remove_https_frontend(https_front),
                ) {
                    debug!(
                        "Failed to remove HTTPS frontend for {} [{}]: {}",
                        hostname, method_tag, e
                    );
                }
            }
        }
    }
}

/// Add a specific subset of an entrypoint's backends (used by the in-place
/// backend diff). `backend_index_base` is the positional offset so the
/// generated `backend_id`s don't collide with backends already registered.
fn add_backends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    backends: &[&Backend],
) {
    for backend_entry in backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                debug!("Failed to parse backend address {backend_entry} for add: {e}");
                continue;
            }
        };
        let backend_id = backend_id(cluster_id, 0, backend_entry);
        let (load_balancing_parameters, backup) = sozu_weight(backend_entry);
        let add = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters,
            sticky_id: None,
            backup,
            unix_path: None,
        };
        if let Err(e) = send_to_worker(
            command_channel,
            format!("add-backend-http-{backend_id}"),
            RequestType::AddBackend(add.clone()),
        ) {
            debug!("Failed to add HTTP backend {backend_id} (may already exist): {e}");
        }
        if entrypoint.config.tls
            && let Err(e) = send_to_worker(
                command_channel_https,
                format!("add-backend-https-{backend_id}"),
                RequestType::AddBackend(add),
            )
        {
            debug!("Failed to add HTTPS backend {backend_id} (may already exist): {e}");
        }
    }
}

/// Remove a specific subset of backends by address-derived id (mirror of
/// [`add_backends`]).
/// Closes the sessions still holding a connection to a backend that left
/// `cluster_id`, or to any of its backends when `backend` is `None`. Sent after
/// the removal, so a client that reconnects reaches what is left. Sōzu lets an
/// HTTP request in flight finish and drains HTTP/2 streams; a WebSocket or TCP
/// session closes at once. Without it, such a session stays tied to a backend
/// that is no longer routed, for as long as the connection lives.
fn close_sessions(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    worker: &str,
    cluster_id: &str,
    backend: Option<(String, SocketAddress)>,
) {
    let (backend_id, address) = match backend {
        Some((id, address)) => (Some(id), Some(address)),
        None => (None, None),
    };
    let target = backend_id.clone().unwrap_or_else(|| cluster_id.to_string());
    if let Err(e) = send_to_worker(
        channel,
        format!("close-sessions-{worker}-{target}"),
        RequestType::CloseSessions(CloseSessions {
            cluster_id: cluster_id.to_string(),
            backend_id,
            address,
        }),
    ) {
        debug!("Failed to close {worker} sessions of {target}: {e}");
    }
}

/// [`close_sessions`] for HTTP backends that left `cluster_id`, on the HTTP
/// worker and, for a TLS route, the HTTPS one.
fn close_http_backend_sessions(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    departed: &[&Backend],
    tls: bool,
) {
    for backend in departed {
        let Ok(address) = parse_backend_address(backend) else {
            continue;
        };
        let id = backend_id(cluster_id, 0, backend);
        close_sessions(
            command_channel,
            "http",
            cluster_id,
            Some((id.clone(), address)),
        );
        if tls {
            close_sessions(
                command_channel_https,
                "https",
                cluster_id,
                Some((id, address)),
            );
        }
    }
}

/// Backends a changed route lost, whose sessions are closed once the route is
/// installed again.
struct DepartedBackends {
    cluster_id: String,
    route: Entrypoint,
    backends: Vec<Backend>,
    /// The route changed protocol: every session of the old one goes, since
    /// its frontend is gone whatever the backends.
    whole_cluster: bool,
}

impl DepartedBackends {
    fn new(cluster_id: &str, old: &Entrypoint, new: &Entrypoint) -> Self {
        Self {
            cluster_id: cluster_id.to_string(),
            route: old.clone(),
            backends: departed_backends(old, new).into_iter().cloned().collect(),
            whole_cluster: old.protocol != new.protocol,
        }
    }
}

/// The departed backends of the routes `outcome` installed again: a route the
/// reload skipped, or did not reach, keeps its sessions.
fn reinstalled_only(
    departed: Vec<DepartedBackends>,
    outcome: &Result<BTreeSet<String>, ReloadFailure>,
) -> Vec<DepartedBackends> {
    departed
        .into_iter()
        .filter(|lost| match outcome {
            Ok(skipped) => !skipped.contains(&lost.cluster_id),
            Err(ReloadFailure { applied, .. }) => applied.contains(&lost.cluster_id),
        })
        .collect()
}

/// Closes the sessions of the backends changed routes lost, after the reload
/// installed the routes again.
fn close_departed_sessions(channels: &mut Channels, departed: &[DepartedBackends]) {
    for lost in departed {
        if lost.whole_cluster {
            match lost.route.protocol {
                Protocol::Http => {
                    close_sessions(&mut channels.http, "http", &lost.cluster_id, None);
                    if lost.route.config.tls {
                        close_sessions(&mut channels.https, "https", &lost.cluster_id, None);
                    }
                }
                Protocol::Tcp => {
                    close_tcp_sessions(&mut channels.tcp, &lost.cluster_id, &lost.route, None)
                }
                Protocol::Udp => {}
            }
            continue;
        }
        if lost.backends.is_empty() {
            continue;
        }
        let backends: Vec<&Backend> = lost.backends.iter().collect();
        match lost.route.protocol {
            Protocol::Http => close_http_backend_sessions(
                &mut channels.http,
                &mut channels.https,
                &lost.cluster_id,
                &backends,
                lost.route.config.tls,
            ),
            Protocol::Tcp => close_tcp_sessions(
                &mut channels.tcp,
                &lost.cluster_id,
                &lost.route,
                Some(&backends),
            ),
            // Sōzu keeps no session for a UDP flow to close.
            Protocol::Udp => {}
        }
    }
}

/// The backends of `old` that `new` no longer has, matched by address.
fn departed_backends<'a>(old: &'a Entrypoint, new: &Entrypoint) -> Vec<&'a Backend> {
    old.backends
        .iter()
        .filter(|b| {
            !new.backends
                .iter()
                .any(|n| n.address == b.address && n.port == b.port)
        })
        .collect()
}

fn remove_backend_set(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    backends: &[&Backend],
    tls: bool,
) {
    for backend_entry in backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                debug!("Failed to parse backend address {backend_entry} for removal: {e}");
                continue;
            }
        };
        let backend_id = backend_id(cluster_id, 0, backend_entry);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };
        if let Err(e) = send_to_worker(
            command_channel,
            format!("rm-backend-http-{backend_id}"),
            RequestType::RemoveBackend(remove.clone()),
        ) {
            debug!("Failed to remove HTTP backend {backend_id}: {e}");
        }
        if tls
            && let Err(e) = send_to_worker(
                command_channel_https,
                format!("rm-backend-https-{backend_id}"),
                RequestType::RemoveBackend(remove),
            )
        {
            debug!("Failed to remove HTTPS backend {backend_id}: {e}");
        }
    }
}

/// The id of the backend standing for the middleware server in a route that
/// goes through it.
fn middleware_backend_id(cluster_id: &str) -> String {
    format!("{cluster_id}-backend-0")
}

/// Remove the backends of `entrypoint`: its own, or the middleware server
/// when it goes through it, the only backend Sōzu then holds for it.
fn remove_backends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    middleware_port: u16,
) {
    let removals: Vec<RemoveBackend> = if middleware::needs_middleware(&entrypoint.config) {
        vec![RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: middleware_backend_id(cluster_id),
            address: SocketAddress::new_v4(127, 0, 0, 1, middleware_port),
        }]
    } else {
        entrypoint
            .backends
            .iter()
            .enumerate()
            .filter_map(
                |(i, backend_entry)| match parse_backend_address(backend_entry) {
                    Ok(address) => Some(RemoveBackend {
                        cluster_id: cluster_id.to_string(),
                        backend_id: backend_id(cluster_id, i, backend_entry),
                        address,
                    }),
                    Err(e) => {
                        debug!(
                            "Failed to parse backend address {} for removal: {}",
                            backend_entry, e
                        );
                        None
                    }
                },
            )
            .collect()
    };
    for (i, remove) in removals.into_iter().enumerate() {
        let backend_id = remove.backend_id.clone();
        if let Err(e) = send_to_worker(
            command_channel,
            format!("rm-backend-http-{}-{}", cluster_id, i),
            RequestType::RemoveBackend(remove.clone()),
        ) {
            debug!("Failed to remove HTTP backend {}: {}", backend_id, e);
        }

        if entrypoint.config.tls
            && let Err(e) = send_to_worker(
                command_channel_https,
                format!("rm-backend-https-{}-{}", cluster_id, i),
                RequestType::RemoveBackend(remove),
            )
        {
            debug!("Failed to remove HTTPS backend {}: {}", backend_id, e);
        }
    }
}

fn remove_cluster(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
) {
    if let Err(e) = send_to_worker(
        command_channel,
        format!("rm-cluster-http-{}", cluster_id),
        RequestType::RemoveCluster(cluster_id.to_string()),
    ) {
        debug!("Failed to remove HTTP cluster {}: {}", cluster_id, e);
    }
    if let Err(e) = send_to_worker(
        command_channel_https,
        format!("rm-cluster-https-{}", cluster_id),
        RequestType::RemoveCluster(cluster_id.to_string()),
    ) {
        debug!("Failed to remove HTTPS cluster {}: {}", cluster_id, e);
    }
}

/// What identifies an ACME twin to Sōzu: its hostname and its predicates,
/// whatever their order and the case of the header names.
fn acme_twin_key(twin: &RequestHttpFrontend) -> AcmeTwinKey {
    let mut predicates: Vec<_> = twin
        .header_predicates
        .iter()
        .map(|p| (p.name.to_ascii_lowercase(), p.kind, p.value.clone()))
        .collect();
    predicates.sort();
    predicates.dedup();
    // The listener too: twins on two ports are two frontends.
    (
        twin.address.port,
        twin.hostname.to_ascii_lowercase(),
        predicates,
    )
}

/// What tells two ACME twins apart: listener port, hostname and header
/// predicates.
type AcmeTwinKey = (u32, String, Vec<(String, i32, Option<String>)>);

/// The ACME twins of `entrypoint` no route in `still_needed` uses: two routes
/// with the same hostname and header predicates share one.
fn stale_acme_twins(
    entrypoint: &Entrypoint,
    http_port: u16,
    still_needed: &[RequestHttpFrontend],
) -> Vec<RequestHttpFrontend> {
    let needed: HashSet<_> = still_needed.iter().map(acme_twin_key).collect();
    build_acme_twins(entrypoint, http_port)
        .into_iter()
        .filter(|twin| !needed.contains(&acme_twin_key(twin)))
        .collect()
}

fn remove_acme_twins(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    entrypoint: &Entrypoint,
    http_port: u16,
    still_needed: &[RequestHttpFrontend],
) {
    for twin in stale_acme_twins(entrypoint, http_port, still_needed) {
        let hostname = twin.hostname.clone();
        if let Err(e) = send_to_worker(
            command_channel,
            format!("rm-frontend-acme-headers-{}", hostname),
            RequestType::remove_http_frontend(twin),
        ) {
            debug!(
                "Failed to remove ACME frontend with header predicates for {}: {}",
                hostname, e
            );
        }
    }
}

fn remove_acme_frontends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    hostnames: &[String],
    http_port: u16,
) {
    for hostname in acme_hostnames(hostnames) {
        let acme_front = build_acme_frontend(hostname, http_port);

        if let Err(e) = send_to_worker(
            command_channel,
            format!("rm-frontend-acme-{}", hostname),
            RequestType::RemoveHttpFrontend(acme_front),
        ) {
            debug!("Failed to remove ACME frontend for {}: {}", hostname, e);
        }
    }
}

/// True when two versions of an entrypoint differ **only in their backend set**
/// — everything that composes the Sōzu frontend (routing rules, middleware, TLS,
/// error pages, plugins, …) is identical. When this holds, a reload must NOT
/// tear the frontend down: doing so opens a window where the route 404s. Instead
/// the caller diffs only the backends, leaving the live frontend in place
/// (zero-downtime scale).
///
/// Default-deny by construction: we compare the whole `config` (and `protocol`)
/// rather than an allow-list of fields, so any new `EntrypointConfig` field is
/// treated as a frontend change automatically — a forgotten field can never be
/// silently classified as "backends-only" and dropped on reload. The one field
/// left out is `mirrors`: like the backends, only the middleware reads them.
fn frontend_unchanged(old: &Entrypoint, new: &Entrypoint) -> bool {
    let frontend = |config: &crate::model::EntrypointConfig| crate::model::EntrypointConfig {
        mirrors: Vec::new(),
        ..config.clone()
    };
    old.protocol == new.protocol && frontend(&old.config) == frontend(&new.config)
}

/// True when a changed cluster can be reloaded by diffing only its backends
/// (zero-downtime scale), instead of tearing the frontend down and re-adding it.
///
/// Two conditions must hold:
/// - [`frontend_unchanged`]: nothing but the backend set differs, and
/// - the entrypoint does **not** route through the middleware server. When
///   middleware is active the Sōzu cluster holds a single synthetic backend
///   pointing at `127.0.0.1:<middleware_port>` — the real backend addresses are
///   never registered in Sōzu, so an in-place backend diff would inject real
///   addresses that bypass the middleware. Those changes take the regular
///   remove-then-readd path, which rebuilds the synthetic backend correctly.
///
/// Applies to every protocol: HTTP, TCP, and UDP all register real backend
/// addresses directly, so a rescale can diff them in place. For UDP this also
/// avoids tearing down the datagram frontend mid-reload (which would drop
/// in-flight flows). Middleware only exists on HTTP, so the check is a no-op for
/// L4 but kept uniform.
fn is_backends_only_change(old: &Entrypoint, new: &Entrypoint) -> bool {
    frontend_unchanged(old, new)
        && !middleware::needs_middleware(&old.config)
        && !middleware::needs_middleware(&new.config)
}

/// True when a changed cluster needs nothing from Sōzu: its frontend is
/// unchanged and it goes through the middleware, before as after, so Sōzu's
/// only backend for it is the middleware. Its backends and mirrors are the
/// middleware's, whose table every reload rebuilds.
fn is_middleware_only_change(old: &Entrypoint, new: &Entrypoint) -> bool {
    // Only an HTTP route goes through the middleware, whatever its config.
    old.protocol == Protocol::Http
        && frontend_unchanged(old, new)
        && middleware::needs_middleware(&old.config)
        && middleware::needs_middleware(&new.config)
}

/// Diff the backend sets of a cluster whose frontend is unchanged, **adding new
/// backends before removing departed ones** so the cluster never drops below
/// its live capacity (no request hits an empty cluster). Backends are matched
/// by address, not by positional index.
/// Pure decision step for [`diff_backends_in_place`]: given the old and new
/// backend sets, return the backends to (re-)add and the backends to remove,
/// matched by address. A backend is `added` when its address is new **or** its
/// weight changed (re-adding the same address+id updates the weight in place on
/// Sōzu); it is `removed` when its address disappears entirely. Extracted so the
/// matching logic — including the weight-only case — is unit-testable without a
/// live worker channel.
fn backend_diff<'a>(
    old: &'a Entrypoint,
    new: &'a Entrypoint,
) -> (Vec<&'a Backend>, Vec<&'a Backend>) {
    let addr = |b: &Backend| format!("{}:{}", b.address, b.port);
    // Map address -> weight on the old side so we can spot a weight-only change
    // (same address, different weight). Sōzu carries weight in AddBackend's
    // load-balancing params; the only way to update a live backend's weight is
    // to re-send AddBackend with the same address+id, which it applies in place.
    let old_weights: HashMap<String, u32> =
        old.backends.iter().map(|b| (addr(b), b.weight)).collect();
    let new_addrs: HashSet<String> = new.backends.iter().map(addr).collect();

    // Add backends that are new OR whose weight changed (before removing any),
    // so capacity never dips. Re-adding an existing address with a new weight is
    // an idempotent in-place update on Sōzu's side, not a duplicate.
    let added = new
        .backends
        .iter()
        .filter(|b| match old_weights.get(&addr(b)) {
            None => true,                                // brand-new address
            Some(&old_weight) => b.weight != old_weight, // weight-only change
        })
        .collect();

    // Remove backends whose address is gone entirely (a re-weighted backend is
    // still present in `new`, so it is never in this set).
    let removed = old
        .backends
        .iter()
        .filter(|b| !new_addrs.contains(&addr(b)))
        .collect();

    (added, removed)
}

fn diff_backends_in_place(
    channels: &mut Channels,
    cluster_id: &str,
    old: &Entrypoint,
    new: &Entrypoint,
) {
    let (added, removed) = backend_diff(old, new);

    match new.protocol {
        Protocol::Http => {
            if !added.is_empty() {
                add_backends(
                    &mut channels.http,
                    &mut channels.https,
                    cluster_id,
                    new,
                    &added,
                );
            }
            if !removed.is_empty() {
                remove_backend_set(
                    &mut channels.http,
                    &mut channels.https,
                    cluster_id,
                    &removed,
                    new.config.tls,
                );
                close_http_backend_sessions(
                    &mut channels.http,
                    &mut channels.https,
                    cluster_id,
                    &removed,
                    new.config.tls,
                );
            }
        }
        Protocol::Tcp => {
            l4_diff_backends_in_place(&mut channels.tcp, "tcp", cluster_id, new, &added, &removed)
        }
        Protocol::Udp => {
            l4_diff_backends_in_place(&mut channels.udp, "udp", cluster_id, new, &added, &removed)
        }
    }
}

/// Apply an in-place backend diff to a single L4 (TCP or UDP) listener channel:
/// add new backends before removing departed ones so the cluster never dips
/// below live capacity, leaving the frontend untouched. Backend ids are
/// address-derived (see [`l4_backend_id`]) so add and remove agree regardless of
/// position in the backend list.
fn l4_diff_backends_in_place(
    channels: &mut L4Channels,
    proto: &str,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    added: &[&Backend],
    removed: &[&Backend],
) {
    let Some(listener_name) = entrypoint.config.entrypoint.as_deref() else {
        return;
    };
    let Some(listener) = channels.get_mut(listener_name) else {
        return;
    };
    let channel = &mut listener.channel;

    for backend_entry in added {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                debug!("Failed to parse {proto} backend address {backend_entry} for add: {e}");
                continue;
            }
        };
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let (load_balancing_parameters, backup) = sozu_weight(backend_entry);
        let add = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters,
            sticky_id: None,
            backup,
            unix_path: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-{proto}-{backend_id}"),
            RequestType::AddBackend(add),
        ) {
            debug!("Failed to add {proto} backend {backend_id} (may already exist): {e}");
        }
    }

    for backend_entry in removed {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("rm-backend-{proto}-{backend_id}"),
            RequestType::RemoveBackend(remove),
        ) {
            debug!("Failed to remove {proto} backend {backend_id}: {e}");
        }
        // Sōzu keeps no session for a UDP flow to close.
        if proto == "tcp" {
            close_sessions(channel, proto, cluster_id, Some((backend_id, address)));
        }
    }
}

/// Applies the removals a reload implies, and returns the backends the
/// changed routes lost: their sessions are closed by the caller once the
/// routes are installed again ([`close_departed_sessions`]).
fn apply_routing_diff(
    previous: &RoutingSnapshot,
    current: &RoutingSnapshot,
    channels: &mut Channels,
) -> Vec<DepartedBackends> {
    let mut departed = Vec::new();
    let needed_twins: Vec<RequestHttpFrontend> = current
        .values()
        .filter(|entrypoint| entrypoint.protocol == Protocol::Http)
        .flat_map(|entrypoint| build_acme_twins(entrypoint, channels.http_port))
        .collect();

    // Handle removed clusters
    for (cluster_id, old) in previous {
        if !current.contains_key(cluster_id) {
            info!("Removing stale cluster: {}", cluster_id);
            match old.protocol {
                Protocol::Http => {
                    let https_addr = channels.https_addr();
                    let http_port = channels.http_port;
                    remove_http_frontends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        http_port,
                        https_addr,
                    );
                    remove_backends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        channels.middleware_port,
                    );
                    close_sessions(&mut channels.http, "http", cluster_id, None);
                    if old.config.tls {
                        close_sessions(&mut channels.https, "https", cluster_id, None);
                    }
                    remove_cluster(&mut channels.http, &mut channels.https, cluster_id);

                    if channels.acme_challenge_port.is_some() {
                        remove_acme_twins(
                            &mut channels.http,
                            old,
                            channels.http_port,
                            &needed_twins,
                        );
                        remove_acme_frontends(
                            &mut channels.http,
                            &old.config.hostnames,
                            listener_http_port(old, channels.http_port),
                        );
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(&mut channels.tcp, cluster_id, old);
                    close_tcp_sessions(&mut channels.tcp, cluster_id, old, None);
                }
                Protocol::Udp => {
                    remove_udp_entrypoint(&mut channels.udp, cluster_id, old);
                }
            }
        }
    }

    // Handle changed clusters: full equality on Entrypoint, so any middleware
    // change (headers, redirect, auth, …) is caught.
    for (cluster_id, old) in previous {
        if let Some(new) = current.get(cluster_id)
            && old != new
        {
            // Backends-only change (e.g. scale up/down): keep the live frontend
            // in place and diff just the backends (add-before-remove). Tearing
            // the frontend down here is what opened a 404 window during a
            // rescale. configure_sozu_routing() skips re-adding such clusters
            // (see is_backends_only_change check there), so this is the whole
            // update.
            if is_middleware_only_change(old, new) {
                debug!(
                    "Cluster {} changed for the middleware only: Sōzu keeps it as is",
                    cluster_id
                );
                continue;
            }
            if is_backends_only_change(old, new) {
                info!("Updating backends in place for cluster: {}", cluster_id);
                diff_backends_in_place(channels, cluster_id, old, new);
                continue;
            }

            info!("Updating changed cluster: {}", cluster_id);
            match old.protocol {
                Protocol::Http => {
                    let https_addr = channels.https_addr();
                    let http_port = channels.http_port;
                    remove_http_frontends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        http_port,
                        https_addr,
                    );
                    remove_backends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        channels.middleware_port,
                    );
                    // Only the backends the route no longer has: one it keeps
                    // is re-added, and closing its sessions would cut every
                    // WebSocket on each change to the route. Through the
                    // middleware, Sōzu's backend is the middleware itself.
                    if !middleware::needs_middleware(&old.config) || old.protocol != new.protocol {
                        departed.push(DepartedBackends::new(cluster_id, old, new));
                    }

                    if channels.acme_challenge_port.is_some() {
                        remove_acme_twins(
                            &mut channels.http,
                            old,
                            channels.http_port,
                            &needed_twins,
                        );
                    }
                    if channels.acme_challenge_port.is_some()
                        && (old.config.hostnames != new.config.hostnames
                            || listener_http_port(old, channels.http_port)
                                != listener_http_port(new, channels.http_port))
                    {
                        remove_acme_frontends(
                            &mut channels.http,
                            &old.config.hostnames,
                            listener_http_port(old, channels.http_port),
                        );
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(&mut channels.tcp, cluster_id, old);
                    // With no listener for the new route, nothing replaces
                    // the old one: its sessions are all that is left.
                    let replaced = new.protocol != Protocol::Tcp
                        || new
                            .config
                            .entrypoint
                            .as_deref()
                            .is_some_and(|name| channels.tcp.contains_key(name));
                    if replaced {
                        departed.push(DepartedBackends::new(cluster_id, old, new));
                    }
                }
                Protocol::Udp => {
                    remove_udp_entrypoint(&mut channels.udp, cluster_id, old);
                }
            }
        }
    }
    departed
}

/// [`close_sessions`] for a TCP route on its listener: the sessions of the
/// `departed` backends, or of the whole cluster when it is `None`.
fn close_tcp_sessions(
    tcp_channels: &mut L4Channels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    departed: Option<&[&Backend]>,
) {
    let Some(listener) = entrypoint
        .config
        .entrypoint
        .as_deref()
        .and_then(|name| tcp_channels.get_mut(name))
    else {
        return;
    };
    let channel = &mut listener.channel;
    match departed {
        None => close_sessions(channel, "tcp", cluster_id, None),
        Some(backends) => {
            for backend in backends {
                if let Ok(address) = parse_backend_address(backend) {
                    let id = l4_backend_id(cluster_id, backend);
                    close_sessions(channel, "tcp", cluster_id, Some((id, address)));
                }
            }
        }
    }
}

fn remove_tcp_entrypoint(tcp_channels: &mut L4Channels, cluster_id: &str, entrypoint: &Entrypoint) {
    let Some(listener_name) = entrypoint.config.entrypoint.as_deref() else {
        return;
    };
    let Some(listener) = tcp_channels.get_mut(listener_name) else {
        return;
    };
    let listener_port = listener.port;
    let channel = &mut listener.channel;

    for backend_entry in &entrypoint.backends {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("rm-backend-tcp-{backend_id}"),
            RequestType::RemoveBackend(remove),
        ) {
            debug!("Failed to remove TCP backend {backend_id}: {e}");
        }
    }

    let tcp_front = RequestTcpFrontend {
        cluster_id: cluster_id.to_string(),
        // The Sōzu TCP worker binds loopback (the public port is owned by the
        // pre-accept forwarder), so the frontend address must match: 127.0.0.1,
        // not 0.0.0.0. `listener_port` is the loopback port here.
        address: SocketAddress::new_v4(127, 0, 0, 1, listener_port),
        // Must mirror what `configure_tcp_entrypoint` sent: Sōzu keys a
        // frontend on `(address, sni, alpn)` and a removal whose tuple does
        // not match is a silent no-op, which would leave a stale route behind
        // on every reload.
        sni: entrypoint.config.sni.clone(),
        ..Default::default()
    };
    if let Err(e) = send_to_worker(
        channel,
        format!("rm-frontend-tcp-{}", cluster_id),
        RequestType::RemoveTcpFrontend(tcp_front),
    ) {
        debug!("Failed to remove TCP frontend for {}: {}", cluster_id, e);
    }

    if let Err(e) = send_to_worker(
        channel,
        format!("rm-cluster-tcp-{}", cluster_id),
        RequestType::RemoveCluster(cluster_id.to_string()),
    ) {
        debug!("Failed to remove TCP cluster {}: {}", cluster_id, e);
    }
}

/// Build the per-cluster `answers` map pushed to Sōzu. Unsupported status
/// codes are dropped with a warning; plain-body entries are wrapped into a
/// full HTTP/1.1 response so the worker can parse them. Values that already
/// start with `HTTP/` or `file://` pass through unchanged.
fn build_cluster_answers(
    error_pages: &BTreeMap<String, String>,
    cluster_id: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (code, value) in error_pages {
        if !crate::error_pages::is_supported_status(code) {
            tracing::warn!(
                "cluster {} error_pages: status '{}' is not supported by sozu, ignored",
                cluster_id,
                code
            );
            continue;
        }
        out.insert(
            code.clone(),
            crate::error_pages::wrap_body_into_http_response(code, value),
        );
    }
    out
}

/// Push `error_pages` onto a `ListenerBuilder`. Unsupported status codes are
/// dropped with a warning; plain-body entries are wrapped into a full
/// HTTP/1.1 response so Sōzu can parse them. Values that already start with
/// `HTTP/` or `file://` pass through unchanged.
fn apply_listener_error_pages(
    builder: &mut ListenerBuilder,
    error_pages: &BTreeMap<String, String>,
    listener_label: &str,
) {
    if error_pages.is_empty() {
        return;
    }
    let mut filtered = BTreeMap::new();
    for (code, value) in error_pages {
        if !crate::error_pages::is_supported_status(code) {
            tracing::warn!(
                "{} listener error_pages: status '{}' is not supported by sozu, ignored",
                listener_label,
                code
            );
            continue;
        }
        filtered.insert(
            code.clone(),
            crate::error_pages::wrap_body_into_http_response(code, value),
        );
    }
    if !filtered.is_empty() {
        builder.with_answers(filtered);
    }
}

/// Apply the `http2` config block onto a `ListenerBuilder`. Each field is only
/// touched when set, so leaving the block empty keeps Sōzu's own defaults (ALPN
/// `["h2", "http/1.1"]`, HTTP/1.1 enabled). The auto-DoS combination
/// `disable_http11 = true` with `http/1.1` in the ALPN list is rejected later by
/// `to_tls`, so no validation is duplicated here.
fn apply_listener_http2(builder: &mut ListenerBuilder, http2: &crate::config::Http2Config) {
    if let Some(alpn) = &http2.alpn_protocols {
        builder.with_alpn_protocols(Some(alpn.clone()));
    }
    if let Some(disable) = http2.disable_http11 {
        builder.disable_http11 = Some(disable);
    }
}

/// Apply `proxy.timeouts` onto an HTTP or HTTPS `ListenerBuilder`. Absent
/// fields keep Sōzu's defaults. Zero is refused: Sōzu would arm a timer that
/// fires on the next tick and close every connection as it opens.
fn apply_listener_timeouts(
    builder: &mut ListenerBuilder,
    timeouts: &ProxyTimeouts,
) -> anyhow::Result<()> {
    for (name, value) in [
        ("client_idle", timeouts.client_idle),
        ("backend_idle", timeouts.backend_idle),
        ("backend_connect", timeouts.backend_connect),
        ("request", timeouts.request),
    ] {
        if value == Some(0) {
            anyhow::bail!(
                "`proxy.timeouts.{name}` must be greater than zero (there is no \"never\" value; use a large number of seconds instead)"
            );
        }
    }
    builder
        .with_front_timeout(timeouts.client_idle)
        .with_back_timeout(timeouts.backend_idle)
        .with_connect_timeout(timeouts.backend_connect)
        .with_request_timeout(timeouts.request);
    Ok(())
}

/// Refuse to start on a client CRL already past its `nextUpdate`: the worker
/// would build the listener and then reject every client the CRL covers.
/// Sōzu's main process runs this check on a configuration it loads; Sōzune
/// builds its listeners itself, so it runs it here.
fn check_client_crls_current(
    listener: &sozu_command_lib::proto::command::HttpsListenerConfig,
    now: i64,
) -> anyhow::Result<()> {
    sozu_lib::https::HttpsListener::check_crls_current(&listener.client_ca_crls, now)
        .map_err(|e| anyhow::anyhow!("Invalid `proxy.https.tls.client_auth.crl_files`: {e}"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Apply a TCP listener's `idle_timeout` onto a `ListenerBuilder`.
///
/// Sōzu keeps two timers per TCP session, one per side, and a byte read on
/// either side re-arms both. Whichever is shorter therefore decides how long a
/// connection may stay silent, so a single value is written to both. `None`
/// leaves Sōzu's defaults in place. Zero is refused: Sōzu would arm a timer
/// that fires on the next tick and close every connection as it opens.
fn apply_tcp_listener_idle_timeout(
    builder: &mut ListenerBuilder,
    idle_timeout: Option<u32>,
) -> anyhow::Result<()> {
    let Some(seconds) = idle_timeout else {
        return Ok(());
    };
    if seconds == 0 {
        anyhow::bail!(
            "`idle_timeout` must be greater than zero (there is no \"never\" value; use a large number of seconds instead)"
        );
    }
    builder
        .with_front_timeout(Some(seconds))
        .with_back_timeout(Some(seconds));
    Ok(())
}

/// Parse a config TLS version string (`"1.2"` / `"1.3"`) into Sōzu's enum.
fn parse_tls_version(s: &str) -> anyhow::Result<TlsVersion> {
    match s {
        "1.2" => Ok(TlsVersion::TlsV12),
        "1.3" => Ok(TlsVersion::TlsV13),
        other => anyhow::bail!("unsupported TLS version `{other}` (accepted: \"1.2\", \"1.3\")"),
    }
}

/// Apply listener-wide TLS options (versions, ciphers) to the HTTPS builder.
///
/// Sōzu takes an explicit *list* of enabled versions, not a range, so a
/// `min`/`max` pair is expanded into the versions it spans. Only 1.2 and 1.3
/// are in play (Sōzune never enables older ones), which keeps the expansion to
/// three cases. A `max < min` pair is rejected rather than silently emptied.
fn apply_listener_tls_options(
    builder: &mut ListenerBuilder,
    tls: &crate::config::TlsOptions,
) -> anyhow::Result<()> {
    let min = tls
        .min_version
        .as_deref()
        .map(parse_tls_version)
        .transpose()?;
    let max = tls
        .max_version
        .as_deref()
        .map(parse_tls_version)
        .transpose()?;

    // Only touch versions when the operator pinned at least one bound; absent
    // leaves Sōzu's default (`[TlsV12, TlsV13]`).
    if min.is_some() || max.is_some() {
        // Default the open bound to the widest Sōzune supports.
        let lo = min.unwrap_or(TlsVersion::TlsV12) as i32;
        let hi = max.unwrap_or(TlsVersion::TlsV13) as i32;
        if hi < lo {
            anyhow::bail!(
                "TLS max_version must be >= min_version (got min={:?}, max={:?})",
                tls.min_version,
                tls.max_version
            );
        }
        let versions: Vec<TlsVersion> = [TlsVersion::TlsV12, TlsVersion::TlsV13]
            .into_iter()
            .filter(|v| {
                let n = *v as i32;
                n >= lo && n <= hi
            })
            .collect();
        builder.with_tls_versions(versions);
    }

    // Sōzu reads ciphers only from `cipher_list` (TLS 1.2 and 1.3 alike, by
    // rustls name); its `cipher_suites` field is never consulted by the worker,
    // so everything goes through this one call.
    if let Some(ciphers) = &tls.ciphers {
        builder.with_cipher_list(Some(ciphers.clone()));
    }

    // Sōzu reads the CA and CRL files itself when the listener is built and
    // refuses to start on one it cannot read, rather than drop a CA or a CRL.
    if let Some(client_auth) = &tls.client_auth {
        use crate::config::ClientAuthMode;
        use sozu_command_lib::config::ClientAuthConfig;
        if client_auth.mode != ClientAuthMode::None && client_auth.ca_files.is_empty() {
            anyhow::bail!(
                "`proxy.https.tls.client_auth.ca_files` is empty: mode `{}` needs at least one CA to check client certificates against",
                client_auth.mode.as_str()
            );
        }
        builder.client_auth = Some(match client_auth.mode {
            ClientAuthMode::None => ClientAuthConfig::None,
            ClientAuthMode::Optional => ClientAuthConfig::Optional,
            ClientAuthMode::Required => ClientAuthConfig::Required,
        });
        builder.client_ca_certificates = Some(client_auth.ca_files.clone());
        builder.client_ca_crls = Some(client_auth.crl_files.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Http2Config;
    use crate::model::{Backend, EntrypointConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
    use tokio::time::{sleep, timeout};

    /// A real Sōzu HTTP worker on a loopback port: its command channel, and
    /// a receiver told when its thread ends.
    fn http_worker() -> (
        Channel<WorkerRequest, WorkerResponse>,
        std::sync::mpsc::Receiver<()>,
    ) {
        let port = pick_loopback_port().unwrap();
        let listener = ListenerBuilder::new_http(SocketAddress::new_v4(127, 0, 0, 1, port))
            .to_http(None)
            .unwrap();
        let (mut command, proxy) = Channel::generate(1000, 1_000_000).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = worker::start_http_worker(listener, proxy, 100, 16384);
            let _ = done_tx.send(());
        });
        wait_for_worker_ready(&mut command, "test", Duration::from_secs(5)).unwrap();
        (command, done_rx)
    }

    /// Send a command and leave its answer unread, as `send_to_worker` does
    /// once it gave up waiting.
    fn send_unanswered(command: &mut Channel<WorkerRequest, WorkerResponse>) {
        command
            .write_message(&WorkerRequest {
                id: "unanswered".into(),
                content: Request {
                    request_type: Some(RequestType::Status(
                        sozu_command_lib::proto::command::Status {},
                    )),
                },
            })
            .unwrap();
        // Long enough for the answer to land in our end of the channel.
        thread::sleep(Duration::from_millis(300));
    }

    /// A worker whose command channel holds an answer we never read sees
    /// the channel's closing as an error, not a close, and keeps running: told
    /// to stop, it stops all the same.
    #[test]
    fn a_worker_told_to_stop_stops_with_an_answer_unread() {
        let (mut command, done) = http_worker();
        send_unanswered(&mut command);
        stop_worker(&mut command, "test");
        drop(command);
        assert!(done.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    fn tls_listener_with_http2(
        http2: &Http2Config,
    ) -> sozu_command_lib::proto::command::HttpsListenerConfig {
        let mut builder = ListenerBuilder::new_https(SocketAddress::new_v4(0, 0, 0, 0, 8443));
        apply_listener_http2(&mut builder, http2);
        builder.to_tls(None).expect("to_tls should succeed")
    }

    fn tls_listener_with_options(
        tls: &crate::config::TlsOptions,
    ) -> anyhow::Result<sozu_command_lib::proto::command::HttpsListenerConfig> {
        let mut builder = ListenerBuilder::new_https(SocketAddress::new_v4(0, 0, 0, 0, 8443));
        apply_listener_tls_options(&mut builder, tls)?;
        builder
            .to_tls(None)
            .map_err(|e| anyhow::anyhow!("to_tls: {e}"))
    }

    fn tcp_listener_with_idle_timeout(
        idle_timeout: Option<u32>,
    ) -> anyhow::Result<sozu_command_lib::proto::command::TcpListenerConfig> {
        let mut builder = ListenerBuilder::new_tcp(SocketAddress::new_v4(127, 0, 0, 1, 5432));
        apply_tcp_listener_idle_timeout(&mut builder, idle_timeout)?;
        builder
            .to_tcp(None)
            .map_err(|e| anyhow::anyhow!("to_tcp: {e}"))
    }

    #[test]
    fn tcp_idle_timeout_unset_keeps_sozu_defaults() {
        let cfg = tcp_listener_with_idle_timeout(None).unwrap();
        assert_eq!(
            cfg.front_timeout,
            sozu_command_lib::config::DEFAULT_FRONT_TIMEOUT
        );
        assert_eq!(
            cfg.back_timeout,
            sozu_command_lib::config::DEFAULT_BACK_TIMEOUT
        );
    }

    #[test]
    fn tcp_idle_timeout_sets_both_sides() {
        // Either timer closes the session, so raising only one would leave
        // the other's default in charge.
        let cfg = tcp_listener_with_idle_timeout(Some(3600)).unwrap();
        assert_eq!(cfg.front_timeout, 3600);
        assert_eq!(cfg.back_timeout, 3600);
    }

    #[test]
    fn tcp_idle_timeout_leaves_connect_timeout_alone() {
        let cfg = tcp_listener_with_idle_timeout(Some(3600)).unwrap();
        assert_eq!(
            cfg.connect_timeout,
            sozu_command_lib::config::DEFAULT_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn tcp_idle_timeout_zero_is_refused() {
        let err = tcp_listener_with_idle_timeout(Some(0)).unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "{err}");
    }

    /// At equal priority the more specific route is tried first: an exact
    /// host before a wildcard before any host, an exact path before a prefix,
    /// a longer prefix before a shorter one. Priority still comes first.
    #[test]
    fn routes_of_equal_priority_go_most_specific_first() {
        assert_eq!(regex_literal_prefix("^/api/v[0-9]+"), "/api/v");
        assert_eq!(regex_literal_prefix("^/.*"), "/");
        // An alternative may match anything: no more specific than `/`.
        let alternation = crate::model::PathConfig {
            rule_type: crate::model::PathRuleType::Regex,
            value: "^/longpath$|^/.*".into(),
        };
        assert_eq!(path_specificity(Some(&alternation)), path_specificity(None));
        let http = |id: &str,
                    host: &str,
                    path: Option<(crate::model::PathRuleType, &str)>,
                    priority: i32| {
            let mut ep = base_ep(vec![Backend::new("10.0.0.1", 80)]);
            ep.id = id.into();
            ep.config.hostnames = vec![host.into()];
            ep.config.path = path.map(|(rule_type, value)| crate::model::PathConfig {
                rule_type,
                value: value.into(),
            });
            ep.config.priority = priority;
            (id.to_string(), ep)
        };
        let storage: BTreeMap<String, Entrypoint> = [
            http("a-any", "*", None, 0),
            http("b-wildcard", "*.example.com", None, 0),
            http("c-root", "app.example.com", None, 0),
            http(
                "d-api",
                "app.example.com",
                Some((crate::model::PathRuleType::Prefix, "/api")),
                0,
            ),
            http(
                "e-exact",
                "app.example.com",
                Some((crate::model::PathRuleType::Exact, "/a")),
                0,
            ),
            http("f-boosted", "*", None, 10),
            http(
                "g-regex",
                "app.example.com",
                Some((crate::model::PathRuleType::Regex, "^/.*")),
                0,
            ),
        ]
        .into_iter()
        .collect();
        let order: Vec<&str> = routing_order(&storage)
            .into_iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "f-boosted",
                "e-exact",
                "d-api",
                "c-root",
                "g-regex",
                "b-wildcard",
                "a-any"
            ]
        );
    }

    /// A route with no valid backend answers 500 only to the requests its
    /// conditions match: the match check runs first.
    #[test]
    fn a_fixed_answer_comes_after_the_match_check() {
        let mut ep = base_ep(Vec::new());
        ep.config.answer = Some(crate::model::FixedAnswer::InvalidBackends);
        // A condition Sōzu cannot route on, left to the middleware.
        ep.config.match_headers = vec![crate::model::MatchCondition {
            key: "Cookie".into(),
            value: "beta=1".into(),
            regex: false,
        }];
        assert!(middleware::needs_middleware(&ep.config));
        let route = middleware::build_middleware_route(
            "c",
            &ep.config,
            &ep.backends,
            &middleware::build_forward_auth_client(),
            &middleware::PluginRegistry::new(),
            &middleware::ip_allow_list::TrustedProxies::default(),
        );
        let names: Vec<&str> = route.middlewares.iter().map(|m| m.name()).collect();
        let matched = names.iter().position(|n| *n == "request-match");
        let invalid = names.iter().position(|n| *n == "fixed-answer");
        assert!(matched.is_some() && matched < invalid, "{names:?}");
    }

    /// Sōzu routes on query conditions in the path rule, in any order and
    /// whatever other parameters the query carries.
    #[test]
    fn query_conditions_are_routed_by_sozu() {
        use crate::model::{MatchCondition, PathConfig, PathRewrite, PathRuleType, UrlRewrite};
        use sozu_lib::router::{PathRule as SozuPathRule, PathRuleResult};
        let condition = |key: &str, value: &str| MatchCondition {
            key: key.into(),
            value: value.into(),
            regex: false,
        };
        let mut ep = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        ep.config.match_query = vec![condition("animal", "dolphin"), condition("color", "blue")];
        let matches = |config: &crate::model::EntrypointConfig, path: &str| {
            let rule = builders::query_path_rule(config).expect("routed by Sōzu");
            SozuPathRule::from_config(rule)
                .is_some_and(|r| r.matches(path.as_bytes()) != PathRuleResult::None)
        };
        assert!(matches(&ep.config, "/?animal=dolphin&color=blue"));
        assert!(matches(&ep.config, "/x?color=blue&animal=dolphin"));
        assert!(matches(
            &ep.config,
            "/?a=1&color=blue&b=2&animal=dolphin&c=3"
        ));
        assert!(!matches(&ep.config, "/?animal=dolphin"));
        assert!(!matches(&ep.config, "/?animal=dolphins&color=blue"));
        assert!(!matches(&ep.config, "/?ANIMAL=dolphin&color=blue"));
        assert!(!matches(&ep.config, "/"));
        // Compared decoded, as the middleware does.
        assert!(matches(&ep.config, "/?animal=dolph%69n&%63olor=blue"));
        assert!(matches(&ep.config, "/?animal=dolph%69n&color=blu%65"));

        // One parameter meets a repeated condition, and a presence check on
        // its key.
        ep.config.match_query = vec![condition("v", "2"), condition("v", "2"), condition("v", "")];
        assert!(matches(&ep.config, "/?v=2"));
        ep.config.match_query = vec![condition("v", ""), condition("v", "2")];
        assert!(matches(&ep.config, "/?v=2"));
        assert!(!matches(&ep.config, "/?v=3"));

        // A value may hold a raw `=`, as the middleware splits on the first.
        ep.config.match_query = vec![condition("token", "a=b")];
        assert!(matches(&ep.config, "/?token=a=b"));
        assert!(matches(&ep.config, "/?token=a%3Db"));

        ep.config.match_query = vec![condition("q", "a&b")];
        assert!(matches(&ep.config, "/?q=a%26b"));
        assert!(!matches(&ep.config, "/?q=a&b"));

        ep.config.match_query = vec![condition("debug", "")];
        ep.config.path = Some(PathConfig {
            rule_type: PathRuleType::Prefix,
            value: "/api".into(),
        });
        assert!(matches(&ep.config, "/api/x?debug"));
        assert!(matches(&ep.config, "/api?debug=1"));
        assert!(!matches(&ep.config, "/apix?debug"));
        assert!(!matches(&ep.config, "/api?debugger=1"));
        assert!(routes_on_query(&ep.config));
        assert!(!middleware::needs_middleware(&ep.config));

        // A `%` in a condition: the middleware keeps the query conditions.
        ep.config.match_query = vec![condition("q", "100%")];
        assert!(builders::query_path_rule(&ep.config).is_none());
        ep.config.match_query = vec![condition("debug", "")];

        // A path rewrite captures parts of the path: the middleware keeps
        // the query conditions.
        ep.config.rewrite = Some(UrlRewrite {
            path: Some(PathRewrite::ReplacePrefixMatch("/v2".into())),
            hostname: None,
        });
        assert!(builders::query_path_rule(&ep.config).is_none());
        assert!(middleware::needs_middleware(&ep.config));
    }

    /// An HTTPS-only route has no frontend on the HTTP listener.
    #[test]
    fn an_https_only_route_skips_the_http_listener() {
        let mut ep = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        ep.config.tls = true;
        ep.config.https_only = true;
        let listeners: Vec<FrontListener> =
            build_http_frontends("c", &ep, 80, SocketAddress::new_v4(0, 0, 0, 0, 443))
                .into_iter()
                .map(|(listener, _)| listener)
                .collect();
        assert!(!listeners.is_empty());
        assert!(listeners.iter().all(|l| *l == FrontListener::Https));
    }

    /// A wildcard taking any number of labels ranks as the `*.` one.
    #[test]
    fn an_any_labels_wildcard_ranks_as_a_wildcard() {
        assert_eq!(
            host_specificity(&[crate::model::any_labels_wildcard("*.example.com")]),
            host_specificity(&["*.example.com".to_string()])
        );
    }

    /// On the same host and path, a route on methods goes first, then the
    /// one with more header conditions Sōzu routes on. Query conditions and
    /// headers left to the middleware do not count.
    #[test]
    fn methods_and_headers_break_ties_on_host_and_path() {
        use crate::model::MatchCondition;
        let condition = |key: &str, value: &str| MatchCondition {
            key: key.into(),
            value: value.into(),
            regex: false,
        };
        let route = |id: &str, methods: &[&str], headers: Vec<MatchCondition>, query: usize| {
            let mut ep = base_ep(vec![Backend::new("10.0.0.1", 80)]);
            ep.id = id.into();
            ep.config.hostnames = vec!["app.example.com".into()];
            ep.config.methods = methods.iter().map(|m| m.to_string()).collect();
            ep.config.match_headers = headers;
            ep.config.match_query = (0..query)
                .map(|i| condition(&format!("q{i}"), "1"))
                .collect();
            (id.to_string(), ep)
        };
        let storage: BTreeMap<String, Entrypoint> = [
            route("a-plain", &[], Vec::new(), 2),
            route("b-one-header", &[], vec![condition("Version", "two")], 0),
            route(
                "c-two-headers",
                &[],
                vec![condition("Version", "two"), condition("Color", "orange")],
                0,
            ),
            route("d-cookie", &[], vec![condition("Cookie", "beta=1")], 0),
            route("e-method", &["GET"], Vec::new(), 0),
        ]
        .into_iter()
        .collect();
        let order: Vec<&str> = routing_order(&storage)
            .into_iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "e-method",
                "c-two-headers",
                "b-one-header",
                "a-plain",
                "d-cookie"
            ]
        );
    }

    /// Only exact hostnames get an ACME challenge frontend.
    #[test]
    fn acme_challenges_are_only_routed_for_exact_hostnames() {
        let hostnames: Vec<String> = [
            "*",
            "*.example.com",
            "/api[0-9]/.example.com",
            "app.example.com",
        ]
        .iter()
        .map(|h| h.to_string())
        .collect();
        assert_eq!(
            acme_hostnames(&hostnames).collect::<Vec<_>>(),
            ["app.example.com"]
        );
    }

    /// A certificate two senders added stays until both removed it.
    #[test]
    fn a_certificate_is_dropped_by_its_last_holder() {
        let mut holders = HashMap::from([("ab".to_string(), 2)]);
        assert!(!release_certificate(&mut holders, "ab"));
        assert!(release_certificate(&mut holders, "ab"));
        // Still counted until the worker confirms the removal.
        assert_eq!(holders.get("ab"), Some(&1));
        // One no sender was counted for is dropped.
        assert!(release_certificate(&mut holders, "cd"));
    }

    /// The TLS gate sends the passthrough listener the SNIs of its routes,
    /// and no other listener's.
    #[test]
    fn passthrough_hosts_are_the_snis_of_its_routes() {
        let route = |id: &str, listener: &str, sni: Option<&str>| {
            (id.to_string(), tcp_ep(id, listener, sni))
        };
        let live: RoutingSnapshot = [
            route(
                "a",
                crate::config::HTTPS_PASSTHROUGH_LISTENER,
                Some("A.example.com"),
            ),
            route(
                "b",
                crate::config::HTTPS_PASSTHROUGH_LISTENER,
                Some("*.b.example.com"),
            ),
            route("c", "tlsgw", Some("c.example.com")),
            route("d", crate::config::HTTPS_PASSTHROUGH_LISTENER, None),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            passthrough_hosts(&live),
            vec!["*.b.example.com".to_string(), "a.example.com".to_string()]
        );
    }

    /// A declared listener cannot take the name of one a Gateway opens, or a
    /// Gateway route would be installed on it, whatever its port.
    #[test]
    fn gateway_listener_names_are_reserved() {
        let mut config = ProxyConfig::default();
        config.tcp = vec![crate::config::TcpListenerConfig {
            name: crate::config::gateway_tcp_listener(9000),
            listen: 7000,
            ip_allow_list: Vec::new(),
            rate_limit: None,
            sni_preread_timeout: None,
            sni_preread_max_bytes: None,
            idle_timeout: None,
        }];
        let err = spawn_tcp_workers(&config).err().unwrap();
        assert!(err.to_string().contains("reserved"), "{err}");

        config.tcp[0].name = crate::config::HTTPS_PASSTHROUGH_LISTENER.to_string();
        let err = spawn_tcp_workers(&config).err().unwrap();
        assert!(err.to_string().contains("reserved"), "{err}");

        let mut config = ProxyConfig::default();
        config.udp = vec![crate::config::UdpListenerConfig {
            name: crate::config::gateway_udp_listener(53),
            listen: 5300,
        }];
        let err = spawn_udp_workers(&config).err().unwrap();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    fn http_listener_with_timeouts(
        timeouts: ProxyTimeouts,
    ) -> anyhow::Result<sozu_command_lib::proto::command::HttpListenerConfig> {
        let mut builder = ListenerBuilder::new_http(SocketAddress::new_v4(0, 0, 0, 0, 8080));
        apply_listener_timeouts(&mut builder, &timeouts)?;
        builder
            .to_http(None)
            .map_err(|e| anyhow::anyhow!("to_http: {e}"))
    }

    #[test]
    fn proxy_timeouts_unset_keep_sozu_defaults() {
        use sozu_command_lib::config::{
            DEFAULT_BACK_TIMEOUT, DEFAULT_CONNECT_TIMEOUT, DEFAULT_FRONT_TIMEOUT,
            DEFAULT_REQUEST_TIMEOUT,
        };
        let cfg = http_listener_with_timeouts(Default::default()).unwrap();
        assert_eq!(cfg.front_timeout, DEFAULT_FRONT_TIMEOUT);
        assert_eq!(cfg.back_timeout, DEFAULT_BACK_TIMEOUT);
        assert_eq!(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    }

    #[test]
    fn proxy_timeouts_reach_the_listener() {
        let cfg = http_listener_with_timeouts(ProxyTimeouts {
            client_idle: Some(300),
            backend_idle: Some(120),
            backend_connect: Some(5),
            request: Some(20),
        })
        .unwrap();
        assert_eq!(cfg.front_timeout, 300);
        assert_eq!(cfg.back_timeout, 120);
        assert_eq!(cfg.connect_timeout, 5);
        assert_eq!(cfg.request_timeout, 20);
    }

    #[test]
    fn a_zero_proxy_timeout_is_refused() {
        let err = http_listener_with_timeouts(ProxyTimeouts {
            backend_idle: Some(0),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("proxy.timeouts.backend_idle"),
            "{err}"
        );
    }

    #[test]
    fn http2_default_advertises_h2_and_http11() {
        let cfg = tls_listener_with_http2(&Http2Config::default());
        assert!(cfg.alpn_protocols.iter().any(|p| p == "h2"));
        assert!(cfg.alpn_protocols.iter().any(|p| p == "http/1.1"));
    }

    #[test]
    fn tls_options_default_leaves_both_versions() {
        // No bound pinned → Sōzu's default (1.2 + 1.3) stays.
        let cfg = tls_listener_with_options(&crate::config::TlsOptions::default()).unwrap();
        assert!(cfg.versions.contains(&(TlsVersion::TlsV12 as i32)));
        assert!(cfg.versions.contains(&(TlsVersion::TlsV13 as i32)));
    }

    #[test]
    fn tls_min_1_3_drops_1_2() {
        let tls = crate::config::TlsOptions {
            min_version: Some("1.3".into()),
            ..Default::default()
        };
        let cfg = tls_listener_with_options(&tls).unwrap();
        assert_eq!(cfg.versions, vec![TlsVersion::TlsV13 as i32]);
    }

    #[test]
    fn tls_max_1_2_drops_1_3() {
        let tls = crate::config::TlsOptions {
            max_version: Some("1.2".into()),
            ..Default::default()
        };
        let cfg = tls_listener_with_options(&tls).unwrap();
        assert_eq!(cfg.versions, vec![TlsVersion::TlsV12 as i32]);
    }

    #[test]
    fn tls_max_below_min_is_rejected() {
        let tls = crate::config::TlsOptions {
            min_version: Some("1.3".into()),
            max_version: Some("1.2".into()),
            ..Default::default()
        };
        let err = tls_listener_with_options(&tls).unwrap_err();
        assert!(
            err.to_string()
                .contains("max_version must be >= min_version")
        );
    }

    #[test]
    fn tls_unknown_version_is_rejected() {
        let tls = crate::config::TlsOptions {
            min_version: Some("1.1".into()),
            ..Default::default()
        };
        let err = tls_listener_with_options(&tls).unwrap_err();
        assert!(err.to_string().contains("unsupported TLS version"));
    }

    #[test]
    fn tls_ciphers_are_forwarded_as_cipher_list() {
        // rustls names, and forwarded to `cipher_list` — the only cipher field
        // Sōzu's worker actually reads.
        let tls = crate::config::TlsOptions {
            ciphers: Some(vec!["TLS13_AES_256_GCM_SHA384".into()]),
            ..Default::default()
        };
        let cfg = tls_listener_with_options(&tls).unwrap();
        assert_eq!(
            cfg.cipher_list,
            vec!["TLS13_AES_256_GCM_SHA384".to_string()]
        );
    }

    fn client_auth_options(
        mode: crate::config::ClientAuthMode,
        ca_files: Vec<String>,
    ) -> crate::config::TlsOptions {
        crate::config::TlsOptions {
            client_auth: Some(crate::config::ClientAuth {
                mode,
                ca_files,
                crl_files: Vec::new(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn client_auth_reaches_the_listener_with_its_ca_inlined() {
        let dir = tempfile::tempdir().unwrap();
        let ca = rcgen::KeyPair::generate()
            .and_then(|key| {
                let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.self_signed(&key)
            })
            .unwrap()
            .pem();
        let ca_path = dir.path().join("client-ca.pem");
        std::fs::write(&ca_path, &ca).unwrap();

        let tls = client_auth_options(
            crate::config::ClientAuthMode::Required,
            vec![ca_path.display().to_string()],
        );
        let cfg = tls_listener_with_options(&tls).unwrap();
        assert_eq!(
            cfg.client_auth,
            Some(sozu_command_lib::proto::command::ClientAuthMode::ClientAuthRequired as i32)
        );
        assert_eq!(cfg.client_ca_certificates, vec![ca]);
    }

    #[test]
    fn an_expired_client_crl_fails_the_listener() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::new(ca, key);
        let crl = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2021, 1, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap()
        .pem()
        .unwrap();
        let listener = sozu_command_lib::proto::command::HttpsListenerConfig {
            client_ca_crls: vec![crl],
            ..Default::default()
        };

        // 2020-06-01, before its nextUpdate.
        assert!(check_client_crls_current(&listener, 1_590_969_600).is_ok());
        let err = check_client_crls_current(&listener, unix_now()).unwrap_err();
        assert!(err.to_string().contains("crl_files"), "{err}");
    }

    #[test]
    fn client_auth_without_a_ca_is_refused() {
        let tls = client_auth_options(crate::config::ClientAuthMode::Optional, Vec::new());
        let err = tls_listener_with_options(&tls).unwrap_err();
        assert!(err.to_string().contains("client_auth.ca_files"), "{err}");
    }

    #[test]
    fn an_unreadable_client_ca_fails_the_listener() {
        let tls = client_auth_options(
            crate::config::ClientAuthMode::Required,
            vec!["/nonexistent/client-ca.pem".into()],
        );
        assert!(tls_listener_with_options(&tls).is_err());
    }

    #[test]
    fn http2_alpn_override_forces_http11_only() {
        let http2 = Http2Config {
            alpn_protocols: Some(vec!["http/1.1".into()]),
            disable_http11: None,
        };
        let cfg = tls_listener_with_http2(&http2);
        assert_eq!(cfg.alpn_protocols, vec!["http/1.1".to_string()]);
        assert!(!cfg.alpn_protocols.iter().any(|p| p == "h2"));
    }

    #[test]
    fn http2_disable_http11_is_propagated() {
        let http2 = Http2Config {
            alpn_protocols: Some(vec!["h2".into()]),
            disable_http11: Some(true),
        };
        let cfg = tls_listener_with_http2(&http2);
        assert_eq!(cfg.disable_http11, Some(true));
        assert_eq!(cfg.alpn_protocols, vec!["h2".to_string()]);
    }

    /// A TCP entrypoint on `listener`, SNI-routed when `sni` is `Some`.
    pub(super) fn tcp_ep(name: &str, listener: &str, sni: Option<&str>) -> Entrypoint {
        let mut ep = base_ep(vec![Backend::new("10.0.0.1", 5432)]);
        ep.id = name.into();
        ep.name = name.into();
        ep.protocol = Protocol::Tcp;
        ep.config.hostnames = Vec::new();
        ep.config.entrypoint = Some(listener.into());
        ep.config.sni = sni.map(str::to_string);
        ep
    }

    fn storage_of(entrypoints: Vec<Entrypoint>) -> BTreeMap<String, Entrypoint> {
        entrypoints
            .into_iter()
            .map(|ep| (ep.id.clone(), ep))
            .collect()
    }

    #[test]
    fn all_sni_on_one_listener_is_not_a_clash() {
        let storage = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("b", "gateway", Some("b.example.com")),
        ]);
        assert!(tcp_sni_mode_clashes(&storage).is_empty());
    }

    #[test]
    fn all_catch_all_on_one_listener_is_not_a_clash() {
        // The pre-2.2.0 shape: one listener, one cluster, no SNI anywhere.
        let storage = storage_of(vec![tcp_ep("a", "gateway", None)]);
        assert!(tcp_sni_mode_clashes(&storage).is_empty());
    }

    /// Just the names on the minority side, for readable assertions.
    fn clash_names(storage: &BTreeMap<String, Entrypoint>, listener: &str) -> Vec<String> {
        tcp_sni_mode_clashes(storage)
            .get(listener)
            .map(|offenders| offenders.iter().map(|(_, name)| name.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn mixing_sni_and_catch_all_on_one_listener_is_reported() {
        let storage = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("b", "gateway", Some("b.example.com")),
            tcp_ep("legacy", "gateway", None),
        ]);
        // The lone catch-all is the minority, so it is what we name.
        assert_eq!(clash_names(&storage, "gateway"), vec!["legacy".to_string()]);
    }

    #[test]
    fn clash_names_the_smaller_side() {
        let storage = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("x", "gateway", None),
            tcp_ep("y", "gateway", None),
        ]);
        assert_eq!(clash_names(&storage, "gateway"), vec!["a".to_string()]);
    }

    #[test]
    fn clashing_entrypoints_are_skipped_by_cluster_id() {
        // The skip list is keyed by cluster id, not name — that is what the
        // reload loop and the snapshot are indexed on.
        let storage = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("legacy", "gateway", None),
        ]);
        let skipped = skipped_on_sni_clash(&storage);
        assert!(skipped.contains("legacy"));
        assert!(!skipped.contains("a"));
    }

    #[test]
    fn a_clean_listener_skips_nothing() {
        let storage = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("b", "gateway", Some("b.example.com")),
        ]);
        assert!(skipped_on_sni_clash(&storage).is_empty());
    }

    /// The production failure this guards, as a state machine over two reloads.
    ///
    /// Reload 1 runs the departing and arriving containers side by side under
    /// one hostname. Sōzu refuses the arriving frontend as a duplicate. If that
    /// rejection is swallowed, the arriving entrypoint is written to the
    /// snapshot as live; reload 2 then finds it unchanged, skips it, and never
    /// retries the add — so when the departing cluster is torn down the
    /// hostname is left with backends and no frontend of its own, and no later
    /// reload repairs it.
    ///
    /// This asserts the skip conditions themselves, so a fourth skip path that
    /// swallowed the retry would fail here rather than pass unnoticed.
    #[test]
    fn a_rejected_frontend_is_reapplied_on_the_next_reload() {
        let entrypoint = base_ep(vec![Backend::new("10.0.0.2", 80)]);

        // Reload 1 rejected the add, so the entrypoint is kept out of the
        // snapshot reload 2 diffs against.
        let mut previous = RoutingSnapshot::new();
        previous.insert("app_new".to_string(), entrypoint.clone());
        let mut skipped = BTreeSet::new();
        note_frontend_outcome("app_new", FrontendOutcome::Rejected, &mut skipped);
        for cluster_id in &skipped {
            previous.remove(cluster_id);
        }

        // Reload 2, against configure_sozu_routing's three skip conditions.
        assert!(
            !skipped_on_sni_clash(&previous).contains("app_new"),
            "no SNI clash, so that guard must not hold the retry back"
        );
        assert_ne!(
            previous.get("app_new"),
            Some(&entrypoint),
            "an unchanged entrypoint is skipped — this is the equality the drop breaks"
        );
        assert!(
            !previous.contains_key("app_new"),
            "with no previous entry the backends-only branch cannot fire either"
        );
    }

    /// The converse, so the fix cannot degrade into "never record anything":
    /// an entrypoint whose frontends landed stays in the snapshot, and reload 2
    /// leaves it alone instead of re-adding a frontend Sōzu would then reject
    /// as a duplicate — the very loop this code avoids elsewhere.
    #[test]
    fn an_installed_frontend_stays_in_the_snapshot() {
        let entrypoint = base_ep(vec![Backend::new("10.0.0.2", 80)]);

        let mut previous = RoutingSnapshot::new();
        previous.insert("app_new".to_string(), entrypoint.clone());
        let mut skipped = BTreeSet::new();
        note_frontend_outcome("app_new", FrontendOutcome::Installed, &mut skipped);
        for cluster_id in &skipped {
            previous.remove(cluster_id);
        }

        assert_eq!(
            previous.get("app_new"),
            Some(&entrypoint),
            "an installed entrypoint stays live, so reload 2 skips it"
        );
    }

    /// A rejection on any one frontend condemns the whole entrypoint, because
    /// the snapshot records entrypoints, not individual frontends: a partially
    /// installed entrypoint recorded as live would strand the frontends that
    /// were refused.
    /// The HTTP fix, restated for L4: an entrypoint whose frontend Sōzu refused
    /// must stay out of the snapshot whatever its protocol, or the next reload
    /// finds it unchanged, skips it, and the route stays dead for good.
    ///
    /// This walks the reload the same way the HTTP test does, but for a TCP
    /// entrypoint — the protocol is not what decides whether a rejection can be
    /// retried.
    #[test]
    fn a_rejected_tcp_frontend_is_reapplied_on_the_next_reload() {
        let entrypoint = tcp_ep("db", "gateway", Some("db.example.com"));

        let mut previous = RoutingSnapshot::new();
        previous.insert("db".to_string(), entrypoint.clone());
        let mut skipped = BTreeSet::new();
        note_frontend_outcome("db", FrontendOutcome::Rejected, &mut skipped);
        for cluster_id in &skipped {
            previous.remove(cluster_id);
        }

        assert_ne!(
            previous.get("db"),
            Some(&entrypoint),
            "an unchanged entrypoint is skipped — this is the equality the drop breaks"
        );
    }

    /// Guards the wiring rather than the helper: every protocol arm of
    /// `configure_sozu_routing` must be able to report a rejection, so a
    /// protocol that silently returns `()` cannot slip back in. A `()` return
    /// makes this fail to compile, which is the point.
    #[test]
    fn every_protocol_reports_whether_its_frontend_landed() {
        fn assert_reports(_: fn(&mut L4Channels, &str, &Entrypoint) -> FrontendOutcome) {}

        assert_reports(configure_tcp_entrypoint);
        assert_reports(configure_udp_entrypoint);
    }

    /// A reload that dies partway must not leave the survivors recorded as live.
    ///
    /// `configure_sozu_routing` walks entrypoints in priority order and gives
    /// up on the first hard error — today a malformed backend address. Whatever
    /// it had not reached yet was never sent to a worker, but the snapshot was
    /// still returned whole, so the next reload found those entrypoints
    /// unchanged, skipped them, and never applied them. The higher the priority
    /// of the broken entrypoint, the more routes go with it.
    ///
    /// `applied` names what actually reached a worker, so the caller can keep
    /// the rest out of the snapshot and let the following reload retry them.
    #[test]
    fn a_failed_reload_keeps_unsent_entrypoints_out_of_the_snapshot() {
        let reached = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let never_reached = base_ep(vec![Backend::new("10.0.0.2", 80)]);

        let mut snapshot = RoutingSnapshot::new();
        snapshot.insert("high_priority".to_string(), reached.clone());
        snapshot.insert("low_priority".to_string(), never_reached);

        // The reload died after the first entrypoint, so only that one landed.
        let applied = BTreeSet::from(["high_priority".to_string()]);
        retain_applied(&mut snapshot, &applied);

        assert_eq!(
            snapshot.get("high_priority"),
            Some(&reached),
            "an entrypoint that reached a worker stays live"
        );
        assert!(
            !snapshot.contains_key("low_priority"),
            "an entrypoint the reload never reached must be retried, not recorded"
        );
    }

    /// A reload that ran to the end records everything it applied, so the next
    /// one skips the unchanged entrypoints instead of re-sending frontends
    /// Sōzu would then refuse as duplicates.
    #[test]
    fn a_complete_reload_keeps_every_applied_entrypoint() {
        let a = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let b = base_ep(vec![Backend::new("10.0.0.2", 80)]);

        let mut snapshot = RoutingSnapshot::new();
        snapshot.insert("a".to_string(), a.clone());
        snapshot.insert("b".to_string(), b.clone());

        let applied = BTreeSet::from(["a".to_string(), "b".to_string()]);
        retain_applied(&mut snapshot, &applied);

        assert_eq!(snapshot.len(), 2, "nothing was held back");
    }

    /// A cluster whose frontends landed but whose backends were all refused is
    /// live in name only: Sōzu has a route and nothing to send it to, so the
    /// hostname serves 503s. Recording it as applied means the next reload
    /// judges it unchanged and never retries the backends, so the 503s stay.
    #[test]
    fn a_cluster_left_without_backends_is_retried() {
        assert_eq!(
            backend_outcome(3, 3),
            FrontendOutcome::Rejected,
            "every backend refused leaves the cluster serving nothing"
        );
    }

    /// One refused backend out of several is not worth another reload: the
    /// cluster still has somewhere to send traffic, and retrying the whole
    /// entrypoint would re-send the frontends Sōzu already accepted, which it
    /// then refuses as duplicates.
    #[test]
    fn a_cluster_that_kept_a_backend_is_left_alone() {
        assert_eq!(backend_outcome(3, 1), FrontendOutcome::Installed);
        assert_eq!(backend_outcome(3, 0), FrontendOutcome::Installed);
    }

    /// An entrypoint that declares no backends at all is a configuration the
    /// operator chose, not a failed send — nothing to retry.
    #[test]
    fn a_cluster_with_no_backends_declared_is_not_a_rejection() {
        assert_eq!(backend_outcome(0, 0), FrontendOutcome::Installed);
    }

    #[test]
    fn a_rejected_entrypoint_joins_the_skipped_set() {
        let mut skipped = BTreeSet::new();
        note_frontend_outcome("app_new", FrontendOutcome::Rejected, &mut skipped);
        assert!(skipped.contains("app_new"));
    }

    #[test]
    fn an_installed_entrypoint_is_left_out_of_the_skipped_set() {
        let mut skipped = BTreeSet::new();
        note_frontend_outcome("app_new", FrontendOutcome::Installed, &mut skipped);
        assert!(skipped.is_empty());
    }

    /// A cluster already skipped for another reason (a SNI clash) must stay
    /// skipped when its frontends happen to land, or the snapshot would record
    /// a route the operator still has to fix.
    #[test]
    fn an_installed_entrypoint_does_not_clear_an_existing_skip() {
        let mut skipped = BTreeSet::from(["app_new".to_string()]);
        note_frontend_outcome("app_new", FrontendOutcome::Installed, &mut skipped);
        assert!(skipped.contains("app_new"));
    }

    #[test]
    fn resolving_a_clash_lets_the_previously_skipped_route_through() {
        // The regression this guards: a skipped entrypoint must stay out of the
        // snapshot, so that once the clash is fixed it is applied instead of
        // being judged "unchanged" and silently left dead forever.
        let clashing = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("legacy", "gateway", None),
        ]);
        assert!(skipped_on_sni_clash(&clashing).contains("legacy"));

        // Operator gives the catch-all an SNI of its own.
        let fixed = storage_of(vec![
            tcp_ep("a", "gateway", Some("a.example.com")),
            tcp_ep("legacy", "gateway", Some("legacy.example.com")),
        ]);
        assert!(skipped_on_sni_clash(&fixed).is_empty());
    }

    #[test]
    fn separate_listeners_never_clash() {
        // Each listener is judged on its own — this is the documented fix for
        // a clash, so it must not itself be reported.
        let storage = storage_of(vec![
            tcp_ep("a", "sni-gw", Some("a.example.com")),
            tcp_ep("legacy", "raw-gw", None),
        ]);
        assert!(tcp_sni_mode_clashes(&storage).is_empty());
    }

    #[test]
    fn non_tcp_entrypoints_are_ignored_by_the_clash_check() {
        // An HTTP entrypoint has no TCP frontend and cannot clash, even when it
        // carries hostnames that look SNI-ish.
        let mut http = base_ep(vec![Backend::new("10.0.0.9", 80)]);
        http.id = "web".into();
        http.config.entrypoint = Some("gateway".into());
        let storage = storage_of(vec![http, tcp_ep("a", "gateway", Some("a.example.com"))]);
        assert!(tcp_sni_mode_clashes(&storage).is_empty());
    }

    fn base_ep(backends: Vec<Backend>) -> Entrypoint {
        Entrypoint {
            id: "svc".into(),
            backends,
            name: "svc".into(),
            protocol: Protocol::Http,
            source: None,
            config: EntrypointConfig {
                hostnames: vec!["app.example.com".into()],
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
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                load_balancer: Default::default(),
                sticky_session: false,
                compress: false,
                entrypoint: None,
                sni: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: Default::default(),
                ip_allow_list: Vec::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
                answer: None,
                mirrors: Vec::new(),
            },
            candidates: Vec::new(),
        }
    }

    /// Sōzu keys a backend by the id it was added under, so an add and its
    /// later removal have to agree on that id. They did not: the first install
    /// numbered backends by their position in the list, while the rescale path
    /// derives the id from the address. `docker compose --scale web=3` then
    /// down to 2 therefore sent `RemoveBackend` for an id Sōzu had never seen,
    /// and the departed container kept taking a third of the traffic — no
    /// error, since the command itself succeeds against a live cluster.
    #[test]
    fn a_backend_is_removed_under_the_id_it_was_added_with() {
        let backend = Backend::new("10.0.0.3", 80);

        assert_eq!(
            backend_id("http_web", 2, &backend),
            backend_id("http_web", 0, &backend),
            "add and remove must name the same backend"
        );
    }

    /// The id must not move when a backend's position changes, or scaling down
    /// the middle of a list renames every backend after it and orphans them
    /// all. Address and port are what identify a backend to us, so they are
    /// what the id is built from.
    #[test]
    fn a_backend_keeps_its_id_when_its_position_moves() {
        let backend = Backend::new("10.0.0.3", 80);

        assert_eq!(
            backend_id("http_web", 0, &backend),
            backend_id("http_web", 7, &backend),
            "position must not appear in the id"
        );
    }

    /// Two backends of one cluster must never collide, including the same host
    /// on two ports.
    /// Sōzu would count a weight of 0 as 1; it is sent as a backup instead.
    #[test]
    fn a_zero_weight_backend_is_a_backup() {
        let (params, backup) = sozu_weight(&Backend::new("10.0.0.1", 80).with_weight(0));
        assert_eq!(params.unwrap().weight, 1);
        assert_eq!(backup, Some(true));

        let (params, backup) = sozu_weight(&Backend::new("10.0.0.1", 80).with_weight(30));
        assert_eq!(params.unwrap().weight, 30);
        assert_eq!(backup, None);

        let (params, _) = sozu_weight(&Backend::new("10.0.0.1", 80).with_weight(u32::MAX));
        assert_eq!(params.unwrap().weight, i32::MAX);
    }

    #[test]
    fn two_backends_of_a_cluster_get_distinct_ids() {
        let a = Backend::new("10.0.0.1", 80);
        let b = Backend::new("10.0.0.2", 80);
        let same_host_other_port = Backend::new("10.0.0.1", 8080);

        assert_ne!(backend_id("http_web", 0, &a), backend_id("http_web", 1, &b));
        assert_ne!(
            backend_id("http_web", 0, &a),
            backend_id("http_web", 1, &same_host_other_port)
        );
    }

    #[test]
    fn scale_changes_only_backends_keeps_frontend() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let new = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        // Only the backend set differs → eligible for the in-place backend diff
        // (no frontend teardown).
        assert!(frontend_unchanged(&old, &new));
        assert!(is_backends_only_change(&old, &new));
        assert_ne!(old, new, "the entrypoints do differ (backends)");
    }

    #[test]
    fn hostname_change_is_a_frontend_change() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.hostnames = vec!["other.example.com".into()];
        assert!(!frontend_unchanged(&old, &new));
        assert!(!is_backends_only_change(&old, &new));
    }

    #[test]
    fn required_client_certificates_redirect_tls_routes_to_https() {
        let mut tls = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        tls.config.tls = true;
        let plain = base_ep(vec![Backend::new("10.0.0.2", 80)]);
        let storage = BTreeMap::from([("tls".to_string(), tls), ("plain".to_string(), plain)]);

        let required = require_https_for_client_certificates(&storage, Some(8443));
        assert!(required["tls"].config.https_redirect);
        assert_eq!(required["tls"].config.https_redirect_port, Some(8443));
        assert!(!required["plain"].config.https_redirect);

        let not_required = require_https_for_client_certificates(&storage, None);
        assert!(!not_required["tls"].config.https_redirect);
    }

    /// A route with header conditions gets an ACME challenge frontend
    /// carrying them; one shared with another route stays while that route
    /// needs it.
    #[test]
    fn an_acme_twin_is_removed_only_when_no_route_needs_it() {
        let mut a = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        assert!(build_acme_twins(&a, 80).is_empty());

        a.config.match_headers = vec![crate::model::MatchCondition {
            key: "X-Canary".into(),
            value: String::new(),
            regex: false,
        }];
        let twins = build_acme_twins(&a, 80);
        assert_eq!(twins.len(), a.config.hostnames.len());
        assert_eq!(twins[0].cluster_id.as_deref(), Some(ACME_CHALLENGE_CLUSTER));
        assert_eq!(twins[0].header_predicates.len(), 1);

        let mut b = a.clone();
        b.config.match_headers[0].key = "x-canary".into();
        assert!(stale_acme_twins(&a, 80, &build_acme_twins(&b, 80)).is_empty());
        // A twin on another listener does not keep one on this listener.
        let mut moved = b.clone();
        moved.config.entrypoint = Some("gateway:http:8080".into());
        assert_eq!(
            stale_acme_twins(&a, 80, &build_acme_twins(&moved, 80)).len(),
            1
        );
        assert_eq!(stale_acme_twins(&a, 80, &[]), twins);
    }

    /// The middleware cannot tell apart two routes on one host and path, so
    /// the frontend names the one Sōzu picked, replacing any client value.
    #[test]
    fn a_middleware_route_names_itself_to_the_middleware() {
        let mut ep = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let plain =
            build_http_frontends("http_web", &ep, 80, SocketAddress::new_v4(0, 0, 0, 0, 443));
        assert!(
            plain[0]
                .1
                .headers
                .iter()
                .all(|h| h.key != middleware::ROUTE_HEADER)
        );

        ep.config.compress = true;
        ep.config.headers = vec![
            HeaderConfig {
                name: "Sozune-Route".into(),
                value: "other".into(),
                direction: HeaderDirection::Request,
                append: false,
            },
            HeaderConfig {
                name: "Sozune-Route".into(),
                value: "shown".into(),
                direction: HeaderDirection::Both,
                append: false,
            },
        ];
        let fronts =
            build_http_frontends("http_web", &ep, 80, SocketAddress::new_v4(0, 0, 0, 0, 443));
        let route: Vec<_> = fronts[0]
            .1
            .headers
            .iter()
            .filter(|h| h.key.eq_ignore_ascii_case(middleware::ROUTE_HEADER))
            .filter(|h| {
                h.position == sozu_command_lib::proto::command::HeaderPosition::Request as i32
            })
            .map(|h| h.val.as_str())
            .collect();
        assert_eq!(route, ["", "http_web"]);
        assert!(fronts[0].1.headers.iter().any(|h| h.val == "shown"
            && h.position == sozu_command_lib::proto::command::HeaderPosition::Response as i32));
    }

    #[test]
    fn header_change_is_a_frontend_change() {
        use crate::model::{HeaderConfig, HeaderDirection};
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.headers = vec![HeaderConfig {
            name: "X-Foo".into(),
            value: "bar".into(),
            direction: HeaderDirection::Request,
            append: false,
        }];
        assert!(!frontend_unchanged(&old, &new));
    }

    #[test]
    fn redirect_change_is_a_frontend_change() {
        use crate::model::RedirectScheme;
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.redirect_scheme = Some(RedirectScheme::UseHttps);
        assert!(!frontend_unchanged(&old, &new));
    }

    // The fields below all feed the Sōzu frontend / cluster config but were
    // absent from the original hand-written allow-list, so a change to any of
    // them alone was silently misclassified as "backends-only" and dropped on
    // reload. Comparing the whole `config` closes that gap; these guard it.

    #[test]
    fn priority_change_is_a_frontend_change() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.priority = 10;
        assert!(!frontend_unchanged(&old, &new));
    }

    #[test]
    fn rate_limit_change_is_a_frontend_change() {
        use crate::model::RateLimitConfig;
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.rate_limit = Some(RateLimitConfig {
            average: 100,
            burst: 200,
        });
        assert!(!frontend_unchanged(&old, &new));
        // Also middleware-bearing, so doubly ineligible for the in-place diff.
        assert!(!is_backends_only_change(&old, &new));
    }

    #[test]
    fn forward_auth_change_is_a_frontend_change() {
        use crate::model::ForwardAuthConfig;
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.forward_auth = Some(ForwardAuthConfig {
            address: "http://auth.internal".into(),
            response_headers: Vec::new(),
            trust_forward_header: false,
        });
        assert!(!frontend_unchanged(&old, &new));
        assert!(!is_backends_only_change(&old, &new));
    }

    #[test]
    fn error_pages_change_is_a_frontend_change() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config
            .error_pages
            .insert("404".into(), "Not here".into());
        assert!(!frontend_unchanged(&old, &new));
    }

    #[test]
    fn plugins_change_is_a_frontend_change() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.plugins = vec!["my-wasm-plugin".into()];
        assert!(!frontend_unchanged(&old, &new));
    }

    #[test]
    fn compress_change_is_a_frontend_change() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.compress = true;
        assert!(!frontend_unchanged(&old, &new));
    }

    fn down(addresses: &[&str]) -> UnhealthyMap {
        addresses
            .iter()
            .map(|address| {
                (
                    address.to_string(),
                    crate::proxy::health::UnhealthyReason {
                        kind: crate::proxy::health::UnhealthyKind::ConnectionRefused,
                        message: "refused".to_string(),
                        since: 0,
                        last_checked: 0,
                    },
                )
            })
            .collect()
    }

    /// An unhealthy backend leaves its route; the healthy ones stay.
    #[test]
    fn an_unhealthy_backend_is_taken_out_of_rotation() {
        let ep = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        let storage = BTreeMap::from([("web".to_string(), ep)]);

        let (routed, evicted) = without_unhealthy_backends(&storage, &down(&["10.0.0.2:80"]));

        assert_eq!(routed["web"].backends, [Backend::new("10.0.0.1", 80)]);
        assert_eq!(evicted["web"], [Backend::new("10.0.0.2", 80)]);
    }

    /// With every backend unhealthy, none is taken out: a probe can be wrong,
    /// and a route with nothing left would refuse every request.
    #[test]
    fn a_route_keeps_its_backends_when_all_are_unhealthy() {
        let ep = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        let storage = BTreeMap::from([("web".to_string(), ep.clone())]);

        let (routed, evicted) =
            without_unhealthy_backends(&storage, &down(&["10.0.0.1:80", "10.0.0.2:80"]));

        assert_eq!(routed["web"], ep);
        assert!(evicted.is_empty());
    }

    /// Primaries down, a healthy backup left: the backup serves.
    #[test]
    fn a_healthy_backup_takes_over_unhealthy_primaries() {
        let ep = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.9", 80).with_weight(0),
        ]);
        let storage = BTreeMap::from([("web".to_string(), ep)]);

        let (routed, _) = without_unhealthy_backends(&storage, &down(&["10.0.0.1:80"]));

        assert_eq!(
            routed["web"].backends,
            [Backend::new("10.0.0.9", 80).with_weight(0)]
        );
    }

    /// Out of rotation is what Sōzu was not given, read from the live routes.
    #[test]
    fn evicted_backends_are_those_the_live_route_lacks() {
        let stored = BTreeMap::from([(
            "web".to_string(),
            base_ep(vec![
                Backend::new("10.0.0.1", 80),
                Backend::new("10.0.0.2", 80),
            ]),
        )]);
        let live = BTreeMap::from([(
            "web".to_string(),
            base_ep(vec![Backend::new("10.0.0.1", 80)]),
        )]);

        let evicted = evicted_from_live(&stored, &live);

        assert_eq!(evicted["web"], [Backend::new("10.0.0.2", 80)]);
        assert!(evicted_from_live(&stored, &stored).is_empty());

        // A weight the reload has not applied yet is not an eviction.
        let mut reweighted = stored.clone();
        reweighted.get_mut("web").unwrap().backends[0].weight = 5;
        assert!(evicted_from_live(&reweighted, &stored).is_empty());
    }

    /// UDP backends are not probed, whatever the map says about the address.
    #[test]
    fn udp_backends_are_never_taken_out() {
        let mut ep = base_ep(vec![
            Backend::new("10.0.0.1", 53),
            Backend::new("10.0.0.2", 53),
        ]);
        ep.protocol = Protocol::Udp;
        assert!(evicted_backends(&ep, &down(&["10.0.0.1:53"])).is_empty());
    }

    /// A route the reload did not install again keeps its sessions; one that
    /// changed protocol loses them all.
    #[test]
    fn departed_sessions_close_only_for_reinstalled_routes() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut moved = old.clone();
        moved.backends = vec![Backend::new("10.0.0.2", 80)];
        let departed = || {
            vec![
                DepartedBackends::new("a", &old, &moved),
                DepartedBackends::new("b", &old, &moved),
            ]
        };
        let ids = |kept: Vec<DepartedBackends>| -> Vec<String> {
            kept.into_iter().map(|d| d.cluster_id).collect()
        };

        let skipped = Ok(BTreeSet::from(["b".to_string()]));
        assert_eq!(ids(reinstalled_only(departed(), &skipped)), ["a"]);
        let failure = Err(ReloadFailure {
            error: anyhow::anyhow!("refused"),
            applied: BTreeSet::from(["b".to_string()]),
        });
        assert_eq!(ids(reinstalled_only(departed(), &failure)), ["b"]);

        let mut tcp = old.clone();
        tcp.protocol = Protocol::Tcp;
        let switched = DepartedBackends::new("a", &old, &tcp);
        assert!(switched.whole_cluster);
        assert!(switched.backends.is_empty());
        assert!(!DepartedBackends::new("a", &old, &moved).whole_cluster);
    }

    /// Only a backend the route no longer has has its sessions closed: one it
    /// keeps, even with another weight, is re-added and keeps them.
    #[test]
    fn departed_backends_are_those_the_route_no_longer_has() {
        let old = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
            Backend::new("10.0.0.3", 80),
        ]);
        let new = base_ep(vec![
            Backend::new("10.0.0.1", 80).with_weight(5),
            Backend::new("10.0.0.3", 8080),
        ]);
        let departed: Vec<String> = departed_backends(&old, &new)
            .iter()
            .map(|b| format!("{}:{}", b.address, b.port))
            .collect();
        assert_eq!(departed, ["10.0.0.2:80", "10.0.0.3:80"]);
        assert!(departed_backends(&old, &old).is_empty());
    }

    #[test]
    fn backend_diff_scale_up_adds_only_new_backend() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let new = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        let (added, removed) = backend_diff(&old, &new);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].address, "10.0.0.2");
        assert!(removed.is_empty());
    }

    #[test]
    fn backend_diff_scale_down_removes_departed_backend() {
        let old = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        let new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let (added, removed) = backend_diff(&old, &new);
        assert!(added.is_empty());
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].address, "10.0.0.2");
    }

    #[test]
    fn backend_diff_weight_only_change_re_adds_backend() {
        // Same address, different weight: must be re-added (so Sōzu updates the
        // weight in place) and never removed. Matching on address alone would
        // drop the new weight silently.
        let old = base_ep(vec![Backend::new("10.0.0.1", 80).with_weight(100)]);
        let new = base_ep(vec![Backend::new("10.0.0.1", 80).with_weight(50)]);
        let (added, removed) = backend_diff(&old, &new);
        assert_eq!(added.len(), 1, "re-weighted backend must be re-added");
        assert_eq!(added[0].weight, 50);
        assert!(
            removed.is_empty(),
            "a re-weighted backend is still present, never removed"
        );
    }

    #[test]
    fn backend_diff_unchanged_backends_are_noop() {
        let old = base_ep(vec![Backend::new("10.0.0.1", 80).with_weight(100)]);
        let new = base_ep(vec![Backend::new("10.0.0.1", 80).with_weight(100)]);
        let (added, removed) = backend_diff(&old, &new);
        assert!(added.is_empty(), "identical weight → no re-add");
        assert!(removed.is_empty());
    }

    #[test]
    fn middleware_entrypoint_is_not_a_backends_only_change() {
        // Same config on both sides, only the backend set grows — frontend is
        // unchanged. But the entrypoint routes through the middleware server
        // (compress = true), so the Sōzu cluster holds a synthetic backend, not
        // these addresses. An in-place backend diff would inject real backends
        // that bypass the middleware, so this must take the remove-then-readd
        // path instead.
        let mut old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        old.config.compress = true;
        let mut new = base_ep(vec![
            Backend::new("10.0.0.1", 80),
            Backend::new("10.0.0.2", 80),
        ]);
        new.config.compress = true;
        assert!(frontend_unchanged(&old, &new));
        assert!(
            !is_backends_only_change(&old, &new),
            "middleware-routed entrypoints must not use the in-place backend diff"
        );
    }

    /// A route through the middleware whose backends or mirrors change needs
    /// nothing from Sōzu; one that starts or stops going through the
    /// middleware does.
    #[test]
    fn a_middleware_route_changing_only_for_the_middleware_keeps_its_frontend() {
        let mirror = |address: &str| crate::model::Mirror {
            backends: vec![Backend::new(address, 8080)],
        };
        let mut old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        old.config.mirrors = vec![mirror("10.0.1.1")];
        let mut new = base_ep(vec![Backend::new("10.0.0.2", 80)]);
        new.config.mirrors = vec![mirror("10.0.1.2")];
        assert!(is_middleware_only_change(&old, &new));
        assert!(!is_backends_only_change(&old, &new));

        // The first mirror moves the route onto the middleware.
        let plain = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        assert!(frontend_unchanged(&plain, &new));
        assert!(!is_middleware_only_change(&plain, &new));
        assert!(!is_backends_only_change(&plain, &new));
    }

    #[test]
    fn lb_algorithm_maps_every_variant() {
        // Each Sōzune LoadBalancer maps to its Sōzu counterpart. HRW and Maglev
        // are the flow-affine algorithms added for UDP.
        use LoadBalancingAlgorithms as S;
        assert_eq!(lb_algorithm(LoadBalancer::RoundRobin), S::RoundRobin);
        assert_eq!(lb_algorithm(LoadBalancer::Random), S::Random);
        assert_eq!(lb_algorithm(LoadBalancer::PowerOfTwo), S::PowerOfTwo);
        assert_eq!(lb_algorithm(LoadBalancer::LeastConnections), S::LeastLoaded);
        assert_eq!(lb_algorithm(LoadBalancer::Hrw), S::Hrw);
        assert_eq!(lb_algorithm(LoadBalancer::Maglev), S::Maglev);
    }

    #[test]
    fn pick_loopback_port_returns_a_usable_port() {
        let port = pick_loopback_port().expect("should pick a port");
        assert_ne!(port, 0);
        // The port was released, so we can bind it again.
        let rebind = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port));
        assert!(rebind.is_ok(), "freed loopback port should be re-bindable");
    }

    // A tiny echo server on loopback, standing in for the Sōzu worker behind the
    // forwarder. Returns the port it bound.
    async fn spawn_echo_backend() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    async fn try_connect_and_echo(port: u16, payload: &[u8]) -> Option<Vec<u8>> {
        let mut s = timeout(
            Duration::from_secs(1),
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .ok()?
        .ok()?;
        s.write_all(payload).await.ok()?;
        let mut buf = vec![0u8; payload.len()];
        timeout(Duration::from_secs(1), s.read_exact(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf)
    }

    #[tokio::test]
    async fn forwarder_passes_allowed_peer_through_to_backend() {
        let backend_port = spawn_echo_backend().await;
        let public_port = pick_loopback_port().unwrap();
        tokio::spawn(run_tcp_forwarder(TcpForwarderSpec {
            name: "test".into(),
            public_port,
            loopback_port: backend_port,
            // 127.0.0.1 is allowed (the test client connects from loopback).
            allow_list: vec!["127.0.0.1/32".into()],
            rate_limit: None,
        }));
        // Give the forwarder a moment to bind.
        sleep(Duration::from_millis(100)).await;

        let echoed = try_connect_and_echo(public_port, b"hello-forwarder").await;
        assert_eq!(echoed.as_deref(), Some(&b"hello-forwarder"[..]));
    }

    #[tokio::test]
    async fn forwarder_drops_peer_outside_allow_list() {
        let backend_port = spawn_echo_backend().await;
        let public_port = pick_loopback_port().unwrap();
        tokio::spawn(run_tcp_forwarder(TcpForwarderSpec {
            name: "test".into(),
            public_port,
            loopback_port: backend_port,
            // Only a foreign IP is allowed, so the loopback test client is denied.
            allow_list: vec!["10.0.0.1/32".into()],
            rate_limit: None,
        }));
        sleep(Duration::from_millis(100)).await;

        // The TCP connection is accepted then immediately closed without
        // forwarding, so no echo comes back.
        let echoed = try_connect_and_echo(public_port, b"should-be-dropped").await;
        assert_eq!(echoed, None, "denied peer must not receive a backend echo");
    }

    #[tokio::test]
    async fn forwarder_empty_allow_list_allows_all() {
        let backend_port = spawn_echo_backend().await;
        let public_port = pick_loopback_port().unwrap();
        tokio::spawn(run_tcp_forwarder(TcpForwarderSpec {
            name: "test".into(),
            public_port,
            loopback_port: backend_port,
            allow_list: Vec::new(), // empty = allow all
            rate_limit: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let echoed = try_connect_and_echo(public_port, b"open-house").await;
        assert_eq!(echoed.as_deref(), Some(&b"open-house"[..]));
    }

    #[tokio::test]
    async fn forwarder_rate_limits_a_flooding_peer() {
        let backend_port = spawn_echo_backend().await;
        let public_port = pick_loopback_port().unwrap();
        // Burst of 2, slow refill: the 3rd rapid connection is dropped.
        tokio::spawn(run_tcp_forwarder(TcpForwarderSpec {
            name: "test".into(),
            public_port,
            loopback_port: backend_port,
            allow_list: Vec::new(),
            rate_limit: Some(TcpRateLimit {
                max_conns: 2,
                per_seconds: 60,
                exempt: Vec::new(),
            }),
        }));
        sleep(Duration::from_millis(100)).await;

        // First two connections fit the burst.
        assert!(try_connect_and_echo(public_port, b"one").await.is_some());
        assert!(try_connect_and_echo(public_port, b"two").await.is_some());
        // The third, before the bucket refills, is rate-limited (dropped).
        assert!(
            try_connect_and_echo(public_port, b"three").await.is_none(),
            "third rapid connection should be rate-limited"
        );
    }

    #[tokio::test]
    async fn forwarder_rate_limit_exempts_listed_source() {
        let backend_port = spawn_echo_backend().await;
        let public_port = pick_loopback_port().unwrap();
        // Same tight limit, but loopback is exempt → never throttled.
        tokio::spawn(run_tcp_forwarder(TcpForwarderSpec {
            name: "test".into(),
            public_port,
            loopback_port: backend_port,
            allow_list: Vec::new(),
            rate_limit: Some(TcpRateLimit {
                max_conns: 1,
                per_seconds: 60,
                exempt: vec!["127.0.0.1/32".into()],
            }),
        }));
        sleep(Duration::from_millis(100)).await;

        // Well past the burst of 1, but exempt, so all succeed.
        assert!(try_connect_and_echo(public_port, b"a").await.is_some());
        assert!(try_connect_and_echo(public_port, b"b").await.is_some());
        assert!(try_connect_and_echo(public_port, b"c").await.is_some());
    }
}
