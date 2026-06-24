mod acme;
mod addr;
mod builders;
mod channel;
mod worker;

use crate::config::{ProxyConfig, TcpRateLimit};
use crate::middleware::ip_allow_list::IpAllowList;
use crate::middleware::rate_limit::{RateLimitResult, RateLimiter};
use crate::middleware::{self, MiddlewareState};
use crate::model::{Backend, Entrypoint, LoadBalancer, Protocol};
use crate::proxy::backend::ProxyInputs;
use crate::proxy::metrics_snapshot;
use acme::{add_certificate, register_acme_challenge_cluster};
use addr::{l4_backend_id, parse_backend_address};
use builders::{
    build_authorized_hashes, build_frontend_headers, build_path_and_rewrite, map_redirect_policy,
    map_redirect_scheme, methods_for_frontend,
};
use channel::{send_to_worker, wait_for_worker_ready, with_reload_budget};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        ActivateListener, AddBackend, Cluster, ListenerType, LoadBalancingAlgorithms,
        LoadBalancingParams, PathRule, QueryMetricsOptions, RemoveBackend, Request,
        RequestHttpFrontend, RequestTcpFrontend, RequestUdpFrontend, ResponseStatus, RulePosition,
        SocketAddress, UdpClusterConfig, WorkerRequest, WorkerResponse, request::RequestType,
        response_content::ContentType,
    },
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

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
    /// Loopback port serving the ACME HTTP-01 challenge responder, when
    /// ACME is enabled. `None` disables every ACME-specific code path.
    acme_challenge_port: Option<u16>,
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
    let max_buffers = config.max_buffers;
    let buffer_size = config.buffer_size;
    let timeout = Duration::from_millis(config.startup_delay_ms);

    for tcp_cfg in &config.tcp {
        if channels.contains_key(&tcp_cfg.name) {
            anyhow::bail!(
                "duplicate TCP listener name `{}` in proxy.tcp",
                tcp_cfg.name
            );
        }

        // Sōzu binds a private loopback port; Sōzune owns the public port via
        // the pre-accept forwarder. The TCP frontend therefore targets the
        // loopback port — stored as `L4ListenerChannel.port`, which
        // configure_tcp_entrypoint already uses to build the frontend address.
        let loopback_port = pick_loopback_port()?;
        let listener_config =
            ListenerBuilder::new_tcp(SocketAddress::new_v4(127, 0, 0, 1, loopback_port))
                .to_tcp(None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Could not create TCP listener `{}` on 127.0.0.1:{}: {}",
                        tcp_cfg.name,
                        loopback_port,
                        e
                    )
                })?;

        let (mut command, proxy_chan) = Channel::generate(1000, config.command_buffer_max_bytes)
            .map_err(|e| {
                anyhow::anyhow!("Could not create TCP channel for `{}`: {}", tcp_cfg.name, e)
            })?;

        let listener_name = tcp_cfg.name.clone();
        let handle = thread::spawn(move || {
            if let Err(e) =
                worker::start_tcp_worker(listener_config, max_buffers, buffer_size, proxy_chan)
            {
                error!("TCP worker `{}` failed: {}", listener_name, e);
            }
        });

        wait_for_worker_ready(&mut command, &format!("TCP[{}]", tcp_cfg.name), timeout)?;
        info!(
            "Sōzu TCP worker `{}` running on 127.0.0.1:{} (public :{})",
            tcp_cfg.name, loopback_port, tcp_cfg.listen
        );

        channels.insert(
            tcp_cfg.name.clone(),
            L4ListenerChannel {
                port: loopback_port,
                channel: command,
            },
        );
        forwarders.push(TcpForwarderSpec {
            name: tcp_cfg.name.clone(),
            public_port: tcp_cfg.listen,
            loopback_port,
            allow_list: tcp_cfg.ip_allow_list.clone(),
            rate_limit: tcp_cfg.rate_limit.clone(),
        });
        handles.push(handle);
    }

    Ok((channels, handles, forwarders))
}

fn spawn_udp_workers(
    config: &ProxyConfig,
) -> anyhow::Result<(L4Channels, Vec<thread::JoinHandle<()>>)> {
    let mut channels: L4Channels = HashMap::new();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let max_buffers = config.max_buffers;
    let buffer_size = config.buffer_size;
    let timeout = Duration::from_millis(config.startup_delay_ms);

    for udp_cfg in &config.udp {
        if channels.contains_key(&udp_cfg.name) {
            anyhow::bail!(
                "duplicate UDP listener name `{}` in proxy.udp",
                udp_cfg.name
            );
        }

        // Build the listener config up front so a bad address fails before we
        // spawn the worker thread.
        let listener_config =
            ListenerBuilder::new_udp(SocketAddress::new_v4(0, 0, 0, 0, udp_cfg.listen))
                .to_udp(None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Could not create UDP listener `{}` on :{}: {}",
                        udp_cfg.name,
                        udp_cfg.listen,
                        e
                    )
                })?;

        let (mut command, proxy_chan) = Channel::generate(1000, config.command_buffer_max_bytes)
            .map_err(|e| {
                anyhow::anyhow!("Could not create UDP channel for `{}`: {}", udp_cfg.name, e)
            })?;

        let listener_name = udp_cfg.name.clone();
        let listener_port = udp_cfg.listen;
        // Unlike TCP/HTTP/HTTPS, `start_udp_worker` takes no listener to
        // pre-activate (Sōzu builds the `UdpProxy` internally). The bare worker
        // starts here; we install the listener over the channel below.
        let handle = thread::spawn(move || {
            if let Err(e) = worker::start_udp_worker(proxy_chan, max_buffers, buffer_size) {
                error!("UDP worker `{}` failed: {}", listener_name, e);
            }
        });

        wait_for_worker_ready(&mut command, &format!("UDP[{}]", udp_cfg.name), timeout)?;

        // Register then bind the listener (AddUdpListener records it, the socket
        // is bound by ActivateListener), the same two-step Sōzu uses natively.
        let address = SocketAddress::new_v4(0, 0, 0, 0, listener_port);
        send_to_worker(
            &mut command,
            format!("add-udp-listener-{}", udp_cfg.name),
            RequestType::AddUdpListener(listener_config),
        )
        .map_err(|e| anyhow::anyhow!("Failed to add UDP listener `{}`: {}", udp_cfg.name, e))?;
        send_to_worker(
            &mut command,
            format!("activate-udp-listener-{}", udp_cfg.name),
            RequestType::ActivateListener(ActivateListener {
                address,
                proxy: ListenerType::Udp.into(),
                from_scm: false,
            }),
        )
        .map_err(|e| {
            anyhow::anyhow!("Failed to activate UDP listener `{}`: {}", udp_cfg.name, e)
        })?;

        info!(
            "Sōzu UDP worker `{}` running on 0.0.0.0:{}",
            udp_cfg.name, listener_port
        );

        channels.insert(
            udp_cfg.name.clone(),
            L4ListenerChannel {
                port: listener_port,
                channel: command,
            },
        );
        handles.push(handle);
    }

    Ok((channels, handles))
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
        middleware_state,
        middleware_port,
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
    let http_listener = http_builder
        .to_http(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTP listener: {}", e))?;

    let mut https_builder = ListenerBuilder::new_https(SocketAddress::new_v4(
        0,
        0,
        0,
        0,
        config.https.listen_address,
    ));
    apply_listener_error_pages(&mut https_builder, &config.https.error_pages, "HTTPS");
    apply_listener_http2(&mut https_builder, &config.https.http2);
    let https_listener = https_builder
        .to_tls(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTPS listener: {}", e))?;

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
            error!("HTTP server failed: {}", e);
        }
    });

    let worker_https_handle = thread::spawn(move || {
        if let Err(e) = worker::start_https_worker(
            https_listener,
            proxy_channel_https,
            max_buffers,
            buffer_size,
        ) {
            error!("HTTPS server failed: {}", e);
        }
    });

    // Wait for workers to be ready by sending a Status probe
    let timeout = Duration::from_millis(config.startup_delay_ms);
    wait_for_worker_ready(&mut command_channel, "HTTP", timeout)?;
    wait_for_worker_ready(&mut command_channel_https, "HTTPS", timeout)?;

    // Spawn one Sōzu TCP worker per declared listener.
    let (tcp_channels, tcp_worker_handles, tcp_forwarders) = spawn_tcp_workers(config)?;
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
    info!(
        "Sōzu HTTPS worker running on 0.0.0.0:{}",
        config.https.listen_address
    );

    // Register ACME challenge cluster if enabled (routes added per-hostname during reload)
    if let Some(challenge_port) = acme_challenge_port
        && let Err(e) = register_acme_challenge_cluster(&mut command_channel, challenge_port)
    {
        error!("Failed to register ACME challenge cluster: {}", e);
    }

    // Start configuration reload handler
    let storage_reload = Arc::clone(&storage);
    let trusted_proxies_reload = Arc::clone(&trusted_proxies);
    let http_port = config.http.listen_address;
    let https_port = config.https.listen_address;
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
        acme_challenge_port,
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
                            info!("Adding certificate for {}", cmd.hostname);
                            if let Err(e) = add_certificate(
                                &mut channels.https,
                                https_port,
                                &cmd.cert_pem,
                                &cmd.chain,
                                &cmd.key_pem,
                                std::slice::from_ref(&cmd.hostname),
                            ) {
                                error!(
                                    "Failed to add certificate for {}: {}",
                                    cmd.hostname, e
                                );
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
                                    info!("Adding certificate for {}", cmd.hostname);
                                    if let Err(e) = add_certificate(
                                        &mut channels.https,
                                        https_port,
                                        &cmd.cert_pem,
                                        &cmd.chain,
                                        &cmd.key_pem,
                                        std::slice::from_ref(&cmd.hostname),
                                    ) {
                                        error!(
                                            "Failed to add certificate for {}: {}",
                                            cmd.hostname, e
                                        );
                                    }
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
                );
            }
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
) -> RoutingSnapshot {
    info!("Received configuration reload request");
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

    let current_snapshot = snapshot_from_storage(&storage_read);

    // Run the reload under a shared consecutive-timeout counter. A worker that
    // goes silent is given up on after a few failed acks, so it can't stall the
    // event loop for PER_COMMAND_TIMEOUT × (number of commands). A healthy reload
    // of hundreds of entrypoints is unaffected: every ack resets the counter, so
    // only a genuinely unresponsive worker trips the short-circuit.
    with_reload_budget(|| {
        apply_routing_diff(previous_snapshot, &current_snapshot, channels);

        // Update middleware route table
        update_middleware_routes(&storage_read, middleware_state, plugins, trusted_proxies);

        match configure_sozu_routing(
            channels,
            &storage_read,
            previous_snapshot,
            cluster_setup_delay_ms,
            middleware_port,
        ) {
            Ok(()) => info!("Configuration reloaded successfully"),
            Err(e) => error!("Failed to reload configuration: {}", e),
        }
    });

    current_snapshot
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

    let forward_auth_client = middleware::build_forward_auth_client();

    for (cluster_id, entrypoint) in storage {
        if !matches!(entrypoint.protocol, Protocol::Http) {
            continue;
        }
        if middleware::needs_middleware(&entrypoint.config) {
            let route = middleware::build_middleware_route(
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
            table.update_routes_for_entrypoint(&entrypoint.config.hostnames, route);
        }
    }
}

fn configure_sozu_routing(
    channels: &mut Channels,
    storage: &BTreeMap<String, Entrypoint>,
    previous: &RoutingSnapshot,
    cluster_setup_delay_ms: u64,
    middleware_port: u16,
) -> anyhow::Result<()> {
    info!(
        "Applying Sōzu configuration for {} entrypoints",
        storage.len()
    );

    // Sort entrypoints by priority descending (higher priority first).
    // Since Sozu Pre rules are matched in insertion order, registering
    // higher-priority routes first ensures they take precedence.
    let mut sorted_entrypoints: Vec<(&String, &Entrypoint)> = storage.iter().collect();
    sorted_entrypoints.sort_by_key(|(_, ep)| std::cmp::Reverse(ep.config.priority));

    for (cluster_id, entrypoint) in sorted_entrypoints {
        // Skip entrypoints that are byte-for-byte identical to the previous
        // snapshot. apply_routing_diff() only removes stale/changed entries,
        // so anything still in `previous` is already live in the workers and
        // re-adding it makes Sōzu reject the command as a duplicate.
        if previous.get(cluster_id) == Some(entrypoint) {
            continue;
        }

        // Backends-only change: apply_routing_diff() already updated the
        // backends in place and left the frontend live. Re-adding here would
        // duplicate the frontend/backends, so skip it.
        if let Some(old) = previous.get(cluster_id)
            && is_backends_only_change(old, entrypoint)
        {
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
                    for hostname in &entrypoint.config.hostnames {
                        let acme_front = RequestHttpFrontend {
                            cluster_id: Some("acme-challenge".to_string()),
                            address: SocketAddress::new_v4(0, 0, 0, 0, channels.http_port),
                            hostname: hostname.clone(),
                            path: PathRule {
                                value: "/.well-known/acme-challenge/".to_string(),
                                kind: 0, // Prefix
                            },
                            method: None,
                            position: RulePosition::Pre as i32,
                            tags: BTreeMap::new(),
                            ..Default::default()
                        };
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
                }

                configure_http_entrypoint(
                    &mut channels.http,
                    &mut channels.https,
                    cluster_id,
                    entrypoint,
                    channels.http_port,
                    channels.https_port,
                    middleware_port,
                )?;
            }
            Protocol::Tcp => {
                configure_tcp_entrypoint(&mut channels.tcp, cluster_id, entrypoint);
            }
            Protocol::Udp => {
                configure_udp_entrypoint(&mut channels.udp, cluster_id, entrypoint);
            }
        }

        thread::sleep(std::time::Duration::from_millis(cluster_setup_delay_ms));
    }

    info!("Sōzu configuration applied successfully");
    Ok(())
}

fn configure_http_entrypoint(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
    http_port: u16,
    https_port: u16,
    middleware_port: u16,
) -> anyhow::Result<()> {
    // Add cluster for both HTTP and HTTPS
    let authorized_hashes = build_authorized_hashes(&entrypoint.config.auth);
    let frontend_required_auth = if authorized_hashes.is_empty() {
        None
    } else {
        Some(true)
    };
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

    // Configure frontends for each hostname
    for hostname in &entrypoint.config.hostnames {
        let (path_rule, frontend_rewrite_path) = build_path_and_rewrite(
            entrypoint.config.path.as_ref(),
            entrypoint.config.strip_prefix,
            entrypoint.config.add_prefix.as_deref(),
            entrypoint.config.rewrite.as_ref(),
            cluster_id,
        );

        let frontend_headers = build_frontend_headers(&entrypoint.config.headers);
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
        // A urlRewrite hostname is a transparent rewrite of the forwarded
        // request's Host header (Sōzu's native frontend rewrite_host). It
        // shares the field with a redirect's rewrite_host; the two never
        // co-exist on one rule (redirect+urlRewrite is rejected upstream),
        // so the redirect value takes the field when present.
        let frontend_rewrite_host = entrypoint.config.rewrite_host.clone().or_else(|| {
            entrypoint
                .config
                .rewrite
                .as_ref()
                .and_then(|r| r.hostname.clone())
        });
        let frontend_rewrite_port = entrypoint.config.rewrite_port.map(|p| p as u32);

        for method in methods_for_frontend(&entrypoint.config.methods) {
            let method_tag = method.as_deref().unwrap_or("any");
            let http_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
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
                ..Default::default()
            };

            if let Err(e) = send_to_worker(
                command_channel,
                format!(
                    "add-frontend-http-{}-{}-{}",
                    cluster_id, hostname, method_tag
                ),
                RequestType::AddHttpFrontend(http_front),
            ) {
                debug!(
                    "Failed to add HTTP frontend for {} [{}] (may already exist): {}",
                    hostname, method_tag, e
                );
            }

            // HTTPS frontend if TLS is enabled
            if entrypoint.config.tls {
                let https_front = RequestHttpFrontend {
                    cluster_id: Some(cluster_id.to_string()),
                    address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
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
                    ..Default::default()
                };

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
                    RequestType::AddHttpsFrontend(https_front),
                ) {
                    Ok(_) => info!("HTTPS frontend added for {} [{}]", hostname, method_tag),
                    Err(e) => error!(
                        "Failed to add HTTPS frontend for {} [{}]: {}",
                        hostname, method_tag, e
                    ),
                }
            }
        }
    }

    // Add backends
    // If this entrypoint needs middleware, route through the middleware server instead
    let use_middleware = middleware::needs_middleware(&entrypoint.config);

    if use_middleware {
        debug!(
            "Routing {} through middleware server at 127.0.0.1:{}",
            entrypoint.name, middleware_port
        );
        let address = SocketAddress::new_v4(127, 0, 0, 1, middleware_port);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: format!("{}-backend-0", cluster_id),
            address,
            load_balancing_parameters: Some(LoadBalancingParams { weight: 100 }),
            sticky_id: None,
            backup: None,
        };

        if let Err(e) = send_to_worker(
            command_channel,
            format!("add-backend-http-{}-0", cluster_id),
            RequestType::AddBackend(backend.clone()),
        ) {
            debug!(
                "Failed to add HTTP middleware backend {} (may already exist): {}",
                backend.backend_id, e
            );
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
    } else {
        debug!(
            "Setting up {} backends for {}: {:?}",
            entrypoint.backends.len(),
            entrypoint.name,
            entrypoint.backends
        );
        for (backend_index, backend_entry) in entrypoint.backends.iter().enumerate() {
            let address = parse_backend_address(backend_entry)?;
            let weight = backend_entry.weight as i32;

            let backend = AddBackend {
                cluster_id: cluster_id.to_string(),
                backend_id: format!("{}-backend-{}", cluster_id, backend_index),
                address,
                load_balancing_parameters: Some(LoadBalancingParams { weight }),
                sticky_id: None,
                backup: None,
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
    }

    Ok(())
}

fn configure_tcp_entrypoint(
    tcp_channels: &mut L4Channels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) {
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
            return;
        }
    };

    let listener = match tcp_channels.get_mut(listener_name) {
        Some(c) => c,
        None => {
            error!(
                "TCP entrypoint `{}` references undeclared listener `{}`, skipping. \
                 Declare it under `proxy.tcp` in the config.",
                entrypoint.name, listener_name
            );
            return;
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
        ..Default::default()
    };

    if let Err(e) = send_to_worker(
        channel,
        format!("add-frontend-tcp-{}", cluster_id),
        RequestType::AddTcpFrontend(tcp_front),
    ) {
        debug!(
            "Failed to add TCP frontend for cluster {} on listener {}: {}",
            cluster_id, listener_name, e
        );
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
        let weight = backend_entry.weight as i32;
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters: Some(LoadBalancingParams { weight }),
            sticky_id: None,
            backup: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-tcp-{backend_id}"),
            RequestType::AddBackend(backend),
        ) {
            debug!("Failed to add TCP backend {backend_id} (may already exist): {e}");
        }
    }
}

fn configure_udp_entrypoint(
    udp_channels: &mut L4Channels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) {
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
            return;
        }
    };

    let listener = match udp_channels.get_mut(listener_name) {
        Some(c) => c,
        None => {
            error!(
                "UDP entrypoint `{}` references undeclared listener `{}`, skipping. \
                 Declare it under `proxy.udp` in the config.",
                entrypoint.name, listener_name
            );
            return;
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

    if let Err(e) = send_to_worker(
        channel,
        format!("add-frontend-udp-{}", cluster_id),
        RequestType::AddUdpFrontend(udp_front),
    ) {
        debug!(
            "Failed to add UDP frontend for cluster {} on listener {}: {}",
            cluster_id, listener_name, e
        );
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
        let weight = backend_entry.weight as i32;
        let backend_id = l4_backend_id(cluster_id, backend_entry);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters: Some(LoadBalancingParams { weight }),
            sticky_id: None,
            backup: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-udp-{backend_id}"),
            RequestType::AddBackend(backend),
        ) {
            debug!("Failed to add UDP backend {backend_id} (may already exist): {e}");
        }
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
                    other => {
                        debug!(
                            "metrics: unexpected content from {} worker: {:?}",
                            name, other
                        );
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
    https_port: u16,
) {
    let (path_rule, _) = build_path_and_rewrite(
        entrypoint.config.path.as_ref(),
        entrypoint.config.strip_prefix,
        entrypoint.config.add_prefix.as_deref(),
        entrypoint.config.rewrite.as_ref(),
        cluster_id,
    );

    for hostname in &entrypoint.config.hostnames {
        for method in methods_for_frontend(&entrypoint.config.methods) {
            let method_tag = method.as_deref().unwrap_or("any");
            let http_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: method.clone(),
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
                ..Default::default()
            };

            if let Err(e) = send_to_worker(
                command_channel,
                format!(
                    "rm-frontend-http-{}-{}-{}",
                    cluster_id, hostname, method_tag
                ),
                RequestType::RemoveHttpFrontend(http_front),
            ) {
                debug!(
                    "Failed to remove HTTP frontend for {} [{}]: {}",
                    hostname, method_tag, e
                );
            }

            if entrypoint.config.tls {
                let https_front = RequestHttpFrontend {
                    cluster_id: Some(cluster_id.to_string()),
                    address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
                    hostname: hostname.clone(),
                    path: path_rule.clone(),
                    method: method.clone(),
                    position: RulePosition::Pre as i32,
                    tags: BTreeMap::new(),
                    ..Default::default()
                };

                if let Err(e) = send_to_worker(
                    command_channel_https,
                    format!(
                        "rm-frontend-https-{}-{}-{}",
                        cluster_id, hostname, method_tag
                    ),
                    RequestType::RemoveHttpsFrontend(https_front),
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
        // Stable, address-derived id so add and remove agree regardless of
        // position in the backend list.
        let backend_id = format!(
            "{cluster_id}-backend-{}-{}",
            backend_entry.address, backend_entry.port
        );
        let add = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters: Some(LoadBalancingParams {
                weight: backend_entry.weight as i32,
            }),
            sticky_id: None,
            backup: None,
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
        let backend_id = format!(
            "{cluster_id}-backend-{}-{}",
            backend_entry.address, backend_entry.port
        );
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

fn remove_backends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) {
    for (i, backend_entry) in entrypoint.backends.iter().enumerate() {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(e) => {
                debug!(
                    "Failed to parse backend address {} for removal: {}",
                    backend_entry, e
                );
                continue;
            }
        };
        let backend_id = format!("{}-backend-{}", cluster_id, i);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };

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

fn remove_acme_frontends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    hostnames: &[String],
    http_port: u16,
) {
    for hostname in hostnames {
        let acme_front = RequestHttpFrontend {
            cluster_id: Some("acme-challenge".to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
            hostname: hostname.clone(),
            path: PathRule {
                value: "/.well-known/acme-challenge/".to_string(),
                kind: 0, // Prefix
            },
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
            ..Default::default()
        };

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
/// silently classified as "backends-only" and dropped on reload.
fn frontend_unchanged(old: &Entrypoint, new: &Entrypoint) -> bool {
    old.protocol == new.protocol && old.config == new.config
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
    frontend_unchanged(old, new) && !middleware::needs_middleware(&new.config)
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
        let add = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
            load_balancing_parameters: Some(LoadBalancingParams {
                weight: backend_entry.weight as i32,
            }),
            sticky_id: None,
            backup: None,
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
    }
}

fn apply_routing_diff(
    previous: &RoutingSnapshot,
    current: &RoutingSnapshot,
    channels: &mut Channels,
) {
    // Handle removed clusters
    for (cluster_id, old) in previous {
        if !current.contains_key(cluster_id) {
            info!("Removing stale cluster: {}", cluster_id);
            match old.protocol {
                Protocol::Http => {
                    remove_http_frontends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        channels.http_port,
                        channels.https_port,
                    );
                    remove_backends(&mut channels.http, &mut channels.https, cluster_id, old);
                    remove_cluster(&mut channels.http, &mut channels.https, cluster_id);

                    if channels.acme_challenge_port.is_some() {
                        remove_acme_frontends(
                            &mut channels.http,
                            &old.config.hostnames,
                            channels.http_port,
                        );
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(&mut channels.tcp, cluster_id, old);
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
            if is_backends_only_change(old, new) {
                info!("Updating backends in place for cluster: {}", cluster_id);
                diff_backends_in_place(channels, cluster_id, old, new);
                continue;
            }

            info!("Updating changed cluster: {}", cluster_id);
            match old.protocol {
                Protocol::Http => {
                    remove_http_frontends(
                        &mut channels.http,
                        &mut channels.https,
                        cluster_id,
                        old,
                        channels.http_port,
                        channels.https_port,
                    );
                    remove_backends(&mut channels.http, &mut channels.https, cluster_id, old);

                    if channels.acme_challenge_port.is_some()
                        && old.config.hostnames != new.config.hostnames
                    {
                        remove_acme_frontends(
                            &mut channels.http,
                            &old.config.hostnames,
                            channels.http_port,
                        );
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(&mut channels.tcp, cluster_id, old);
                }
                Protocol::Udp => {
                    remove_udp_entrypoint(&mut channels.udp, cluster_id, old);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Http2Config;
    use crate::model::{Backend, EntrypointConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
    use tokio::time::{sleep, timeout};

    fn tls_listener_with_http2(
        http2: &Http2Config,
    ) -> sozu_command_lib::proto::command::HttpsListenerConfig {
        let mut builder = ListenerBuilder::new_https(SocketAddress::new_v4(0, 0, 0, 0, 8443));
        apply_listener_http2(&mut builder, http2);
        builder.to_tls(None).expect("to_tls should succeed")
    }

    #[test]
    fn http2_default_advertises_h2_and_http11() {
        let cfg = tls_listener_with_http2(&Http2Config::default());
        assert!(cfg.alpn_protocols.iter().any(|p| p == "h2"));
        assert!(cfg.alpn_protocols.iter().any(|p| p == "http/1.1"));
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
                health_check: None,
                retry: None,
                circuit_breaker: None,
                rate_limit: None,
                in_flight_req: None,
                load_balancer: Default::default(),
                sticky_session: false,
                compress: false,
                entrypoint: None,
                methods: Vec::new(),
                acme: None,
                plugins: Vec::new(),
                plugin_config: std::collections::BTreeMap::new(),
                error_pages: Default::default(),
                ip_allow_list: Vec::new(),
                match_headers: Vec::new(),
                match_query: Vec::new(),
                match_client_ip: Vec::new(),
            },
        }
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
    fn header_change_is_a_frontend_change() {
        use crate::model::{HeaderConfig, HeaderDirection};
        let old = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        let mut new = base_ep(vec![Backend::new("10.0.0.1", 80)]);
        new.config.headers = vec![HeaderConfig {
            name: "X-Foo".into(),
            value: "bar".into(),
            direction: HeaderDirection::Request,
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
