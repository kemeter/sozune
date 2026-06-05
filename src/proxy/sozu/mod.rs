mod acme;
mod addr;
mod builders;
mod channel;

use crate::config::ProxyConfig;
use crate::middleware::{self, MiddlewareState};
use crate::model::{Entrypoint, LoadBalancer, Protocol};
use crate::proxy::backend::ProxyInputs;
use crate::proxy::metrics_snapshot;
use acme::{add_certificate, register_acme_challenge_cluster};
use addr::parse_backend_address;
use builders::{
    build_authorized_hashes, build_frontend_headers, build_path_and_rewrite, map_redirect_policy,
    map_redirect_scheme, methods_for_frontend,
};
use channel::{send_to_worker, wait_for_worker_ready};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        AddBackend, Cluster, LoadBalancingAlgorithms, LoadBalancingParams, PathRule,
        QueryMetricsOptions, RemoveBackend, Request, RequestHttpFrontend, RequestTcpFrontend,
        ResponseStatus, RulePosition, SocketAddress, WorkerRequest, WorkerResponse,
        request::RequestType, response_content::ContentType,
    },
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};

/// Map Sōzune's [`LoadBalancer`](crate::model::LoadBalancer) to the Sōzu
/// worker's `LoadBalancingAlgorithms` discriminant.
fn lb_algorithm(lb: LoadBalancer) -> LoadBalancingAlgorithms {
    match lb {
        LoadBalancer::RoundRobin => LoadBalancingAlgorithms::RoundRobin,
        LoadBalancer::Random => LoadBalancingAlgorithms::Random,
        LoadBalancer::PowerOfTwo => LoadBalancingAlgorithms::PowerOfTwo,
        LoadBalancer::LeastConnections => LoadBalancingAlgorithms::LeastLoaded,
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

/// Command channel for a single Sōzu TCP worker, paired with the port it
/// binds. We need the port at routing time to build `RequestTcpFrontend`.
struct TcpListenerChannel {
    port: u16,
    channel: Channel<WorkerRequest, WorkerResponse>,
}

/// TCP workers keyed by listener name (matches `proxy.tcp[].name`).
/// One worker = one listener.
type TcpChannels = HashMap<String, TcpListenerChannel>;

/// Bundle of every Sōzu worker channel a reload needs to talk to, plus the
/// ports they're bound on. Grouped together because every function in the
/// reload path already has to pass all of them — this turns a 6-parameter
/// drag into one `&mut Channels`.
struct Channels {
    http: Channel<WorkerRequest, WorkerResponse>,
    https: Channel<WorkerRequest, WorkerResponse>,
    tcp: TcpChannels,
    http_port: u16,
    https_port: u16,
    /// Loopback port serving the ACME HTTP-01 challenge responder, when
    /// ACME is enabled. `None` disables every ACME-specific code path.
    acme_challenge_port: Option<u16>,
}

fn snapshot_from_storage(storage: &BTreeMap<String, Entrypoint>) -> RoutingSnapshot {
    storage
        .iter()
        .filter(|(_, ep)| matches!(ep.protocol, Protocol::Http | Protocol::Tcp))
        .map(|(id, ep)| (id.clone(), ep.clone()))
        .collect()
}

fn spawn_tcp_workers(
    config: &ProxyConfig,
) -> anyhow::Result<(TcpChannels, Vec<thread::JoinHandle<()>>)> {
    let mut channels: TcpChannels = HashMap::new();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
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

        let listener_config =
            ListenerBuilder::new_tcp(SocketAddress::new_v4(0, 0, 0, 0, tcp_cfg.listen))
                .to_tcp(None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Could not create TCP listener `{}` on :{}: {}",
                        tcp_cfg.name,
                        tcp_cfg.listen,
                        e
                    )
                })?;

        let (mut command, proxy_chan) = Channel::generate(1000, 10000).map_err(|e| {
            anyhow::anyhow!("Could not create TCP channel for `{}`: {}", tcp_cfg.name, e)
        })?;

        let listener_name = tcp_cfg.name.clone();
        let listener_port = tcp_cfg.listen;
        let handle = thread::spawn(move || {
            if let Err(e) = sozu_lib::tcp::testing::start_tcp_worker(
                listener_config,
                max_buffers,
                buffer_size,
                proxy_chan,
            ) {
                error!("TCP worker `{}` failed: {}", listener_name, e);
            }
        });

        wait_for_worker_ready(&mut command, &format!("TCP[{}]", tcp_cfg.name), timeout)?;
        info!(
            "Sōzu TCP worker `{}` running on 0.0.0.0:{}",
            tcp_cfg.name, listener_port
        );

        channels.insert(
            tcp_cfg.name.clone(),
            TcpListenerChannel {
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
    let https_listener = https_builder
        .to_tls(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTPS listener: {}", e))?;

    // Create communication channels
    let (mut command_channel, proxy_channel) = Channel::generate(1000, 10000)
        .map_err(|e| anyhow::anyhow!("Could not create HTTP channel: {}", e))?;
    let (mut command_channel_https, proxy_channel_https) = Channel::generate(1000, 10000)
        .map_err(|e| anyhow::anyhow!("Could not create HTTPS channel: {}", e))?;

    let worker_http_handle = thread::spawn(move || {
        if let Err(e) = sozu_lib::http::testing::start_http_worker(
            http_listener,
            proxy_channel,
            max_buffers,
            buffer_size,
        ) {
            error!("HTTP server failed: {}", e);
        }
    });

    let worker_https_handle = thread::spawn(move || {
        if let Err(e) = sozu_lib::https::testing::start_https_worker(
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
    let (tcp_channels, tcp_worker_handles) = spawn_tcp_workers(config)?;

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

    // Now that every worker is up and the static ACME cluster has been
    // registered, fold the three command channels into a single `Channels`
    // and hand it to the reload thread by value. Splitting them again here
    // would just push the 6-parameter mess further down.
    let mut channels = Channels {
        http: command_channel,
        https: command_channel_https,
        tcp: tcp_channels,
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
                                (poll_worker_metrics(&mut channels.http, "HTTP"), "HTTP"),
                                (poll_worker_metrics(&mut channels.https, "HTTPS"), "HTTPS"),
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
                debug!(
                    "UDP protocol not yet implemented for entrypoint: {}",
                    entrypoint.name
                );
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
    tcp_channels: &mut TcpChannels,
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
        address: SocketAddress::new_v4(0, 0, 0, 0, listener_port),
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

    for (idx, backend_entry) in entrypoint.backends.iter().enumerate() {
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
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: format!("{}-backend-{}", cluster_id, idx),
            address,
            load_balancing_parameters: Some(LoadBalancingParams { weight }),
            sticky_id: None,
            backup: None,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("add-backend-tcp-{}-{}", cluster_id, idx),
            RequestType::AddBackend(backend),
        ) {
            debug!("Failed to add TCP backend {}-{}: {}", cluster_id, idx, e);
        }
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

    let deadline = std::time::Instant::now() + Duration::from_millis(2000);
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
                Protocol::Udp => {}
            }
        }
    }

    // Handle changed clusters: full equality on Entrypoint, so any middleware
    // change (headers, redirect, auth, …) is caught.
    for (cluster_id, old) in previous {
        if let Some(new) = current.get(cluster_id)
            && old != new
        {
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
                Protocol::Udp => {}
            }
        }
    }
}

fn remove_tcp_entrypoint(
    tcp_channels: &mut TcpChannels,
    cluster_id: &str,
    entrypoint: &Entrypoint,
) {
    let Some(listener_name) = entrypoint.config.entrypoint.as_deref() else {
        return;
    };
    let Some(listener) = tcp_channels.get_mut(listener_name) else {
        return;
    };
    let listener_port = listener.port;
    let channel = &mut listener.channel;

    for (idx, backend_entry) in entrypoint.backends.iter().enumerate() {
        let address = match parse_backend_address(backend_entry) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: format!("{}-backend-{}", cluster_id, idx),
            address,
        };
        if let Err(e) = send_to_worker(
            channel,
            format!("rm-backend-tcp-{}-{}", cluster_id, idx),
            RequestType::RemoveBackend(remove),
        ) {
            debug!("Failed to remove TCP backend {}-{}: {}", cluster_id, idx, e);
        }
    }

    let tcp_front = RequestTcpFrontend {
        cluster_id: cluster_id.to_string(),
        address: SocketAddress::new_v4(0, 0, 0, 0, listener_port),
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
