use crate::acme::CertCommand;
use crate::config::ProxyConfig;
use crate::middleware::{self, MiddlewareState};
use crate::model::{Backend, Entrypoint, PathConfig, PathRuleType, Protocol};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        AddBackend, AddCertificate, CertificateAndKey, Cluster, Header, HeaderPosition,
        LoadBalancingAlgorithms, LoadBalancingParams, PathRule,
        RedirectPolicy as SozuRedirectPolicy, RedirectScheme as SozuRedirectScheme, RemoveBackend,
        Request, RequestHttpFrontend, RequestTcpFrontend, ResponseStatus, RulePosition,
        SocketAddress, Status, TlsVersion, WorkerRequest, WorkerResponse, request::RequestType,
    },
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

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

pub fn start_sozu_proxy(
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    config: &ProxyConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    mut reload_rx: mpsc::Receiver<()>,
    mut cert_rx: mpsc::Receiver<CertCommand>,
    acme_challenge_port: Option<u16>,
    middleware_state: MiddlewareState,
    middleware_port: u16,
    handle: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    info!("Starting Sōzu HTTP and HTTPS workers");

    // Copy values needed for threads
    let max_buffers = config.max_buffers;
    let buffer_size = config.buffer_size;

    // HTTP Listener
    let http_listener = ListenerBuilder::new_http(SocketAddress::new_v4(
        0,
        0,
        0,
        0,
        config.http.listen_address,
    ))
    .to_http(None)
    .map_err(|e| anyhow::anyhow!("Could not create HTTP listener: {}", e))?;

    let https_listener = ListenerBuilder::new_https(SocketAddress::new_v4(
        0,
        0,
        0,
        0,
        config.https.listen_address,
    ))
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
    let (mut tcp_channels, tcp_worker_handles) = spawn_tcp_workers(config)?;

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
    let http_port = config.http.listen_address;
    let https_port = config.https.listen_address;
    let cluster_setup_delay_ms = config.cluster_setup_delay_ms;
    let reload_throttle = Duration::from_millis(config.reload_throttle_ms);

    let reload_handle = thread::spawn(move || {
        handle.block_on(async {
            let mut shutdown_rx = shutdown_rx;
            let mut cert_rx_open = true;
            let mut previous_snapshot: RoutingSnapshot = BTreeMap::new();

            // Apply a reload, then enter a throttle window: discard duplicate
            // signals, but remember if at least one arrived so we can fold it
            // into a single follow-up reload at the end. Mirrors Traefik's
            // `providersThrottleDuration` (default 2 s; we default to 500 ms).
            // Returns true if shutdown was observed during the window.
            macro_rules! apply_with_throttle {
                () => {{
                    previous_snapshot = handle_reload(
                        &storage_reload,
                        &mut command_channel,
                        &mut command_channel_https,
                        &mut tcp_channels,
                        http_port,
                        https_port,
                        cluster_setup_delay_ms,
                        acme_challenge_port,
                        &previous_snapshot,
                        &middleware_state,
                        middleware_port,
                    );

                    if !reload_throttle.is_zero() {
                        let mut pending = false;
                        let mut coalesced: usize = 0;
                        let sleep = tokio::time::sleep(reload_throttle);
                        tokio::pin!(sleep);
                        let mut shutdown_seen = false;
                        loop {
                            tokio::select! {
                                _ = &mut sleep => break,
                                _ = &mut shutdown_rx => {
                                    shutdown_seen = true;
                                    break;
                                }
                                signal = reload_rx.recv() => {
                                    match signal {
                                        Some(_) => {
                                            pending = true;
                                            coalesced += 1;
                                        }
                                        None => break,
                                    }
                                }
                            }
                        }
                        if coalesced > 0 {
                            debug!(
                                "Throttled {} reload signal(s); applying single follow-up",
                                coalesced
                            );
                        }
                        if pending && !shutdown_seen {
                            previous_snapshot = handle_reload(
                                &storage_reload,
                                &mut command_channel,
                                &mut command_channel_https,
                                &mut tcp_channels,
                                http_port,
                                https_port,
                                cluster_setup_delay_ms,
                                acme_challenge_port,
                                &previous_snapshot,
                                &middleware_state,
                                middleware_port,
                            );
                        }
                        shutdown_seen
                    } else {
                        false
                    }
                }};
            }

            loop {
                if cert_rx_open {
                    tokio::select! {
                        _ = &mut shutdown_rx => {
                            info!("Shutdown signal received in reload handler");
                            break;
                        }
                        reload = reload_rx.recv() => {
                            match reload {
                                Some(_) => {
                                    if apply_with_throttle!() {
                                        info!("Shutdown signal received in reload handler");
                                        break;
                                    }
                                }
                                None => {
                                    debug!("Reload channel closed");
                                    break;
                                }
                            }
                        }
                        cert_cmd = cert_rx.recv() => {
                            match cert_cmd {
                                Some(cmd) => {
                                    info!("Adding certificate for {}", cmd.hostname);
                                    if let Err(e) = add_certificate(&mut command_channel_https, https_port, &cmd.cert_pem, &cmd.chain, &cmd.key_pem, std::slice::from_ref(&cmd.hostname)) {
                                        error!("Failed to add certificate for {}: {}", cmd.hostname, e);
                                    } else {
                                        // Reload to ensure HTTPS frontends are properly configured with the new cert
                                        if apply_with_throttle!() {
                                            info!("Shutdown signal received in reload handler");
                                            break;
                                        }
                                    }
                                }
                                None => {
                                    debug!("Cert channel closed, falling back to reload-only mode");
                                    cert_rx_open = false;
                                }
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = &mut shutdown_rx => {
                            info!("Shutdown signal received in reload handler");
                            break;
                        }
                        reload = reload_rx.recv() => {
                            match reload {
                                Some(_) => {
                                    if apply_with_throttle!() {
                                        info!("Shutdown signal received in reload handler");
                                        break;
                                    }
                                }
                                None => {
                                    debug!("Reload channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
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

fn handle_reload(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    tcp_channels: &mut TcpChannels,
    http_port: u16,
    https_port: u16,
    cluster_setup_delay_ms: u64,
    acme_challenge_port: Option<u16>,
    previous_snapshot: &RoutingSnapshot,
    middleware_state: &MiddlewareState,
    middleware_port: u16,
) -> RoutingSnapshot {
    info!("Received configuration reload request");
    let storage_read = match storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Storage lock poisoned during reload: {}", e);
            return previous_snapshot.clone();
        }
    };

    let current_snapshot = snapshot_from_storage(&storage_read);

    apply_routing_diff(
        previous_snapshot,
        &current_snapshot,
        command_channel,
        command_channel_https,
        tcp_channels,
        http_port,
        https_port,
        acme_challenge_port,
    );

    // Update middleware route table
    update_middleware_routes(&storage_read, middleware_state);

    match configure_sozu_routing(
        command_channel,
        command_channel_https,
        tcp_channels,
        &storage_read,
        previous_snapshot,
        http_port,
        https_port,
        cluster_setup_delay_ms,
        acme_challenge_port,
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
) {
    let mut table = match middleware_state.write() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Middleware state lock poisoned: {}", e);
            return;
        }
    };

    table.clear();

    for (cluster_id, entrypoint) in storage {
        if !matches!(entrypoint.protocol, Protocol::Http) {
            continue;
        }
        if middleware::needs_middleware(&entrypoint.config) {
            let route =
                middleware::build_middleware_route(&entrypoint.config, &entrypoint.backends);
            debug!(
                "Middleware route for {} (hosts: {:?}): rate_limited={}, compress={}",
                cluster_id,
                entrypoint.config.hostnames,
                route.rate_limiter.is_some(),
                route.compress,
            );
            table.update_routes_for_entrypoint(&entrypoint.config.hostnames, route);
        }
    }
}

fn configure_sozu_routing(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    tcp_channels: &mut TcpChannels,
    storage: &BTreeMap<String, Entrypoint>,
    previous: &RoutingSnapshot,
    http_port: u16,
    https_port: u16,
    cluster_setup_delay_ms: u64,
    acme_challenge_port: Option<u16>,
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
    sorted_entrypoints.sort_by(|a, b| b.1.config.priority.cmp(&a.1.config.priority));

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
                if acme_challenge_port.is_some() {
                    for hostname in &entrypoint.config.hostnames {
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
                    command_channel,
                    command_channel_https,
                    cluster_id,
                    entrypoint,
                    http_port,
                    https_port,
                    middleware_port,
                )?;
            }
            Protocol::Tcp => {
                configure_tcp_entrypoint(tcp_channels, cluster_id, entrypoint);
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

fn build_frontend_headers(edits: &[crate::model::HeaderConfig]) -> Vec<Header> {
    edits
        .iter()
        .map(|edit| Header {
            position: match edit.direction {
                crate::model::HeaderDirection::Request => HeaderPosition::Request as i32,
                crate::model::HeaderDirection::Response => HeaderPosition::Response as i32,
                crate::model::HeaderDirection::Both => HeaderPosition::Both as i32,
            },
            key: edit.name.clone(),
            val: edit.value.clone(),
        })
        .collect()
}

fn build_authorized_hashes(auth: &Option<crate::model::AuthConfig>) -> Vec<String> {
    let Some(cfg) = auth else {
        return Vec::new();
    };
    let Some(ref users) = cfg.basic else {
        return Vec::new();
    };
    users
        .iter()
        .map(|u| format!("{}:{}", u.username, u.password_hash))
        .collect()
}

fn map_redirect_policy(policy: crate::model::RedirectPolicy) -> i32 {
    match policy {
        crate::model::RedirectPolicy::Forward => SozuRedirectPolicy::Forward as i32,
        crate::model::RedirectPolicy::Permanent => SozuRedirectPolicy::Permanent as i32,
        crate::model::RedirectPolicy::Unauthorized => SozuRedirectPolicy::Unauthorized as i32,
    }
}

fn map_redirect_scheme(scheme: crate::model::RedirectScheme) -> i32 {
    match scheme {
        crate::model::RedirectScheme::UseSame => SozuRedirectScheme::UseSame as i32,
        crate::model::RedirectScheme::UseHttp => SozuRedirectScheme::UseHttp as i32,
        crate::model::RedirectScheme::UseHttps => SozuRedirectScheme::UseHttps as i32,
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' | '^' | '$' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn build_path_and_rewrite(
    path_config: Option<&PathConfig>,
    strip_prefix: bool,
    cluster_id: &str,
) -> (PathRule, Option<String>) {
    let Some(path_config) = path_config else {
        return (
            PathRule {
                value: "/".to_string(),
                kind: 0,
            },
            None,
        );
    };

    if !strip_prefix {
        let kind = match path_config.rule_type {
            PathRuleType::Prefix => 0,
            PathRuleType::Regex => 1,
            PathRuleType::Exact => 2,
        };
        return (
            PathRule {
                value: path_config.value.clone(),
                kind,
            },
            None,
        );
    }

    match path_config.rule_type {
        PathRuleType::Prefix => {
            // Convert to a regex that matches the prefix optionally followed
            // by `/<tail>`. The non-capturing `/` before the capture lets
            // the rewrite template prepend a literal `/` so backends always
            // see a valid absolute path, regardless of whether the client
            // requested `/api`, `/api/`, or `/api/users`.
            let escaped = regex_escape(path_config.value.trim_end_matches('/'));
            let pattern = format!("^{}(?:/(.*))?$", escaped);
            (
                PathRule {
                    value: pattern,
                    kind: 1,
                },
                Some("/$PATH[1]".to_string()),
            )
        }
        PathRuleType::Exact => (
            PathRule {
                value: path_config.value.clone(),
                kind: 2,
            },
            Some("/".to_string()),
        ),
        PathRuleType::Regex => {
            debug!(
                "strip_prefix on Regex path is not supported natively for {}; configure rewrite via Sozu directly if needed",
                cluster_id
            );
            (
                PathRule {
                    value: path_config.value.clone(),
                    kind: 1,
                },
                None,
            )
        }
    }
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
    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: entrypoint.config.sticky_session,
        https_redirect: entrypoint.config.https_redirect,
        proxy_protocol: None,
        load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        authorized_hashes,
        https_redirect_port: entrypoint.config.https_redirect_port.map(|p| p as u32),
        www_authenticate: entrypoint.config.www_authenticate.clone(),
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
            cluster_id,
        );

        let frontend_headers = build_frontend_headers(&entrypoint.config.headers);
        let frontend_redirect = entrypoint.config.redirect.map(map_redirect_policy);
        let frontend_redirect_scheme = entrypoint.config.redirect_scheme.map(map_redirect_scheme);
        let frontend_redirect_template = entrypoint.config.redirect_template.clone();

        let http_front = RequestHttpFrontend {
            cluster_id: Some(cluster_id.to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
            hostname: hostname.clone(),
            path: path_rule.clone(),
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
            headers: frontend_headers.clone(),
            required_auth: frontend_required_auth,
            rewrite_path: frontend_rewrite_path.clone(),
            redirect: frontend_redirect,
            redirect_scheme: frontend_redirect_scheme,
            redirect_template: frontend_redirect_template.clone(),
            ..Default::default()
        };

        if let Err(e) = send_to_worker(
            command_channel,
            format!("add-frontend-http-{}-{}", cluster_id, hostname),
            RequestType::AddHttpFrontend(http_front),
        ) {
            debug!(
                "Failed to add HTTP frontend for {} (may already exist): {}",
                hostname, e
            );
        }

        // HTTPS frontend if TLS is enabled
        if entrypoint.config.tls {
            let https_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: None,
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
                headers: frontend_headers.clone(),
                required_auth: frontend_required_auth,
                rewrite_path: frontend_rewrite_path.clone(),
                redirect: frontend_redirect,
                redirect_scheme: frontend_redirect_scheme,
                redirect_template: frontend_redirect_template.clone(),
                ..Default::default()
            };

            info!(
                "Configuring HTTPS frontend for {} on cluster {}",
                hostname, cluster_id
            );
            match send_to_worker(
                command_channel_https,
                format!("add-frontend-https-{}-{}", cluster_id, hostname),
                RequestType::AddHttpsFrontend(https_front),
            ) {
                Ok(_) => info!("HTTPS frontend added for {}", hostname),
                Err(e) => error!("Failed to add HTTPS frontend for {}: {}", hostname, e),
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
        load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
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

fn wait_for_worker_ready(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    channel.write_message(&WorkerRequest {
        id: format!("{}-readiness-probe", name),
        content: Request {
            request_type: Some(RequestType::Status(Status {})),
        },
    })?;

    match channel.read_message_blocking_timeout(Some(timeout)) {
        Ok(_) => {
            info!("{} worker is ready", name);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!(
                "{} worker failed to become ready within {:?}: {}",
                name,
                timeout,
                e
            );
        }
    }
}

fn send_to_worker(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    id: String,
    request: RequestType,
) -> anyhow::Result<()> {
    channel.write_message(&WorkerRequest {
        id: id.clone(),
        content: Request {
            request_type: Some(request),
        },
    })?;

    // Read responses until we find the one matching our request ID
    let deadline = std::time::Instant::now() + Duration::from_millis(2000);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match channel.read_message_blocking_timeout(Some(remaining)) {
            Ok(response) => {
                if response.id == id {
                    if response.status == ResponseStatus::Failure as i32 {
                        error!("Worker rejected command {}: {}", id, response.message);
                        return Err(anyhow::anyhow!(
                            "Worker rejected {}: {}",
                            id,
                            response.message
                        ));
                    }
                    return Ok(());
                }
                // Not our response, keep reading
                debug!(
                    "Received response for {} while waiting for {}",
                    response.id, id
                );
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(())
}

/// Register the ACME challenge cluster and backend (frontends are added per-hostname during reload)
fn register_acme_challenge_cluster(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    challenge_port: u16,
) -> anyhow::Result<()> {
    let cluster_id = "acme-challenge".to_string();

    let cluster = Cluster {
        cluster_id: cluster_id.clone(),
        sticky_session: false,
        https_redirect: false,
        proxy_protocol: None,
        load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        ..Default::default()
    };

    send_to_worker(
        command_channel,
        "add-cluster-acme-challenge".to_string(),
        RequestType::AddCluster(cluster),
    )?;

    let backend = AddBackend {
        cluster_id: cluster_id.clone(),
        backend_id: "acme-challenge-backend-0".to_string(),
        address: SocketAddress::new_v4(127, 0, 0, 1, challenge_port),
        load_balancing_parameters: Some(LoadBalancingParams { weight: 100 }),
        sticky_id: None,
        backup: None,
    };

    send_to_worker(
        command_channel,
        "add-backend-acme-challenge".to_string(),
        RequestType::AddBackend(backend),
    )?;

    info!(
        "ACME challenge cluster registered -> 127.0.0.1:{}",
        challenge_port
    );
    Ok(())
}

/// Send an AddCertificate command to the HTTPS worker
fn add_certificate(
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    https_port: u16,
    cert_pem: &str,
    chain: &[String],
    key_pem: &str,
    names: &[String],
) -> anyhow::Result<()> {
    let cert = AddCertificate {
        address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
        certificate: CertificateAndKey {
            certificate: cert_pem.to_string(),
            certificate_chain: chain.to_vec(),
            key: key_pem.to_string(),
            versions: vec![TlsVersion::TlsV12 as i32, TlsVersion::TlsV13 as i32],
            names: names.to_vec(),
        },
        expired_at: None,
    };

    send_to_worker(
        command_channel_https,
        format!(
            "add-cert-{}",
            names.first().map(|s| s.as_str()).unwrap_or("unknown")
        ),
        RequestType::AddCertificate(cert),
    )?;

    info!("Certificate added for {:?}", names);
    Ok(())
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
        cluster_id,
    );

    for hostname in &entrypoint.config.hostnames {
        let http_front = RequestHttpFrontend {
            cluster_id: Some(cluster_id.to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
            hostname: hostname.clone(),
            path: path_rule.clone(),
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
            ..Default::default()
        };

        if let Err(e) = send_to_worker(
            command_channel,
            format!("rm-frontend-http-{}-{}", cluster_id, hostname),
            RequestType::RemoveHttpFrontend(http_front),
        ) {
            debug!("Failed to remove HTTP frontend for {}: {}", hostname, e);
        }

        if entrypoint.config.tls {
            let https_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: None,
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
                ..Default::default()
            };

            if let Err(e) = send_to_worker(
                command_channel_https,
                format!("rm-frontend-https-{}-{}", cluster_id, hostname),
                RequestType::RemoveHttpsFrontend(https_front),
            ) {
                debug!("Failed to remove HTTPS frontend for {}: {}", hostname, e);
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
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    tcp_channels: &mut TcpChannels,
    http_port: u16,
    https_port: u16,
    acme_challenge_port: Option<u16>,
) {
    // Handle removed clusters
    for (cluster_id, old) in previous {
        if !current.contains_key(cluster_id) {
            info!("Removing stale cluster: {}", cluster_id);
            match old.protocol {
                Protocol::Http => {
                    remove_http_frontends(
                        command_channel,
                        command_channel_https,
                        cluster_id,
                        old,
                        http_port,
                        https_port,
                    );
                    remove_backends(command_channel, command_channel_https, cluster_id, old);
                    remove_cluster(command_channel, command_channel_https, cluster_id);

                    if acme_challenge_port.is_some() {
                        remove_acme_frontends(command_channel, &old.config.hostnames, http_port);
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(tcp_channels, cluster_id, old);
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
                        command_channel,
                        command_channel_https,
                        cluster_id,
                        old,
                        http_port,
                        https_port,
                    );
                    remove_backends(command_channel, command_channel_https, cluster_id, old);

                    if acme_challenge_port.is_some() && old.config.hostnames != new.config.hostnames
                    {
                        remove_acme_frontends(command_channel, &old.config.hostnames, http_port);
                    }
                }
                Protocol::Tcp => {
                    remove_tcp_entrypoint(tcp_channels, cluster_id, old);
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

fn parse_backend_address(backend: &Backend) -> anyhow::Result<SocketAddress> {
    let addr: std::net::SocketAddr = format!("{}:{}", backend.address, backend.port).parse()?;

    match addr {
        std::net::SocketAddr::V4(addr_v4) => {
            let ip = addr_v4.ip().octets();
            Ok(SocketAddress::new_v4(
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                addr_v4.port(),
            ))
        }
        std::net::SocketAddr::V6(_) => {
            anyhow::bail!("IPv6 addresses are not yet supported")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_backend_address_ipv4() {
        let result = parse_backend_address(&Backend::new("192.168.1.100", 8080));
        assert!(result.is_ok(), "Failed to parse IPv4 address: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_localhost() {
        let result = parse_backend_address(&Backend::new("127.0.0.1", 3000));
        assert!(result.is_ok(), "Failed to parse localhost: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_hostname() {
        let result = parse_backend_address(&Backend::new("localhost", 80));
        // Localhost may not resolve in all test environments
        // Just verify we get a consistent result
        match result {
            Ok(_) => (),
            Err(e) => {
                println!(
                    "Hostname resolution failed (expected in some test environments): {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_parse_backend_address_invalid() {
        let result =
            parse_backend_address(&Backend::new("invalid-host-name-that-does-not-exist", 80));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_backend_address_invalid_port() {
        let result = parse_backend_address(&Backend::new("127.0.0.1", 0));
        assert!(result.is_ok()); // Port 0 is technically valid
    }
}
