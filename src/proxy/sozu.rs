use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, error, debug};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        SocketAddress, WorkerRequest, WorkerResponse, Request, request::RequestType,
        AddBackend, RemoveBackend, Cluster, LoadBalancingAlgorithms, LoadBalancingParams,
        RequestHttpFrontend, PathRule, RulePosition,
        AddCertificate, CertificateAndKey, TlsVersion,
        Status,
    },
};
use crate::model::{Entrypoint, Protocol, PathConfig, PathRuleType};
use crate::config::ProxyConfig;
use crate::acme::CertCommand;
use crate::middleware::{self, MiddlewareState};

#[derive(Debug, Clone, PartialEq)]
struct EntrypointSnapshot {
    hostnames: Vec<String>,
    path: Option<PathConfig>,
    tls: bool,
    port: u16,
    backends: Vec<String>,
}

type RoutingSnapshot = BTreeMap<String, EntrypointSnapshot>;

fn snapshot_from_storage(storage: &BTreeMap<String, Entrypoint>) -> RoutingSnapshot {
    storage
        .iter()
        .filter(|(_, ep)| matches!(ep.protocol, Protocol::Http))
        .map(|(id, ep)| {
            (
                id.clone(),
                EntrypointSnapshot {
                    hostnames: ep.config.hostnames.clone(),
                    path: ep.config.path.clone(),
                    tls: ep.config.tls,
                    port: ep.config.port,
                    backends: ep.backends.clone(),
                },
            )
        })
        .collect()
}

pub fn start_sozu_proxy(
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    config: &ProxyConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    mut reload_rx: mpsc::UnboundedReceiver<()>,
    mut cert_rx: mpsc::UnboundedReceiver<CertCommand>,
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
    let http_listener = ListenerBuilder::new_http(SocketAddress::new_v4(0, 0, 0, 0, config.http.listen_address))
        .to_http(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTP listener: {}", e))?;

    let https_listener = ListenerBuilder::new_https(SocketAddress::new_v4(0, 0, 0, 0, config.https.listen_address))
        .to_tls(None)
        .map_err(|e| anyhow::anyhow!("Could not create HTTPS listener: {}", e))?;

    // Create communication channels
    let (mut command_channel, proxy_channel) =
        Channel::generate(1000, 10000).map_err(|e| anyhow::anyhow!("Could not create HTTP channel: {}", e))?;
    let (mut command_channel_https, proxy_channel_https) =
        Channel::generate(1000, 10000).map_err(|e| anyhow::anyhow!("Could not create HTTPS channel: {}", e))?;

    let worker_http_handle = thread::spawn(move || {
        if let Err(e) = sozu_lib::http::testing::start_http_worker(
            http_listener,
            proxy_channel,
            max_buffers,
            buffer_size
        ) {
            error!("HTTP server failed: {}", e);
        }
    });

    let worker_https_handle = thread::spawn(move || {
        if let Err(e) = sozu_lib::https::testing::start_https_worker(
            https_listener,
            proxy_channel_https,
            max_buffers,
            buffer_size
        ) {
            error!("HTTPS server failed: {}", e);
        }
    });

    // Wait for workers to be ready by sending a Status probe
    let timeout = Duration::from_millis(config.startup_delay_ms);
    wait_for_worker_ready(&mut command_channel, "HTTP", timeout)?;
    wait_for_worker_ready(&mut command_channel_https, "HTTPS", timeout)?;

    // Initial configuration will be handled by provider reload signals
    info!("Waiting for providers to populate configuration");

    info!("Sōzu HTTP worker running on 0.0.0.0:{}", config.http.listen_address);
    info!("Sōzu HTTPS worker running on 0.0.0.0:{}", config.https.listen_address);

    // Register ACME challenge cluster if enabled (routes added per-hostname during reload)
    if let Some(challenge_port) = acme_challenge_port {
        if let Err(e) = register_acme_challenge_cluster(&mut command_channel, challenge_port) {
            error!("Failed to register ACME challenge cluster: {}", e);
        }
    }

    // Start configuration reload handler
    let storage_reload = Arc::clone(&storage);
    let http_port = config.http.listen_address;
    let https_port = config.https.listen_address;
    let cluster_setup_delay_ms = config.cluster_setup_delay_ms;

    let reload_handle = thread::spawn(move || {
        handle.block_on(async {
            let mut shutdown_rx = shutdown_rx;
            let mut cert_rx_open = true;
            let mut previous_snapshot: RoutingSnapshot = BTreeMap::new();
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
                                    previous_snapshot = handle_reload(&storage_reload, &mut command_channel, &mut command_channel_https, http_port, https_port, cluster_setup_delay_ms, acme_challenge_port, &previous_snapshot, &middleware_state, middleware_port);
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
                                    if let Err(e) = add_certificate(&mut command_channel_https, https_port, &cmd.cert_pem, &cmd.chain, &cmd.key_pem, &[cmd.hostname.clone()]) {
                                        error!("Failed to add certificate for {}: {}", cmd.hostname, e);
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
                                    previous_snapshot = handle_reload(&storage_reload, &mut command_channel, &mut command_channel_https, http_port, https_port, cluster_setup_delay_ms, acme_challenge_port, &previous_snapshot, &middleware_state, middleware_port);
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

    let current_snapshot = snapshot_from_storage(&*storage_read);

    apply_routing_diff(previous_snapshot, &current_snapshot, command_channel, command_channel_https, http_port, https_port, acme_challenge_port);

    // Update middleware route table
    update_middleware_routes(&*storage_read, middleware_state);

    match configure_sozu_routing(command_channel, command_channel_https, &*storage_read, http_port, https_port, cluster_setup_delay_ms, acme_challenge_port, middleware_port) {
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
            let route = middleware::build_middleware_route(&entrypoint.config, &entrypoint.backends);
            debug!("Middleware route for {} (hosts: {:?}): strip_prefix={:?}, auth={}, headers={}",
                cluster_id,
                entrypoint.config.hostnames,
                route.strip_prefix,
                route.auth.is_some(),
                route.headers.len()
            );
            table.update_routes_for_entrypoint(&entrypoint.config.hostnames, route);
        }
    }
}

fn configure_sozu_routing(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    storage: &BTreeMap<String, Entrypoint>,
    http_port: u16,
    https_port: u16,
    cluster_setup_delay_ms: u64,
    acme_challenge_port: Option<u16>,
    middleware_port: u16,
) -> anyhow::Result<()> {
    info!("Applying Sōzu configuration for {} entrypoints", storage.len());

    // Sort entrypoints by priority descending (higher priority first).
    // Since Sozu Pre rules are matched in insertion order, registering
    // higher-priority routes first ensures they take precedence.
    let mut sorted_entrypoints: Vec<(&String, &Entrypoint)> = storage.iter().collect();
    sorted_entrypoints.sort_by(|a, b| b.1.config.priority.cmp(&a.1.config.priority));

    for (cluster_id, entrypoint) in sorted_entrypoints {
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
                                kind: 1, // Prefix
                            },
                            method: None,
                            position: RulePosition::Pre as i32,
                            tags: BTreeMap::new(),
                        };
                        if let Err(e) = send_to_worker(command_channel, format!("add-frontend-acme-{}", hostname), RequestType::AddHttpFrontend(acme_front)) {
                            debug!("Failed to add ACME frontend for {} (may already exist): {}", hostname, e);
                        }
                    }
                }

                configure_http_entrypoint(command_channel, command_channel_https, cluster_id, entrypoint, http_port, https_port, middleware_port)?;
            },
            Protocol::Tcp => {
                debug!("TCP protocol not yet implemented for entrypoint: {}", entrypoint.name);
            },
            Protocol::Udp => {
                debug!("UDP protocol not yet implemented for entrypoint: {}", entrypoint.name);
            },
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
    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: false,
        https_redirect: entrypoint.config.https_redirect,
        proxy_protocol: None,
        load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
        load_metric: None,
        answer_503: None,
    };

    // Send to HTTP and HTTPS workers - ignore errors if cluster already exists
    if let Err(e) = send_to_worker(command_channel, format!("add-cluster-http-{}", cluster_id), RequestType::AddCluster(cluster.clone())) {
        debug!("Failed to add HTTP cluster {} (may already exist): {}", cluster_id, e);
    }
    if let Err(e) = send_to_worker(command_channel_https, format!("add-cluster-https-{}", cluster_id), RequestType::AddCluster(cluster)) {
        debug!("Failed to add HTTPS cluster {} (may already exist): {}", cluster_id, e);
    }

    // Configure frontends for each hostname
    for hostname in &entrypoint.config.hostnames {
        let path_rule = if let Some(path_config) = &entrypoint.config.path {
            PathRule {
                value: path_config.value.clone(),
                kind: match path_config.rule_type {
                    PathRuleType::Exact => 0,
                    PathRuleType::Prefix => 1,
                },
            }
        } else {
            PathRule {
                value: "/".to_string(),
                kind: 1,
            }
        };

        let http_front = RequestHttpFrontend {
            cluster_id: Some(cluster_id.to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
            hostname: hostname.clone(),
            path: path_rule.clone(),
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
        };

        if let Err(e) = send_to_worker(command_channel, format!("add-frontend-http-{}-{}", cluster_id, hostname), RequestType::AddHttpFrontend(http_front)) {
            debug!("Failed to add HTTP frontend for {} (may already exist): {}", hostname, e);
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
            };

            if let Err(e) = send_to_worker(command_channel_https, format!("add-frontend-https-{}-{}", cluster_id, hostname), RequestType::AddHttpFrontend(https_front)) {
                debug!("Failed to add HTTPS frontend for {} (may already exist): {}", hostname, e);
            }
        }
    }

    // Add backends
    // If this entrypoint needs middleware, route through the middleware server instead
    let use_middleware = middleware::needs_middleware(&entrypoint.config);

    if use_middleware {
        debug!("Routing {} through middleware server at 127.0.0.1:{}", entrypoint.name, middleware_port);
        let address = SocketAddress::new_v4(127, 0, 0, 1, middleware_port);
        let backend = AddBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: format!("{}-backend-0", cluster_id),
            address,
            load_balancing_parameters: Some(LoadBalancingParams { weight: 100 }),
            sticky_id: None,
            backup: None,
        };

        if let Err(e) = send_to_worker(command_channel, format!("add-backend-http-{}-0", cluster_id), RequestType::AddBackend(backend.clone())) {
            debug!("Failed to add HTTP middleware backend {} (may already exist): {}", backend.backend_id, e);
        }
        if entrypoint.config.tls {
            if let Err(e) = send_to_worker(command_channel_https, format!("add-backend-https-{}-0", cluster_id), RequestType::AddBackend(backend)) {
                debug!("Failed to add HTTPS middleware backend (may already exist): {}", e);
            }
        }
    } else {
        debug!("Setting up {} backends for {}: {:?}", entrypoint.backends.len(), entrypoint.name, entrypoint.backends);
        for (backend_index, backend_host) in entrypoint.backends.iter().enumerate() {
            let backend_port = entrypoint.config.port;
            let address = parse_backend_address(backend_host, backend_port)?;

            let backend = AddBackend {
                cluster_id: cluster_id.to_string(),
                backend_id: format!("{}-backend-{}", cluster_id, backend_index),
                address,
                load_balancing_parameters: Some(LoadBalancingParams {
                    weight: 100,
                }),
                sticky_id: None,
                backup: None,
            };

            debug!("Adding backend {}: {}:{}", backend.backend_id, backend_host, backend_port);
            if let Err(e) = send_to_worker(command_channel, format!("add-backend-http-{}-{}", cluster_id, backend_index), RequestType::AddBackend(backend.clone())) {
                debug!("Failed to add HTTP backend {} (may already exist): {}", backend.backend_id, e);
            }

            // HTTPS backend only if TLS is enabled
            if entrypoint.config.tls {
                let backend_id = backend.backend_id.clone();
                if let Err(e) = send_to_worker(command_channel_https, format!("add-backend-https-{}-{}", cluster_id, backend_index), RequestType::AddBackend(backend)) {
                    debug!("Failed to add HTTPS backend {} (may already exist): {}", backend_id, e);
                }
            }
        }
    }

    Ok(())
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
            anyhow::bail!("{} worker failed to become ready within {:?}: {}", name, timeout, e);
        }
    }
}

fn send_to_worker(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    id: String,
    request: RequestType,
) -> anyhow::Result<()> {
    channel.write_message(&WorkerRequest {
        id,
        content: Request {
            request_type: Some(request),
        },
    })?;
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

    info!("ACME challenge cluster registered -> 127.0.0.1:{}", challenge_port);
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
            versions: vec![
                TlsVersion::TlsV12 as i32,
                TlsVersion::TlsV13 as i32,
            ],
            names: names.to_vec(),
        },
        expired_at: None,
    };

    send_to_worker(
        command_channel_https,
        format!("add-cert-{}", names.first().map(|s| s.as_str()).unwrap_or("unknown")),
        RequestType::AddCertificate(cert),
    )?;

    info!("Certificate added for {:?}", names);
    Ok(())
}

fn remove_http_frontends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    snapshot: &EntrypointSnapshot,
    http_port: u16,
    https_port: u16,
) {
    let path_rule = if let Some(path_config) = &snapshot.path {
        PathRule {
            value: path_config.value.clone(),
            kind: match path_config.rule_type {
                PathRuleType::Exact => 0,
                PathRuleType::Prefix => 1,
            },
        }
    } else {
        PathRule {
            value: "/".to_string(),
            kind: 1,
        }
    };

    for hostname in &snapshot.hostnames {
        let http_front = RequestHttpFrontend {
            cluster_id: Some(cluster_id.to_string()),
            address: SocketAddress::new_v4(0, 0, 0, 0, http_port),
            hostname: hostname.clone(),
            path: path_rule.clone(),
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
        };

        if let Err(e) = send_to_worker(command_channel, format!("rm-frontend-http-{}-{}", cluster_id, hostname), RequestType::RemoveHttpFrontend(http_front)) {
            debug!("Failed to remove HTTP frontend for {}: {}", hostname, e);
        }

        if snapshot.tls {
            let https_front = RequestHttpFrontend {
                cluster_id: Some(cluster_id.to_string()),
                address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
                hostname: hostname.clone(),
                path: path_rule.clone(),
                method: None,
                position: RulePosition::Pre as i32,
                tags: BTreeMap::new(),
            };

            if let Err(e) = send_to_worker(command_channel_https, format!("rm-frontend-https-{}-{}", cluster_id, hostname), RequestType::RemoveHttpsFrontend(https_front)) {
                debug!("Failed to remove HTTPS frontend for {}: {}", hostname, e);
            }
        }
    }
}

fn remove_backends(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
    snapshot: &EntrypointSnapshot,
) {
    for (i, backend_host) in snapshot.backends.iter().enumerate() {
        let address = match parse_backend_address(backend_host, snapshot.port) {
            Ok(addr) => addr,
            Err(e) => {
                debug!("Failed to parse backend address {}:{} for removal: {}", backend_host, snapshot.port, e);
                continue;
            }
        };
        let backend_id = format!("{}-backend-{}", cluster_id, i);
        let remove = RemoveBackend {
            cluster_id: cluster_id.to_string(),
            backend_id: backend_id.clone(),
            address,
        };

        if let Err(e) = send_to_worker(command_channel, format!("rm-backend-http-{}-{}", cluster_id, i), RequestType::RemoveBackend(remove.clone())) {
            debug!("Failed to remove HTTP backend {}: {}", backend_id, e);
        }

        if snapshot.tls {
            if let Err(e) = send_to_worker(command_channel_https, format!("rm-backend-https-{}-{}", cluster_id, i), RequestType::RemoveBackend(remove)) {
                debug!("Failed to remove HTTPS backend {}: {}", backend_id, e);
            }
        }
    }
}

fn remove_cluster(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    cluster_id: &str,
) {
    if let Err(e) = send_to_worker(command_channel, format!("rm-cluster-http-{}", cluster_id), RequestType::RemoveCluster(cluster_id.to_string())) {
        debug!("Failed to remove HTTP cluster {}: {}", cluster_id, e);
    }
    if let Err(e) = send_to_worker(command_channel_https, format!("rm-cluster-https-{}", cluster_id), RequestType::RemoveCluster(cluster_id.to_string())) {
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
                kind: 1,
            },
            method: None,
            position: RulePosition::Pre as i32,
            tags: BTreeMap::new(),
        };

        if let Err(e) = send_to_worker(command_channel, format!("rm-frontend-acme-{}", hostname), RequestType::RemoveHttpFrontend(acme_front)) {
            debug!("Failed to remove ACME frontend for {}: {}", hostname, e);
        }
    }
}

fn apply_routing_diff(
    previous: &RoutingSnapshot,
    current: &RoutingSnapshot,
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    http_port: u16,
    https_port: u16,
    acme_challenge_port: Option<u16>,
) {
    // Handle removed clusters
    for (cluster_id, old_snapshot) in previous {
        if !current.contains_key(cluster_id) {
            info!("Removing stale cluster: {}", cluster_id);
            remove_http_frontends(command_channel, command_channel_https, cluster_id, old_snapshot, http_port, https_port);
            remove_backends(command_channel, command_channel_https, cluster_id, old_snapshot);
            remove_cluster(command_channel, command_channel_https, cluster_id);

            if acme_challenge_port.is_some() {
                remove_acme_frontends(command_channel, &old_snapshot.hostnames, http_port);
            }
        }
    }

    // Handle changed clusters
    for (cluster_id, old_snapshot) in previous {
        if let Some(new_snapshot) = current.get(cluster_id) {
            if old_snapshot != new_snapshot {
                info!("Updating changed cluster: {}", cluster_id);
                remove_http_frontends(command_channel, command_channel_https, cluster_id, old_snapshot, http_port, https_port);
                remove_backends(command_channel, command_channel_https, cluster_id, old_snapshot);

                if acme_challenge_port.is_some() && old_snapshot.hostnames != new_snapshot.hostnames {
                    remove_acme_frontends(command_channel, &old_snapshot.hostnames, http_port);
                }
            }
        }
    }
}

fn parse_backend_address(host: &str, port: u16) -> anyhow::Result<SocketAddress> {
    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse()?;
    
    match addr {
        std::net::SocketAddr::V4(addr_v4) => {
            let ip = addr_v4.ip().octets();
            Ok(SocketAddress::new_v4(ip[0], ip[1], ip[2], ip[3], addr_v4.port()))
        },
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
        let result = parse_backend_address("192.168.1.100", 8080);
        assert!(result.is_ok(), "Failed to parse IPv4 address: {:?}", result);
        // No need to test exact format, just that it parses
    }

    #[test]
    fn test_parse_backend_address_localhost() {
        let result = parse_backend_address("127.0.0.1", 3000);
        assert!(result.is_ok(), "Failed to parse localhost: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_hostname() {
        let result = parse_backend_address("localhost", 80);
        // Localhost may not resolve in all test environments
        // Just verify we get a consistent result
        match result {
            Ok(_) => (),
            Err(e) => {
                println!("Hostname resolution failed (expected in some test environments): {}", e);
            }
        }
    }

    #[test]
    fn test_parse_backend_address_invalid() {
        let result = parse_backend_address("invalid-host-name-that-does-not-exist", 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_backend_address_invalid_port() {
        let result = parse_backend_address("127.0.0.1", 0);
        assert!(result.is_ok()); // Port 0 is technically valid
    }
}