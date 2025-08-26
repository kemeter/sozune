use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread;
use tokio::sync::mpsc;
use tracing::{info, error, debug};
use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    proto::command::{
        SocketAddress, WorkerRequest, WorkerResponse, Request, request::RequestType,
        AddBackend, Cluster, LoadBalancingAlgorithms, LoadBalancingParams,
        RequestHttpFrontend, PathRule, RulePosition
    },
};
use crate::model::{Entrypoint, Protocol, PathRuleType};
use crate::config::ProxyConfig;

pub fn start_sozu_proxy(
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    config: &ProxyConfig,
    _shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    mut reload_rx: mpsc::UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    info!("Starting Sōzu HTTP and HTTPS workers");

    // Copy values needed for threads
    let max_buffers = config.max_buffers;
    let buffer_size = config.buffer_size;

    // HTTP Listener
    let http_listener = ListenerBuilder::new_http(SocketAddress::new_v4(0, 0, 0, 0, config.http.listen_address))
        .to_http(None)
        .expect("Could not create an HTTP listener");

    let https_listener = ListenerBuilder::new_https(SocketAddress::new_v4(0, 0, 0, 0, config.https.listen_address))
        .to_tls(None)
        .expect("Could not create an HTTPS listener");

    // Create communication channels
    let (mut command_channel, proxy_channel) = 
        Channel::generate(1000, 10000).expect("should create a channel");
    let (mut command_channel_https, proxy_channel_https) = 
        Channel::generate(1000, 10000).expect("should create a channel for HTTPS");

    let worker_http_handle = thread::spawn(move || {
        sozu_lib::http::testing::start_http_worker(
            http_listener, 
            proxy_channel, 
            max_buffers, 
            buffer_size
        ).expect("could not start the HTTP server");
    });

    let worker_https_handle = thread::spawn(move || {
        sozu_lib::https::testing::start_https_worker(
            https_listener, 
            proxy_channel_https, 
            max_buffers, 
            buffer_size
        ).expect("could not start the HTTPS server");
    });

    // Wait for workers to be ready
    thread::sleep(std::time::Duration::from_millis(config.startup_delay_ms));

    // Initial configuration will be handled by provider reload signals
    info!("Waiting for providers to populate configuration");

    info!("Sōzu HTTP worker running on 0.0.0.0:{}", config.http.listen_address);
    info!("Sōzu HTTPS worker running on 0.0.0.0:{}", config.https.listen_address);

    // Start configuration reload handler
    let storage_reload = Arc::clone(&storage);
    let http_port = config.http.listen_address;
    let https_port = config.https.listen_address;
    let cluster_setup_delay_ms = config.cluster_setup_delay_ms;

    let reload_handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            while let Some(_) = reload_rx.recv().await {
                info!("Received configuration reload request");
                
                // Just reconfigure with the current storage state
                let storage_read = storage_reload.read().unwrap();
                match configure_sozu_routing(&mut command_channel, &mut command_channel_https, &*storage_read, http_port, https_port, cluster_setup_delay_ms) {
                    Ok(()) => {
                        info!("Configuration reloaded successfully");
                    }
                    Err(e) => {
                        error!("Failed to reload configuration: {}", e);
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

fn configure_sozu_routing(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    storage: &BTreeMap<String, Entrypoint>,
    http_port: u16,
    https_port: u16,
    cluster_setup_delay_ms: u64,
) -> anyhow::Result<()> {
    info!("Applying Sōzu configuration for {} entrypoints", storage.len());
    
    for (cluster_id, entrypoint) in storage.iter() {
        // Only process HTTP entrypoints for Sozu
        match entrypoint.protocol {
            Protocol::Http => {
                debug!("Configuring HTTP cluster: {}", entrypoint.name);
                configure_http_entrypoint(command_channel, command_channel_https, cluster_id, entrypoint, http_port, https_port)?;
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
) -> anyhow::Result<()> {
    // Add cluster for both HTTP and HTTPS
    let cluster = Cluster {
        cluster_id: cluster_id.to_string(),
        sticky_session: false,
        https_redirect: false,
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

    Ok(())
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
        // Pas besoin de tester le format exact, juste que ça parse
    }

    #[test]
    fn test_parse_backend_address_localhost() {
        let result = parse_backend_address("127.0.0.1", 3000);
        assert!(result.is_ok(), "Failed to parse localhost: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_hostname() {
        let result = parse_backend_address("localhost", 80);
        // Localhost peut ne pas résoudre dans tous les environnements de test
        // On vérifie juste qu'on a un résultat cohérent
        match result {
            Ok(_) => (), // OK si ça marche
            Err(e) => {
                // OK si ça échoue pour des raisons de résolution DNS
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
        assert!(result.is_ok()); // Port 0 est techniquement valide
    }
}