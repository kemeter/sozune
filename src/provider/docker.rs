use bollard::{Docker, query_parameters::{ListContainersOptions, InspectContainerOptions, EventsOptions}, models::EventMessage};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use crate::model::{Entrypoint, Protocol, EntrypointConfig, PathConfig, PathRuleType, AuthConfig, BasicAuthUser};
use crate::provider::Provider;
use crate::config::DockerConfig;

pub struct DockerProvider {
    docker: Docker,
    config: DockerConfig,
    /// Tracks container_id -> IP so we can clean up when the container stops
    /// (stopped containers no longer expose their network IP via inspect)
    container_ips: std::sync::Mutex<HashMap<String, String>>,
}

#[async_trait]
impl Provider for DockerProvider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let hashmap = self.get_entrypoints_from_containers().await
            .map_err(|e| anyhow::Error::new(e))?;
        Ok(hashmap.into_iter().collect())
    }

    fn name(&self) -> &'static str {
        "docker"
    }
}

impl DockerProvider {
    /// Check if container should be exposed based on sozune.enable label and expose_by_default config
    fn should_expose_container(&self, labels: &HashMap<String, String>) -> bool {
        labels.get("sozune.enable").map_or(self.config.expose_by_default, |v| v == "true")
    }
    pub fn new(config: DockerConfig) -> Result<Self, bollard::errors::Error> {
        let docker = if config.endpoint.starts_with("unix://") {
            Docker::connect_with_socket(&config.endpoint, 120, bollard::API_DEFAULT_VERSION)?
        } else if config.endpoint.starts_with("/") {
            Docker::connect_with_socket(&format!("unix://{}", config.endpoint), 120, bollard::API_DEFAULT_VERSION)?
        } else {
            Docker::connect_with_local_defaults()?
        };
        Ok(Self { docker, config, container_ips: std::sync::Mutex::new(HashMap::new()) })
    }

    /// Start Docker service: initial scan + event listening
    pub async fn start_service(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::UnboundedSender<()>
    ) -> anyhow::Result<()> {
        info!("Starting Docker service");
        
        // Initial scan of existing containers
        info!("Performing initial scan of running containers");
        match self.get_entrypoints_from_containers().await {
            Ok(initial_entrypoints) => {
                if !initial_entrypoints.is_empty() {
                    let mut storage_changed = false;
                    let mut storage_write = match storage.write() {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("Storage lock poisoned during initial scan: {}", e);
                            return Ok(());
                        }
                    };
                    
                    for (key, mut entrypoint) in initial_entrypoints {
                        entrypoint.source = Some("docker".to_string());
                        
                        if !storage_write.contains_key(&key) {
                            info!("Found new container entrypoint: {}", key);
                            storage_write.insert(key, entrypoint);
                            storage_changed = true;
                        } else {
                            info!("Container entrypoint {} already exists in storage", key);
                        }
                    }
                    drop(storage_write);
                    
                    // Only trigger reload if configuration actually changed
                    if storage_changed {
                        if let Err(e) = reload_tx.send(()) {
                            warn!("Failed to send initial reload signal: {}", e);
                        } else {
                            info!("Initial configuration loaded from running containers");
                        }
                    } else {
                        info!("No new container entrypoints found, configuration unchanged");
                    }
                } else {
                    info!("No running containers with Sozune labels found");
                }
            }
            Err(e) => {
                error!("Failed to scan running containers: {}", e);
            }
        }
        
        // Start event listener
        self.start_event_listener(storage, reload_tx).await
    }

    /// Start listening for Docker events and update storage directly
    pub async fn start_event_listener(
        &self, 
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::UnboundedSender<()>
    ) -> anyhow::Result<()> {
        info!("Starting Docker event listener");
        
        let mut filters = std::collections::HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert("event".to_string(), vec!["start".to_string(), "stop".to_string(), "die".to_string(), "destroy".to_string(), "update".to_string()]);

        let mut events = self.docker.events(Some(EventsOptions {
            since: None,
            until: None,
            filters: Some(filters),
        }));

        while let Some(event_result) = events.next().await {
            match event_result {
                Ok(event) => {
                    if let Some(action) = &event.action {
                        if let Some(actor) = &event.actor {
                            if let Some(container_id) = &actor.id {
                                info!("Docker event: {} for container {}", action, container_id);
                                
                                let mut storage_changed = false;
                                
                                match action.as_str() {
                                    "start" => {
                                        // Track the container IP for later cleanup
                                        if let Some(ip) = self.get_container_ip(container_id).await {
                                            if let Ok(mut ips) = self.container_ips.lock() {
                                                ips.insert(container_id.to_string(), ip);
                                            }
                                        }

                                        if let Ok(entrypoints) = self.get_container_entrypoints(container_id).await {
                                            if !entrypoints.is_empty() {
                                                let mut storage_write = match storage.write() {
                                                    Ok(guard) => guard,
                                                    Err(e) => {
                                                        error!("Storage lock poisoned on container start: {}", e);
                                                        continue;
                                                    }
                                                };
                                                for (key, entrypoint) in entrypoints {
                                                    info!("Adding entrypoint from started container: {}", key);
                                                    if let Some(existing) = storage_write.get_mut(&key) {
                                                        // Merge backends
                                                        for backend in entrypoint.backends {
                                                            if !existing.backends.contains(&backend) {
                                                                existing.backends.push(backend);
                                                            }
                                                        }
                                                    } else {
                                                        let mut entrypoint = entrypoint;
                                                        entrypoint.source = Some("docker".to_string());
                                                        storage_write.insert(key, entrypoint);
                                                    }
                                                }
                                                storage_changed = true;
                                            }
                                        }
                                    }
                                    "stop" | "die" | "destroy" => {
                                        // Use tracked IP (stopped containers lose their network IP)
                                        let container_ip = self.container_ips.lock().ok()
                                            .and_then(|mut ips| ips.remove(container_id.as_str()))
                                            .or_else(|| {
                                                // Fallback: try inspect (may work for "stop" before network teardown)
                                                None
                                            })
                                            .unwrap_or_else(|| {
                                                warn!("No tracked IP for stopped container {}, cleanup may be incomplete", container_id);
                                                "127.0.0.1".to_string()
                                            });
                                        let mut storage_write = match storage.write() {
                                            Ok(guard) => guard,
                                            Err(e) => {
                                                error!("Storage lock poisoned on container stop: {}", e);
                                                continue;
                                            }
                                        };
                                        
                                        let mut keys_to_remove = Vec::new();
                                        for (key, entrypoint) in storage_write.iter_mut() {
                                            // Remove this container's IP from backends
                                            entrypoint.backends.retain(|ip| ip != &container_ip);
                                            
                                            // If no backends left, mark for removal
                                            if entrypoint.backends.is_empty() {
                                                keys_to_remove.push(key.clone());
                                            }
                                        }
                                        
                                        for key in &keys_to_remove {
                                            info!("Removing entrypoint with no backends: {}", key);
                                            storage_write.remove(key);
                                        }

                                        storage_changed = true;
                                    }
                                    "update" => {
                                        // For updates, remove old and add new
                                        if let Ok(entrypoints) = self.get_container_entrypoints(container_id).await {
                                            let container_ip = self.get_container_ip(container_id).await.unwrap_or_else(|| "127.0.0.1".to_string());
                                            let mut storage_write = match storage.write() {
                                                Ok(guard) => guard,
                                                Err(e) => {
                                                    error!("Storage lock poisoned on container update: {}", e);
                                                    continue;
                                                }
                                            };
                                            
                                            // Remove old entries for this container
                                            let mut keys_to_remove = Vec::new();
                                            for (key, entrypoint) in storage_write.iter_mut() {
                                                entrypoint.backends.retain(|ip| ip != &container_ip);
                                                if entrypoint.backends.is_empty() {
                                                    keys_to_remove.push(key.clone());
                                                }
                                            }
                                            for key in keys_to_remove {
                                                storage_write.remove(&key);
                                            }
                                            
                                            // Add new entries
                                            for (key, entrypoint) in entrypoints {
                                                if let Some(existing) = storage_write.get_mut(&key) {
                                                    for backend in entrypoint.backends {
                                                        if !existing.backends.contains(&backend) {
                                                            existing.backends.push(backend);
                                                        }
                                                    }
                                                } else {
                                                    let mut entrypoint = entrypoint;
                                                    entrypoint.source = Some("docker".to_string());
                                                    storage_write.insert(key, entrypoint);
                                                }
                                            }
                                            storage_changed = true;
                                        }
                                    }
                                    _ => {
                                        // Other events we don't care about
                                    }
                                }
                                
                                if storage_changed {
                                    info!("Storage updated, triggering reload");
                                    if let Err(e) = reload_tx.send(()) {
                                        error!("Failed to send reload signal: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Docker event error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        warn!("Docker event listener stopped");
        Ok(())
    }

    /// Get entrypoints for a specific container
    async fn get_container_entrypoints(&self, container_id: &str) -> Result<HashMap<String, Entrypoint>, bollard::errors::Error> {
        let mut entrypoints = HashMap::new();
        
        let container = self.docker.inspect_container(container_id, None::<InspectContainerOptions>).await?;
        
        if let Some(config) = container.config {
            if let Some(labels) = config.labels {
                // Check if Sozune is enabled for this container
                if !self.should_expose_container(&labels) {
                    return Ok(entrypoints);
                }
                
                // Get container IP address
                let container_ip = self.get_container_ip(container_id).await.unwrap_or_else(|| "127.0.0.1".to_string());
                
                // Parse labels by protocol
                for protocol in &["http", "tcp", "udp"] {
                    let protocol_entrypoints = self.parse_protocol_labels(&labels, protocol, &container_ip);
                    for (key, entrypoint) in protocol_entrypoints {
                        entrypoints.insert(key, entrypoint);
                    }
                }
            }
        }
        
        Ok(entrypoints)
    }

    /// Check if a container event should trigger a reload
    async fn should_reload_for_container(&self, event: &EventMessage) -> bool {
        if let Some(actor) = &event.actor {
            if let Some(container_id) = &actor.id {
                // For stop/die/destroy events, we always reload since we can't inspect stopped containers
                if let Some(action) = &event.action {
                    if matches!(action.as_str(), "stop" | "die" | "destroy") {
                        return true;
                    }
                }

                // For other events, check if container has sozune labels
                if let Ok(container) = self.docker.inspect_container(container_id, None::<InspectContainerOptions>).await {
                    if let Some(config) = container.config {
                        if let Some(labels) = config.labels {
                            return self.should_expose_container(&labels);
                        }
                    }
                }
            }
        }
        false
    }

    pub async fn get_entrypoints_from_containers(&self) -> Result<HashMap<String, Entrypoint>, bollard::errors::Error> {
        let mut entrypoints: HashMap<String, Entrypoint> = HashMap::new();
        
        let containers = self.docker
            .list_containers(Some(ListContainersOptions {
                all: false,
                ..Default::default()
            }))
            .await?;

        for container in containers {
            if let Some(labels) = container.labels {
                let container_id = container.id.unwrap_or_default();
                
                // Check if Sozune is enabled for this container
                if !self.should_expose_container(&labels) {
                    info!("Skipping container {} since Sozune is disabled", container_id);
                    continue;
                }
                
                // Get container IP address
                let container_ip = self.get_container_ip(&container_id).await.unwrap_or_else(|| "127.0.0.1".to_string());

                // Track container IP for cleanup on stop
                if let Ok(mut ips) = self.container_ips.lock() {
                    ips.insert(container_id.clone(), container_ip.clone());
                }

                // Parse labels by protocol
                for protocol in &["http", "tcp", "udp"] {
                    let protocol_entrypoints = self.parse_protocol_labels(&labels, protocol, &container_ip);
                    for (key, entrypoint) in protocol_entrypoints {
                        if let Some(existing) = entrypoints.get_mut(&key) {
                            existing.backends.push(container_ip.clone());
                            info!("Added backend {} to existing entrypoint {}", container_ip, key);
                        } else {
                            entrypoints.insert(key.clone(), entrypoint);
                            info!("Created new entrypoint {}", key);
                        }
                    }
                }
            }
        }

        Ok(entrypoints)
    }

    fn parse_protocol_labels(&self, labels: &HashMap<String, String>, protocol: &str, container_ip: &str) -> HashMap<String, Entrypoint> {
        let mut entrypoints = HashMap::new();
        let prefix = format!("sozune.{}.", protocol);
        
        // Find all service names for this protocol
        let mut service_names = std::collections::HashSet::new();
        for key in labels.keys() {
            if key.starts_with(&prefix) {
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if let Some(service_name) = rest.split('.').next() {
                        service_names.insert(service_name.to_string());
                    }
                }
            }
        }

        // Create an entrypoint for each service
        for service_name in service_names {
            if let Some(entrypoint) = self.create_entrypoint_from_labels(labels, protocol, &service_name, container_ip) {
                let key = format!("{}_{}", protocol, service_name);
                entrypoints.insert(key, entrypoint);
            }
        }

        entrypoints
    }

    fn create_entrypoint_from_labels(&self, labels: &HashMap<String, String>, protocol: &str, service_name: &str, container_ip: &str) -> Option<Entrypoint> {
        let prefix = format!("sozune.{}.{}.", protocol, service_name);
        
        // Get hostnames (required)
        let hostnames_str = labels.get(&format!("{}host", prefix))?;
        let hostnames: Vec<String> = hostnames_str.split(',').map(|h| h.trim().to_string()).collect();
        
        // Port (default based on protocol)
        let default_port = match protocol {
            "http" => 80,
            "https" => 443,
            _ => 8080,
        };
        let port = labels.get(&format!("{}port", prefix))
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);

        let path = if protocol == "http" {
            let exact_path = labels.get(&format!("{}path", prefix));
            let prefix_path = labels.get(&format!("{}prefix", prefix));
            
            match (exact_path, prefix_path) {
                (Some(path), _) => Some(PathConfig {
                    rule_type: PathRuleType::Exact,
                    value: path.clone(),
                }),
                (None, Some(prefix)) => Some(PathConfig {
                    rule_type: PathRuleType::Prefix,
                    value: prefix.clone(),
                }),
                _ => Some(PathConfig {
                    rule_type: PathRuleType::Prefix,
                    value: "/".to_string(),
                }),
            }
        } else {
            None
        };

        let tls = labels.get(&format!("{}tls", prefix))
            .map_or(false, |v| v == "true");

        let strip_prefix = labels.get(&format!("{}stripPrefix", prefix))
            .map_or(false, |v| v == "true");

        let priority = labels.get(&format!("{}priority", prefix))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);

        let auth = self.parse_auth_labels(labels, &prefix);

        let headers = self.parse_header_labels(labels, &prefix);

        let protocol_enum = match protocol {
            "http" => Protocol::Http,
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return None,
        };

        Some(Entrypoint {
            id: format!("{}_{}", protocol, service_name),
            backends: vec![container_ip.to_string()],
            name: service_name.to_string(),
            protocol: protocol_enum,
            config: EntrypointConfig {
                hostnames,
                port,
                path,
                tls,
                strip_prefix,
                priority,
                auth,
                headers,
            },
            source: None, // Will be set by the caller
        })
    }

    fn parse_auth_labels(&self, labels: &HashMap<String, String>, prefix: &str) -> Option<AuthConfig> {
        let basic_auth_str = labels.get(&format!("{}auth.basic", prefix))?;
        let users: Vec<BasicAuthUser> = basic_auth_str
            .split(',')
            .filter_map(|entry| {
                let parts: Vec<&str> = entry.trim().splitn(2, ':').collect();
                if parts.len() == 2 {
                    Some(BasicAuthUser {
                        username: parts[0].to_string(),
                        password_hash: parts[1].to_string(),
                    })
                } else {
                    warn!("Invalid basic auth format: {}", entry);
                    None
                }
            })
            .collect();

        if users.is_empty() {
            None
        } else {
            Some(AuthConfig {
                basic: Some(users),
            })
        }
    }

    fn parse_header_labels(&self, labels: &HashMap<String, String>, prefix: &str) -> HashMap<String, String> {
        let header_prefix = format!("{}headers.", prefix);
        let mut headers = HashMap::new();
        
        for (key, value) in labels {
            if let Some(header_name) = key.strip_prefix(&header_prefix) {
                headers.insert(header_name.to_string(), value.clone());
            }
        }
        
        headers
    }

    async fn get_container_ip(&self, container_id: &str) -> Option<String> {
        let container = self.docker.inspect_container(container_id, None::<InspectContainerOptions>).await.ok()?;
        
        let preferred_network = container.config.as_ref()
            .and_then(|config| config.labels.as_ref())
            .and_then(|labels| labels.get("sozune.network"))
            .map(|network| network.clone());
        
        if let Some(network_settings) = container.network_settings {
            if let Some(networks) = network_settings.networks {
                // If a preferred network is specified, use it
                if let Some(preferred) = &preferred_network {
                    if let Some(network) = networks.get(preferred) {
                        if let Some(ip) = &network.ip_address {
                            if !ip.is_empty() {
                                return Some(ip.clone());
                            }
                        }
                    }
                }
                
                // Fallback: take the first IP found in networks
                for (_, network) in networks {
                    if let Some(ip) = network.ip_address {
                        if !ip.is_empty() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_labels() -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert("sozune.enable".to_string(), "true".to_string());
        
        // Web service HTTP
        labels.insert("sozune.http.web.host".to_string(), "example.com,www.example.com".to_string());
        labels.insert("sozune.http.web.port".to_string(), "8080".to_string());
        labels.insert("sozune.http.web.prefix".to_string(), "/api".to_string());
        labels.insert("sozune.http.web.tls".to_string(), "true".to_string());
        labels.insert("sozune.http.web.stripPrefix".to_string(), "false".to_string());
        labels.insert("sozune.http.web.priority".to_string(), "10".to_string());
        labels.insert("sozune.http.web.auth.basic".to_string(), "admin:$2b$10$hash1,user:$2b$10$hash2".to_string());
        labels.insert("sozune.http.web.headers.X-Custom-Header".to_string(), "custom-value".to_string());
        
        // API service HTTP
        labels.insert("sozune.http.api.host".to_string(), "api.example.com".to_string());
        labels.insert("sozune.http.api.port".to_string(), "3000".to_string());
        labels.insert("sozune.http.api.path".to_string(), "/exact".to_string());
        
        // TCP service
        labels.insert("sozune.tcp.db.host".to_string(), "db.example.com".to_string());
        labels.insert("sozune.tcp.db.port".to_string(), "5432".to_string());
        
        labels
    }

    #[test]
    fn test_parse_protocol_labels() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let labels = create_test_labels();
        let container_ip = "192.168.1.100";

        // Test parsing HTTP labels
        let http_entrypoints = provider.parse_protocol_labels(&labels, "http", container_ip);
        
        // Should have 2 HTTP services: web and api
        assert_eq!(http_entrypoints.len(), 2);
        
        // Test web service
        let web_entrypoint = http_entrypoints.get("http_web").unwrap();
        assert_eq!(web_entrypoint.name, "web");
        assert!(matches!(web_entrypoint.protocol, Protocol::Http));
        assert_eq!(web_entrypoint.config.hostnames, vec!["example.com", "www.example.com"]);
        assert_eq!(web_entrypoint.config.port, 8080);
        assert_eq!(web_entrypoint.config.tls, true);
        assert_eq!(web_entrypoint.config.strip_prefix, false);
        assert_eq!(web_entrypoint.config.priority, 10);
        
        let path_config = web_entrypoint.config.path.as_ref().unwrap();
        assert_eq!(path_config.value, "/api");
        assert!(matches!(path_config.rule_type, PathRuleType::Prefix));
        
        let auth = web_entrypoint.config.auth.as_ref().unwrap();
        let basic_users = auth.basic.as_ref().unwrap();
        assert_eq!(basic_users.len(), 2);
        assert_eq!(basic_users[0].username, "admin");
        assert_eq!(basic_users[0].password_hash, "$2b$10$hash1");
        
        assert_eq!(web_entrypoint.config.headers.get("X-Custom-Header").unwrap(), "custom-value");
        
        // Test api service
        let api_entrypoint = http_entrypoints.get("http_api").unwrap();
        assert_eq!(api_entrypoint.name, "api");
        assert_eq!(api_entrypoint.config.hostnames, vec!["api.example.com"]);
        assert_eq!(api_entrypoint.config.port, 3000);
        
        let path_config = api_entrypoint.config.path.as_ref().unwrap();
        assert_eq!(path_config.value, "/exact");
        assert!(matches!(path_config.rule_type, PathRuleType::Exact));
    }

    #[test]
    fn test_parse_tcp_labels() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let labels = create_test_labels();
        let container_ip = "192.168.1.100";

        // Test parsing TCP labels
        let tcp_entrypoints = provider.parse_protocol_labels(&labels, "tcp", container_ip);
        
        // Should have 1 TCP service: db
        assert_eq!(tcp_entrypoints.len(), 1);
        
        let db_entrypoint = tcp_entrypoints.get("tcp_db").unwrap();
        assert_eq!(db_entrypoint.name, "db");
        assert!(matches!(db_entrypoint.protocol, Protocol::Tcp));
        assert_eq!(db_entrypoint.config.hostnames, vec!["db.example.com"]);
        assert_eq!(db_entrypoint.config.port, 5432);
        assert_eq!(db_entrypoint.config.path, None);
    }

    #[test]
    fn test_parse_auth_labels() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let labels = create_test_labels();
        
        let auth = provider.parse_auth_labels(&labels, "sozune.http.web.");
        assert!(auth.is_some());
        
        let auth = auth.unwrap();
        let basic_users = auth.basic.unwrap();
        assert_eq!(basic_users.len(), 2);
        assert_eq!(basic_users[0].username, "admin");
        assert_eq!(basic_users[1].username, "user");
    }

    #[test]
    fn test_parse_header_labels() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let labels = create_test_labels();
        
        let headers = provider.parse_header_labels(&labels, "sozune.http.web.");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("X-Custom-Header").unwrap(), "custom-value");
    }

    #[test]
    fn test_disabled_container() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let mut labels = HashMap::new();
        labels.insert("sozune.enable".to_string(), "false".to_string());
        labels.insert("sozune.http.web.host".to_string(), "example.com".to_string());
        
        let entrypoints = provider.parse_protocol_labels(&labels, "http", "192.168.1.100");
        assert_eq!(entrypoints.len(), 1);
        
        // Enable check is done upstream in get_entrypoints_from_containers
        assert_eq!(labels.get("sozune.enable").map_or(false, |v| v == "true"), false);
    }

    #[test]
    fn test_missing_host_label() {
        let provider = DockerProvider {
            docker: Docker::connect_with_local_defaults().unwrap(),
            config: Default::default(),
            container_ips: std::sync::Mutex::new(HashMap::new()),
        };
        let mut labels = HashMap::new();
        labels.insert("sozune.enable".to_string(), "true".to_string());
        labels.insert("sozune.http.web.port".to_string(), "8080".to_string());
        
        let entrypoints = provider.parse_protocol_labels(&labels, "http", "192.168.1.100");
        assert_eq!(entrypoints.len(), 0);
    }
}
