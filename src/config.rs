use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub providers: ProvidersConfig,
    pub api: ApiConfig,
    pub proxy: ProxyConfig,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct ProvidersConfig {
    pub docker: Option<DockerConfig>,
    pub config_file: Option<ConfigFileConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DockerConfig {
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen_address: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConfigFileConfig {
    pub enabled: bool,
    pub path: String,
    pub watch: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub http: HttpConfig,
    pub https: HttpsConfig,
    #[serde(default = "default_max_buffers")]
    pub max_buffers: usize,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_startup_delay_ms")]
    pub startup_delay_ms: u64,
    #[serde(default = "default_cluster_setup_delay_ms")]
    pub cluster_setup_delay_ms: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HttpConfig {
    #[serde(default = "default_http_port", deserialize_with = "deserialize_port_with_env")]
    pub listen_address: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HttpsConfig {
    #[serde(default = "default_https_port", deserialize_with = "deserialize_https_port_with_env")]
    pub listen_address: u16,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "/var/run/docker.sock".to_string(),
            expose_by_default: false,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_api_listen_address(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen_address: default_http_port(),
        }
    }
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            listen_address: default_https_port(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            http: Default::default(),
            https: Default::default(),
            max_buffers: default_max_buffers(),
            buffer_size: default_buffer_size(),
            startup_delay_ms: default_startup_delay_ms(),
            cluster_setup_delay_ms: default_cluster_setup_delay_ms(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            providers: Default::default(),
            api: Default::default(),
            proxy: Default::default(),
        }
    }
}

fn default_max_buffers() -> usize {
    500
}

fn default_buffer_size() -> usize {
    16384
}

fn default_startup_delay_ms() -> u64 {
    1000
}

fn default_cluster_setup_delay_ms() -> u64 {
    500
}

fn default_api_listen_address() -> String {
    "0.0.0.0:3035".to_string()
}

fn default_http_port() -> u16 {
    8080
}

fn default_https_port() -> u16 {
    8443
}

fn get_env_port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(default)
}

fn deserialize_port_with_env<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let port = u16::deserialize(deserializer).unwrap_or(default_http_port());
    Ok(get_env_port("SOZU_HTTP_PORT", port))
}

fn deserialize_https_port_with_env<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let port = u16::deserialize(deserializer).unwrap_or(default_https_port());
    Ok(get_env_port("SOZU_HTTPS_PORT", port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(default_http_port(), 8080);
        assert_eq!(default_https_port(), 8443);
        assert_eq!(default_max_buffers(), 500);
        assert_eq!(default_buffer_size(), 16384);
        assert_eq!(default_startup_delay_ms(), 1000);
        assert_eq!(default_cluster_setup_delay_ms(), 500);
    }

    #[test]
    fn test_get_env_port_with_valid_env() {
        unsafe {
            std::env::set_var("TEST_PORT", "9000");
            let result = get_env_port("TEST_PORT", 8080);
            assert_eq!(result, 9000);
            std::env::remove_var("TEST_PORT");
        }
    }

    #[test]
    fn test_get_env_port_with_invalid_env() {
        unsafe {
            std::env::set_var("TEST_PORT_INVALID", "not_a_number");
            let result = get_env_port("TEST_PORT_INVALID", 8080);
            assert_eq!(result, 8080);
            std::env::remove_var("TEST_PORT_INVALID");
        }
    }

    #[test]
    fn test_get_env_port_no_env() {
        let result = get_env_port("NON_EXISTENT_PORT", 3000);
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_proxy_config_deserialization() {
        let yaml = r#"
http:
  listen_address: 9080
https:
  listen_address: 9443
max_buffers: 1000
buffer_size: 32768
startup_delay_ms: 2000
cluster_setup_delay_ms: 1000
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.http.listen_address, 9080);
        assert_eq!(config.https.listen_address, 9443);
        assert_eq!(config.max_buffers, 1000);
        assert_eq!(config.buffer_size, 32768);
        assert_eq!(config.startup_delay_ms, 2000);
        assert_eq!(config.cluster_setup_delay_ms, 1000);
    }

    #[test]
    fn test_proxy_config_with_defaults() {
        let yaml = r#"
http:
  listen_address: 9080
https:
  listen_address: 9443
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.http.listen_address, 9080);
        assert_eq!(config.https.listen_address, 9443);
        // Vérifier que les valeurs par défaut sont utilisées
        assert_eq!(config.max_buffers, 500);
        assert_eq!(config.buffer_size, 16384);
        assert_eq!(config.startup_delay_ms, 1000);
        assert_eq!(config.cluster_setup_delay_ms, 500);
    }
}
