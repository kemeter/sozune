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
    #[serde(default, deserialize_with = "deserialize_docker_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_docker_endpoint_with_env")]
    pub endpoint: String,
    #[serde(default, deserialize_with = "deserialize_docker_expose_by_default_with_env")]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiConfig {
    #[serde(default, deserialize_with = "deserialize_api_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_api_listen_address_with_env")]
    pub listen_address: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConfigFileConfig {
    #[serde(default, deserialize_with = "deserialize_config_file_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_config_file_path_with_env")]
    pub path: String,
    #[serde(default, deserialize_with = "deserialize_config_file_watch_with_env")]
    pub watch: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub http: HttpConfig,
    pub https: HttpsConfig,
    #[serde(default = "default_max_buffers", deserialize_with = "deserialize_max_buffers_with_env")]
    pub max_buffers: usize,
    #[serde(default = "default_buffer_size", deserialize_with = "deserialize_buffer_size_with_env")]
    pub buffer_size: usize,
    #[serde(default = "default_startup_delay_ms", deserialize_with = "deserialize_startup_delay_ms_with_env")]
    pub startup_delay_ms: u64,
    #[serde(default = "default_cluster_setup_delay_ms", deserialize_with = "deserialize_cluster_setup_delay_ms_with_env")]
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

fn get_env_with_parse<T: std::str::FromStr>(var: &str, default: T) -> T {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

// Macro pour générer les fonctions de désérialisation
macro_rules! deserialize_with_env {
    ($fn_name:ident, $env_var:expr, $type:ty, $default_fn:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = <$type>::deserialize(deserializer).unwrap_or_else(|_| $default_fn());
            Ok(get_env_with_parse($env_var, value))
        }
    };
    ($fn_name:ident, $env_var:expr, $type:ty, $default_value:expr, literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = <$type>::deserialize(deserializer).unwrap_or($default_value);
            Ok(get_env_with_parse($env_var, value))
        }
    };
}

deserialize_with_env!(deserialize_port_with_env, "SOZUNE_HTTP_PORT", u16, default_http_port);
deserialize_with_env!(deserialize_https_port_with_env, "SOZUNE_HTTPS_PORT", u16, default_https_port);

// Fonction spécialisée pour les booléens
fn get_env_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .ok()
        .and_then(|v| match v.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

// Fonction spécialisée pour les String
fn get_env_string(var: &str, default: String) -> String {
    std::env::var(var).unwrap_or(default)
}

// Macro spécialisée pour les booléens
macro_rules! deserialize_bool_with_env {
    ($fn_name:ident, $env_var:expr, $default_value:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<bool, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = bool::deserialize(deserializer).unwrap_or($default_value);
            Ok(get_env_bool($env_var, value))
        }
    };
}

// Macro spécialisée pour les String
macro_rules! deserialize_string_with_env {
    ($fn_name:ident, $env_var:expr, $default_fn:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer).unwrap_or_else(|_| $default_fn());
            Ok(get_env_string($env_var, value))
        }
    };
    ($fn_name:ident, $env_var:expr, $default_value:expr, literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer).unwrap_or_else(|_| $default_value.to_string());
            Ok(get_env_string($env_var, value))
        }
    };
}

// Génération de toutes les fonctions avec les macros
deserialize_bool_with_env!(deserialize_docker_enabled_with_env, "SOZUNE_PROVIDER_DOCKER_ENABLED", false);
deserialize_string_with_env!(deserialize_docker_endpoint_with_env, "SOZUNE_PROVIDER_DOCKER_ENDPOINT", "/var/run/docker.sock", literal);
deserialize_bool_with_env!(deserialize_docker_expose_by_default_with_env, "SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT", false);

deserialize_bool_with_env!(deserialize_config_file_enabled_with_env, "SOZUNE_PROVIDER_CONFIG_FILE_ENABLED", false);
deserialize_string_with_env!(deserialize_config_file_path_with_env, "SOZUNE_PROVIDER_CONFIG_FILE_PATH", "/etc/sozune/config.yaml", literal);
deserialize_bool_with_env!(deserialize_config_file_watch_with_env, "SOZUNE_PROVIDER_CONFIG_FILE_WATCH", true);

deserialize_bool_with_env!(deserialize_api_enabled_with_env, "SOZUNE_API_ENABLED", false);
deserialize_string_with_env!(deserialize_api_listen_address_with_env, "SOZUNE_API_LISTEN_ADDRESS", default_api_listen_address);

deserialize_with_env!(deserialize_max_buffers_with_env, "SOZUNE_PROXY_MAX_BUFFERS", usize, default_max_buffers);
deserialize_with_env!(deserialize_buffer_size_with_env, "SOZUNE_PROXY_BUFFER_SIZE", usize, default_buffer_size);
deserialize_with_env!(deserialize_startup_delay_ms_with_env, "SOZUNE_PROXY_STARTUP_DELAY_MS", u64, default_startup_delay_ms);
deserialize_with_env!(deserialize_cluster_setup_delay_ms_with_env, "SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS", u64, default_cluster_setup_delay_ms);

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
