use std::fs;
use std::env;
use std::path::Path;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Config {
    pub(crate) docker: DockerConfig,
    pub(crate) api: ApiConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct DockerConfig {
    pub(crate) enabled: bool,
    pub(crate) endpoint: String
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct ApiConfig {
    pub(crate) address: String,
    pub(crate) port: u16
}

pub(crate) fn load_config() -> Config {
    let config_file = env::var("SOZUNE_CONFIG_FILE").unwrap_or("/etc/sozune/config.toml".to_string());

    info!("Use config file : {}", config_file);

    if Path::new(&config_file).exists() {
        debug!("Parse config file {}", &config_file);

        let contents = fs::read_to_string(config_file).expect("Unable to read file");
        let config: Config = toml::from_str(&contents).unwrap();

        return config;
    }

    info!("No config file found, using default configuration");

    return Config {
        api: ApiConfig {
            address: "0.0.0.0".to_string(),
            port: 3025
        },
        docker: DockerConfig {
            enabled: true,
            endpoint: "unix:///var/run/docker.sock".to_string()
        }
    }
}
