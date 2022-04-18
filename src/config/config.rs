use std::fs::File;
use std::io::Read;
use std::fs;
use std::env;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Config {
    pub(crate) docker: DockerConfig,
    pub(crate) api: ApiConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct DockerConfig {
    pub(crate) endpoint: String
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct ApiConfig {
    pub(crate) address: String,
    pub(crate) port: u16
}

pub(crate) fn load_config() -> Config {
    let home_dir = env::var("HOME").unwrap();
    let sozune_config_file = env::var("SOZUNE_CONFIG_FILE").unwrap_or("".to_string());
    let file = if sozune_config_file.len() == 0 {
        format!("{}/.config/kemeter/sozune/config.toml", home_dir)
    }  else {
        format!("{}/config.toml", sozune_config_file)
    };

    debug!("Use config file : {}", file);

    if fs::metadata(file.clone()).is_ok() {
        let mut config = File::open(file).expect("Unable to open file");
        let mut contents = String::new();

        config.read_to_string(&mut contents).expect("Unable to read file");

        let config: Config = toml::from_str(&contents).unwrap();

        return config;
    }

    debug!("No config file found, using default config file: {}", file);

    return Config {
        api: ApiConfig {
            address: "0.0.0.0".to_string(),
            port: 3030
        },
        docker: DockerConfig {
            endpoint: "unix:///var/run/docker.sock".to_string()
        }
    }
}
