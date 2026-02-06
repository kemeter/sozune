use std::sync::{Arc, RwLock};
use anyhow::Context;
use tracing::{info, warn, error, debug};
use signal_hook_tokio::Signals;
use signal_hook::consts::{SIGINT, SIGTERM};
use futures_util::stream::StreamExt;
use tokio::sync::mpsc;

use crate::config::AppConfig;

mod api;
mod provider;
mod proxy;
mod config;
mod model;

pub use model::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("sozune=info".parse().expect("valid log directive")))
        .init();

    info!("Starting Sozune proxy");

    let config_path = std::env::var("CONFIG_PATH")
        .unwrap_or_else(|_| "config.yaml".to_string());

    let config = if tokio::fs::try_exists(&config_path).await.unwrap_or(false) {
        info!("Loading configuration from: {}", config_path);
        let config_content = tokio::fs::read_to_string(&config_path).await
            .context("Failed to read a config file")?;
        
        serde_yaml::from_str(&config_content)
            .context("Failed to parse a config file")?
    } else {
        info!("Configuration file not found, using the default configuration");
        AppConfig::default()
    };

    // Create empty storage - providers will populate it
    let storage = Arc::new(RwLock::new(std::collections::BTreeMap::new()));
    let storage_proxy = Arc::clone(&storage);

    // Create a channel for reload signals
    let (reload_tx, reload_rx) = mpsc::unbounded_channel();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_config = config.proxy.clone();
    let proxy_task = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        proxy::backend::init_proxy(storage_proxy, &proxy_config, shutdown_rx, reload_rx)
    });

    // Start provider services (Docker, etc.)
    let provider_task = tokio::spawn({
        let storage_providers = Arc::clone(&storage);
        let reload_tx_providers = reload_tx.clone();
        let config = config.clone();
        
        async move {
            provider::factory::start_services(&config, storage_providers, reload_tx_providers).await
        }
    });

    let storage_server = storage.clone();
    let api_config = config.api.clone();
    let api_task = tokio::spawn(async move {
        if api_config.enabled {
            info!("Starting API server");
            api::server::serve(api_config, storage_server).await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    info!("Starting all servers...");

    // Signal handling for graceful shutdown
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    let signal_handle = signals.handle();

    let signal_task = tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGINT => {
                    debug!("Received SIGINT, initiating graceful shutdown...");
                    break;
                }
                SIGTERM => {
                    debug!("Received SIGTERM, initiating graceful shutdown...");
                    break;
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let tasks_future = async {
        tokio::try_join!(proxy_task, api_task, provider_task)
    };
    
    tokio::select! {
        result = tasks_future => {
            signal_handle.close();
            let (proxy_result, api_result, provider_result) = result?;
            
            match proxy_result {
                Ok(_) => debug!("Proxy task completed successfully"),
                Err(e) => error!("Proxy task failed: {}", e),
            }

            match api_result {
                Ok(_) => debug!("API task completed successfully"),
                Err(e) => error!("API task failed: {}", e),
            }

            match provider_result {
                Ok(_) => info!("Provider services completed successfully"),
                Err(e) => error!("Provider services failed: {}", e),
            }
        },
        _ = signal_task => {
            info!("Shutdown signal received, stopping servers...");
            signal_handle.close();
            let _ = shutdown_tx.send(());
            
            // Force exit after short delay
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            warn!("Forcing shutdown");
            std::process::exit(0);
        }
    }

    debug!("All tasks completed");
    Ok(())
}


