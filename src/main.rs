use anyhow::Context;
use clap::Parser;
use futures_util::stream::StreamExt;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

use crate::cli::{Cli, Command};
use crate::config::AppConfig;

mod acme;
mod api;
mod cli;
mod config;
mod config_load;
mod dashboard;
mod diagnostics;
mod labels;
mod middleware;
mod model;
mod provider;
mod proxy;
mod util;

pub use model::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing();

    let config_path = cli::resolve_config_path(cli.config.as_deref());

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(&config_path).await,
        Command::Validate(args) => {
            let exit = cli::validate::run(args, &config_path).await?;
            std::process::exit(exit);
        }
        Command::Explain(args) => {
            let exit = cli::explain::run(args);
            std::process::exit(exit);
        }
        Command::Doctor(args) => {
            let exit = cli::doctor::run(args, &config_path).await;
            std::process::exit(exit);
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sozune=info".parse().expect("valid log directive"))
                .add_directive("bollard=warn".parse().expect("valid log directive"))
                .add_directive("hyper=warn".parse().expect("valid log directive"))
                .add_directive("hyper_util=warn".parse().expect("valid log directive"))
                .add_directive("rustls=warn".parse().expect("valid log directive"))
                .add_directive("sozu_lib=warn".parse().expect("valid log directive"))
                .add_directive(
                    "sozu_command_lib=warn"
                        .parse()
                        .expect("valid log directive"),
                )
                .add_directive("mio=warn".parse().expect("valid log directive"))
                .add_directive("h2=warn".parse().expect("valid log directive"))
                .add_directive("kube=warn".parse().expect("valid log directive"))
                .add_directive("tower=warn".parse().expect("valid log directive")),
        )
        .init();
}

async fn serve(config_path: &str) -> anyhow::Result<()> {
    info!("Starting Sozune proxy");

    let config = if tokio::fs::try_exists(config_path).await.unwrap_or(false) {
        info!("Loading configuration from: {}", config_path);
        let config_content = tokio::fs::read_to_string(config_path)
            .await
            .with_context(|| format!("could not read config file at {config_path}"))?;

        config_load::parse_yaml(std::path::Path::new(config_path), &config_content)?
    } else {
        info!("Configuration file not found, using the default configuration");
        AppConfig::default()
    };

    // Create empty storage - providers will populate it
    let storage = Arc::new(RwLock::new(std::collections::BTreeMap::new()));
    let storage_proxy = Arc::clone(&storage);

    // Diagnostics store, populated by providers at parse time and read by the API.
    let diagnostics_store = diagnostics::new_store();

    // Create bounded channels to prevent memory exhaustion
    let (reload_tx, reload_rx) = mpsc::channel(64);
    let (cert_tx, cert_rx) = mpsc::channel(64);

    // Notify ACME manager when storage changes (new TLS entrypoints)
    let acme_notify = Arc::new(Notify::new());

    // Determine ACME challenge port
    let acme_enabled = config.acme.as_ref().is_some_and(|a| a.enabled);
    let acme_challenge_port = if acme_enabled {
        Some(config.acme.as_ref().unwrap().challenge_port)
    } else {
        None
    };

    // Create middleware state shared between middleware server and proxy reload
    let middleware_state: middleware::MiddlewareState =
        Arc::new(RwLock::new(middleware::MiddlewareRouteTable::default()));
    let middleware_state_proxy = Arc::clone(&middleware_state);
    let middleware_port = config.middleware.port;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_config = config.proxy.clone();
    let handle = tokio::runtime::Handle::current();
    let proxy_task = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        proxy::backend::init_proxy(
            storage_proxy,
            &proxy_config,
            shutdown_rx,
            reload_rx,
            cert_rx,
            acme_challenge_port,
            middleware_state_proxy,
            middleware_port,
            handle,
        )
    });

    // Start provider services (Docker, etc.)
    let provider_task = tokio::spawn({
        let storage_providers = Arc::clone(&storage);
        let reload_tx_providers = reload_tx.clone();
        let acme_notify_providers = Arc::clone(&acme_notify);
        let diagnostics_providers = Arc::clone(&diagnostics_store);
        let config = config.clone();

        async move {
            provider::factory::start_services(
                &config,
                storage_providers,
                reload_tx_providers,
                acme_notify_providers,
                diagnostics_providers,
            )
            .await
        }
    });

    // Build the health checker up-front so its unhealthy-backend state can be
    // shared with the API (read by `GET /entrypoints`) and the runtime task.
    let health_checker = proxy::health::HealthChecker::new(Arc::clone(&storage), reload_tx.clone());
    let unhealthy_backends = health_checker.unhealthy_backends();

    let storage_server = storage.clone();
    let reload_tx_api = reload_tx.clone();
    let api_config = config.api.clone();
    let unhealthy_api = Arc::clone(&unhealthy_backends);
    let diagnostics_api = Arc::clone(&diagnostics_store);
    let api_task = tokio::spawn(async move {
        if api_config.enabled {
            info!("Starting API server");
            api::server::serve(
                api_config,
                storage_server,
                reload_tx_api,
                unhealthy_api,
                diagnostics_api,
            )
            .await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    let dashboard_config = config.dashboard.clone();
    let dashboard_task = tokio::spawn(async move {
        if dashboard_config.enabled {
            info!("Starting Dashboard server");
            dashboard::server::serve(dashboard_config).await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    // Start backend health checker
    let health_task = tokio::spawn(async move {
        health_checker.run().await;
        Ok::<(), anyhow::Error>(())
    });

    // Start middleware server
    let middleware_task = tokio::spawn({
        let middleware_state = Arc::clone(&middleware_state);
        async move { middleware::serve(middleware_port, middleware_state).await }
    });

    // Start ACME module if enabled
    let acme_task = tokio::spawn({
        let storage_acme = Arc::clone(&storage);
        let config = config.clone();

        async move {
            if let Some(acme_config) = config.acme
                && acme_config.enabled
            {
                if acme_config.email.is_empty() {
                    warn!(
                        "ACME is enabled but no contact email is set; certificate provisioning will be skipped (set acme.email in the config file to enable it)"
                    );
                    return Ok(());
                }

                info!("Starting ACME certificate manager");

                let challenges = Arc::new(RwLock::new(HashMap::new()));

                // Start the challenge server
                let challenge_port = acme_config.challenge_port;
                let challenges_server = Arc::clone(&challenges);
                tokio::spawn(async move {
                    if let Err(e) =
                        acme::challenge_server::serve(challenge_port, challenges_server).await
                    {
                        error!("ACME challenge server failed: {}", e);
                    }
                });

                // Run the ACME manager
                let manager = acme::AcmeManager::new(
                    acme_config,
                    challenges,
                    storage_acme,
                    cert_tx,
                    Arc::clone(&acme_notify),
                );

                if let Err(e) = manager.run().await {
                    error!("ACME manager failed: {}", e);
                }
            }

            Ok::<(), anyhow::Error>(())
        }
    });

    info!("Starting all servers...");

    // Signal handling for graceful shutdown
    let mut signals = Signals::new([SIGINT, SIGTERM])?;
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

    let secondary_tasks_future = async {
        tokio::try_join!(
            api_task,
            dashboard_task,
            provider_task,
            acme_task,
            middleware_task,
            health_task
        )
    };

    tokio::pin!(proxy_task);

    tokio::select! {
        result = &mut proxy_task => {
            signal_handle.close();
            match result {
                Ok(Ok(_)) => debug!("Proxy task completed successfully"),
                Ok(Err(e)) => error!("Proxy task failed: {}", e),
                Err(e) => error!("Proxy task panicked: {:?}", e),
            }
        },
        result = secondary_tasks_future => {
            signal_handle.close();
            let (api_result, dashboard_result, provider_result, acme_result, middleware_result, health_result) = result?;

            match api_result {
                Ok(_) => debug!("API task completed successfully"),
                Err(e) => error!("API task failed: {}", e),
            }

            match dashboard_result {
                Ok(_) => debug!("Dashboard task completed successfully"),
                Err(e) => error!("Dashboard task failed: {}", e),
            }

            match provider_result {
                Ok(_) => info!("Provider services completed successfully"),
                Err(e) => error!("Provider services failed: {}", e),
            }

            match acme_result {
                Ok(_) => debug!("ACME task completed successfully"),
                Err(e) => error!("ACME task failed: {}", e),
            }

            match middleware_result {
                Ok(_) => debug!("Middleware task completed successfully"),
                Err(e) => error!("Middleware task failed: {}", e),
            }

            match health_result {
                Ok(_) => debug!("Health checker completed successfully"),
                Err(e) => error!("Health checker failed: {}", e),
            }
        },
        _ = signal_task => {
            info!("Shutdown signal received, stopping servers...");
            signal_handle.close();
            let _ = shutdown_tx.send(());

            match tokio::time::timeout(std::time::Duration::from_secs(10), proxy_task).await {
                Ok(Ok(Ok(_))) => info!("Proxy shut down gracefully"),
                Ok(Ok(Err(e))) => error!("Proxy shut down with error: {}", e),
                Ok(Err(e)) => error!("Proxy task panicked: {:?}", e),
                Err(_) => {
                    warn!("Graceful shutdown timed out, forcing exit");
                    std::process::exit(1);
                }
            }
        }
    }

    debug!("All tasks completed");
    Ok(())
}
