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
mod error_pages;
mod labels;
mod middleware;
mod model;
mod provider;
mod proxy;
mod tracing_otel;
mod util;

pub use model::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_path = cli::resolve_config_path(cli.config.as_deref());

    // Resolve enough config before installing the tracing subscriber: it is
    // global and set once, so the log format (text/JSON) and the optional OTLP
    // tracing layer have to be known up front. Env wins over YAML wins over
    // defaults. The returned guard keeps the OTLP exporter alive and flushes it
    // on drop — bind it for the whole process.
    let early_cfg = resolve_early_config(&config_path).await;
    let _tracing_guard = init_tracing(&early_cfg.log, &early_cfg.tracing);

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

fn log_env_filter() -> tracing_subscriber::EnvFilter {
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
        .add_directive("tower=warn".parse().expect("valid log directive"))
}

/// Install the global tracing subscriber: a fmt layer (text or JSON) plus,
/// when `tracing.enabled`, an OpenTelemetry OTLP layer. Returns the OTLP guard
/// (kept alive by the caller, flushed on drop) or `None` when tracing is off or
/// the exporter failed to build (in which case we degrade to logs-only).
fn init_tracing(
    log: &config::LogConfig,
    tracing_cfg: &config::TracingConfig,
) -> Option<tracing_otel::TracingGuard> {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // The fmt layer mirrors the previous behaviour: text by default, or
    // newline-delimited JSON with flattened fields.
    let fmt_layer = match log.format {
        config::LogFormat::Text => tracing_subscriber::fmt::layer().boxed(),
        config::LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .boxed(),
    };

    let registry = tracing_subscriber::registry()
        .with(log_env_filter())
        .with(fmt_layer);

    if !tracing_cfg.enabled {
        registry.init();
        return None;
    }

    match tracing_otel::build_layer(tracing_cfg) {
        Ok((otel_layer, guard)) => {
            registry.with(otel_layer).init();
            info!(
                "Distributed tracing enabled, exporting OTLP to {}",
                tracing_cfg.endpoint
            );
            Some(guard)
        }
        Err(e) => {
            // Don't crash on a bad collector endpoint — run logs-only.
            registry.init();
            error!("tracing: failed to initialise OTLP exporter, continuing without traces: {e}");
            None
        }
    }
}

/// Best-effort early config used only to set up tracing before the real config
/// is loaded and validated in `serve`. Env wins over YAML wins over defaults;
/// any read/parse error is swallowed and defaults stand (logging still works).
async fn resolve_early_config(config_path: &str) -> config::AppConfig {
    let mut cfg = if tokio::fs::try_exists(config_path).await.unwrap_or(false)
        && let Ok(content) = tokio::fs::read_to_string(config_path).await
        && let Ok(parsed) = config_load::parse_yaml(std::path::Path::new(config_path), &content)
    {
        parsed
    } else {
        config::AppConfig::default()
    };
    // Apply env overrides so SOZUNE_LOG_FORMAT / SOZUNE_TRACING_* win, exactly
    // as they will in `serve`.
    cfg.apply_env_overrides();
    cfg
}

async fn serve(config_path: &str) -> anyhow::Result<()> {
    info!("Starting Sozune proxy");

    let mut config = if tokio::fs::try_exists(config_path).await.unwrap_or(false) {
        info!("Loading configuration from: {}", config_path);
        let config_content = tokio::fs::read_to_string(config_path)
            .await
            .with_context(|| format!("could not read config file at {config_path}"))?;

        config_load::parse_yaml(std::path::Path::new(config_path), &config_content)?
    } else {
        info!("Configuration file not found, using the default configuration");
        AppConfig::default()
    };
    config.apply_env_overrides();

    // Create empty storage - providers will populate it
    let storage = Arc::new(RwLock::new(std::collections::BTreeMap::new()));
    let storage_proxy = Arc::clone(&storage);

    // Diagnostics store, populated by providers at parse time and read by the API.
    let diagnostics_store = diagnostics::new_store();

    // Create bounded channels to prevent memory exhaustion
    let (reload_tx, reload_rx) = mpsc::channel(64);
    let (cert_tx, cert_rx) = mpsc::channel(64);
    let (metrics_poll_tx, metrics_poll_rx) = mpsc::channel::<()>(8);

    // Snapshot of the latest metrics polled from Sōzu workers, shared with
    // the API metrics endpoint.
    let metrics_store = proxy::metrics_snapshot::new_store();

    // Live request-latency histogram, written by the middleware proxy handler
    // and read by the API `/metrics` endpoint. Shared (same Arc) across both.
    let request_metrics_store = proxy::request_metrics::new_store();

    // Notify ACME manager when storage changes (new TLS entrypoints)
    let acme_notify = Arc::new(Notify::new());

    // Single lookup of the (optional) enabled ACME block — used both for the
    // proxy challenge port and for the API's `acme_enabled` flag below.
    let active_acme = config.acme.as_ref().filter(|a| a.enabled);
    let acme_enabled = active_acme.is_some();
    let acme_challenge_port = active_acme.map(|a| a.challenge_port);

    // Create middleware state shared between middleware server and proxy reload
    let middleware_state: middleware::MiddlewareState =
        Arc::new(RwLock::new(middleware::MiddlewareRouteTable::default()));
    let middleware_state_proxy = Arc::clone(&middleware_state);
    let middleware_port = config.middleware.port;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_config = config.proxy.clone();
    let handle = tokio::runtime::Handle::current();
    let plugin_fetch_client = middleware::build_forward_auth_client();
    let plugins = middleware::build_plugin_registry(&config.plugins, &plugin_fetch_client, &handle);
    let metrics_store_proxy = Arc::clone(&metrics_store);
    let proxy_task = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        proxy::backend::init_proxy(
            proxy::backend::ProxyInputs {
                storage: storage_proxy,
                shutdown_rx,
                reload_rx,
                cert_rx,
                metrics_poll_rx,
                metrics_store: metrics_store_proxy,
                acme_challenge_port,
                middleware_state: middleware_state_proxy,
                middleware_port,
                plugins,
                handle,
            },
            &proxy_config,
        )
    });

    // Poll Sōzu workers for metrics every 5 seconds. Drop on full channel —
    // a backed-up poller means the proxy mainloop is busy and we should not
    // pile on more work; the next tick will retry.
    let metrics_poll_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            if metrics_poll_tx.try_send(()).is_err() {
                debug!("Metrics poll channel full or closed, skipping tick");
            }
        }
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
    let api_config = config.api.clone();
    let api_state = api::server::AppState {
        storage: storage_server,
        reload_tx: reload_tx.clone(),
        users: config.api.users.clone(),
        unhealthy_backends: Arc::clone(&unhealthy_backends),
        diagnostics: Arc::clone(&diagnostics_store),
        acme_enabled,
        providers: config.providers.clone(),
        metrics: Arc::clone(&metrics_store),
        request_metrics: Arc::clone(&request_metrics_store),
        config: Arc::new(config.clone()),
    };
    // Dedicated `/metrics` listener — independent of the API, so metrics can be
    // scraped without enabling/exposing the admin API. Reuses the same state and
    // handler; clone the state before `api_task` moves the original.
    let metrics_config = config.metrics.clone();
    let metrics_state = api_state.clone();
    let metrics_task = tokio::spawn(async move {
        if metrics_config.enabled {
            info!("Starting Metrics server");
            api::metrics_server::serve(metrics_config, metrics_state).await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    let api_task = tokio::spawn(async move {
        if api_config.enabled {
            info!("Starting API server");
            api::server::serve(api_config, api_state).await?;
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
        let request_metrics_mw = Arc::clone(&request_metrics_store);
        async move { middleware::serve(middleware_port, middleware_state, request_metrics_mw).await }
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
            metrics_task,
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
            let (api_result, metrics_result, dashboard_result, provider_result, acme_result, middleware_result, health_result) = result?;

            match api_result {
                Ok(_) => debug!("API task completed successfully"),
                Err(e) => error!("API task failed: {}", e),
            }

            match metrics_result {
                Ok(_) => debug!("Metrics task completed successfully"),
                Err(e) => error!("Metrics task failed: {}", e),
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
                    // Don't `process::exit` here: that would skip `main`'s
                    // tracing guard drop and lose the last span batch. Returning
                    // the error unwinds cleanly so the guard flushes on the way
                    // out, then `main` reports the failure.
                    warn!("Graceful shutdown timed out");
                    metrics_poll_task.abort();
                    anyhow::bail!("graceful shutdown timed out after 10s");
                }
            }
        }
    }

    metrics_poll_task.abort();

    debug!("All tasks completed");
    Ok(())
}

/// Shared lock serialising every test that mutates `std::env`. Tests across
/// modules race on the global environment otherwise (and edition 2024 marks
/// `set_var`/`remove_var` `unsafe` for exactly this reason). Kept at the end of
/// the file so no non-test item follows a `#[cfg(test)]` module.
#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::Mutex;
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
}
