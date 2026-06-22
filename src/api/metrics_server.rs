//! Dedicated `/metrics` listener.
//!
//! Serves only the Prometheus `/metrics` endpoint on its own port, reusing the
//! same handler and shared [`AppState`] as the API. This lets an operator
//! scrape metrics without enabling (or exposing) the admin API: the two are
//! gated by independent `enabled` flags. When the API *is* enabled it keeps
//! serving `/metrics` too, so existing scrapers are unaffected.

use crate::api::server::AppState;
use crate::config::MetricsConfig;
use axum::Router;
use axum::routing::get;
use std::net::SocketAddr;
use std::str::FromStr;
use tracing::info;

pub async fn serve(config: MetricsConfig, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(crate::api::metrics::metrics))
        .with_state(state);

    let addr = SocketAddr::from_str(&config.listen_address).map_err(|e| {
        anyhow::anyhow!(
            "Invalid metrics listen address '{}': {}",
            config.listen_address,
            e
        )
    })?;

    info!("Metrics listening on http://{}/metrics", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
