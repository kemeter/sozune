use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use tracing::{error, info};

pub type ChallengeState = Arc<RwLock<HashMap<String, String>>>;

async fn handle_challenge(
    State(challenges): State<ChallengeState>,
    Path(token): Path<String>,
) -> Result<String, StatusCode> {
    let challenges = challenges.read().map_err(|e| {
        error!("Challenge state lock poisoned: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    challenges.get(&token).cloned().ok_or(StatusCode::NOT_FOUND)
}

pub async fn serve(port: u16, challenges: ChallengeState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(handle_challenge))
        .with_state(challenges);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("ACME challenge server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
