use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use axum::Router;
use axum::routing::get;
use crate::model::Entrypoint;
use tracing::{info, error};
use crate::config::ApiConfig;

pub async fn serve(config: ApiConfig, storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/entrypoints", get(move || {
            let storage = storage.clone();
            async move {
                let storage_read = match storage.read() {
                    Ok(guard) => guard,
                    Err(e) => {
                        error!("Storage lock poisoned: {}", e);
                        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                [(axum::http::header::CONTENT_TYPE, "application/json")],
                                r#"{"error":"internal server error"}"#.to_string());
                    }
                };
                match serde_json::to_string(&*storage_read) {
                    Ok(json) => (axum::http::StatusCode::OK,
                                 [(axum::http::header::CONTENT_TYPE, "application/json")],
                                 json),
                    Err(e) => {
                        error!("Failed to serialize entrypoints: {}", e);
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                         [(axum::http::header::CONTENT_TYPE, "application/json")],
                         r#"{"error":"serialization error"}"#.to_string())
                    }
                }
            }
        }));
    let addr = SocketAddr::from_str(&config.listen_address)
        .map_err(|e| anyhow::anyhow!("Invalid API listen address '{}': {}", config.listen_address, e))?;
    info!("Listening API server on {}", addr);

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
