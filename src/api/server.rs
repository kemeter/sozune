use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use axum::Router;
use axum::routing::get;
use crate::model::Entrypoint;
use tracing::{info};
use crate::config::ApiConfig;

pub async fn serve(config: ApiConfig, storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>) {
    let app = Router::new()
        .route("/entrypoints", get(move || {
            let storage = storage.clone();
            async move {
                let storage_read = storage.read().unwrap();
                (axum::http::StatusCode::OK,
                 [(axum::http::header::CONTENT_TYPE, "application/json")],
                 serde_json::to_string(&*storage_read).unwrap())
            }
        }));
    let addr = SocketAddr::from_str(&*config.listen_address);
    info!("Listening API server on {:?}", addr);

    axum_server::bind(addr.expect("REASON"))
        .serve(app.into_make_service())
        .await
        .unwrap();
}