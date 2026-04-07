use crate::config::ApiConfig;
use crate::model::{Entrypoint, EntrypointConfig, Protocol};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self as axum_middleware, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    pub reload_tx: mpsc::Sender<()>,
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateEntrypointRequest {
    pub name: String,
    pub backends: Vec<String>,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let token = match &state.token {
        Some(t) => t,
        None => return next.run(req).await,
    };

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = &header[7..];
            if provided == token {
                next.run(req).await
            } else {
                warn!("Invalid bearer token from {:?}", req.headers().get("host"));
                Json(serde_json::json!({"error": "invalid token"}))
                    .into_response_with_status(StatusCode::UNAUTHORIZED)
            }
        }
        _ => {
            Json(serde_json::json!({"error": "missing or invalid authorization header"}))
                .into_response_with_status(StatusCode::UNAUTHORIZED)
        }
    }
}

trait IntoResponseWithStatus {
    fn into_response_with_status(self, status: StatusCode) -> Response;
}

impl IntoResponseWithStatus for Json<serde_json::Value> {
    fn into_response_with_status(self, status: StatusCode) -> Response {
        (status, self).into_response()
    }
}

pub async fn serve(
    config: ApiConfig,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let state = AppState {
        storage,
        reload_tx,
        token: config.token.clone(),
    };

    let protected = Router::new()
        .route("/entrypoints", get(list_entrypoints).post(create_entrypoint))
        .route(
            "/entrypoints/{id}",
            get(get_entrypoint)
                .put(update_entrypoint)
                .delete(delete_entrypoint),
        )
        .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state);

    let addr = SocketAddr::from_str(&config.listen_address).map_err(|e| {
        anyhow::anyhow!(
            "Invalid API listen address '{}': {}",
            config.listen_address,
            e
        )
    })?;
    info!("Listening API server on {}", addr);

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

async fn list_entrypoints(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let storage = match state.storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Storage lock poisoned: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };
    (StatusCode::OK, Json(serde_json::json!(*storage)))
}

async fn get_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let storage = match state.storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Storage lock poisoned: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    match storage.get(&id) {
        Some(entrypoint) => (StatusCode::OK, Json(serde_json::json!(entrypoint))),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "entrypoint not found"})),
        ),
    }
}

async fn create_entrypoint(
    State(state): State<AppState>,
    Json(payload): Json<CreateEntrypointRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let id = uuid::Uuid::new_v4().to_string();

    let entrypoint = Entrypoint {
        id: id.clone(),
        name: payload.name,
        backends: payload.backends,
        protocol: payload.protocol,
        config: payload.config,
        source: Some("api".to_string()),
    };

    {
        let mut storage = match state.storage.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Storage lock poisoned: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                );
            }
        };
        storage.insert(id, entrypoint.clone());
    }

    if let Err(e) = state.reload_tx.send(()).await {
        error!("Failed to send reload signal: {}", e);
    }

    info!("Created entrypoint: {}", entrypoint.id);
    (StatusCode::CREATED, Json(serde_json::json!(entrypoint)))
}

async fn update_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateEntrypointRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    {
        let mut storage = match state.storage.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Storage lock poisoned: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                );
            }
        };

        match storage.get(&id) {
            Some(existing) => {
                if existing.source.as_deref() != Some("api") {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({"error": "cannot modify entrypoint managed by another source"})),
                    );
                }
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "entrypoint not found"})),
                );
            }
        }

        let entrypoint = Entrypoint {
            id: id.clone(),
            name: payload.name,
            backends: payload.backends,
            protocol: payload.protocol,
            config: payload.config,
            source: Some("api".to_string()),
        };
        storage.insert(id.clone(), entrypoint);
    }

    if let Err(e) = state.reload_tx.send(()).await {
        error!("Failed to send reload signal: {}", e);
    }

    let storage = state.storage.read().unwrap();
    let entrypoint = &storage[&id];
    info!("Updated entrypoint: {}", id);
    (StatusCode::OK, Json(serde_json::json!(entrypoint)))
}

async fn delete_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    {
        let mut storage = match state.storage.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Storage lock poisoned: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                );
            }
        };

        match storage.get(&id) {
            Some(existing) => {
                if existing.source.as_deref() != Some("api") {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({"error": "cannot delete entrypoint managed by another source"})),
                    );
                }
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "entrypoint not found"})),
                );
            }
        }

        storage.remove(&id);
    }

    if let Err(e) = state.reload_tx.send(()).await {
        error!("Failed to send reload signal: {}", e);
    }

    info!("Deleted entrypoint: {}", id);
    (StatusCode::NO_CONTENT, Json(serde_json::json!(null)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn test_state() -> AppState {
        let (reload_tx, _reload_rx) = mpsc::channel(64);
        AppState {
            storage: Arc::new(RwLock::new(BTreeMap::new())),
            reload_tx,
            token: None,
        }
    }

    fn test_state_with_token(token: &str) -> AppState {
        let (reload_tx, _reload_rx) = mpsc::channel(64);
        AppState {
            storage: Arc::new(RwLock::new(BTreeMap::new())),
            reload_tx,
            token: Some(token.to_string()),
        }
    }

    fn test_app(state: AppState) -> Router {
        let protected = Router::new()
            .route("/entrypoints", get(list_entrypoints).post(create_entrypoint))
            .route(
                "/entrypoints/{id}",
                get(get_entrypoint)
                    .put(update_entrypoint)
                    .delete(delete_entrypoint),
            )
            .route_layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware));

        Router::new()
            .route("/health", get(health))
            .merge(protected)
            .with_state(state)
    }

    fn sample_entrypoint_json() -> serde_json::Value {
        serde_json::json!({
            "name": "web",
            "backends": ["127.0.0.1:3000"],
            "protocol": "Http",
            "config": {
                "hostnames": ["example.com"],
                "port": 80,
                "path": null,
                "tls": false,
                "strip_prefix": false,
                "https_redirect": false,
                "priority": 0,
                "auth": null,
                "headers": {}
            }
        })
    }

    async fn body_to_json(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_health() {
        let app = test_app(test_state());

        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_list_entrypoints_empty() {
        let app = test_app(test_state());

        let response = app
            .oneshot(Request::get("/entrypoints").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_entrypoint() {
        let state = test_state();
        let app = test_app(state.clone());

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["name"], "web");
        assert_eq!(json["source"], "api");
        assert!(json["id"].as_str().is_some());

        let storage = state.storage.read().unwrap();
        assert_eq!(storage.len(), 1);
    }

    #[tokio::test]
    async fn test_get_entrypoint() {
        let state = test_state();
        let app = test_app(state.clone());

        // Create first
        let response = app
            .clone()
            .oneshot(
                Request::post("/entrypoints")
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body_to_json(response.into_body()).await;
        let id = created["id"].as_str().unwrap();

        // Get
        let response = app
            .oneshot(
                Request::get(&format!("/entrypoints/{}", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["name"], "web");
    }

    #[tokio::test]
    async fn test_get_entrypoint_not_found() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::get("/entrypoints/00000000-0000-0000-0000-000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_entrypoint() {
        let state = test_state();
        let app = test_app(state.clone());

        // Create
        let response = app
            .clone()
            .oneshot(
                Request::post("/entrypoints")
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body_to_json(response.into_body()).await;
        let id = created["id"].as_str().unwrap();

        // Update
        let mut updated_json = sample_entrypoint_json();
        updated_json["name"] = serde_json::json!("web-updated");

        let response = app
            .oneshot(
                Request::put(&format!("/entrypoints/{}", id))
                    .header("content-type", "application/json")
                    .body(Body::from(updated_json.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["name"], "web-updated");
    }

    #[tokio::test]
    async fn test_delete_entrypoint() {
        let state = test_state();
        let app = test_app(state.clone());

        // Create
        let response = app
            .clone()
            .oneshot(
                Request::post("/entrypoints")
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body_to_json(response.into_body()).await;
        let id = created["id"].as_str().unwrap();

        // Delete
        let response = app
            .oneshot(
                Request::delete(&format!("/entrypoints/{}", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let storage = state.storage.read().unwrap();
        assert!(storage.is_empty());
    }

    #[tokio::test]
    async fn test_cannot_modify_docker_entrypoint() {
        let state = test_state();

        // Insert a docker-managed entrypoint directly
        {
            let mut storage = state.storage.write().unwrap();
            storage.insert(
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                Entrypoint {
                    id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    name: "docker-service".to_string(),
                    backends: vec!["172.17.0.2:8080".to_string()],
                    protocol: Protocol::Http,
                    config: EntrypointConfig {
                        hostnames: vec!["docker.local".to_string()],
                        port: 80,
                        path: None,
                        tls: false,
                        strip_prefix: false,
                        https_redirect: false,
                        priority: 0,
                        auth: None,
                        headers: std::collections::HashMap::new(),
                    },
                    source: Some("docker".to_string()),
                },
            );
        }

        let app = test_app(state);

        // Try to update
        let response = app
            .clone()
            .oneshot(
                Request::put("/entrypoints/550e8400-e29b-41d4-a716-446655440000")
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Try to delete
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/entrypoints/550e8400-e29b-41d4-a716-446655440000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_auth_required_when_token_configured() {
        let state = test_state_with_token("secret-token");
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_valid_token() {
        let state = test_state_with_token("secret-token");
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_invalid_token() {
        let state = test_state_with_token("secret-token");
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_health_not_protected() {
        let state = test_state_with_token("secret-token");
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
