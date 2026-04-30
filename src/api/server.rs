use crate::api::auth::{AuthOutcome, Identity, check};
use crate::config::{ApiConfig, ApiUser, Role};
use crate::model::{Entrypoint, EntrypointConfig, Protocol};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::http::{HeaderValue, Method, header};
use axum::middleware::{self as axum_middleware, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    pub reload_tx: mpsc::Sender<()>,
    pub users: Vec<ApiUser>,
}

#[derive(Deserialize)]
pub struct CreateEntrypointRequest {
    pub name: String,
    pub backends: Vec<String>,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
    pub backend_weights: Option<std::collections::HashMap<String, u32>>,
}

/// Authenticate the request with HTTP Basic, then attach the resolved
/// `Identity` to request extensions so downstream handlers and the role
/// guard can read it back.
async fn auth_middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    if state.users.is_empty() {
        return unauthorized("API has no users configured, refusing all requests");
    }

    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match check(header, &state.users) {
        AuthOutcome::Authenticated(identity) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        AuthOutcome::Invalid => {
            warn!(
                "Rejected API request with invalid credentials from {:?}",
                req.headers().get("host")
            );
            unauthorized("invalid credentials")
        }
        AuthOutcome::Missing => unauthorized("missing or invalid authorization header"),
    }
}

/// Block write methods (POST/PUT/DELETE) when the authenticated user is
/// `read-only`. Runs after `auth_middleware` so the `Identity` is always
/// present in extensions.
async fn require_admin(req: Request, next: Next) -> Response {
    let is_write = !matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    );
    if !is_write {
        return next.run(req).await;
    }

    let identity = req.extensions().get::<Identity>().cloned();
    match identity {
        Some(id) if id.role == Role::Admin => next.run(req).await,
        Some(id) => {
            warn!(
                "User '{}' (read-only) attempted {} {}",
                id.name,
                req.method(),
                req.uri().path()
            );
            forbidden("read-only role cannot perform this operation")
        }
        None => unauthorized("missing identity"),
    }
}

fn unauthorized(message: &str) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": message})),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"sozune\""),
    );
    response
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": message})),
    )
        .into_response()
}

pub async fn serve(
    config: ApiConfig,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    if config.users.is_empty() {
        anyhow::bail!(
            "API enabled but no users configured. Add at least one entry under `api.users`."
        );
    }

    let state = AppState {
        storage,
        reload_tx,
        users: config.users.clone(),
    };

    let protected = Router::new()
        .route(
            "/entrypoints",
            get(list_entrypoints).post(create_entrypoint),
        )
        .route(
            "/entrypoints/{id}",
            get(get_entrypoint)
                .put(update_entrypoint)
                .delete(delete_entrypoint),
        )
        .route_layer(axum_middleware::from_fn(require_admin));

    let me_route = Router::new().route("/me", get(me));

    let authed = protected
        .merge(me_route)
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let mut app = Router::new()
        .route("/health", get(health))
        .merge(authed)
        .with_state(state);

    let allow_origin = if config.cors_origins.is_empty() {
        AllowOrigin::any()
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|o| match HeaderValue::from_str(o) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Invalid CORS origin '{}': {}", o, e);
                    None
                }
            })
            .collect();
        AllowOrigin::list(origins)
    };

    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    app = app.layer(cors);

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

/// Returns the authenticated user's identity. The dashboard hits this on
/// login to validate credentials and learn its role.
async fn me(req: Request) -> (StatusCode, Json<serde_json::Value>) {
    let identity = req.extensions().get::<Identity>().cloned();
    match identity {
        Some(id) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": id.name,
                "role": match id.role {
                    Role::Admin => "admin",
                    Role::ReadOnly => "read-only",
                },
            })),
        ),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "missing identity"})),
        ),
    }
}

async fn list_entrypoints(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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
    let list: Vec<&Entrypoint> = storage.values().collect();
    (StatusCode::OK, Json(serde_json::json!(list)))
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
        backend_weights: payload.backend_weights.unwrap_or_default(),
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
                        Json(
                            serde_json::json!({"error": "cannot modify entrypoint managed by another source"}),
                        ),
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
            backend_weights: payload.backend_weights.unwrap_or_default(),
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
                        Json(
                            serde_json::json!({"error": "cannot delete entrypoint managed by another source"}),
                        ),
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

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use sha2::Digest;

    fn hash_password(password: &str) -> String {
        let digest = sha2::Sha256::digest(password.as_bytes());
        let mut out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }

    fn user(name: &str, password: &str, role: Role) -> ApiUser {
        ApiUser {
            name: name.into(),
            hash: hash_password(password),
            role,
        }
    }

    fn basic(user: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
    }

    fn test_state() -> AppState {
        test_state_with_users(vec![user("admin", "admin-pass", Role::Admin)])
    }

    fn test_state_with_users(users: Vec<ApiUser>) -> AppState {
        let (reload_tx, _reload_rx) = mpsc::channel(64);
        AppState {
            storage: Arc::new(RwLock::new(BTreeMap::new())),
            reload_tx,
            users,
        }
    }

    fn test_app(state: AppState) -> Router {
        let protected = Router::new()
            .route(
                "/entrypoints",
                get(list_entrypoints).post(create_entrypoint),
            )
            .route(
                "/entrypoints/{id}",
                get(get_entrypoint)
                    .put(update_entrypoint)
                    .delete(delete_entrypoint),
            )
            .route_layer(axum_middleware::from_fn(require_admin));

        let me_route = Router::new().route("/me", get(me));

        let authed = protected
            .merge(me_route)
            .route_layer(axum_middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ));

        Router::new()
            .route("/health", get(health))
            .merge(authed)
            .with_state(state)
    }

    /// Default credential matching `test_state()`'s default admin user.
    fn admin_auth() -> String {
        basic("admin", "admin-pass")
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
                "headers": []
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
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
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
                    .header("authorization", admin_auth())
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
                    .header("authorization", admin_auth())
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
                Request::get(format!("/entrypoints/{}", id))
                    .header("authorization", admin_auth())
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
                    .header("authorization", admin_auth())
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
                    .header("authorization", admin_auth())
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
                Request::put(format!("/entrypoints/{}", id))
                    .header("authorization", admin_auth())
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
                    .header("authorization", admin_auth())
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
                Request::delete(format!("/entrypoints/{}", id))
                    .header("authorization", admin_auth())
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
                        https_redirect_port: None,
                        redirect: None,
                        redirect_scheme: None,
                        redirect_template: None,
                        www_authenticate: None,
                        priority: 0,
                        auth: None,
                        headers: Vec::new(),
                        backend_timeout: None,
                        rate_limit: None,
                        sticky_session: false,
                        compress: false,
                    },
                    source: Some("docker".to_string()),
                    backend_weights: std::collections::HashMap::new(),
                },
            );
        }

        let app = test_app(state);

        // Try to update
        let response = app
            .clone()
            .oneshot(
                Request::put("/entrypoints/550e8400-e29b-41d4-a716-446655440000")
                    .header("authorization", admin_auth())
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
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn missing_credentials_rejected() {
        let app = test_app(test_state());

        let response = app
            .oneshot(Request::get("/entrypoints").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .get("www-authenticate")
                .is_some_and(|v| v.to_str().unwrap_or("").starts_with("Basic"))
        );
    }

    #[tokio::test]
    async fn valid_credentials_accepted() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_password_rejected() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", basic("admin", "wrong"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn read_only_user_can_read() {
        let state = test_state_with_users(vec![
            user("admin", "admin-pass", Role::Admin),
            user("readonly", "ro-pass", Role::ReadOnly),
        ]);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", basic("readonly", "ro-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn read_only_user_cannot_write() {
        let state = test_state_with_users(vec![user("readonly", "ro-pass", Role::ReadOnly)]);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("authorization", basic("readonly", "ro-pass"))
                    .header("content-type", "application/json")
                    .body(Body::from(sample_entrypoint_json().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn health_not_protected() {
        let app = test_app(test_state());

        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn me_returns_admin_identity() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::get("/me")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["name"], "admin");
        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn me_returns_read_only_identity() {
        let state = test_state_with_users(vec![user("viewer", "viewer-pass", Role::ReadOnly)]);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::get("/me")
                    .header("authorization", basic("viewer", "viewer-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["name"], "viewer");
        assert_eq!(json["role"], "read-only");
    }

    #[tokio::test]
    async fn me_requires_auth() {
        let app = test_app(test_state());

        let response = app
            .oneshot(Request::get("/me").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
