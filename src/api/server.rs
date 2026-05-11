use crate::api::auth::{AuthOutcome, Identity, check};
use crate::config::{ApiConfig, ApiUser, Role};
use crate::model::{Backend, Entrypoint, EntrypointConfig, Protocol};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::http::{HeaderValue, Method, header};
use axum::middleware::{self as axum_middleware, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    pub unhealthy_backends: Arc<RwLock<HashSet<String>>>,
    pub diagnostics: crate::diagnostics::DiagnosticsStore,
    pub acme_enabled: bool,
    /// Snapshot of the provider section from `config.yaml`. Read-only — used
    /// by `GET /providers` to surface which providers are configured and
    /// whether their `enabled` flag is set.
    pub providers: crate::config::ProvidersConfig,
}

/// Build the JSON payload for an entrypoint, augmenting it with the
/// `unhealthy_backends` list (subset of `backends` that the health checker
/// has marked down) and the `diagnostics` produced for this entrypoint by the
/// label parser (empty when none).
///
/// Diagnostics are looked up by `entrypoint.id` first (the cluster_id used at
/// runtime), then by `entrypoint.source` which is set to the candidate id by
/// most providers. The first non-empty match wins.
fn entrypoint_payload(
    entrypoint: &Entrypoint,
    unhealthy: &HashSet<String>,
    diagnostics: &HashMap<String, Vec<crate::labels::diagnostic::Diagnostic>>,
) -> serde_json::Value {
    let unhealthy_for_ep: Vec<String> = entrypoint
        .backends
        .iter()
        .map(|b| b.to_string())
        .filter(|key| unhealthy.contains(key))
        .collect();

    let diags_for_ep: Vec<crate::labels::diagnostic::Diagnostic> = diagnostics
        .get(&entrypoint.id)
        .or_else(|| {
            entrypoint
                .source
                .as_ref()
                .and_then(|s| diagnostics.get(s.as_str()))
        })
        .cloned()
        .unwrap_or_default();

    let mut value = serde_json::json!(entrypoint);
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "unhealthy_backends".to_string(),
            serde_json::json!(unhealthy_for_ep),
        );
        obj.insert("diagnostics".to_string(), serde_json::json!(diags_for_ep));
    }
    value
}

#[derive(Deserialize)]
pub struct CreateEntrypointRequest {
    pub name: String,
    pub backends: Vec<Backend>,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
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
    unhealthy_backends: Arc<RwLock<HashSet<String>>>,
    diagnostics: crate::diagnostics::DiagnosticsStore,
    acme_enabled: bool,
    providers: crate::config::ProvidersConfig,
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
        unhealthy_backends,
        diagnostics,
        acme_enabled,
        providers,
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
        .route("/diagnostics", get(list_diagnostics))
        .route("/providers", get(list_providers))
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
            error!(
                "internal state corrupted (configuration store), restart required: {}",
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };
    let unhealthy = match state.unhealthy_backends.read() {
        Ok(guard) => guard.clone(),
        Err(e) => {
            error!(
                "internal state corrupted (health tracking), restart required: {}",
                e
            );
            HashSet::new()
        }
    };
    let mut diagnostics = read_diagnostics(&state);
    merge_collision_lints(&storage, &mut diagnostics);
    let list: Vec<serde_json::Value> = storage
        .values()
        .map(|ep| entrypoint_payload(ep, &unhealthy, &diagnostics))
        .collect();
    (StatusCode::OK, Json(serde_json::json!(list)))
}

/// Compute W018 route-collision diagnostics on the live storage and append
/// them to the diagnostics map under the entrypoint id so they show up next to
/// the per-candidate diagnostics. Idempotent — duplicate codes are not
/// deduplicated, callers should treat the map as additive.
fn merge_collision_lints(
    storage: &BTreeMap<String, Entrypoint>,
    diagnostics: &mut HashMap<String, Vec<crate::labels::diagnostic::Diagnostic>>,
) {
    let pairs: Vec<(&str, &Entrypoint)> =
        storage.iter().map(|(id, ep)| (id.as_str(), ep)).collect();
    for (ep_id, diag) in crate::labels::lint::lint_collection(&pairs) {
        diagnostics.entry(ep_id).or_default().push(diag);
    }
}

fn read_diagnostics(
    state: &AppState,
) -> HashMap<String, Vec<crate::labels::diagnostic::Diagnostic>> {
    match state.diagnostics.read() {
        Ok(guard) => guard.clone(),
        Err(e) => {
            error!(
                "internal state corrupted (diagnostics store), restart required: {}",
                e
            );
            HashMap::new()
        }
    }
}

/// `GET /diagnostics` — snapshot of every per-entrypoint diagnostic plus
/// recomputed global lints (e.g. ACME-without-TLS) and runtime collision
/// lints (W018) that are not stored at parse time.
async fn list_diagnostics(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let mut grouped: HashMap<String, Vec<crate::labels::diagnostic::Diagnostic>> =
        crate::diagnostics::snapshot(&state.diagnostics)
            .into_iter()
            .collect();

    if let Ok(storage) = state.storage.read() {
        merge_collision_lints(&storage, &mut grouped);
    }

    let mut total: usize = grouped.values().map(|v| v.len()).sum();
    let mut by_candidate: Vec<serde_json::Value> = grouped
        .into_iter()
        .map(|(id, diags)| {
            serde_json::json!({
                "candidate_id": id,
                "diagnostics": diags,
            })
        })
        .collect();
    // Stable order so the dashboard doesn't shuffle on every poll.
    by_candidate.sort_by(|a, b| {
        a["candidate_id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["candidate_id"].as_str().unwrap_or(""))
    });

    let global = global_lints(&state);
    total += global.len();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "total": total,
            "global": global,
            "items": by_candidate,
        })),
    )
}

/// Recompute lints that span the full entrypoint set (not attached to a
/// single candidate). Today: only `W015 ACME enabled but no entrypoint
/// declares tls=true`.
fn global_lints(state: &AppState) -> Vec<crate::labels::diagnostic::Diagnostic> {
    let storage = match state.storage.read() {
        Ok(g) => g,
        Err(e) => {
            error!(
                "internal state corrupted (configuration store), restart required: {}",
                e
            );
            return Vec::new();
        }
    };
    let eps: Vec<&Entrypoint> = storage.values().collect();
    let mut out = Vec::new();
    if let Some(d) = crate::labels::lint::lint_acme_without_tls(state.acme_enabled, &eps) {
        out.push(d);
    }
    out
}

/// `GET /providers` — snapshot of every provider sōzune knows about, its
/// configured `enabled` flag, and how many entrypoints it currently owns in
/// the storage. Lets the dashboard render a "what's wired up?" overview
/// without inferring it from the entrypoint list.
async fn list_providers(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let storage = match state.storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!(
                "internal state corrupted (configuration store), restart required: {}",
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    // Count entrypoints per source so the dashboard can show "Docker: 5
    // entrypoints" next to each provider row. Sources sōzune emits today
    // are listed under `documented_sources` below; an unknown source still
    // gets counted but won't have a matching provider row.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for ep in storage.values() {
        if let Some(src) = ep.source.as_deref() {
            *counts.entry(src.to_string()).or_insert(0) += 1;
        }
    }

    let p = &state.providers;
    // Iterate `provider::ALL` so the response order, and the set of names,
    // come from the same source as `Provider::name()` and `Entrypoint::source`.
    // Adding a new provider only requires registering its constant in
    // `provider/mod.rs` and matching it below.
    let items: Vec<serde_json::Value> = crate::provider::ALL
        .iter()
        .map(|&name| {
            let (configured, enabled) = match name {
                crate::provider::DOCKER => (
                    p.docker.is_some(),
                    p.docker.as_ref().is_some_and(|c| c.enabled),
                ),
                crate::provider::PODMAN => (
                    p.podman.is_some(),
                    p.podman.as_ref().is_some_and(|c| c.enabled),
                ),
                crate::provider::SWARM => (
                    p.swarm.is_some(),
                    p.swarm.as_ref().is_some_and(|c| c.enabled),
                ),
                crate::provider::KUBERNETES => (
                    p.kubernetes.is_some(),
                    p.kubernetes.as_ref().is_some_and(|c| c.enabled),
                ),
                crate::provider::NOMAD => (
                    p.nomad.is_some(),
                    p.nomad.as_ref().is_some_and(|c| c.enabled),
                ),
                crate::provider::HTTP => {
                    (p.http.is_some(), p.http.as_ref().is_some_and(|c| c.enabled))
                }
                crate::provider::CONFIG => (
                    p.config_file.is_some(),
                    p.config_file.as_ref().is_some_and(|c| c.enabled),
                ),
                _ => (false, false),
            };
            serde_json::json!({
                "name": name,
                "enabled": enabled,
                "configured": configured,
                "entrypoint_count": counts.get(name).copied().unwrap_or(0),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "providers": items,
        })),
    )
}

async fn get_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let storage = match state.storage.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!(
                "internal state corrupted (configuration store), restart required: {}",
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };
    let unhealthy = match state.unhealthy_backends.read() {
        Ok(guard) => guard.clone(),
        Err(e) => {
            error!(
                "internal state corrupted (health tracking), restart required: {}",
                e
            );
            HashSet::new()
        }
    };

    let mut diagnostics = read_diagnostics(&state);
    merge_collision_lints(&storage, &mut diagnostics);

    match storage.get(&id) {
        Some(entrypoint) => (
            StatusCode::OK,
            Json(entrypoint_payload(entrypoint, &unhealthy, &diagnostics)),
        ),
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
                error!(
                    "internal state corrupted (configuration store), restart required: {}",
                    e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                );
            }
        };
        storage.insert(id, entrypoint.clone());
    }

    if let Err(e) = state.reload_tx.send(()).await {
        error!(
            "could not apply configuration update; will retry on next change: {}",
            e
        );
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
                error!(
                    "internal state corrupted (configuration store), restart required: {}",
                    e
                );
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
        };
        storage.insert(id.clone(), entrypoint);
    }

    if let Err(e) = state.reload_tx.send(()).await {
        error!(
            "could not apply configuration update; will retry on next change: {}",
            e
        );
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
                error!(
                    "internal state corrupted (configuration store), restart required: {}",
                    e
                );
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
        error!(
            "could not apply configuration update; will retry on next change: {}",
            e
        );
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
            unhealthy_backends: Arc::new(RwLock::new(HashSet::new())),
            diagnostics: crate::diagnostics::new_store(),
            acme_enabled: false,
            providers: crate::config::ProvidersConfig::default(),
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
            .route("/diagnostics", get(list_diagnostics))
            .route("/providers", get(list_providers))
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
            "backends": [
                { "address": "127.0.0.1", "port": 3000, "weight": 100 }
            ],
            "protocol": "Http",
            "config": {
                "hostnames": ["example.com"],
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
                    backends: vec![Backend::new("172.17.0.2", 8080)],
                    protocol: Protocol::Http,
                    config: EntrypointConfig {
                        hostnames: vec!["docker.local".to_string()],
                        path: None,
                        tls: false,
                        strip_prefix: false,
                        add_prefix: None,
                        https_redirect: false,
                        https_redirect_port: None,
                        redirect: None,
                        redirect_scheme: None,
                        redirect_template: None,
                        www_authenticate: None,
                        priority: 0,
                        auth: None,
                        forward_auth: None,
                        headers: Vec::new(),
                        backend_timeout: None,
                        rate_limit: None,
                        sticky_session: false,
                        compress: false,
                        entrypoint: None,
                        methods: Vec::new(),
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

    // ---- Payload validation ---------------------------------------------------

    #[tokio::test]
    async fn create_with_malformed_json_returns_400() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from("{not valid json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_with_missing_required_field_returns_422() {
        let app = test_app(test_state());

        // Missing `name` (required)
        let payload = serde_json::json!({
            "backends": [{ "address": "127.0.0.1", "port": 3000, "weight": 100 }],
            "protocol": "Http",
            "config": {
                "hostnames": ["example.com"],
                "path": null,
                "tls": false,
                "strip_prefix": false,
                "https_redirect": false,
                "priority": 0,
                "auth": null,
                "headers": []
            }
        });

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_with_wrong_field_type_returns_422() {
        let app = test_app(test_state());

        // backends is a string instead of a list of Backend objects
        let payload = serde_json::json!({
            "name": "web",
            "backends": "127.0.0.1:3000",
            "protocol": "Http",
            "config": {
                "hostnames": ["example.com"],
                "path": null,
                "tls": false,
                "strip_prefix": false,
                "https_redirect": false,
                "priority": 0,
                "auth": null,
                "headers": []
            }
        });

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("authorization", admin_auth())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_with_empty_body_returns_415() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::post("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum returns 415 when content-type is missing on Json<...> extractor
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // ---- Backend serialization ------------------------------------------------

    #[tokio::test]
    async fn created_entrypoint_serializes_backends_as_objects() {
        let app = test_app(test_state());

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
        let backends = json["backends"].as_array().expect("backends array");
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0]["address"], "127.0.0.1");
        assert_eq!(backends[0]["port"], 3000);
        assert_eq!(backends[0]["weight"], 100);
    }

    // ---- unhealthy_backends ---------------------------------------------------

    #[tokio::test]
    async fn unhealthy_backends_field_lists_marked_down_addresses() {
        let state = test_state();
        // Create an entrypoint via the API.
        let app = test_app(state.clone());
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
        let id = body_to_json(response.into_body()).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Mark the backend down.
        state
            .unhealthy_backends
            .write()
            .unwrap()
            .insert("127.0.0.1:3000".to_string());

        let response = app
            .oneshot(
                Request::get(format!("/entrypoints/{id}"))
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        let unhealthy = json["unhealthy_backends"]
            .as_array()
            .expect("unhealthy_backends array");
        assert_eq!(unhealthy.len(), 1);
        assert_eq!(unhealthy[0], "127.0.0.1:3000");
    }

    #[tokio::test]
    async fn unhealthy_backends_field_is_empty_when_all_healthy() {
        let app = test_app(test_state());

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
        let id = body_to_json(response.into_body()).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = app
            .oneshot(
                Request::get(format!("/entrypoints/{id}"))
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_to_json(response.into_body()).await;
        let unhealthy = json["unhealthy_backends"]
            .as_array()
            .expect("unhealthy_backends array");
        assert!(unhealthy.is_empty());
    }

    // ---- List + listing semantics ---------------------------------------------

    #[tokio::test]
    async fn list_returns_all_entrypoints_regardless_of_source() {
        let state = test_state();

        // Pre-seed one Docker-sourced entrypoint that the API can't modify.
        {
            let mut storage = state.storage.write().unwrap();
            storage.insert(
                "docker-1".to_string(),
                Entrypoint {
                    id: "docker-1".to_string(),
                    name: "docker-svc".to_string(),
                    backends: vec![Backend::new("172.17.0.2", 8080)],
                    protocol: Protocol::Http,
                    config: EntrypointConfig {
                        hostnames: vec!["docker.local".to_string()],
                        path: None,
                        tls: false,
                        strip_prefix: false,
                        add_prefix: None,
                        https_redirect: false,
                        https_redirect_port: None,
                        redirect: None,
                        redirect_scheme: None,
                        redirect_template: None,
                        www_authenticate: None,
                        priority: 0,
                        auth: None,
                        forward_auth: None,
                        headers: Vec::new(),
                        backend_timeout: None,
                        rate_limit: None,
                        sticky_session: false,
                        compress: false,
                        entrypoint: None,
                        methods: Vec::new(),
                    },
                    source: Some("docker".to_string()),
                },
            );
        }

        // Create one through the API too.
        let app = test_app(state);
        let _ = app
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
        let json = body_to_json(response.into_body()).await;
        let entries = json.as_array().expect("entrypoints array");
        assert_eq!(entries.len(), 2);
        let sources: Vec<&str> = entries
            .iter()
            .map(|e| e["source"].as_str().unwrap())
            .collect();
        assert!(sources.contains(&"docker"));
        assert!(sources.contains(&"api"));
    }

    #[tokio::test]
    async fn delete_returns_404_for_unknown_id() {
        let app = test_app(test_state());

        let response = app
            .oneshot(
                Request::delete("/entrypoints/does-not-exist")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cannot_delete_entrypoint_managed_by_another_source() {
        let state = test_state();
        {
            let mut storage = state.storage.write().unwrap();
            storage.insert(
                "docker-1".to_string(),
                Entrypoint {
                    id: "docker-1".to_string(),
                    name: "docker-svc".to_string(),
                    backends: vec![Backend::new("172.17.0.2", 8080)],
                    protocol: Protocol::Http,
                    config: EntrypointConfig {
                        hostnames: vec!["docker.local".to_string()],
                        path: None,
                        tls: false,
                        strip_prefix: false,
                        add_prefix: None,
                        https_redirect: false,
                        https_redirect_port: None,
                        redirect: None,
                        redirect_scheme: None,
                        redirect_template: None,
                        www_authenticate: None,
                        priority: 0,
                        auth: None,
                        forward_auth: None,
                        headers: Vec::new(),
                        backend_timeout: None,
                        rate_limit: None,
                        sticky_session: false,
                        compress: false,
                        entrypoint: None,
                        methods: Vec::new(),
                    },
                    source: Some("docker".to_string()),
                },
            );
        }

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::delete("/entrypoints/docker-1")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ---- diagnostics surfacing ------------------------------------------------

    /// Build a minimal HTTP entrypoint with the given id, hostname and path.
    /// Source is set so we exercise the `entrypoint.source` lookup path used
    /// by `entrypoint_payload` to attach diagnostics keyed on candidate id.
    fn make_ep(id: &str, host: &str, path: Option<&str>, source: Option<&str>) -> Entrypoint {
        Entrypoint {
            id: id.to_string(),
            name: id.to_string(),
            backends: vec![Backend::new("10.0.0.1", 80)],
            protocol: Protocol::Http,
            config: EntrypointConfig {
                hostnames: vec![host.to_string()],
                path: path.map(|p| crate::model::PathConfig {
                    rule_type: crate::model::PathRuleType::Prefix,
                    value: p.to_string(),
                }),
                tls: false,
                strip_prefix: false,
                add_prefix: None,
                https_redirect: false,
                https_redirect_port: None,
                redirect: None,
                redirect_scheme: None,
                redirect_template: None,
                www_authenticate: None,
                priority: 0,
                auth: None,
                forward_auth: None,
                headers: Vec::new(),
                backend_timeout: None,
                rate_limit: None,
                sticky_session: false,
                compress: false,
                entrypoint: None,
                methods: Vec::new(),
            },
            source: source.map(|s| s.to_string()),
        }
    }

    fn diag_w001(label: &str, value: &str) -> crate::labels::diagnostic::Diagnostic {
        crate::labels::diagnostic::Diagnostic::new(
            crate::labels::diagnostic::DiagnosticCode::W001InvalidPort,
            "port is not a valid u16, falling back to 80",
        )
        .with_label(label)
        .with_value(value)
    }

    #[tokio::test]
    async fn diagnostics_endpoint_returns_empty_when_nothing_in_store() {
        let app = test_app(test_state());
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["total"], 0);
        assert_eq!(json["global"].as_array().unwrap().len(), 0);
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn diagnostics_endpoint_groups_per_candidate() {
        let state = test_state();
        crate::diagnostics::set(
            &state.diagnostics,
            "docker-aaaa",
            vec![diag_w001("sozune.http.web.port", "abc")],
        );
        crate::diagnostics::set(
            &state.diagnostics,
            "docker-bbbb",
            vec![diag_w001("sozune.http.api.port", "xyz")],
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["total"], 2);
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        // Items are sorted by candidate_id, see `list_diagnostics`.
        assert_eq!(items[0]["candidate_id"], "docker-aaaa");
        assert_eq!(items[1]["candidate_id"], "docker-bbbb");
    }

    #[tokio::test]
    async fn diagnostics_endpoint_serializes_severity_derived_from_code() {
        let state = test_state();
        crate::diagnostics::set(
            &state.diagnostics,
            "c1",
            vec![diag_w001("sozune.http.x.port", "abc")],
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let diag = &json["items"][0]["diagnostics"][0];
        assert_eq!(diag["code"], "W001");
        assert_eq!(
            diag["severity"], "warn",
            "severity must be derived from the code prefix"
        );
        assert_eq!(diag["label"], "sozune.http.x.port");
        assert_eq!(diag["value"], "abc");
        assert!(diag["message"].as_str().unwrap().contains("port"));
    }

    #[tokio::test]
    async fn diagnostics_endpoint_includes_acme_global_when_acme_enabled_no_tls() {
        let mut state = test_state();
        state.acme_enabled = true;
        // Add an entrypoint without TLS so the global lint fires.
        state
            .storage
            .write()
            .unwrap()
            .insert("ep-1".into(), make_ep("ep-1", "example.com", None, None));

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let global = json["global"].as_array().unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0]["code"], "W015");
    }

    #[tokio::test]
    async fn diagnostics_endpoint_omits_acme_global_when_at_least_one_tls_endpoint() {
        let mut state = test_state();
        state.acme_enabled = true;
        let mut tls_ep = make_ep("ep-tls", "secure.example.com", None, None);
        tls_ep.config.tls = true;
        state
            .storage
            .write()
            .unwrap()
            .insert("ep-tls".into(), tls_ep);

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["global"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn diagnostics_endpoint_surfaces_w018_collisions_on_runtime_storage() {
        let state = test_state();
        // Two entrypoints sharing the same (host, path).
        state.storage.write().unwrap().insert(
            "ep-a".into(),
            make_ep("ep-a", "collision.example.com", Some("/api"), None),
        );
        state.storage.write().unwrap().insert(
            "ep-b".into(),
            make_ep("ep-b", "collision.example.com", Some("/api"), None),
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let items = json["items"].as_array().unwrap();
        // Both entrypoints should carry a W018, attributed to their entrypoint id.
        assert_eq!(items.len(), 2);
        for item in items {
            let codes: Vec<&str> = item["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["code"].as_str().unwrap())
                .collect();
            assert!(codes.contains(&"W018"), "expected W018 on {item:?}");
        }
    }

    #[tokio::test]
    async fn diagnostics_endpoint_requires_auth() {
        let app = test_app(test_state());
        let response = app
            .oneshot(Request::get("/diagnostics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn diagnostics_endpoint_allows_read_only_user() {
        let app = test_app(test_state_with_users(vec![user(
            "viewer",
            "viewer-pass",
            Role::ReadOnly,
        )]));
        let response = app
            .oneshot(
                Request::get("/diagnostics")
                    .header("authorization", basic("viewer", "viewer-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "GET /diagnostics is a read endpoint and must be open to read-only users"
        );
    }

    // ---- /providers -----------------------------------------------------------

    #[tokio::test]
    async fn providers_endpoint_lists_every_known_provider() {
        let app = test_app(test_state());
        let response = app
            .oneshot(
                Request::get("/providers")
                    .header("authorization", basic("admin", "admin-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = json["providers"].as_array().expect("providers is an array");

        // Every provider known to sōzune must appear in the list, even when
        // not configured — the dashboard relies on the full set to show
        // "configure me" rows next to inactive providers.
        let names: Vec<&str> = items.iter().map(|p| p["name"].as_str().unwrap()).collect();
        for expected in [
            "docker",
            "podman",
            "swarm",
            "kubernetes",
            "nomad",
            "http",
            "config",
        ] {
            assert!(
                names.contains(&expected),
                "missing provider `{}` in /providers response: got {:?}",
                expected,
                names
            );
        }
    }

    #[tokio::test]
    async fn providers_endpoint_counts_entrypoints_per_source() {
        let state = test_state();
        {
            let mut storage = state.storage.write().unwrap();
            storage.insert(
                "a".into(),
                make_ep("a", "x.example.com", None, Some("docker")),
            );
            storage.insert(
                "b".into(),
                make_ep("b", "y.example.com", None, Some("docker")),
            );
            storage.insert(
                "c".into(),
                make_ep("c", "z.example.com", None, Some("nomad")),
            );
        }
        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/providers")
                    .header("authorization", basic("admin", "admin-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = json["providers"].as_array().unwrap();
        let count_for = |name: &str| -> u64 {
            items
                .iter()
                .find(|p| p["name"] == name)
                .and_then(|p| p["entrypoint_count"].as_u64())
                .unwrap()
        };
        assert_eq!(count_for("docker"), 2);
        assert_eq!(count_for("nomad"), 1);
        assert_eq!(count_for("swarm"), 0);
    }

    #[tokio::test]
    async fn providers_endpoint_allows_read_only_user() {
        let app = test_app(test_state_with_users(vec![user(
            "viewer",
            "viewer-pass",
            Role::ReadOnly,
        )]));
        let response = app
            .oneshot(
                Request::get("/providers")
                    .header("authorization", basic("viewer", "viewer-pass"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "GET /providers is a read endpoint and must be open to read-only users"
        );
    }

    // ---- diagnostics on /entrypoints payload ----------------------------------

    #[tokio::test]
    async fn list_entrypoints_attaches_diagnostics_keyed_by_entrypoint_id() {
        let state = test_state();
        state
            .storage
            .write()
            .unwrap()
            .insert("ep-1".into(), make_ep("ep-1", "example.com", None, None));
        crate::diagnostics::set(
            &state.diagnostics,
            "ep-1",
            vec![diag_w001("sozune.http.web.port", "abc")],
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let diags = arr[0]["diagnostics"].as_array().unwrap();
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0]["code"], "W001");
    }

    #[tokio::test]
    async fn list_entrypoints_falls_back_to_diagnostics_keyed_by_source() {
        // Diagnostics are stored under the candidate id; for Docker etc. the
        // entrypoint id (cluster_id) does not match the candidate id, but the
        // candidate id ends up in `entrypoint.source` indirectly. Here we
        // verify the source-based fallback.
        let state = test_state();
        state.storage.write().unwrap().insert(
            "http_web".into(),
            make_ep(
                "http_web",
                "example.com",
                None,
                Some("docker-container-aaaa"),
            ),
        );
        crate::diagnostics::set(
            &state.diagnostics,
            "docker-container-aaaa",
            vec![diag_w001("sozune.http.web.port", "abc")],
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let diags = json[0]["diagnostics"].as_array().unwrap();
        assert_eq!(
            diags.len(),
            1,
            "diagnostic stored under source must be surfaced"
        );
        assert_eq!(diags[0]["code"], "W001");
    }

    #[tokio::test]
    async fn list_entrypoints_diagnostics_field_is_empty_when_none() {
        let state = test_state();
        state.storage.write().unwrap().insert(
            "ep-clean".into(),
            make_ep("ep-clean", "ok.example.com", None, None),
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/entrypoints")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let diags = json[0]["diagnostics"].as_array().unwrap();
        assert!(diags.is_empty());
    }

    #[tokio::test]
    async fn get_entrypoint_includes_diagnostics_field() {
        let state = test_state();
        state
            .storage
            .write()
            .unwrap()
            .insert("ep-1".into(), make_ep("ep-1", "example.com", None, None));
        crate::diagnostics::set(
            &state.diagnostics,
            "ep-1",
            vec![diag_w001("sozune.http.web.port", "abc")],
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/entrypoints/ep-1")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_to_json(response.into_body()).await;
        let diags = json["diagnostics"].as_array().unwrap();
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0]["code"], "W001");
    }

    #[tokio::test]
    async fn get_entrypoint_includes_runtime_w018_collision() {
        let state = test_state();
        state.storage.write().unwrap().insert(
            "ep-a".into(),
            make_ep("ep-a", "collision.example.com", Some("/api"), None),
        );
        state.storage.write().unwrap().insert(
            "ep-b".into(),
            make_ep("ep-b", "collision.example.com", Some("/api"), None),
        );

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::get("/entrypoints/ep-a")
                    .header("authorization", admin_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_to_json(response.into_body()).await;
        let codes: Vec<&str> = json["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["code"].as_str().unwrap())
            .collect();
        assert!(codes.contains(&"W018"));
    }
}
