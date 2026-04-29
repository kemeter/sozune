use crate::config::DashboardConfig;
use axum::Router;
use axum::body::Body;
use axum::extract::Path;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use std::str::FromStr;
use tracing::info;

#[derive(RustEmbed)]
#[folder = "dashboard/build/"]
struct Assets;

pub async fn serve(config: DashboardConfig) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/{*path}", get(asset));

    let addr = SocketAddr::from_str(&config.listen_address).map_err(|e| {
        anyhow::anyhow!(
            "Invalid dashboard listen address '{}': {}",
            config.listen_address,
            e
        )
    })?;

    info!("Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> Response {
    serve_file("index.html")
}

async fn asset(Path(path): Path<String>, uri: Uri) -> Response {
    if let Some(response) = try_serve(&path) {
        return response;
    }

    let trimmed = uri.path().trim_start_matches('/');
    if !trimmed.is_empty()
        && let Some(response) = try_serve(trimmed)
    {
        return response;
    }

    serve_file("index.html")
}

fn try_serve(path: &str) -> Option<Response> {
    if Assets::get(path).is_some() {
        Some(serve_file(path))
    } else {
        None
    }
}

fn serve_file(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data.into_owned()))
                .unwrap_or_else(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to build response",
                    )
                        .into_response()
                })
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
