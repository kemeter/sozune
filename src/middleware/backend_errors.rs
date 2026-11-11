//! Replaces a route's error responses with a page of its own, like Traefik's
//! `errors` middleware. `error_pages` only cover the answers Sōzu makes
//! itself; this covers what the route answers: its backend, or the
//! middleware when it cannot reach the backend or one of its steps refuses
//! the request.

use std::ops::RangeInclusive;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName, LAST_MODIFIED,
    TRANSFER_ENCODING,
};
use axum::http::{HeaderValue, Method, Response, StatusCode};
use tracing::warn;

use crate::model::BackendErrorsConfig;

/// How long the page at `url` may take to come.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest page taken from `url`.
const MAX_FETCHED_PAGE: usize = 1024 * 1024;
const HTML: &str = "text/html; charset=utf-8";

/// The headers that describe the body, which go with it.
const BODY_HEADERS: [HeaderName; 7] = [
    CONTENT_LENGTH,
    CONTENT_TYPE,
    CONTENT_ENCODING,
    TRANSFER_ENCODING,
    CONTENT_RANGE,
    ETAG,
    LAST_MODIFIED,
];

pub struct BackendErrors {
    status: Vec<RangeInclusive<u16>>,
    page: Option<Bytes>,
    url: Option<String>,
    client: reqwest::Client,
}

impl BackendErrors {
    /// `None` when the config replaces nothing: no valid status, or neither a
    /// page nor a URL. The reason is logged.
    pub fn new(config: &BackendErrorsConfig, client: reqwest::Client) -> Option<Self> {
        let status = match config.status_ranges() {
            Ok(status) if !status.is_empty() => status,
            Ok(_) => {
                warn!("errors: no status given, the route's errors are not replaced");
                return None;
            }
            Err(e) => {
                warn!("errors: {e}, the route's errors are not replaced");
                return None;
            }
        };
        let page = config
            .page
            .as_deref()
            .filter(|page| !page.is_empty())
            .map(load_page);
        let url = config.url.clone().filter(|url| !url.trim().is_empty());
        if page.is_none() && url.is_none() {
            warn!("errors: neither a page nor a URL given, the route's errors are not replaced");
            return None;
        }
        Some(Self {
            status,
            page,
            url,
            client,
        })
    }

    pub fn replaces(&self, status: StatusCode) -> bool {
        let code = status.as_u16();
        self.status.iter().any(|range| range.contains(&code))
    }

    /// `response` with the route's page for body: the one at `url`, else
    /// `page`. Its status and other headers stay. Unchanged when there is no
    /// page to serve.
    pub async fn replace(
        &self,
        method: &Method,
        path_and_query: &str,
        response: Response<Body>,
    ) -> Response<Body> {
        let fetched = self.fetch(response.status(), path_and_query).await;
        let Some((body, content_type)) = fetched.or_else(|| {
            self.page
                .clone()
                .map(|page| (page, HeaderValue::from_static(HTML)))
        }) else {
            return response;
        };
        let (mut parts, _) = response.into_parts();
        for name in BODY_HEADERS {
            parts.headers.remove(name);
        }
        parts.headers.insert(CONTENT_TYPE, content_type);
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        let body = if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(body)
        };
        Response::from_parts(parts, body)
    }

    /// The page at `url` for `status`, with its content type. `None`, logged,
    /// when it cannot be had.
    async fn fetch(
        &self,
        status: StatusCode,
        path_and_query: &str,
    ) -> Option<(Bytes, HeaderValue)> {
        let url = page_url(self.url.as_ref()?, status.as_u16(), path_and_query);
        let fetched = async {
            let response = self
                .client
                .get(&url)
                .timeout(FETCH_TIMEOUT)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("it answered {}", response.status()));
            }
            let too_large = || format!("it is larger than {MAX_FETCHED_PAGE} bytes");
            if response
                .content_length()
                .is_some_and(|len| len > MAX_FETCHED_PAGE as u64)
            {
                return Err(too_large());
            }
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static(HTML));
            let body = response.bytes().await.map_err(|e| e.to_string())?;
            if body.len() > MAX_FETCHED_PAGE {
                return Err(too_large());
            }
            Ok((body, content_type))
        }
        .await;
        fetched
            .inspect_err(|e| warn!("errors: the page at {url} is not served: {e}"))
            .ok()
    }
}

/// An inline page, or the contents of a `file://` one, which only static
/// config can give: a file that cannot be read is logged and the value
/// itself served, as for `error_pages`.
fn load_page(value: &str) -> Bytes {
    match value.strip_prefix("file://") {
        Some(path) => match std::fs::read(path) {
            Ok(contents) => Bytes::from(contents),
            Err(e) => {
                warn!("errors: failed to read '{path}': {e}");
                Bytes::from(value.to_string())
            }
        },
        None => Bytes::from(value.to_string()),
    }
}

/// `template` with `{status}` replaced by the status and `{url}` by the
/// request's path and query, percent-encoded so that it fits in a query.
fn page_url(template: &str, status: u16, path_and_query: &str) -> String {
    template
        .replace("{status}", &status.to_string())
        .replace("{url}", &percent_encode(path_and_query))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{RETRY_AFTER, SET_COOKIE};

    fn config(status: &[&str], page: Option<&str>, url: Option<String>) -> BackendErrorsConfig {
        BackendErrorsConfig {
            status: status.iter().map(|s| s.to_string()).collect(),
            page: page.map(str::to_string),
            url,
        }
    }

    fn errors(status: &[&str], page: Option<&str>, url: Option<String>) -> BackendErrors {
        BackendErrors::new(&config(status, page, url), reqwest::Client::new()).unwrap()
    }

    fn backend_error(status: u16) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_ENCODING, "gzip")
            .header(RETRY_AFTER, "30")
            .header(SET_COOKIE, "session=1")
            .body(Body::from("{\"error\":\"boom\"}"))
            .unwrap()
    }

    async fn body_of(response: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// A server answering `GET /<status>.html` with a page naming the status
    /// and the `from` query, and `404` to anything else.
    async fn page_server() -> String {
        use axum::extract::{Path, Query};
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/{page}",
            get(
                |Path(page): Path<String>,
                 Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    match page.strip_suffix(".html") {
                        Some(status) => (
                            StatusCode::OK,
                            [(CONTENT_TYPE, "text/html")],
                            format!(
                                "page {status} for {}",
                                query.get("from").cloned().unwrap_or_default()
                            ),
                        ),
                        None => (
                            StatusCode::NOT_FOUND,
                            [(CONTENT_TYPE, "text/plain")],
                            String::new(),
                        ),
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[test]
    fn statuses_are_codes_and_ranges() {
        let ranges = config(&["500-599", "404, 429"], None, None)
            .status_ranges()
            .unwrap();
        assert_eq!(ranges, vec![500..=599, 404..=404, 429..=429]);
    }

    #[test]
    fn statuses_outside_errors_are_refused() {
        for bad in ["200", "300-499", "600", "599-500", "5xx"] {
            assert!(config(&[bad], None, None).status_ranges().is_err(), "{bad}");
        }
    }

    #[test]
    fn nothing_to_replace_or_serve_is_no_middleware() {
        let client = reqwest::Client::new;
        assert!(BackendErrors::new(&config(&[], Some("down"), None), client()).is_none());
        assert!(BackendErrors::new(&config(&["5xx"], Some("down"), None), client()).is_none());
        assert!(BackendErrors::new(&config(&["500-599"], None, None), client()).is_none());
        assert!(BackendErrors::new(&config(&["500-599"], Some(""), None), client()).is_none());
    }

    #[test]
    fn only_the_listed_statuses_are_replaced() {
        let errors = errors(&["500-599", "404"], Some("down"), None);
        assert!(errors.replaces(StatusCode::BAD_GATEWAY));
        assert!(errors.replaces(StatusCode::NOT_FOUND));
        assert!(!errors.replaces(StatusCode::FORBIDDEN));
        assert!(!errors.replaces(StatusCode::OK));
    }

    #[tokio::test]
    async fn the_page_replaces_the_body_and_keeps_the_status_and_headers() {
        let errors = errors(&["500-599"], Some("<h1>down</h1>"), None);
        let response = errors
            .replace(&Method::GET, "/api", backend_error(503))
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let headers = response.headers();
        assert_eq!(headers[CONTENT_TYPE], HTML);
        assert_eq!(headers[CONTENT_LENGTH], "13");
        assert!(headers.get(CONTENT_ENCODING).is_none());
        assert_eq!(headers[RETRY_AFTER], "30");
        assert_eq!(headers[SET_COOKIE], "session=1");
        assert_eq!(body_of(response).await, "<h1>down</h1>");
    }

    #[tokio::test]
    async fn a_head_request_gets_the_headers_only() {
        let errors = errors(&["500-599"], Some("<h1>down</h1>"), None);
        let response = errors.replace(&Method::HEAD, "/", backend_error(500)).await;
        assert_eq!(response.headers()[CONTENT_LENGTH], "13");
        assert_eq!(body_of(response).await, "");
    }

    #[tokio::test]
    async fn the_page_is_fetched_for_the_status_and_request() {
        let server = page_server().await;
        let errors = errors(
            &["500-599"],
            Some("fallback"),
            Some(format!("{server}/{{status}}.html?from={{url}}")),
        );
        let response = errors
            .replace(&Method::GET, "/a b?x=1", backend_error(502))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/html");
        assert_eq!(body_of(response).await, "page 502 for /a b?x=1");
    }

    #[tokio::test]
    async fn a_failed_fetch_falls_back_to_the_page() {
        let server = page_server().await;
        let errors = errors(
            &["500-599"],
            Some("fallback"),
            Some(format!("{server}/missing")),
        );
        let response = errors.replace(&Method::GET, "/", backend_error(500)).await;
        assert_eq!(body_of(response).await, "fallback");
    }

    #[tokio::test]
    async fn without_a_page_a_failed_fetch_keeps_the_response() {
        let server = page_server().await;
        let errors = errors(&["500-599"], None, Some(format!("{server}/missing")));
        let response = errors.replace(&Method::GET, "/", backend_error(500)).await;
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(body_of(response).await, "{\"error\":\"boom\"}");
    }

    #[test]
    fn a_file_page_is_read_and_a_missing_one_served_as_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("500.html");
        std::fs::write(&path, "<h1>from disk</h1>").unwrap();
        assert_eq!(
            load_page(&format!("file://{}", path.display())),
            "<h1>from disk</h1>"
        );
        assert_eq!(load_page("file:///nope/500.html"), "file:///nope/500.html");
    }

    #[test]
    fn the_request_url_is_encoded_for_a_query() {
        assert_eq!(
            page_url("http://pages/{status}.html?from={url}", 503, "/a b?x=1&y"),
            "http://pages/503.html?from=%2Fa%20b%3Fx%3D1%26y"
        );
    }
}
