//! WebAssembly middleware: runs an [http-wasm](https://http-wasm.io) guest as
//! a Sōzune middleware.
//!
//! The bridge has two halves:
//! - [`HttpState`] — an in-memory snapshot of the request/response that
//!   implements the host crate's [`Host`] trait. We snapshot because the guest
//!   ABI is synchronous and works on buffered bytes, whereas axum bodies are
//!   async and streamed. This mirrors the snapshot pattern already used by
//!   `forward_auth`.
//! - [`WasmMiddleware`] — implements Sōzune's [`Middleware`] trait, driving the
//!   guest's `handle_request`/`handle_response` phases around the backend call.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use http_wasm_host::{
    FetchRequest, FetchResponse, Fetcher, HeaderKind, Host, Limits, Next, Plugin, SendOutcome, Sink,
};
use tracing::{error, warn};

use super::chain::{Flow, Middleware, RequestCtx};

/// Maximum request/response body we buffer for a guest. Bodies larger than this
/// are passed through untouched (the guest sees an empty body). Keeps a hostile
/// or huge upload from exhausting memory.
const MAX_BUFFERED_BODY: usize = 1024 * 1024;

/// In-memory view of one HTTP exchange handed to a guest. Field mutations made
/// by the guest are read back by [`WasmMiddleware`] after each phase.
struct HttpState {
    method: String,
    uri: String,
    version: String,
    source_addr: String,
    status: u32,
    config: Vec<u8>,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
    req_body: Vec<u8>,
    req_body_cursor: usize,
    resp_body: Vec<u8>,
    resp_body_cursor: usize,
}

impl HttpState {
    fn headers_for(&self, kind: HeaderKind) -> &Vec<(String, String)> {
        match kind {
            HeaderKind::Request | HeaderKind::RequestTrailers => &self.req_headers,
            HeaderKind::Response | HeaderKind::ResponseTrailers => &self.resp_headers,
        }
    }

    fn headers_mut(&mut self, kind: HeaderKind) -> &mut Vec<(String, String)> {
        match kind {
            HeaderKind::Request | HeaderKind::RequestTrailers => &mut self.req_headers,
            HeaderKind::Response | HeaderKind::ResponseTrailers => &mut self.resp_headers,
        }
    }
}

impl Host for HttpState {
    fn method(&self) -> String {
        self.method.clone()
    }
    fn set_method(&mut self, method: &str) {
        self.method = method.to_string();
    }
    fn uri(&self) -> String {
        self.uri.clone()
    }
    fn set_uri(&mut self, uri: &str) {
        self.uri = uri.to_string();
    }
    fn protocol_version(&self) -> String {
        self.version.clone()
    }
    fn source_addr(&self) -> String {
        self.source_addr.clone()
    }
    fn status_code(&self) -> u32 {
        self.status
    }
    fn set_status_code(&mut self, status: u32) {
        self.status = status;
    }

    fn header_names(&self, kind: HeaderKind) -> Vec<String> {
        let mut names: Vec<String> = self
            .headers_for(kind)
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
    fn header_values(&self, kind: HeaderKind, name: &str) -> Vec<String> {
        let lower = name.to_ascii_lowercase();
        self.headers_for(kind)
            .iter()
            .filter(|(n, _)| *n == lower)
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn set_header_value(&mut self, kind: HeaderKind, name: &str, value: &str) {
        let lower = name.to_ascii_lowercase();
        let headers = self.headers_mut(kind);
        headers.retain(|(n, _)| *n != lower);
        headers.push((lower, value.to_string()));
    }
    fn add_header_value(&mut self, kind: HeaderKind, name: &str, value: &str) {
        self.headers_mut(kind)
            .push((name.to_ascii_lowercase(), value.to_string()));
    }
    fn remove_header(&mut self, kind: HeaderKind, name: &str) {
        let lower = name.to_ascii_lowercase();
        self.headers_mut(kind).retain(|(n, _)| *n != lower);
    }

    fn read_body(&mut self, kind: HeaderKind, max: usize) -> Vec<u8> {
        let (body, cursor) = match kind {
            HeaderKind::Request | HeaderKind::RequestTrailers => {
                (&self.req_body, &mut self.req_body_cursor)
            }
            HeaderKind::Response | HeaderKind::ResponseTrailers => {
                (&self.resp_body, &mut self.resp_body_cursor)
            }
        };
        let start = (*cursor).min(body.len());
        let end = (start + max).min(body.len());
        *cursor = end;
        body[start..end].to_vec()
    }
    fn write_body(&mut self, kind: HeaderKind, data: &[u8]) {
        match kind {
            HeaderKind::Request | HeaderKind::RequestTrailers => self.req_body = data.to_vec(),
            HeaderKind::Response | HeaderKind::ResponseTrailers => self.resp_body = data.to_vec(),
        }
    }

    fn config(&self) -> Vec<u8> {
        self.config.clone()
    }
}

/// Snapshot the headers of an axum `HeaderMap` into the `(lowercase_name, value)`
/// pairs `HttpState` keeps. Non-UTF-8 values are skipped (the guest ABI is
/// UTF-8 / string based).
fn snapshot_headers(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_string(), v.to_string()))
        })
        .collect()
}

/// Overwrite an axum `HeaderMap` from `(name, value)` pairs, dropping any that
/// fail to parse back into valid header name/value.
fn apply_headers(headers: &mut axum::http::HeaderMap, pairs: &[(String, String)]) {
    headers.clear();
    for (name, value) in pairs {
        if let (Ok(n), Ok(v)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(value),
        ) {
            headers.append(n, v);
        }
    }
}

/// Serves the guest's `http_fetch` calls over the network. Bridges the
/// synchronous guest ABI to the async reqwest client by blocking on the shared
/// runtime. Outbound requests are restricted to `allowed_hosts` (anti-SSRF):
/// the guest may pick the path/query, but only against pre-declared hosts.
struct HostFetcher {
    client: reqwest::Client,
    handle: tokio::runtime::Handle,
    allowed_hosts: Vec<String>,
}

/// Whether `url`'s host is permitted by `allowed_hosts`. An allow-list entry
/// may be a bare host (`crowdsec`) or include a port (`crowdsec:8080`); a URL is
/// accepted if its host alone, or its `host:port` authority, matches an entry.
/// This dual match is why a config entry like `127.0.0.1:8080` works even though
/// `Url::host_str` returns just `127.0.0.1`.
fn host_allowed(url: &reqwest::Url, allowed_hosts: &[String]) -> bool {
    let host = url.host_str().unwrap_or_default();
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    allowed_hosts.iter().any(|h| h == host || h == &authority)
}

impl Fetcher for HostFetcher {
    fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, String> {
        // Validate the target against the allow-list before doing anything.
        let url = reqwest::Url::parse(&request.url).map_err(|e| format!("invalid url: {e}"))?;
        if !host_allowed(&url, &self.allowed_hosts) {
            return Err(format!(
                "host '{}' not in plugin allow-list",
                url.host_str().unwrap_or_default()
            ));
        }

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| format!("invalid method: {e}"))?;

        // The guest ABI is synchronous; block on the async client. `block_in_place`
        // is safe on the multi-thread runtime sōzune runs on.
        tokio::task::block_in_place(|| {
            self.handle.block_on(async {
                let mut builder = self.client.request(method, url);
                for (name, value) in &request.headers {
                    builder = builder.header(name, value);
                }
                if !request.body.is_empty() {
                    builder = builder.body(request.body);
                }
                let resp = builder.send().await.map_err(|e| e.to_string())?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(n, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (n.as_str().to_string(), v.to_string()))
                    })
                    .collect();
                let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
                Ok(FetchResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
    }
}

/// Serves the guest's fire-and-forget `http_send` calls. Enqueues each request
/// onto a bounded channel without blocking; a background worker drains it and
/// performs the POSTs. Requests to hosts outside `allowed_hosts` are dropped at
/// enqueue time (anti-SSRF). When the queue is full, events are dropped rather
/// than blocking the request path — analytics is best-effort.
struct EventSink {
    tx: tokio::sync::mpsc::Sender<FetchRequest>,
    allowed_hosts: Vec<String>,
}

impl EventSink {
    /// Build the sink and spawn its draining worker on `handle`. The worker
    /// lives for the process; it stops when all senders are dropped.
    fn new(
        client: reqwest::Client,
        handle: &tokio::runtime::Handle,
        allowed_hosts: Vec<String>,
        queue_size: usize,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchRequest>(queue_size);
        handle.spawn(async move {
            while let Some(req) = rx.recv().await {
                let Ok(url) = reqwest::Url::parse(&req.url) else {
                    continue;
                };
                let Ok(method) = reqwest::Method::from_bytes(req.method.as_bytes()) else {
                    continue;
                };
                let mut builder = client.request(method, url);
                for (name, value) in &req.headers {
                    builder = builder.header(name, value);
                }
                if !req.body.is_empty() {
                    builder = builder.body(req.body);
                }
                // Fire-and-forget: we don't surface the result, only log failures.
                if let Err(e) = builder.send().await {
                    warn!("wasm plugin event send failed: {e}");
                }
            }
        });
        Self { tx, allowed_hosts }
    }
}

impl Sink for EventSink {
    fn send(&self, request: FetchRequest) -> SendOutcome {
        match reqwest::Url::parse(&request.url) {
            Ok(url) if host_allowed(&url, &self.allowed_hosts) => {}
            _ => return SendOutcome::Rejected,
        }
        match self.tx.try_send(request) {
            Ok(()) => SendOutcome::Queued,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => SendOutcome::QueueFull,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => SendOutcome::Rejected,
        }
    }
}

/// Bounded queue size for a plugin's outbound events.
const EVENT_QUEUE_SIZE: usize = 1024;

/// A compiled http-wasm guest wired in as a middleware.
pub struct WasmMiddleware {
    name: &'static str,
    plugin: Arc<Plugin>,
    config: Vec<u8>,
}

impl WasmMiddleware {
    /// Compile a guest from `.wasm` bytes with the given per-invocation limits
    /// and guest configuration.
    pub fn from_bytes(wasm: &[u8], config: Vec<u8>, limits: Limits) -> anyhow::Result<Self> {
        let plugin = Plugin::from_bytes(wasm, limits)
            .map_err(|e| anyhow::anyhow!("failed to load wasm plugin: {e}"))?;
        Ok(Self {
            name: "wasm",
            plugin: Arc::new(plugin),
            config,
        })
    }

    /// Like [`from_bytes`](Self::from_bytes) but enables the network extensions:
    /// the guest's `http_fetch` (blocking) and `http_send` (fire-and-forget)
    /// calls go through `client`, both restricted to `allowed_hosts`.
    pub fn from_bytes_with_network(
        wasm: &[u8],
        config: Vec<u8>,
        limits: Limits,
        client: reqwest::Client,
        handle: tokio::runtime::Handle,
        allowed_hosts: Vec<String>,
    ) -> anyhow::Result<Self> {
        let fetcher = Arc::new(HostFetcher {
            client: client.clone(),
            handle: handle.clone(),
            allowed_hosts: allowed_hosts.clone(),
        });
        let sink = Arc::new(EventSink::new(
            client,
            &handle,
            allowed_hosts,
            EVENT_QUEUE_SIZE,
        ));
        let plugin = Plugin::from_bytes(wasm, limits)
            .map_err(|e| anyhow::anyhow!("failed to load wasm plugin: {e}"))?
            .with_fetcher(fetcher)
            .with_sink(sink);
        Ok(Self {
            name: "wasm",
            plugin: Arc::new(plugin),
            config,
        })
    }

    /// Build an `HttpState` snapshot from the request, ready for the request
    /// phase. The request body is consumed and buffered into the state.
    async fn snapshot_request(&self, ctx: &RequestCtx, req: Request<Body>) -> (HttpState, Vec<u8>) {
        let (parts, body) = req.into_parts();
        let body_bytes = buffer_body(body).await;
        let state = HttpState {
            method: parts.method.to_string(),
            uri: parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| parts.uri.path().to_string()),
            version: format!("{:?}", parts.version),
            source_addr: ctx.client_addr.map(|a| a.to_string()).unwrap_or_default(),
            status: 0,
            config: self.config.clone(),
            req_headers: snapshot_headers(&parts.headers),
            resp_headers: Vec::new(),
            req_body: body_bytes.clone(),
            req_body_cursor: 0,
            resp_body: Vec::new(),
            resp_body_cursor: 0,
        };
        (state, body_bytes)
    }
}

/// Buffer an axum body up to [`MAX_BUFFERED_BODY`]. Returns empty on error or
/// oversize (the guest then sees no body).
async fn buffer_body(body: Body) -> Vec<u8> {
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.len() > MAX_BUFFERED_BODY {
                warn!("wasm middleware: body exceeds {MAX_BUFFERED_BODY} bytes, not buffered");
                Vec::new()
            } else {
                bytes.to_vec()
            }
        }
        Err(e) => {
            warn!("wasm middleware: failed to read body: {e}");
            Vec::new()
        }
    }
}

/// Build the short-circuit response the guest authored (status + headers + body).
fn build_short_circuit(state: &HttpState) -> Response<Body> {
    let status = StatusCode::from_u16(state.status as u16).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    if let Some(map) = builder.headers_mut() {
        apply_headers(map, &state.resp_headers);
    }
    builder
        .body(Body::from(state.resp_body.clone()))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        })
}

#[async_trait::async_trait]
impl Middleware for WasmMiddleware {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // Take ownership of the body to buffer it, leaving an empty body behind
        // that we replace afterwards.
        let taken = std::mem::replace(req, Request::new(Body::empty()));
        let (mut state, _orig_body) = self.snapshot_request(ctx, taken).await;

        let outcome = self.plugin.handle_request(&mut state);

        match outcome {
            Ok(Next::Stop) => Flow::ShortCircuit(build_short_circuit(&state)),
            Ok(Next::Continue(_ctx)) => {
                // Re-apply guest mutations onto the forwarded request.
                apply_headers(req.headers_mut(), &state.req_headers);
                if let Ok(uri) = state.uri.parse() {
                    *req.uri_mut() = uri;
                }
                if let Ok(method) = state.method.parse() {
                    *req.method_mut() = method;
                }
                *req.body_mut() = Body::from(state.req_body.clone());
                // A guest may stage response headers from the request phase;
                // carry them to the response side via the shared context.
                ctx.pending_response_headers.extend(state.resp_headers);
                Flow::Continue
            }
            Err(e) => {
                error!("wasm middleware '{}' request phase failed: {e}", self.name);
                Flow::ShortCircuit(
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("wasm plugin error\n"))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                )
            }
        }
    }

    async fn on_response(&self, ctx: &RequestCtx, resp: Response<Body>) -> Response<Body> {
        let (parts, body) = resp.into_parts();
        let body_bytes = buffer_body(body).await;
        // Start from the backend's response headers, then merge any headers the
        // guest staged during the request phase. The guest can still read and
        // mutate the full set in `handle_response`.
        let mut resp_headers = snapshot_headers(&parts.headers);
        resp_headers.extend(ctx.pending_response_headers.iter().cloned());
        let mut state = HttpState {
            method: String::new(),
            uri: String::new(),
            version: format!("{:?}", parts.version),
            source_addr: String::new(),
            status: parts.status.as_u16() as u32,
            config: self.config.clone(),
            req_headers: Vec::new(),
            resp_headers,
            req_body: Vec::new(),
            req_body_cursor: 0,
            resp_body: body_bytes,
            resp_body_cursor: 0,
        };

        if let Err(e) = self.plugin.handle_response(&mut state, 0, false) {
            error!("wasm middleware '{}' response phase failed: {e}", self.name);
            // On failure, pass the original response through unchanged.
            let mut rebuilt = Response::new(Body::from(state.resp_body));
            *rebuilt.status_mut() = parts.status;
            *rebuilt.headers_mut() = parts.headers;
            return rebuilt;
        }

        let status = StatusCode::from_u16(state.status as u16).unwrap_or(parts.status);
        let mut builder = Response::builder().status(status).version(parts.version);
        if let Some(map) = builder.headers_mut() {
            apply_headers(map, &state.resp_headers);
        }
        builder
            .body(Body::from(state.resp_body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> HttpState {
        HttpState {
            method: "GET".into(),
            uri: "/".into(),
            version: "HTTP/1.1".into(),
            source_addr: String::new(),
            status: 200,
            config: Vec::new(),
            req_headers: vec![("x-a".into(), "1".into())],
            resp_headers: Vec::new(),
            req_body: b"hello".to_vec(),
            req_body_cursor: 0,
            resp_body: Vec::new(),
            resp_body_cursor: 0,
        }
    }

    #[test]
    fn header_get_set_add_remove_roundtrip() {
        let mut s = state();
        assert_eq!(s.header_values(HeaderKind::Request, "x-a"), vec!["1"]);

        s.add_header_value(HeaderKind::Request, "X-A", "2");
        assert_eq!(s.header_values(HeaderKind::Request, "x-a"), vec!["1", "2"]);

        s.set_header_value(HeaderKind::Request, "x-a", "only");
        assert_eq!(s.header_values(HeaderKind::Request, "x-a"), vec!["only"]);

        s.remove_header(HeaderKind::Request, "x-a");
        assert!(s.header_values(HeaderKind::Request, "x-a").is_empty());
    }

    #[test]
    fn read_body_advances_cursor_and_signals_eof() {
        let mut s = state();
        assert_eq!(s.read_body(HeaderKind::Request, 3), b"hel".to_vec());
        assert_eq!(s.read_body(HeaderKind::Request, 10), b"lo".to_vec());
        // further reads are empty (EOF)
        assert!(s.read_body(HeaderKind::Request, 10).is_empty());
    }

    #[test]
    fn write_body_replaces_response_body() {
        let mut s = state();
        s.write_body(HeaderKind::Response, b"new body");
        assert_eq!(s.resp_body, b"new body");
    }

    #[test]
    fn request_and_response_headers_are_separate() {
        let mut s = state();
        s.add_header_value(HeaderKind::Response, "x-resp", "v");
        assert!(s.header_values(HeaderKind::Request, "x-resp").is_empty());
        assert_eq!(s.header_values(HeaderKind::Response, "x-resp"), vec!["v"]);
    }

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).unwrap()
    }

    #[test]
    fn allow_list_matches_host_and_port_against_bare_host_entry() {
        // Entry without port matches a URL on any port (host_str has no port).
        let allowed = vec!["crowdsec".to_string()];
        assert!(host_allowed(
            &url("http://crowdsec:8080/v1/decisions"),
            &allowed
        ));
        assert!(host_allowed(&url("http://crowdsec/x"), &allowed));
    }

    #[test]
    fn allow_list_matches_host_port_entry() {
        // Regression: a `host:port` entry must match even though Url::host_str
        // returns only the host. This is the bug found testing CrowdSec for real
        // (config had 127.0.0.1:8080, host_str returns 127.0.0.1).
        let allowed = vec!["127.0.0.1:8080".to_string()];
        assert!(host_allowed(
            &url("http://127.0.0.1:8080/v1/decisions?ip=9.9.9.9"),
            &allowed
        ));
    }

    #[test]
    fn allow_list_rejects_unlisted_host() {
        let allowed = vec!["crowdsec:8080".to_string()];
        assert!(!host_allowed(&url("http://evil.example/"), &allowed));
        // wrong port when the entry pins a port
        assert!(!host_allowed(&url("http://crowdsec:9999/"), &allowed));
    }

    #[test]
    fn empty_allow_list_rejects_everything() {
        assert!(!host_allowed(&url("http://crowdsec:8080/"), &[]));
    }

    fn beacon(url: &str) -> FetchRequest {
        FetchRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![],
            body: b"{}".to_vec(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_sink_queues_allowed_and_rejects_others() {
        let client = reqwest::Client::new();
        let handle = tokio::runtime::Handle::current();
        let sink = EventSink::new(client, &handle, vec!["umami:3000".to_string()], 8);

        // Allowed host → queued.
        assert_eq!(
            sink.send(beacon("http://umami:3000/api/send")),
            SendOutcome::Queued
        );
        // Host not on the allow-list → rejected, never enqueued.
        assert_eq!(
            sink.send(beacon("http://evil.example/api/send")),
            SendOutcome::Rejected
        );
        // Unparseable URL → rejected.
        assert_eq!(sink.send(beacon("not a url")), SendOutcome::Rejected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_sink_reports_queue_full() {
        // A tiny queue with no draining (worker can't keep up) fills quickly.
        // We point at an unroutable host so the worker stays busy/blocked on the
        // first item, letting subsequent try_sends hit the bound.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let handle = tokio::runtime::Handle::current();
        let sink = EventSink::new(client, &handle, vec!["10.255.255.1".to_string()], 1);

        // Fire many; with a queue of 1 and a stalled worker, some must be QueueFull.
        let mut full_seen = false;
        for _ in 0..50 {
            if sink.send(beacon("http://10.255.255.1/x")) == SendOutcome::QueueFull {
                full_seen = true;
                break;
            }
        }
        assert!(full_seen, "expected the bounded queue to report QueueFull");
    }
}
