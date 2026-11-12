//! etcd store, read through the JSON API of etcd v3 (`/v3/kv/range`), so it
//! needs no gRPC client. With a user, a token from `/v3/auth/authenticate`
//! is sent on every request and asked again when etcd stops taking it.

use super::KvStore;
use crate::config::{ClientTlsFiles, EtcdConfig};
use crate::util::client_tls::{client_identity, read_ca};
use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::sync::Mutex;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct EtcdStore {
    endpoint: String,
    credentials: Option<(String, String)>,
    client: reqwest::Client,
    token: Mutex<Option<String>>,
}

impl EtcdStore {
    pub fn new(config: &EtcdConfig) -> anyhow::Result<Self> {
        let endpoint = config.endpoint.trim_end_matches('/').to_string();
        let tls_set = config.tls.ca.is_some() || config.tls.cert.is_some();
        if tls_set && !endpoint.starts_with("https://") {
            anyhow::bail!("etcd TLS settings need an https:// endpoint, got {endpoint}");
        }
        let credentials = match (config.username.is_empty(), config.password.is_empty()) {
            (true, true) => None,
            (false, _) => Some((config.username.clone(), config.password.clone())),
            (true, false) => anyhow::bail!("etcd password set without a username"),
        };
        Ok(Self {
            endpoint,
            credentials,
            client: client(&config.tls)?,
            token: Mutex::new(None),
        })
    }

    async fn authenticate(&self) -> anyhow::Result<Option<String>> {
        let Some((name, password)) = &self.credentials else {
            return Ok(None);
        };
        let url = format!("{}/v3/auth/authenticate", self.endpoint);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "name": name, "password": password }))
            .send()
            .await
            .with_context(|| format!("etcd request to {url} failed"))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "etcd refused the login of `{name}` ({status}): {}",
                error_message(response).await
            );
        }
        let body: AuthResponse = response
            .json()
            .await
            .context("Failed to decode the etcd login response")?;
        Ok(Some(body.token))
    }

    async fn range(
        &self,
        prefix: &str,
        token: Option<&str>,
    ) -> anyhow::Result<Result<RangeResponse, reqwest::StatusCode>> {
        let url = format!("{}/v3/kv/range", self.endpoint);
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "key": STANDARD.encode(prefix),
            "range_end": STANDARD.encode(prefix_end(prefix.as_bytes())),
        }));
        if let Some(token) = token {
            request = request.header("Authorization", token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("etcd request to {url} failed"))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED && self.credentials.is_some() {
            return Ok(Err(status));
        }
        if !status.is_success() {
            anyhow::bail!(
                "etcd returned {status} for {url}: {}",
                error_message(response).await
            );
        }
        let body = response
            .json()
            .await
            .with_context(|| format!("Failed to decode the etcd response from {url}"))?;
        Ok(Ok(body))
    }
}

#[async_trait]
impl KvStore for EtcdStore {
    async fn list(&self, prefix: &str) -> anyhow::Result<BTreeMap<String, String>> {
        let mut token = self.token.lock().await;
        if token.is_none() {
            *token = self.authenticate().await?;
        }
        let body = match self.range(prefix, token.as_deref()).await? {
            Ok(body) => body,
            // The token expired, or etcd restarted: log in again, once.
            Err(_) => {
                *token = self.authenticate().await?;
                match self.range(prefix, token.as_deref()).await? {
                    Ok(body) => body,
                    Err(status) => anyhow::bail!("etcd refused the new token ({status})"),
                }
            }
        };
        drop(token);
        decode(body)
    }
}

/// The client, trusting `tls.ca` on top of the usual roots and presenting
/// the client certificate when one is set.
fn client(tls: &ClientTlsFiles) -> anyhow::Result<reqwest::Client> {
    let mut builder = crate::util::http_client::builder().timeout(REQUEST_TIMEOUT);
    if let Some(ca) = &tls.ca {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&read_ca(ca)?).context("invalid PEM in tls.ca")?,
        );
    }
    if let Some((mut cert, key)) = client_identity(tls)? {
        cert.push(b'\n');
        cert.extend_from_slice(&key);
        builder = builder.identity(
            reqwest::Identity::from_pem(&cert).context("invalid PEM in tls.cert or tls.key")?,
        );
    }
    builder.build().context("Failed to build the etcd client")
}

/// The end of the range of keys starting with `prefix`: the prefix with its
/// last byte below 0xff incremented, the bytes after it dropped.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return end;
        }
    }
    // Every byte is 0xff: the range runs to the end of the keyspace.
    vec![0]
}

fn decode(body: RangeResponse) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for kv in body.kvs {
        let key = STANDARD
            .decode(&kv.key)
            .context("etcd returned a key that is not base64")?;
        let value = STANDARD
            .decode(&kv.value)
            .context("etcd returned a value that is not base64")?;
        // A key or a value that is not text is no route.
        if let (Ok(key), Ok(value)) = (String::from_utf8(key), String::from_utf8(value)) {
            out.insert(key, value);
        }
    }
    Ok(out)
}

/// etcd's `error` (or `message`) of a failed request, else the body.
async fn error_message(response: reqwest::Response) -> String {
    let body = response.text().await.unwrap_or_default();
    serde_json::from_str::<ErrorResponse>(&body)
        .ok()
        .and_then(|e| e.error.or(e.message))
        .unwrap_or(body)
}

#[derive(Deserialize)]
struct AuthResponse {
    token: String,
}

#[derive(Deserialize)]
struct RangeResponse {
    #[serde(default)]
    kvs: Vec<RawKv>,
}

#[derive(Deserialize)]
struct RawKv {
    key: String,
    /// Left out by etcd when the value is empty.
    #[serde(default)]
    value: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: Option<String>,
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn the_range_ends_after_the_prefix() {
        assert_eq!(prefix_end(b"sozune/"), b"sozune0");
        assert_eq!(prefix_end(b"a\xff"), b"b");
        assert_eq!(prefix_end(b"\xff\xff"), [0]);
    }

    #[test]
    fn keys_and_values_are_decoded_and_non_text_dropped() {
        let body: RangeResponse = serde_json::from_value(serde_json::json!({
            "header": { "revision": "7" },
            "kvs": [
                { "key": STANDARD.encode("sozune/web/servers/a"), "value": STANDARD.encode("10.0.0.5") },
                { "key": STANDARD.encode("sozune/web/labels/sozune.enable") },
                { "key": STANDARD.encode("sozune/bin"), "value": STANDARD.encode([0xff, 0xfe]) },
            ],
            "count": "3"
        }))
        .unwrap();
        let out = decode(body).unwrap();
        assert_eq!(out["sozune/web/servers/a"], "10.0.0.5");
        assert_eq!(out["sozune/web/labels/sozune.enable"], "");
        assert!(!out.contains_key("sozune/bin"));
    }

    #[test]
    fn tls_needs_an_https_endpoint_and_a_password_a_user() {
        let mut config = EtcdConfig {
            tls: ClientTlsFiles {
                ca: Some("/ca.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = EtcdStore::new(&config).err().unwrap().to_string();
        assert!(err.contains("https://"), "{err}");
        config.tls = ClientTlsFiles::default();
        config.password = "secret".into();
        let err = EtcdStore::new(&config).err().unwrap().to_string();
        assert!(err.contains("username"), "{err}");
    }

    /// A fake etcd that takes `token-<n>` for the n-th login only, so a
    /// login refreshes the token of the one before.
    #[derive(Clone, Default)]
    struct Fake {
        logins: Arc<AtomicUsize>,
    }

    async fn authenticate(
        State(fake): State<Fake>,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if body["name"] != "sozune" || body["password"] != "secret" {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "etcdserver: authentication failed, invalid user ID or password", "code": 3 }),
                ),
            );
        }
        let n = fake.logins.fetch_add(1, Ordering::SeqCst) + 1;
        (
            StatusCode::OK,
            Json(serde_json::json!({ "token": format!("token-{n}") })),
        )
    }

    async fn range(
        State(fake): State<Fake>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let expected = format!("token-{}", fake.logins.load(Ordering::SeqCst));
        if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "etcdserver: invalid auth token", "code": 16 })),
            );
        }
        assert_eq!(body["key"], STANDARD.encode("sozune/"));
        assert_eq!(body["range_end"], STANDARD.encode("sozune0"));
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "kvs": [{ "key": STANDARD.encode("sozune/web/servers/a"), "value": STANDARD.encode("10.0.0.5") }]
            })),
        )
    }

    async fn fake_etcd(fake: Fake) -> String {
        let app = axum::Router::new()
            .route("/v3/auth/authenticate", post(authenticate))
            .route("/v3/kv/range", post(range))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://127.0.0.1:{port}")
    }

    fn config(endpoint: String, password: &str) -> EtcdConfig {
        EtcdConfig {
            endpoint,
            username: "sozune".into(),
            password: password.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_refused_token_is_renewed_once() {
        let fake = Fake::default();
        let store = EtcdStore::new(&config(fake_etcd(fake.clone()).await, "secret")).unwrap();
        let out = store.list("sozune/").await.unwrap();
        assert_eq!(out["sozune/web/servers/a"], "10.0.0.5");
        assert_eq!(fake.logins.load(Ordering::SeqCst), 1);

        store.list("sozune/").await.unwrap();
        assert_eq!(fake.logins.load(Ordering::SeqCst), 1, "the token is kept");

        // Another client logs in: etcd now refuses the token held.
        fake.logins.fetch_add(1, Ordering::SeqCst);
        store.list("sozune/").await.unwrap();
        assert_eq!(fake.logins.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_wrong_password_names_the_user_and_etcd_reason() {
        let store = EtcdStore::new(&config(fake_etcd(Fake::default()).await, "nope")).unwrap();
        let err = store.list("sozune/").await.unwrap_err().to_string();
        assert!(err.contains("`sozune`"), "{err}");
        assert!(err.contains("invalid user ID or password"), "{err}");
    }
}
