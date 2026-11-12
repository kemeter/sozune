//! Redis store, which Valkey serves too: the keys under the prefix are found
//! with `SCAN` and read with `MGET`. A key that holds no string (a hash, a
//! list...) is left out.

use super::KvStore;
use crate::config::RedisConfig;
use crate::util::client_tls::{client_identity, read_ca};
use anyhow::Context as _;
use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use redis::{AsyncConnectionConfig, Client, IntoConnectionInfo, TlsCertificates};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::sync::Mutex;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Keys asked per `SCAN` step, and read per `MGET`.
const BATCH: usize = 500;

pub struct RedisStore {
    client: Client,
    /// Kept between polls, dropped on an error so the next poll reconnects.
    connection: Mutex<Option<MultiplexedConnection>>,
}

impl RedisStore {
    pub fn new(config: &RedisConfig) -> anyhow::Result<Self> {
        let tls = config.tls.ca.is_some() || config.tls.cert.is_some();
        if tls && !config.endpoint.starts_with("rediss://") {
            anyhow::bail!(
                "Redis TLS settings need a rediss:// endpoint, got {}",
                config.endpoint
            );
        }
        let mut info = config
            .endpoint
            .as_str()
            .into_connection_info()
            .with_context(|| format!("invalid Redis endpoint `{}`", config.endpoint))?;
        let mut settings = info.redis_settings().clone();
        if !config.username.is_empty() {
            settings = settings.set_username(&config.username);
        }
        if !config.password.is_empty() {
            settings = settings.set_password(&config.password);
        }
        if let Some(db) = config.db {
            settings = settings.set_db(db);
        }
        info = info.set_redis_settings(settings);

        let client = if config.endpoint.starts_with("rediss://") {
            // Both rustls providers are compiled in: pick the one the rest of
            // Sōzune uses, or rustls cannot choose and the client panics.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let root_cert = match &config.tls.ca {
                Some(ca) => Some(read_ca(ca)?),
                None => None,
            };
            let client_tls = client_identity(&config.tls)?.map(|(client_cert, client_key)| {
                redis::ClientTlsConfig {
                    client_cert,
                    client_key,
                }
            });
            Client::build_with_tls(
                info,
                TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )
        } else {
            Client::open(info)
        }
        .context("Failed to build the Redis client")?;
        Ok(Self {
            client,
            connection: Mutex::new(None),
        })
    }

    async fn connection(&self) -> anyhow::Result<MultiplexedConnection> {
        let mut held = self.connection.lock().await;
        if let Some(connection) = held.as_ref() {
            return Ok(connection.clone());
        }
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT));
        let connection = self
            .client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .context("could not connect to Redis")?;
        *held = Some(connection.clone());
        Ok(connection)
    }

    async fn read(
        &self,
        connection: &mut MultiplexedConnection,
        prefix: &str,
    ) -> redis::RedisResult<BTreeMap<String, String>> {
        let pattern = format!("{}*", escape_glob(prefix));
        let mut keys = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(BATCH)
                .query_async(connection)
                .await?;
            keys.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        // SCAN may return a key more than once.
        keys.sort();
        keys.dedup();

        let mut out = BTreeMap::new();
        for chunk in keys.chunks(BATCH) {
            let values: Vec<Option<String>> = redis::cmd("MGET")
                .arg(chunk)
                .query_async(connection)
                .await?;
            for (key, value) in chunk.iter().zip(values) {
                if let Some(value) = value {
                    out.insert(key.clone(), value);
                }
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl KvStore for RedisStore {
    async fn list(&self, prefix: &str) -> anyhow::Result<BTreeMap<String, String>> {
        let mut connection = self.connection().await?;
        match self.read(&mut connection, prefix).await {
            Ok(out) => Ok(out),
            Err(e) => {
                *self.connection.lock().await = None;
                Err(anyhow::Error::new(e).context("Redis read failed"))
            }
        }
    }
}

/// `prefix` as a `SCAN MATCH` pattern that matches it literally.
fn escape_glob(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_characters_of_the_prefix_are_escaped() {
        assert_eq!(escape_glob("sozune/"), "sozune/");
        assert_eq!(escape_glob("a*b?[c]\\/"), "a\\*b\\?\\[c\\]\\\\/");
    }

    #[test]
    fn tls_settings_need_a_rediss_endpoint() {
        let config = RedisConfig {
            tls: crate::config::ClientTlsFiles {
                ca: Some("/ca.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = RedisStore::new(&config).err().unwrap().to_string();
        assert!(err.contains("rediss://"), "{err}");
    }

    #[test]
    fn an_invalid_endpoint_is_refused() {
        let config = RedisConfig {
            endpoint: "http://127.0.0.1:6379".into(),
            ..Default::default()
        };
        let err = RedisStore::new(&config).err().unwrap().to_string();
        assert!(err.contains("invalid Redis endpoint"), "{err}");
    }

    #[test]
    fn credentials_and_db_override_the_url() {
        let config = RedisConfig {
            endpoint: "redis://olduser:oldpass@127.0.0.1:6379/1".into(),
            username: "sozune".into(),
            password: "secret".into(),
            db: Some(3),
            ..Default::default()
        };
        let store = RedisStore::new(&config).unwrap();
        let settings = store.client.get_connection_info().redis_settings();
        assert_eq!(settings.username(), Some("sozune"));
        assert_eq!(settings.password(), Some("secret"));
        assert_eq!(settings.db(), 3);
    }

    #[tokio::test]
    async fn an_unreachable_server_is_an_error_not_a_hang() {
        let config = RedisConfig {
            endpoint: "redis://127.0.0.1:1".into(),
            ..Default::default()
        };
        let store = RedisStore::new(&config).unwrap();
        let err = store.list("sozune/").await.unwrap_err();
        assert!(format!("{err:#}").contains("connect"), "{err:#}");
    }
}
