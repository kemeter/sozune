//! Key-value providers: routes read from the keys of an etcd or Redis store.
//!
//! Both stores hold the same tree under a root key (`sozune` by default):
//!
//! ```text
//! sozune/<service>/labels/<label>  = <value>
//! sozune/<service>/servers/<name>  = <ip>[:<port>]
//! ```
//!
//! A service's labels are the ones a container would carry
//! (`sozune.http.web.host`, ...), and each of its servers becomes one
//! backend, as each replica of a container does. A server's port fills in
//! the `sozune.<proto>.<svc>.port` its labels leave unset. The stores have
//! no change feed Sōzune relies on, so the tree is read again at every poll,
//! and a reload only happens when the routes it gives change.

use crate::diagnostics::{self, DiagnosticsStore};
use crate::labels::candidate::{Candidate, NetworkInfo};
use crate::labels::diagnostic::log_diagnostics;
use crate::model::Entrypoint;
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

pub mod etcd;
pub mod redis;

/// Protocols whose services take a backend port.
const PROTOCOLS: &[&str] = &["http", "tcp", "udp"];

/// A store that lists the keys under a prefix.
#[async_trait]
pub trait KvStore: Send + Sync {
    /// Every key starting with `prefix` and its value. A key whose value is
    /// not text is left out.
    async fn list(&self, prefix: &str) -> anyhow::Result<BTreeMap<String, String>>;
}

/// Polls a [`KvStore`] and merges the routes of its tree into the storage.
pub struct KvProvider<S> {
    name: &'static str,
    store: S,
    root_key: String,
    poll_interval: Duration,
    expose_by_default: bool,
    /// The keys the last poll could not use, so each is reported once.
    ignored: Mutex<BTreeSet<String>>,
}

impl<S: KvStore> KvProvider<S> {
    pub fn new(
        name: &'static str,
        store: S,
        root_key: &str,
        poll_interval: u64,
        expose_by_default: bool,
    ) -> Self {
        Self {
            name,
            store,
            root_key: root_key.trim_end_matches('/').to_string(),
            poll_interval: Duration::from_secs(poll_interval.max(1)),
            expose_by_default,
            ignored: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The candidates of the tree, and the keys it holds that are none of a
    /// service's, with why.
    pub async fn scan(&self) -> anyhow::Result<(Vec<Candidate>, BTreeMap<String, String>)> {
        let prefix = format!("{}/", self.root_key);
        let kvs = self.store.list(&prefix).await?;
        let tree = parse_tree(&prefix, &kvs);
        let ignored = tree.ignored.clone();
        Ok((tree.candidates(self.name, self.expose_by_default), ignored))
    }

    async fn provide_into(
        &self,
        diagnostics: &DiagnosticsStore,
    ) -> anyhow::Result<BTreeMap<String, Entrypoint>> {
        let (candidates, ignored) = self.scan().await?;
        self.report_ignored(&ignored);
        Ok(entrypoints_of(self.name, candidates, diagnostics))
    }

    /// Warns about the keys that are newly unusable, once each.
    fn report_ignored(&self, ignored: &BTreeMap<String, String>) {
        let Ok(mut known) = self.ignored.lock() else {
            return;
        };
        for (key, reason) in ignored {
            if !known.contains(key) {
                warn!("{} provider: ignoring key `{key}`: {reason}", self.name);
            }
        }
        *known = ignored.keys().cloned().collect();
    }

    async fn poll_once(
        &self,
        storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: &mpsc::Sender<()>,
        acme_notify: &Arc<Notify>,
        diagnostics: &DiagnosticsStore,
    ) {
        let new_entrypoints = match self.provide_into(diagnostics).await {
            Ok(map) => map,
            Err(e) => {
                warn!("{} poll failed: {e:#}", self.name);
                return;
            }
        };

        let needs_update = {
            let storage_read = match storage.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
                    return;
                }
            };
            let old_ids: HashSet<&String> = storage_read
                .iter()
                .filter(|(_, ep)| ep.source.as_deref() == Some(self.name))
                .map(|(id, _)| id)
                .collect();
            let new_ids: HashSet<&String> = new_entrypoints.keys().collect();
            old_ids != new_ids
                || new_entrypoints
                    .iter()
                    .any(|(id, ep)| storage_read.get(id).is_none_or(|existing| existing != ep))
        };
        if !needs_update {
            return;
        }

        {
            let mut storage_write = match storage.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("internal state corrupted (configuration store), restart required: {e}");
                    return;
                }
            };
            storage_write.retain(|_, ep| ep.source.as_deref() != Some(self.name));
            for (id, entrypoint) in new_entrypoints {
                debug!(
                    "{} entrypoint: {id} ({} backend(s))",
                    self.name,
                    entrypoint.backends.len()
                );
                storage_write.insert(id, entrypoint);
            }
        }

        info!("{} provider config changed, triggering reload", self.name);
        if let Err(e) = reload_tx.send(()).await {
            warn!("could not apply configuration update; will retry on next change: {e}");
        }
        acme_notify.notify_one();
    }

    pub async fn start_polling(
        &self,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        reload_tx: mpsc::Sender<()>,
        acme_notify: Arc<Notify>,
        diagnostics: DiagnosticsStore,
    ) -> anyhow::Result<()> {
        info!(
            "Starting {} provider on `{}/` (poll={}s, expose_by_default={})",
            self.name,
            self.root_key,
            self.poll_interval.as_secs(),
            self.expose_by_default,
        );
        loop {
            self.poll_once(&storage, &reload_tx, &acme_notify, &diagnostics)
                .await;
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

/// Parses the candidates into entrypoints, the servers of a service becoming
/// the backends of its routes.
fn entrypoints_of(
    source: &str,
    candidates: Vec<Candidate>,
    diagnostics: &DiagnosticsStore,
) -> BTreeMap<String, Entrypoint> {
    let mut entrypoints: BTreeMap<String, Entrypoint> = BTreeMap::new();
    for candidate in candidates {
        let result = diagnostics::parse_and_store(diagnostics, &candidate);
        log_diagnostics(&candidate, &result.diagnostics);
        for (key, mut entrypoint) in result.entrypoints {
            let Some(backend) = entrypoint.backends.first().cloned() else {
                continue;
            };
            if let Some(existing) = entrypoints.get_mut(&key) {
                existing.add_candidates(&entrypoint.candidates);
                if !existing.backends.iter().any(|b| b.same_address(&backend)) {
                    existing.backends.push(backend);
                }
            } else {
                entrypoint.source = Some(source.to_string());
                entrypoints.insert(key, entrypoint);
            }
        }
    }
    // The servers of a service share its weight.
    for entrypoint in entrypoints.values_mut() {
        crate::model::split_service_weights(&mut entrypoint.backends);
    }
    entrypoints
}

/// A server of a service: the address its backend gets.
#[derive(Debug, Clone, PartialEq)]
struct Server {
    ip: IpAddr,
    port: Option<u16>,
}

#[derive(Debug, Default)]
struct Service {
    labels: HashMap<String, String>,
    servers: BTreeMap<String, Server>,
}

/// The services of a tree, and the keys it holds that are none of theirs.
#[derive(Debug, Default)]
struct Tree {
    services: BTreeMap<String, Service>,
    /// Key, and why it is not used.
    ignored: BTreeMap<String, String>,
}

impl Tree {
    /// One candidate per server, carrying its service's labels.
    fn candidates(self, provider: &'static str, expose_by_default: bool) -> Vec<Candidate> {
        let mut out = Vec::new();
        for (name, service) in self.services {
            for (server_name, server) in &service.servers {
                out.push(Candidate {
                    provider,
                    id: format!("{name}/{server_name}"),
                    display_name: name.clone(),
                    labels: with_server_port(&service.labels, server.port),
                    networks: vec![NetworkInfo {
                        name: provider.to_string(),
                        ip: Some(server.ip.to_string()),
                    }],
                    enabled_default: expose_by_default,
                    health: None,
                });
            }
        }
        out
    }
}

/// Reads the keys under `prefix` as services.
fn parse_tree(prefix: &str, kvs: &BTreeMap<String, String>) -> Tree {
    let mut tree = Tree::default();
    for (key, value) in kvs {
        let Some(rest) = key.strip_prefix(prefix) else {
            continue;
        };
        let mut parts = rest.splitn(3, '/');
        let (Some(service), Some(kind), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            tree.ignored.insert(
                key.clone(),
                format!("expected `{prefix}<service>/labels/<label>` or `{prefix}<service>/servers/<name>`"),
            );
            continue;
        };
        if service.is_empty() || name.is_empty() || name.contains('/') {
            tree.ignored.insert(
                key.clone(),
                "the service and the label or server name must be non-empty, without `/`"
                    .to_string(),
            );
            continue;
        }
        match kind {
            "labels" => {
                tree.services
                    .entry(service.to_string())
                    .or_default()
                    .labels
                    .insert(name.to_string(), value.trim().to_string());
            }
            "servers" => match parse_server(value) {
                Ok(server) => {
                    tree.services
                        .entry(service.to_string())
                        .or_default()
                        .servers
                        .insert(name.to_string(), server);
                }
                Err(reason) => {
                    tree.ignored.insert(key.clone(), reason);
                }
            },
            other => {
                tree.ignored.insert(
                    key.clone(),
                    format!("unknown `{other}`, expected `labels` or `servers`"),
                );
            }
        }
    }
    for (name, service) in &tree.services {
        if service.servers.is_empty() {
            tree.ignored.insert(
                format!("{prefix}{name}/"),
                "the service has no server, so nothing to route to".to_string(),
            );
        }
    }
    tree
}

/// `ip`, `ip:port`, `ipv6` or `[ipv6]:port`. A hostname is refused: the
/// backend of a route is an address.
fn parse_server(value: &str) -> Result<Server, String> {
    let value = value.trim();
    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err(format!("`{value}`: the port must be between 1 and 65535"));
        }
        return Ok(Server {
            ip: addr.ip(),
            port: Some(addr.port()),
        });
    }
    let bare = value.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(Server { ip, port: None });
    }
    Err(format!(
        "`{value}` is not an IP address with an optional port (a hostname is not resolved)"
    ))
}

/// The labels, with `port` as the backend port of every service that sets
/// none. Explicit ports win.
fn with_server_port(
    labels: &HashMap<String, String>,
    port: Option<u16>,
) -> HashMap<String, String> {
    let mut labels = labels.clone();
    let Some(port) = port else {
        return labels;
    };
    let services: BTreeSet<String> = labels
        .keys()
        .filter_map(|key| {
            let mut parts = key.splitn(4, '.');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("sozune"), Some(proto), Some(svc), Some(_)) if PROTOCOLS.contains(&proto) => {
                    Some(format!("sozune.{proto}.{svc}"))
                }
                _ => None,
            }
        })
        .collect();
    for service in services {
        labels
            .entry(format!("{service}.port"))
            .or_insert_with(|| port.to_string());
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kvs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    struct Fixed(BTreeMap<String, String>);

    #[async_trait]
    impl KvStore for Fixed {
        async fn list(&self, prefix: &str) -> anyhow::Result<BTreeMap<String, String>> {
            Ok(self
                .0
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    #[test]
    fn a_service_gets_one_candidate_per_server() {
        let tree = parse_tree(
            "sozune/",
            &kvs(&[
                ("sozune/web/labels/sozune.http.web.host", "app.example.com"),
                ("sozune/web/servers/a", "10.0.0.5:8080"),
                ("sozune/web/servers/b", "10.0.0.6:8080"),
            ]),
        );
        assert!(tree.ignored.is_empty(), "{:?}", tree.ignored);
        let candidates = tree.candidates("etcd", true);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].id, "web/a");
        assert_eq!(candidates[0].display_name, "web");
        assert_eq!(candidates[0].networks[0].ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            candidates[1]
                .labels
                .get("sozune.http.web.host")
                .map(String::as_str),
            Some("app.example.com")
        );
        assert!(candidates[0].enabled_default);
    }

    #[test]
    fn the_server_port_fills_the_ports_the_labels_leave_unset() {
        let labels = HashMap::from([
            (
                "sozune.http.web.host".to_string(),
                "a.example.com".to_string(),
            ),
            (
                "sozune.http.api.host".to_string(),
                "b.example.com".to_string(),
            ),
            ("sozune.http.api.port".to_string(), "9000".to_string()),
            ("sozune.tcp.db.listener".to_string(), "pg".to_string()),
            ("sozune.middlewares".to_string(), "x".to_string()),
        ]);
        let out = with_server_port(&labels, Some(8080));
        assert_eq!(out["sozune.http.web.port"], "8080");
        assert_eq!(out["sozune.http.api.port"], "9000", "an explicit port wins");
        assert_eq!(out["sozune.tcp.db.port"], "8080");
        assert!(!out.keys().any(|k| k.starts_with("sozune.middlewares.")));
        assert_eq!(with_server_port(&labels, None), labels);
    }

    #[test]
    fn servers_take_ipv4_ipv6_with_or_without_a_port() {
        let cases = [
            ("10.0.0.5", "10.0.0.5", None),
            ("10.0.0.5:80", "10.0.0.5", Some(80)),
            ("::1", "::1", None),
            ("[::1]", "::1", None),
            ("[fd00::2]:8443", "fd00::2", Some(8443)),
            (" 10.0.0.5:80\n", "10.0.0.5", Some(80)),
        ];
        for (value, ip, port) in cases {
            let server = parse_server(value).unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(server.ip.to_string(), ip, "{value}");
            assert_eq!(server.port, port, "{value}");
        }
    }

    #[test]
    fn a_hostname_or_a_zero_port_is_refused() {
        assert!(
            parse_server("backend.internal:80")
                .unwrap_err()
                .contains("hostname")
        );
        assert!(parse_server("10.0.0.5:0").unwrap_err().contains("port"));
        assert!(parse_server("").is_err());
    }

    #[test]
    fn keys_outside_the_layout_are_reported() {
        let tree = parse_tree(
            "sozune/",
            &kvs(&[
                ("sozune/web", "x"),
                ("sozune/web/hosts/a", "x"),
                ("sozune/web/servers/a/b", "10.0.0.5"),
                ("sozune/web/servers/c", "db.internal"),
                ("sozune/lonely/labels/sozune.http.l.host", "l.example.com"),
                ("sozune/web/servers/ok", "10.0.0.5"),
            ]),
        );
        let ignored: Vec<&str> = tree.ignored.keys().map(String::as_str).collect();
        assert_eq!(
            ignored,
            [
                "sozune/lonely/",
                "sozune/web",
                "sozune/web/hosts/a",
                "sozune/web/servers/a/b",
                "sozune/web/servers/c",
            ]
        );
        assert_eq!(tree.services["web"].servers.len(), 1);
    }

    #[test]
    fn the_root_prefix_is_matched_whole() {
        let tree = parse_tree(
            "sozune/",
            &kvs(&[("sozune-other/web/servers/a", "10.0.0.5")]),
        );
        assert!(tree.services.is_empty());
        assert!(tree.ignored.is_empty());
    }

    #[tokio::test]
    async fn the_servers_of_a_service_become_the_backends_of_its_route() {
        let store = Fixed(kvs(&[
            ("sozune/web/labels/sozune.http.web.host", "app.example.com"),
            ("sozune/web/servers/a", "10.0.0.5:8080"),
            ("sozune/web/servers/b", "10.0.0.6:8081"),
            ("other/web/servers/c", "10.0.0.7:8080"),
        ]));
        let provider = KvProvider::new(crate::provider::ETCD, store, "sozune/", 5, true);
        let entrypoints = provider
            .provide_into(&diagnostics::new_store())
            .await
            .unwrap();
        assert_eq!(entrypoints.len(), 1, "{entrypoints:?}");
        let entrypoint = entrypoints.values().next().unwrap();
        assert_eq!(entrypoint.source.as_deref(), Some(crate::provider::ETCD));
        assert_eq!(entrypoint.config.hostnames, ["app.example.com"]);
        let mut addresses: Vec<String> = entrypoint
            .backends
            .iter()
            .map(|b| format!("{}:{}", b.address, b.port))
            .collect();
        addresses.sort();
        assert_eq!(addresses, ["10.0.0.5:8080", "10.0.0.6:8081"]);
    }

    #[tokio::test]
    async fn without_expose_by_default_a_service_needs_sozune_enable() {
        let store = Fixed(kvs(&[
            ("sozune/web/labels/sozune.http.web.host", "app.example.com"),
            ("sozune/web/servers/a", "10.0.0.5:8080"),
            ("sozune/api/labels/sozune.enable", "true"),
            ("sozune/api/labels/sozune.http.api.host", "api.example.com"),
            ("sozune/api/servers/a", "10.0.0.6:8080"),
        ]));
        let provider = KvProvider::new(crate::provider::REDIS, store, "sozune", 5, false);
        let entrypoints = provider
            .provide_into(&diagnostics::new_store())
            .await
            .unwrap();
        let hosts: Vec<&str> = entrypoints
            .values()
            .flat_map(|e| e.config.hostnames.iter().map(String::as_str))
            .collect();
        assert_eq!(hosts, ["api.example.com"]);
    }

    #[tokio::test]
    async fn a_poll_replaces_the_routes_of_the_store_only() {
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> = Arc::default();
        let (tx, mut rx) = mpsc::channel(4);
        let notify = Arc::new(Notify::new());
        let diag = diagnostics::new_store();
        let docker_tree = parse_tree(
            "sozune/",
            &kvs(&[
                ("sozune/d/labels/sozune.http.d.host", "d.example.com"),
                ("sozune/d/servers/a", "10.0.0.9:80"),
            ]),
        );
        let other = entrypoints_of(
            crate::provider::DOCKER,
            docker_tree.candidates(crate::provider::DOCKER, true),
            &diag,
        )
        .into_values()
        .next()
        .unwrap();
        storage
            .write()
            .unwrap()
            .insert("docker-route".into(), other);

        let store = Fixed(kvs(&[
            ("sozune/web/labels/sozune.http.web.host", "app.example.com"),
            ("sozune/web/servers/a", "10.0.0.5:8080"),
        ]));
        let provider = KvProvider::new(crate::provider::ETCD, store, "sozune", 5, true);
        provider.poll_once(&storage, &tx, &notify, &diag).await;
        assert!(rx.try_recv().is_ok(), "a new route reloads");
        assert_eq!(storage.read().unwrap().len(), 2);

        provider.poll_once(&storage, &tx, &notify, &diag).await;
        assert!(rx.try_recv().is_err(), "an unchanged tree does not reload");
        assert!(storage.read().unwrap().contains_key("docker-route"));
    }
}
