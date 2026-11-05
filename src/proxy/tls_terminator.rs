//! TLS termination for TCP routes routed by SNI (`terminate_tls`).
//!
//! Sōzu's TCP workers never decrypt: they read the SNI of a `ClientHello` and
//! splice the bytes to a backend. A TCP route that terminates TLS (Gateway
//! API's TLSRoute on a listener in `Terminate` mode) is therefore routed by
//! the worker, on its SNI, to a terminator of its own on loopback. The
//! terminator completes the handshake with the certificate the HTTPS worker
//! holds for the name, and splices the plaintext to one of the route's
//! backends, picked by weight. The worker sees the terminator as the route's
//! only backend, so its backends changing never touches the worker.
//!
//! Routes in both modes can share a listener: the worker sends each name to
//! its own route, terminated or not.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::model::{Backend, Entrypoint, Protocol};

/// How long a client has to complete its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for a backend to accept the connection before trying
/// the next one.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A certificate the terminators can present: the names it covers and its
/// chain and key, as PEM.
pub struct TerminatorCertificate<'a> {
    pub names: &'a [String],
    pub cert_pem: &'a str,
    pub chain: &'a [String],
    pub key_pem: &'a str,
}

/// A certificate the terminators present for one name: when it expires, as
/// a Unix timestamp, and its key.
type NamedCertificate = (String, i64, Arc<CertifiedKey>);

/// The certificates the terminators present, picked by SNI.
#[derive(Debug, Default)]
struct SniCertificates {
    by_name: RwLock<Vec<NamedCertificate>>,
}

impl SniCertificates {
    /// The certificate for `sni`: one naming it exactly, or else a wildcard
    /// covering it; among several, the one expiring last, which a renewal
    /// brings while the one it replaces is still held.
    fn lookup(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let sni = sni.to_ascii_lowercase();
        let by_name = self.by_name.read().ok()?;
        let latest = |matching: &dyn Fn(&str) -> bool| {
            by_name
                .iter()
                .filter(|(name, _, _)| matching(name))
                .max_by_key(|(_, not_after, _)| *not_after)
                .map(|(_, _, key)| Arc::clone(key))
        };
        latest(&|name| name == sni)
            .or_else(|| latest(&|name| crate::manual_certs::covers(name, &sni)))
    }
}

impl ResolvesServerCert for SniCertificates {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name()?)
    }
}

/// Parse a certificate for the terminators.
fn certified_key(cert: &TerminatorCertificate<'_>) -> anyhow::Result<CertifiedKey> {
    let mut chain = CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("cannot parse the certificate: {e}"))?;
    for pem in cert.chain {
        chain.extend(
            CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("cannot parse the chain: {e}"))?,
        );
    }
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot parse the private key: {e}"))?;
    CertifiedKey::from_der(chain, key, &rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|e| anyhow::anyhow!("the private key does not match the certificate: {e}"))
}

/// The backends one terminator splices to, and where it starts picking.
/// Its connections follow the list: one to a backend that leaves it is
/// closed, as Sōzu closes those of the routes it serves itself.
struct Backends {
    list: watch::Sender<Vec<Backend>>,
    next: AtomicUsize,
}

impl Default for Backends {
    fn default() -> Self {
        Self {
            list: watch::channel(Vec::new()).0,
            next: AtomicUsize::new(0),
        }
    }
}

impl Backends {
    /// The backends to try for one connection, in order: by weight among
    /// those of a positive weight, starting from the next turn, then those
    /// of weight 0, which serve only when no other can.
    fn order(&self) -> Vec<Backend> {
        let list = self.list.borrow();
        let (primary, backup): (Vec<&Backend>, Vec<&Backend>) =
            list.iter().partition(|b| b.weight > 0);
        let mut ordered: Vec<Backend> = Vec::with_capacity(list.len());
        let total: u64 = primary.iter().map(|b| u64::from(b.weight)).sum();
        if total > 0 {
            let turn = (self.next.fetch_add(1, Ordering::Relaxed) as u64) % total;
            let mut acc = 0;
            let start = primary
                .iter()
                .position(|b| {
                    acc += u64::from(b.weight);
                    turn < acc
                })
                .unwrap_or(0);
            ordered.extend(
                primary[start..]
                    .iter()
                    .chain(&primary[..start])
                    .map(|b| (*b).clone()),
            );
        }
        ordered.extend(backup.into_iter().cloned());
        ordered
    }
}

/// One route's terminator: its loopback port and the task accepting there.
struct Terminator {
    port: u16,
    backends: Arc<Backends>,
    task: JoinHandle<()>,
}

impl Drop for Terminator {
    /// Its connections are closed with it.
    fn drop(&mut self) {
        self.backends.list.send_replace(Vec::new());
        self.task.abort();
    }
}

/// The terminators of the routes that terminate TLS, by route id.
pub struct Terminators {
    certificates: Arc<SniCertificates>,
    acceptor: Option<TlsAcceptor>,
    running: HashMap<String, Terminator>,
}

impl Default for Terminators {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminators {
    pub fn new() -> Self {
        let certificates = Arc::new(SniCertificates::default());
        // Named explicitly: the dependency tree carries two crypto
        // providers, so `ServerConfig::builder()` cannot infer one.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let acceptor = match ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(builder) => Some(TlsAcceptor::from(Arc::new(
                builder
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::clone(&certificates) as Arc<dyn ResolvesServerCert>),
            ))),
            Err(e) => {
                error!("TLS termination for TCP routes is unavailable: {e}");
                None
            }
        };
        Self {
            certificates,
            acceptor,
            running: HashMap::new(),
        }
    }

    /// Present these certificates from now on, in place of the previous
    /// ones. One that cannot be parsed is left out.
    pub fn set_certificates<'a>(
        &self,
        certificates: impl Iterator<Item = TerminatorCertificate<'a>>,
    ) {
        let mut by_name = Vec::new();
        for cert in certificates {
            match certified_key(&cert) {
                Ok(key) => {
                    let key = Arc::new(key);
                    let not_after = cheti::cert_lifetime(cert.cert_pem)
                        .map(|life| life.not_after)
                        .unwrap_or(i64::MIN);
                    for name in cert.names {
                        by_name.push((name.to_ascii_lowercase(), not_after, Arc::clone(&key)));
                    }
                }
                Err(e) => warn!(
                    "TLS termination: certificate for {} left out: {e}",
                    cert.names.join(", ")
                ),
            }
        }
        match self.certificates.by_name.write() {
            Ok(mut current) => *current = by_name,
            Err(e) => error!("TLS termination: certificate store poisoned: {e}"),
        }
    }

    /// `storage` with the routes that terminate TLS sent to their
    /// terminator, which forwards to their backends; the terminators of
    /// routes gone are stopped. A route whose terminator cannot start is
    /// left out, and tried again on the next reload.
    pub fn route_through(
        &mut self,
        storage: &BTreeMap<String, Entrypoint>,
    ) -> BTreeMap<String, Entrypoint> {
        let terminated: Vec<&String> = storage
            .iter()
            .filter(|(_, ep)| terminates(ep))
            .map(|(id, _)| id)
            .collect();
        self.running.retain(|id, _| terminated.contains(&id));
        let mut out = BTreeMap::new();
        for (id, ep) in storage {
            if !terminates(ep) {
                out.insert(id.clone(), ep.clone());
                continue;
            }
            let Some(terminator) = self.terminator(id) else {
                continue;
            };
            terminator.backends.list.send_replace(ep.backends.clone());
            let mut routed = ep.clone();
            routed.backends = vec![Backend::new(
                Ipv4Addr::LOCALHOST.to_string(),
                terminator.port,
            )];
            out.insert(id.clone(), routed);
        }
        out
    }

    /// `routes`, as [`Self::route_through`] gave them to the workers, with
    /// the routes that terminate TLS showing the backends their terminator
    /// forwards to rather than the terminator itself.
    pub fn as_served(&self, routes: &BTreeMap<String, Entrypoint>) -> BTreeMap<String, Entrypoint> {
        routes
            .iter()
            .map(|(id, ep)| {
                let mut ep = ep.clone();
                if let Some(t) = self.running.get(id).filter(|_| terminates(&ep)) {
                    ep.backends = t.backends.list.borrow().clone();
                }
                (id.clone(), ep)
            })
            .collect()
    }

    /// The terminator of route `id`, started if it is not yet.
    fn terminator(&mut self, id: &str) -> Option<&Terminator> {
        if !self.running.contains_key(id) {
            let acceptor = self.acceptor.clone()?;
            let listener = match bind_loopback() {
                Ok(l) => l,
                Err(e) => {
                    error!("TLS termination: cannot start the terminator of `{id}`: {e}");
                    return None;
                }
            };
            let port = listener.local_addr().ok()?.port();
            let backends = Arc::new(Backends::default());
            let task = tokio::spawn(serve(
                id.to_string(),
                listener,
                acceptor,
                Arc::clone(&backends),
            ));
            debug!("TLS termination: terminator of `{id}` on 127.0.0.1:{port}");
            self.running.insert(
                id.to_string(),
                Terminator {
                    port,
                    backends,
                    task,
                },
            );
        }
        self.running.get(id)
    }

    #[cfg(test)]
    fn running_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.running.keys().cloned().collect();
        ids.sort();
        ids
    }
}

/// Whether `ep` is a TCP route terminating TLS.
fn terminates(ep: &Entrypoint) -> bool {
    ep.protocol == Protocol::Tcp && ep.config.terminate_tls && ep.config.sni.is_some()
}

/// A loopback listener on a free port, bound before the worker is told
/// about it: no other process can take the port in between.
fn bind_loopback() -> anyhow::Result<TcpListener> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

/// Accept the connections the worker sends to route `id`, terminate their
/// TLS and splice them to its backends.
async fn serve(id: String, listener: TcpListener, acceptor: TlsAcceptor, backends: Arc<Backends>) {
    info!("TLS termination: serving route `{id}`");
    loop {
        let (inbound, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TLS termination: `{id}` accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let backends = Arc::clone(&backends);
        let id = id.clone();
        tokio::spawn(async move {
            let mut tls =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(inbound)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => {
                        debug!("TLS termination: `{id}` handshake failed: {e}");
                        return;
                    }
                    Err(_) => {
                        debug!("TLS termination: `{id}` handshake timed out");
                        return;
                    }
                };
            // Before the backend is picked: a change meanwhile is seen.
            let mut list = backends.list.subscribe();
            let Some((mut outbound, backend)) = connect(&backends.order()).await else {
                warn!("TLS termination: `{id}` has no backend to reach");
                return;
            };
            tokio::select! {
                copied = copy_bidirectional(&mut tls, &mut outbound) => {
                    if let Err(e) = copied {
                        debug!("TLS termination: `{id}` connection closed: {e}");
                    }
                }
                () = departed(&mut list, &backend) => debug!(
                    "TLS termination: `{id}` closes a connection to {}:{}, out of the route",
                    backend.address, backend.port
                ),
            }
        });
    }
}

/// Resolves once `backend` is no longer in the list.
async fn departed(list: &mut watch::Receiver<Vec<Backend>>, backend: &Backend) {
    loop {
        if !list
            .borrow_and_update()
            .iter()
            .any(|b| b.address == backend.address && b.port == backend.port)
        {
            return;
        }
        if list.changed().await.is_err() {
            return;
        }
    }
}

/// A connection to the first of `backends` that accepts one, and that one.
async fn connect(backends: &[Backend]) -> Option<(TcpStream, Backend)> {
    for backend in backends {
        let address = (backend.address.as_str(), backend.port);
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Some((stream, backend.clone())),
            Ok(Err(e)) => debug!(
                "TLS termination: backend {}:{} refused: {e}",
                backend.address, backend.port
            ),
            Err(_) => debug!(
                "TLS termination: backend {}:{} timed out",
                backend.address, backend.port
            ),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntrypointConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn terminated(sni: &str, backends: Vec<Backend>) -> Entrypoint {
        Entrypoint {
            id: format!("tls/{sni}"),
            name: sni.to_string(),
            backends,
            protocol: Protocol::Tcp,
            config: EntrypointConfig {
                sni: Some(sni.to_string()),
                terminate_tls: true,
                entrypoint: Some("tls".to_string()),
                ..Default::default()
            },
            source: None,
            candidates: Vec::new(),
        }
    }

    fn self_signed(name: &str) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    #[test]
    fn backends_are_tried_by_weight_then_backups() {
        let backends = Backends::default();
        backends.list.send_replace(vec![
            Backend::new("a", 1).with_weight(1),
            Backend::new("spare", 1).with_weight(0),
            Backend::new("b", 1).with_weight(3),
        ]);
        let firsts: Vec<String> = (0..4)
            .map(|_| backends.order()[0].address.clone())
            .collect();
        assert_eq!(firsts, ["a", "b", "b", "b"]);
        let order: Vec<String> = backends.order().into_iter().map(|b| b.address).collect();
        assert_eq!(order, ["a", "b", "spare"]);
    }

    #[test]
    fn a_wildcard_certificate_covers_one_label() {
        let terminators = Terminators::new();
        let (cert, key) = self_signed("*.example.com");
        let names = vec!["*.example.com".to_string()];
        terminators.set_certificates(std::iter::once(TerminatorCertificate {
            names: &names,
            cert_pem: &cert,
            chain: &[],
            key_pem: &key,
        }));
        assert!(terminators.certificates.lookup("tls.example.com").is_some());
        assert!(terminators.certificates.lookup("TLS.Example.com").is_some());
        assert!(terminators.certificates.lookup("a.b.example.com").is_none());
        assert!(terminators.certificates.lookup("example.com").is_none());
    }

    #[tokio::test]
    async fn routes_terminating_tls_go_through_their_terminator() {
        let mut terminators = Terminators::new();
        let mut storage = BTreeMap::new();
        let ep = terminated("tls.example.com", vec![Backend::new("10.0.0.1", 3000)]);
        let mut passthrough = terminated("abc.example.com", vec![Backend::new("10.0.0.2", 8443)]);
        passthrough.config.terminate_tls = false;
        storage.insert(ep.id.clone(), ep.clone());
        storage.insert(passthrough.id.clone(), passthrough.clone());

        let routed = terminators.route_through(&storage);
        let through = &routed[&ep.id].backends;
        assert_eq!(through.len(), 1);
        assert_eq!(through[0].address, "127.0.0.1");
        assert_eq!(routed[&passthrough.id], passthrough);
        // Shown with the backends the terminator forwards to.
        assert_eq!(terminators.as_served(&routed), storage);
        assert_eq!(terminators.running_ids(), std::slice::from_ref(&ep.id));

        // Same port across reloads, whatever the backends do.
        let mut moved = ep.clone();
        moved.backends = vec![Backend::new("10.0.0.9", 3000)];
        storage.insert(ep.id.clone(), moved);
        assert_eq!(
            terminators.route_through(&storage)[&ep.id].backends,
            *through
        );

        storage.remove(&ep.id);
        terminators.route_through(&storage);
        assert!(terminators.running_ids().is_empty());
    }

    #[tokio::test]
    async fn a_terminator_hands_the_plaintext_to_a_backend() {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            // Held open: only the terminator closes it.
            let _ = s.read(&mut buf).await;
        });

        let mut terminators = Terminators::new();
        let (cert, key) = self_signed("tls.example.com");
        let names = vec!["tls.example.com".to_string()];
        terminators.set_certificates(std::iter::once(TerminatorCertificate {
            names: &names,
            cert_pem: &cert,
            chain: &[],
            key_pem: &key,
        }));
        let ep = terminated(
            "tls.example.com",
            vec![Backend::new("127.0.0.1", backend_port)],
        );
        let mut storage = BTreeMap::from([(ep.id.clone(), ep.clone())]);
        let port = terminators.route_through(&storage)[&ep.id].backends[0].port;

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(cert.as_bytes()).unwrap())
            .unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut tls = connector
            .connect("tls.example.com".try_into().unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        // The backend leaves the route: its connection is closed.
        let mut gone = ep.clone();
        gone.backends.clear();
        storage.insert(ep.id.clone(), gone);
        terminators.route_through(&storage);
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "the connection stayed open");
    }

    #[test]
    fn the_certificate_expiring_last_wins() {
        let terminators = Terminators::new();
        let make = |days: i64| {
            let mut params =
                rcgen::CertificateParams::new(vec!["tls.example.com".to_string()]).unwrap();
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
            let key = rcgen::KeyPair::generate().unwrap();
            (params.self_signed(&key).unwrap(), key)
        };
        let (old, old_key) = make(10);
        let (new, new_key) = make(90);
        let names = vec!["tls.example.com".to_string()];
        let (old_pem, old_key_pem) = (old.pem(), old_key.serialize_pem());
        let (new_pem, new_key_pem) = (new.pem(), new_key.serialize_pem());
        // Whatever their order.
        terminators.set_certificates(
            [
                TerminatorCertificate {
                    names: &names,
                    cert_pem: &new_pem,
                    chain: &[],
                    key_pem: &new_key_pem,
                },
                TerminatorCertificate {
                    names: &names,
                    cert_pem: &old_pem,
                    chain: &[],
                    key_pem: &old_key_pem,
                },
            ]
            .into_iter(),
        );
        let picked = terminators.certificates.lookup("tls.example.com").unwrap();
        assert_eq!(
            picked.end_entity_cert().unwrap().as_ref(),
            new.der().as_ref()
        );
    }
}
