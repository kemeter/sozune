//! TLS termination for Gateway `HTTPS` listeners.
//!
//! A listener's `tls.certificateRefs` name `kubernetes.io/tls` Secrets. This
//! module watches those Secrets, keeps what they hold in the
//! [`GatewayScope`], and hands the certificates the accepted Gateways
//! reference to the HTTPS worker, taking back those no Gateway references any
//! more. Sōzu picks the certificate by the SNI of each handshake, so routes
//! need no reference to them.

use super::gateway::GatewayScope;
use crate::acme::{CertAction, CertCommand, certificate_fingerprint, split_pem_chain};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// The certificate and key a TLS Secret holds, checked.
#[derive(Debug, PartialEq)]
pub struct SecretCertificate {
    /// DNS names the certificate covers.
    pub names: Vec<String>,
    pub cert_pem: String,
    pub chain: Vec<String>,
    pub key_pem: String,
    /// What Sōzu knows the certificate by.
    pub fingerprint: String,
    /// When the certificate expires, as a Unix timestamp.
    pub not_after: i64,
}

impl SecretCertificate {
    /// Have the HTTPS worker do `action` with this certificate. Answers
    /// whether it did, or `None` once the proxy is gone.
    async fn apply(&self, cert_tx: &mpsc::Sender<CertCommand>, action: CertAction) -> Option<bool> {
        let (accepted, answer) = oneshot::channel();
        let command = CertCommand {
            names: self.names.clone(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            chain: self.chain.clone(),
            accepted: Some(accepted),
            action,
        };
        cert_tx.send(command).await.ok()?;
        Some(answer.await.unwrap_or(false))
    }
}

/// Read and check the certificate of a TLS Secret: its `tls.crt` chain and
/// `tls.key`, the key matching the certificate, the certificate valid now.
pub fn certificate_from_secret(secret: &Secret) -> Result<SecretCertificate, String> {
    let field = |key: &str| -> Result<String, String> {
        let bytes = secret
            .data
            .as_ref()
            .and_then(|d| d.get(key))
            .ok_or_else(|| format!("it has no `{key}`"))?;
        String::from_utf8(bytes.0.clone()).map_err(|_| format!("its `{key}` is not PEM"))
    };
    let chain_pem = field("tls.crt")?;
    let key_pem = field("tls.key")?;
    let names = crate::manual_certs::check(&chain_pem, &key_pem).map_err(|e| format!("{e:#}"))?;
    let not_after = cheti::cert_lifetime(&chain_pem)
        .map_err(|e| format!("cannot parse the certificate: {e}"))?
        .not_after;
    let (cert_pem, chain) = split_pem_chain(&chain_pem);
    let fingerprint = certificate_fingerprint(&cert_pem).map_err(|e| format!("{e:#}"))?;
    Ok(SecretCertificate {
        names,
        cert_pem,
        chain,
        key_pem,
        fingerprint,
        not_after,
    })
}

/// How often the TLS Secrets are checked for a certificate that expired
/// since it was read, which no watch event announces.
const EXPIRY_CHECK: Duration = Duration::from_secs(60);

/// Watch the `kubernetes.io/tls` Secrets and keep the scope in sync with
/// them.
pub async fn run_tls_secret_watcher(client: Client, scope: GatewayScope) -> anyhow::Result<()> {
    let api: Api<Secret> = Api::all(client);
    let config = watcher::Config::default().fields("type=kubernetes.io/tls");
    // Backed off: without the RBAC to read Secrets, every attempt fails at
    // once, and the watcher would otherwise retry in a tight loop.
    let mut stream = watcher::watcher(api, config).default_backoff().boxed();
    info!("Gateway API: TLS Secret watcher started");

    // The Secrets a relist brings back: those it does not are gone.
    let mut relisted: HashSet<(String, String)> = HashSet::new();
    let mut expiry = tokio::time::interval(EXPIRY_CHECK);
    loop {
        let event = tokio::select! {
            event = stream.next() => match event {
                Some(event) => event,
                None => break,
            },
            _ = expiry.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default();
                scope.expire_tls_secrets(now);
                continue;
            }
        };
        match event {
            Ok(Event::Apply(secret)) | Ok(Event::InitApply(secret)) => {
                let Some(key) = secret_key(&secret) else {
                    continue;
                };
                relisted.insert(key.clone());
                let certificate = certificate_from_secret(&secret);
                if let Err(e) = &certificate {
                    debug!(
                        "Gateway API: TLS Secret {}/{} unusable: {}",
                        key.0, key.1, e
                    );
                }
                scope.upsert_tls_secret(key, certificate.map(Arc::new));
            }
            Ok(Event::Delete(secret)) => {
                if let Some(key) = secret_key(&secret) {
                    scope.remove_tls_secret(&key);
                }
            }
            Ok(Event::Init) => relisted.clear(),
            Ok(Event::InitDone) => scope.retain_tls_secrets(&relisted),
            Err(e) => error!("Gateway API: TLS Secret watcher error: {}", e),
        }
    }

    warn!("Gateway API: TLS Secret watcher stream ended unexpectedly");
    Ok(())
}

fn secret_key(secret: &Secret) -> Option<(String, String)> {
    Some((
        secret.metadata.namespace.clone()?,
        secret.metadata.name.clone()?,
    ))
}

/// How long a certificate the HTTPS worker refused waits before it is sent
/// again, when nothing else changes in between.
const RETRY_DELAY: Duration = Duration::from_secs(30);

/// Hand the HTTPS worker the certificates the accepted Gateways reference,
/// and take back those they no longer do, each time the scope changes.
///
/// `files` are the fingerprints of the certificates read from
/// `proxy.https.tls.certificates`: Sōzu holds one copy of a certificate,
/// whoever sent it, so one a Secret shares with a file is left to the file —
/// never replaced, never taken back.
pub async fn run_certificate_sync(
    scope: GatewayScope,
    cert_tx: mpsc::Sender<CertCommand>,
    files: HashSet<String>,
) {
    // What the HTTPS worker holds for the Gateways, as it confirmed.
    let mut installed: BTreeMap<String, Arc<SecretCertificate>> = BTreeMap::new();
    loop {
        let wanted: BTreeMap<String, Arc<SecretCertificate>> = scope
            .referenced_certificates()
            .into_iter()
            .filter(|c| !files.contains(&c.fingerprint))
            .map(|c| (c.fingerprint.clone(), c))
            .collect();
        let mut refused = false;

        for (fingerprint, certificate) in &wanted {
            let action = match installed.get(fingerprint) {
                Some(held) if held == certificate => continue,
                // The same leaf with another chain or key.
                Some(_) => CertAction::Replace,
                None => {
                    info!(
                        "Gateway API: serving the certificate for {}",
                        certificate.names.join(", ")
                    );
                    CertAction::Add
                }
            };
            match certificate.apply(&cert_tx, action).await {
                Some(true) => {
                    installed.insert(fingerprint.clone(), Arc::clone(certificate));
                }
                Some(false) => refused = true,
                None => return,
            }
        }

        let unwanted: Vec<String> = installed
            .keys()
            .filter(|fingerprint| !wanted.contains_key(*fingerprint))
            .cloned()
            .collect();
        for fingerprint in unwanted {
            let Some(certificate) = installed.get(&fingerprint) else {
                continue;
            };
            match certificate.apply(&cert_tx, CertAction::Remove).await {
                Some(true) => {
                    installed.remove(&fingerprint);
                }
                Some(false) => refused = true,
                None => return,
            }
        }

        // A refused command is sent again: on the next change, or after a
        // while if nothing changes.
        if refused {
            tokio::select! {
                _ = scope.certificates_changed() => {}
                _ = tokio::time::sleep(RETRY_DELAY) => {}
            }
        } else {
            scope.certificates_changed().await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use rcgen::{CertificateParams, KeyPair};

    /// A self-signed certificate for `names`, and its key, as PEM.
    pub(crate) fn self_signed(names: &[&str]) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// A TLS Secret holding `cert` and `key`.
    pub(crate) fn tls_secret(ns: &str, name: &str, cert: &str, key: &str) -> Secret {
        let mut secret = Secret::default();
        secret.metadata.namespace = Some(ns.into());
        secret.metadata.name = Some(name.into());
        secret.type_ = Some("kubernetes.io/tls".into());
        secret.data = Some(
            [
                ("tls.crt".to_string(), ByteString(cert.as_bytes().to_vec())),
                ("tls.key".to_string(), ByteString(key.as_bytes().to_vec())),
            ]
            .into(),
        );
        secret
    }

    #[test]
    fn a_tls_secret_gives_its_certificate() {
        let (cert, key) = self_signed(&["shop.example.com"]);
        let certificate =
            certificate_from_secret(&tls_secret("default", "shop", &cert, &key)).unwrap();
        assert_eq!(certificate.names, ["shop.example.com"]);
        assert!(certificate.chain.is_empty());
        // The fingerprint is the one Sōzu removes a certificate by.
        let sozu = sozu_command_lib::certificate::calculate_fingerprint(cert.as_bytes()).unwrap();
        let sozu: String = sozu.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(certificate.fingerprint, sozu);
    }

    #[test]
    fn an_unusable_tls_secret_says_why() {
        let (cert, _) = self_signed(&["shop.example.com"]);
        let (_, other_key) = self_signed(&["shop.example.com"]);
        let mismatched = certificate_from_secret(&tls_secret("default", "s", &cert, &other_key));
        assert!(mismatched.unwrap_err().contains("does not match"));

        let mut missing = tls_secret("default", "s", &cert, &other_key);
        missing.data.as_mut().unwrap().remove("tls.key");
        assert!(
            certificate_from_secret(&missing)
                .unwrap_err()
                .contains("tls.key")
        );
    }
}
