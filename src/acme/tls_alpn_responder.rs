//! Serves TLS-ALPN-01 challenge certificates on a loopback listener.
//!
//! When an ACME CA validates a TLS-ALPN-01 challenge it opens a TLS connection
//! offering only the `acme-tls/1` ALPN protocol and an SNI of the domain, and
//! expects the special challenge certificate cheti built. This responder
//! terminates that handshake: it accepts only `acme-tls/1`, looks up the
//! challenge certificate for the requested SNI, and presents it.
//!
//! It listens on loopback. Routing the CA's `acme-tls/1` connection on the
//! public 443 to this loopback port is the proxy's job (the SNI+ALPN preread on
//! the TCP listener) and lives elsewhere; here we only terminate and answer.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use cheti::{ACME_TLS_ALPN_NAME, ChallengeResponder, DnsError};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

/// Challenge certificates currently presented, keyed by lowercased SNI.
type ChallengeCerts = Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>;

/// Shared handle to the presented challenge certificates. The ACME manager
/// writes to it through [`ChallengeResponder`]; the loopback listener reads it
/// to answer handshakes. Cheap to clone.
#[derive(Clone, Default)]
pub struct TlsAlpnResponder {
    certs: ChallengeCerts,
}

impl TlsAlpnResponder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the `CertifiedKey` from the DER cheti produced. Kept separate so
    /// the error path is testable without ACME.
    fn build_certified_key(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<CertifiedKey, DnsError> {
        let cert = rustls::pki_types::CertificateDer::from(cert_der);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
            .map_err(|e| DnsError::Other(format!("challenge key is not usable: {e}")))?;
        Ok(CertifiedKey::new(vec![cert], signing_key))
    }
}

#[async_trait]
impl ChallengeResponder for TlsAlpnResponder {
    async fn present(
        &self,
        domain: &str,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<(), DnsError> {
        let certified = Self::build_certified_key(cert_der, key_der)?;
        let mut certs = self
            .certs
            .write()
            .map_err(|e| DnsError::Other(format!("challenge cert store poisoned: {e}")))?;
        certs.insert(domain.to_ascii_lowercase(), Arc::new(certified));
        debug!("TLS-ALPN-01 challenge certificate presented for {domain}");
        Ok(())
    }

    async fn cleanup(&self, domain: &str) -> Result<(), DnsError> {
        if let Ok(mut certs) = self.certs.write() {
            certs.remove(&domain.to_ascii_lowercase());
            debug!("TLS-ALPN-01 challenge certificate removed for {domain}");
        }
        Ok(())
    }
}

/// A rustls certificate resolver that only ever answers `acme-tls/1`
/// handshakes, and only for a domain that currently has a challenge
/// certificate presented. Every other handshake gets no certificate, so the
/// TLS layer aborts it — this listener is not meant to serve real traffic.
#[derive(Debug)]
struct ChallengeCertResolver {
    certs: ChallengeCerts,
}

impl ResolvesServerCert for ChallengeCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // The responder is single-purpose: it must only ever answer the ACME
        // challenge protocol. rustls only offers a protocol it was configured
        // with, but guard anyway so a stray connection can't be served.
        let is_acme = client_hello
            .alpn()
            .map(|mut it| it.any(|p| p == ACME_TLS_ALPN_NAME))
            .unwrap_or(false);
        if !is_acme {
            return None;
        }
        let sni = client_hello.server_name()?.to_ascii_lowercase();
        self.certs.read().ok()?.get(&sni).cloned()
    }
}

/// Bind the loopback responder on `port` and serve `acme-tls/1` challenge
/// handshakes from `responder`'s store until the process exits.
pub async fn serve(port: u16, responder: TlsAlpnResponder) -> anyhow::Result<()> {
    let resolver = Arc::new(ChallengeCertResolver {
        certs: responder.certs.clone(),
    });
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Advertise only `acme-tls/1`: the CA offers exactly that, and a normal
    // client offering h2/http1.1 finds no overlap and is turned away.
    config.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    info!("TLS-ALPN-01 responder listening on 127.0.0.1:{port}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TLS-ALPN-01 responder accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // The handshake is the whole exchange: the CA inspects the
            // presented certificate and closes. No application data flows, so
            // completing (or failing) the accept is all there is to do.
            if let Err(e) = acceptor.accept(stream).await {
                debug!("TLS-ALPN-01 handshake did not complete: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheti::build_challenge_certificate;

    /// A real RFC 8737 challenge cert/key pair from cheti, for exercising the
    /// responder's DER handling.
    fn challenge_der(domain: &str) -> (Vec<u8>, Vec<u8>) {
        let cert = build_challenge_certificate(domain, &[0x11; 32]).unwrap();
        (cert.cert_der, cert.key_der)
    }

    #[test]
    fn build_certified_key_accepts_a_real_challenge_pair() {
        let (cert_der, key_der) = challenge_der("example.com");
        assert!(TlsAlpnResponder::build_certified_key(cert_der, key_der).is_ok());
    }

    #[test]
    fn build_certified_key_rejects_a_bogus_key() {
        let (cert_der, _) = challenge_der("example.com");
        let err = TlsAlpnResponder::build_certified_key(cert_der, vec![0, 1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("not usable"));
    }

    #[tokio::test]
    async fn present_then_cleanup_round_trips_through_the_store() {
        let responder = TlsAlpnResponder::new();
        let (cert_der, key_der) = challenge_der("app.example.com");

        responder
            .present("App.Example.COM", cert_der, key_der)
            .await
            .unwrap();
        // Stored lowercased, the form the resolver looks up by.
        assert!(
            responder
                .certs
                .read()
                .unwrap()
                .contains_key("app.example.com")
        );

        responder.cleanup("app.example.com").await.unwrap();
        assert!(responder.certs.read().unwrap().is_empty());
    }
}
