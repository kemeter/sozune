pub mod challenge_server;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::AcmeConfig;
use crate::model::Entrypoint;

use self::challenge_server::ChallengeState;

/// Command sent from ACME manager to the proxy reload handler
pub struct CertCommand {
    pub hostname: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub chain: Vec<String>,
}

pub struct AcmeManager {
    config: AcmeConfig,
    challenges: ChallengeState,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    cert_tx: mpsc::UnboundedSender<CertCommand>,
    certs_dir: PathBuf,
}

impl AcmeManager {
    pub fn new(
        config: AcmeConfig,
        challenges: ChallengeState,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        cert_tx: mpsc::UnboundedSender<CertCommand>,
    ) -> Self {
        let certs_dir = PathBuf::from(&config.certs_dir);
        Self {
            config,
            challenges,
            storage,
            cert_tx,
            certs_dir,
        }
    }

    /// Main entry point: load existing certs, provision missing ones, then renewal loop
    pub async fn run(&self) -> anyhow::Result<()> {
        // Load existing certificates from disk
        self.load_existing_certs().await;

        // Initial provisioning
        if let Err(e) = self.provision_all().await {
            error!("Initial ACME provisioning failed: {}", e);
        }

        // Renewal loop: check every 12 hours
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
        loop {
            interval.tick().await;
            info!("Running ACME renewal check");
            if let Err(e) = self.provision_all().await {
                error!("ACME renewal check failed: {}", e);
            }
        }
    }

    /// Scan storage for entrypoints with tls: true and provision certificates
    async fn provision_all(&self) -> anyhow::Result<()> {
        let hostnames = self.collect_tls_hostnames();
        if hostnames.is_empty() {
            debug!("No TLS-enabled hostnames found, skipping ACME provisioning");
            return Ok(());
        }

        info!("Found {} TLS-enabled hostname(s) to check", hostnames.len());

        for hostname in &hostnames {
            match self.needs_certificate(hostname).await {
                true => {
                    info!("Requesting certificate for {}", hostname);
                    if let Err(e) = self.provision_certificate(hostname).await {
                        error!("Failed to provision certificate for {}: {}", hostname, e);
                    }
                }
                false => {
                    debug!("Certificate for {} is still valid, skipping", hostname);
                }
            }
        }

        Ok(())
    }

    /// Collect all unique hostnames with tls: true from storage
    fn collect_tls_hostnames(&self) -> Vec<String> {
        let storage = match self.storage.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Storage lock poisoned: {}", e);
                return Vec::new();
            }
        };

        let mut hostnames = Vec::new();
        for entrypoint in storage.values() {
            if entrypoint.config.tls {
                for hostname in &entrypoint.config.hostnames {
                    if !hostnames.contains(hostname) {
                        hostnames.push(hostname.clone());
                    }
                }
            }
        }
        hostnames
    }

    /// Check if a hostname needs a new certificate (missing or expiring within 30 days)
    async fn needs_certificate(&self, hostname: &str) -> bool {
        let cert_path = self.certs_dir.join(hostname).join("cert.pem");
        if !cert_path.exists() {
            return true;
        }

        // Read and parse existing cert to check expiration
        match tokio::fs::read_to_string(&cert_path).await {
            Ok(pem_data) => is_cert_expiring_soon(&pem_data, 30),
            Err(_) => true,
        }
    }

    /// Full ACME HTTP-01 flow for a single hostname
    async fn provision_certificate(&self, hostname: &str) -> anyhow::Result<()> {
        let server_url = if self.config.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        // Create or load ACME account
        let (account, _credentials) = self.get_or_create_account(server_url).await?;

        // Create order
        let identifiers = vec![Identifier::Dns(hostname.to_string())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        // Process authorizations and collect challenge tokens for cleanup
        let mut challenge_tokens: Vec<String> = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut auth_handle = result?;
            let mut challenge = auth_handle
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found"))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();

            // Store token → key_authorization in shared challenge state
            {
                let mut challenges = self
                    .challenges
                    .write()
                    .map_err(|e| anyhow::anyhow!("Challenge state lock poisoned: {}", e))?;
                challenges.insert(token.clone(), key_auth.as_str().to_string());
            }

            debug!("Challenge token stored: {} (type: HTTP-01)", token);
            challenge_tokens.push(token);

            // Tell ACME server we're ready
            challenge.set_ready().await?;
        }
        // Drop authorizations borrow so we can use order again
        drop(authorizations);

        // Wait for order to become ready
        let ready_result = Self::poll_order_ready(&mut order).await;

        // Clean up challenge tokens regardless of outcome
        self.cleanup_challenge_tokens(&challenge_tokens);

        ready_result?;
        info!("Order for {} is ready", hostname);

        // Generate key pair and CSR
        let key_pair = KeyPair::generate()?;
        let params = CertificateParams::new(vec![hostname.to_string()])?;
        let csr = params.serialize_request(&key_pair)?;

        // Finalize order with CSR
        order.finalize_csr(csr.der()).await?;

        // Poll for certificate
        let cert_chain_pem = Self::poll_certificate(&mut order).await?;

        // Save to disk
        let key_pem = key_pair.serialize_pem();
        self.save_certificate(hostname, &cert_chain_pem, &key_pem)
            .await?;

        // Parse chain and send to Sozu
        let (cert_pem, chain) = split_pem_chain(&cert_chain_pem);
        self.cert_tx.send(CertCommand {
            hostname: hostname.to_string(),
            cert_pem,
            key_pem,
            chain,
        })?;

        info!("Certificate for {} provisioned successfully", hostname);
        Ok(())
    }

    /// Get or create an ACME account
    async fn get_or_create_account(
        &self,
        server_url: &str,
    ) -> anyhow::Result<(Account, AccountCredentials)> {
        let creds_path = self.certs_dir.join("account_credentials.json");

        // Try to load existing credentials
        if creds_path.exists() {
            match tokio::fs::read_to_string(&creds_path).await {
                Ok(data) => {
                    match serde_json::from_str::<AccountCredentials>(&data) {
                        Ok(credentials) => {
                            match Account::builder()?.from_credentials(credentials).await {
                                Ok(account) => {
                                    // Re-parse from already loaded data (from_credentials consumed the first parse)
                                    let creds: AccountCredentials = serde_json::from_str(&data)?;
                                    info!("Loaded existing ACME account");
                                    return Ok((account, creds));
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to restore ACME account, creating new one: {}",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse account credentials, creating new one: {}",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read account credentials: {}", e);
                }
            }
        }

        // Create new account
        let contact = if self.config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", self.config.email)]
        };

        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contact.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                server_url.to_string(),
                None,
            )
            .await?;

        // Save credentials
        tokio::fs::create_dir_all(&self.certs_dir).await?;
        let creds_json = serde_json::to_string_pretty(&credentials)?;
        tokio::fs::write(&creds_path, &creds_json).await?;
        info!("Created new ACME account");

        Ok((account, credentials))
    }

    /// Remove challenge tokens from shared state after order completion
    fn cleanup_challenge_tokens(&self, tokens: &[String]) {
        match self.challenges.write() {
            Ok(mut challenges) => {
                for token in tokens {
                    challenges.remove(token);
                }
                debug!("Cleaned up {} challenge token(s)", tokens.len());
            }
            Err(e) => {
                error!("Challenge state lock poisoned during cleanup: {}", e);
            }
        }
    }

    /// Poll until order status becomes Ready
    async fn poll_order_ready(order: &mut instant_acme::Order) -> anyhow::Result<()> {
        let mut retries = 0;
        loop {
            let state = order.refresh().await?;
            match state.status {
                OrderStatus::Ready => return Ok(()),
                OrderStatus::Invalid => {
                    return Err(anyhow::anyhow!("Order became invalid"));
                }
                OrderStatus::Pending => {
                    retries += 1;
                    if retries > 30 {
                        return Err(anyhow::anyhow!(
                            "Order still pending after {} retries",
                            retries
                        ));
                    }
                    debug!("Order still pending, waiting... (attempt {})", retries);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                status => {
                    debug!("Order status: {:?}, waiting...", status);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Poll until certificate is available
    async fn poll_certificate(order: &mut instant_acme::Order) -> anyhow::Result<String> {
        let mut retries = 0;
        loop {
            match order.certificate().await? {
                Some(cert) => return Ok(cert),
                None => {
                    retries += 1;
                    if retries > 30 {
                        return Err(anyhow::anyhow!(
                            "Certificate not available after {} retries",
                            retries
                        ));
                    }
                    debug!(
                        "Certificate not yet available, waiting... (attempt {})",
                        retries
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Save certificate and key to disk
    async fn save_certificate(
        &self,
        hostname: &str,
        cert_chain_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<()> {
        let cert_dir = self.certs_dir.join(hostname);
        tokio::fs::create_dir_all(&cert_dir).await?;

        tokio::fs::write(cert_dir.join("cert.pem"), cert_chain_pem).await?;
        tokio::fs::write(cert_dir.join("key.pem"), key_pem).await?;

        info!("Certificate saved to {}", cert_dir.display());
        Ok(())
    }

    /// Load existing certificates from certs_dir and send them to Sozu
    async fn load_existing_certs(&self) {
        let certs_dir = &self.certs_dir;
        if !certs_dir.exists() {
            debug!("Certs directory does not exist, skipping load");
            return;
        }

        let mut entries = match tokio::fs::read_dir(certs_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to read certs directory: {}", e);
                return;
            }
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let hostname = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Skip account credentials directory
            if hostname == "account_credentials.json" {
                continue;
            }

            let cert_path = path.join("cert.pem");
            let key_path = path.join("key.pem");

            if !cert_path.exists() || !key_path.exists() {
                continue;
            }

            let cert_pem = match tokio::fs::read_to_string(&cert_path).await {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to read cert for {}: {}", hostname, e);
                    continue;
                }
            };

            let key_pem = match tokio::fs::read_to_string(&key_path).await {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to read key for {}: {}", hostname, e);
                    continue;
                }
            };

            // Check if cert is expired (not just expiring soon)
            if is_cert_expiring_soon(&cert_pem, 0) {
                warn!("Certificate for {} is expired, skipping load", hostname);
                continue;
            }

            let (cert, chain) = split_pem_chain(&cert_pem);
            if let Err(e) = self.cert_tx.send(CertCommand {
                hostname: hostname.clone(),
                cert_pem: cert,
                key_pem,
                chain,
            }) {
                error!("Failed to send cert command for {}: {}", hostname, e);
            } else {
                info!("Loaded existing certificate for {}", hostname);
            }
        }
    }
}

/// Split a PEM chain into the leaf certificate and the rest of the chain
fn split_pem_chain(pem_chain: &str) -> (String, Vec<String>) {
    let pem_blocks: Vec<&str> = pem_chain
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .collect();

    if pem_blocks.is_empty() {
        return (pem_chain.to_string(), Vec::new());
    }

    let leaf = format!("{}-----END CERTIFICATE-----\n", pem_blocks[0].trim_start());

    let chain: Vec<String> = pem_blocks[1..]
        .iter()
        .map(|block| format!("{}-----END CERTIFICATE-----\n", block.trim_start()))
        .collect();

    (leaf, chain)
}

/// Check if a PEM certificate is expiring within `days` days.
/// Returns true if cert is invalid or expiring soon.
fn is_cert_expiring_soon(pem_data: &str, days: i64) -> bool {
    // Parse the PEM to extract the leaf cert and check its notAfter field.
    // Falls back to assuming renewal is needed if parsing fails.
    match parse_cert_expiry(pem_data) {
        Some(expiry) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let threshold = now + (days * 86400);
            expiry < threshold
        }
        None => {
            warn!("Could not parse certificate expiry, assuming renewal needed");
            true
        }
    }
}

/// Parse the notAfter timestamp from a PEM certificate.
/// Returns Unix timestamp or None if parsing fails.
fn parse_cert_expiry(pem_data: &str) -> Option<i64> {
    // Extract the first PEM block
    let begin = pem_data.find("-----BEGIN CERTIFICATE-----")?;
    let end = pem_data.find("-----END CERTIFICATE-----")?;
    let b64_start = begin + "-----BEGIN CERTIFICATE-----".len();
    let b64 = &pem_data[b64_start..end];

    // Decode base64
    let der = base64_decode(b64)?;

    // Parse ASN.1 DER to find validity.notAfter
    // TBSCertificate is the first element of the SEQUENCE
    // validity is at a known position in TBSCertificate
    parse_x509_not_after(&der)
}

/// Simple base64 decoder (no external dependency needed)
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        let mut buf = [0u8; 4];
        let mut valid = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                break;
            }
            buf[i] = TABLE.iter().position(|&c| c == byte)? as u8;
            valid = i + 1;
        }
        if valid >= 2 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if valid >= 3 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if valid >= 4 {
            output.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(output)
}

/// Parse X.509 DER to extract notAfter as a Unix timestamp
fn parse_x509_not_after(der: &[u8]) -> Option<i64> {
    // X.509 structure:
    // SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    // tbsCertificate = SEQUENCE { version, serialNumber, signature, issuer, validity, ... }
    // validity = SEQUENCE { notBefore, notAfter }

    let (_, content) = parse_asn1_sequence(der)?;
    let (_, tbs) = parse_asn1_sequence(content)?;

    let mut pos = 0;

    // version [0] EXPLICIT (optional, skip if present)
    if tbs.get(pos)? & 0xe0 == 0xa0 {
        let (len, next) = parse_asn1_element(&tbs[pos..])?;
        pos += len + next;
    }

    // serialNumber (INTEGER, skip)
    let (len, next) = parse_asn1_element(&tbs[pos..])?;
    pos += len + next;

    // signature (SEQUENCE, skip)
    let (len, next) = parse_asn1_element(&tbs[pos..])?;
    pos += len + next;

    // issuer (SEQUENCE, skip)
    let (len, next) = parse_asn1_element(&tbs[pos..])?;
    pos += len + next;

    // validity (SEQUENCE)
    let (_, validity_content) = parse_asn1_sequence(&tbs[pos..])?;

    // notBefore (skip)
    let (len, next) = parse_asn1_element(validity_content)?;
    let not_after_data = &validity_content[len + next..];

    // notAfter
    parse_asn1_time(not_after_data)
}

/// Parse an ASN.1 SEQUENCE and return (header_len, content)
fn parse_asn1_sequence(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.first()? != &0x30 {
        return None;
    }
    let (header_len, content_len) = parse_asn1_length(&data[1..])?;
    let total_header = 1 + header_len;
    Some((
        total_header,
        &data[total_header..total_header + content_len],
    ))
}

/// Parse an ASN.1 element and return (header_size, content_size) — total = header + content
fn parse_asn1_element(data: &[u8]) -> Option<(usize, usize)> {
    let tag_len = 1;
    let (len_bytes, content_len) = parse_asn1_length(&data[tag_len..])?;
    Some((tag_len + len_bytes, content_len))
}

/// Parse ASN.1 length bytes. Returns (number_of_length_bytes, actual_length)
fn parse_asn1_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((1, first as usize))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (*data.get(1 + i)? as usize);
        }
        Some((1 + num_bytes, length))
    }
}

/// Parse an ASN.1 UTCTime or GeneralizedTime to Unix timestamp
fn parse_asn1_time(data: &[u8]) -> Option<i64> {
    let tag = *data.first()?;
    let (header, content_len) = parse_asn1_element(data)?;
    let time_str = std::str::from_utf8(&data[header..header + content_len]).ok()?;

    let (year, month, day, hour, min, sec) = if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ
        let y: i32 = time_str.get(0..2)?.parse().ok()?;
        let year = if y >= 50 { 1900 + y } else { 2000 + y };
        (
            year,
            time_str.get(2..4)?.parse::<u32>().ok()?,
            time_str.get(4..6)?.parse::<u32>().ok()?,
            time_str.get(6..8)?.parse::<u32>().ok()?,
            time_str.get(8..10)?.parse::<u32>().ok()?,
            time_str.get(10..12)?.parse::<u32>().ok()?,
        )
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        (
            time_str.get(0..4)?.parse::<i32>().ok()?,
            time_str.get(4..6)?.parse::<u32>().ok()?,
            time_str.get(6..8)?.parse::<u32>().ok()?,
            time_str.get(8..10)?.parse::<u32>().ok()?,
            time_str.get(10..12)?.parse::<u32>().ok()?,
            time_str.get(12..14)?.parse::<u32>().ok()?,
        )
    } else {
        return None;
    };

    // Convert to Unix timestamp (simplified, no leap seconds)
    let days = days_from_civil(year, month, day)?;
    Some(days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64)
}

/// Convert a civil date to days since Unix epoch (algorithm from Howard Hinnant)
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let m = m as i64;
    let d = d as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe as i64 * 365 + yoe as i64 / 4 - yoe as i64 / 100 + doy;
    Some(era * 146097 + doe - 719468)
}
