pub mod challenge_server;
pub mod inventory;
pub mod resolver;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cheti::{AccountStore, Dns01Solver, FileAccountStore};
use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder, Order, OrderStatus};
use rcgen::{CertificateParams, KeyPair};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::AcmeConfig;
use crate::model::Entrypoint;

use self::challenge_server::ChallengeState;
use self::resolver::{Resolver, build_resolver};

/// Upper bound, in days, on how early a certificate may be renewed before
/// expiry. The renewal trigger is `min(total_lifetime / 3, RENEWAL_FLOOR_DAYS)`:
/// the ratio adapts to short-lived certs, and this floor stops a long-lived cert
/// from being reissued months ahead of time. Set to 30 so the common 90-day
/// Let's Encrypt profile keeps renewing at the 30-days-left mark.
const RENEWAL_FLOOR_DAYS: u32 = 30;

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
    cert_tx: mpsc::Sender<CertCommand>,
    certs_dir: PathBuf,
    notify: Arc<Notify>,
}

impl AcmeManager {
    pub fn new(
        config: AcmeConfig,
        challenges: ChallengeState,
        storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
        cert_tx: mpsc::Sender<CertCommand>,
        notify: Arc<Notify>,
    ) -> Self {
        let certs_dir = PathBuf::from(&config.certs_dir);
        Self {
            config,
            challenges,
            storage,
            cert_tx,
            certs_dir,
            notify,
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

        // Renewal loop: check every 12 hours OR when notified of new entrypoints
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    info!("Running ACME renewal check");
                }
                _ = self.notify.notified() => {
                    // Small delay to let storage settle
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    info!("Running ACME check after storage update");
                }
            }
            if let Err(e) = self.provision_all().await {
                error!("ACME provisioning failed: {}", e);
            }
        }
    }

    /// Scan storage for entrypoints with tls: true and provision certificates
    async fn provision_all(&self) -> anyhow::Result<()> {
        let certs = self.collect_tls_certs();
        if certs.is_empty() {
            debug!("No TLS-enabled hostnames found, skipping ACME provisioning");
            return Ok(());
        }

        info!("Found {} TLS-enabled hostname(s) to check", certs.len());

        for (hostname, resolver_name) in &certs {
            match self.needs_certificate(hostname).await {
                true => {
                    info!("Requesting certificate for {}", hostname);
                    if let Err(e) = self
                        .provision_certificate(hostname, resolver_name.as_deref())
                        .await
                    {
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

    /// Collect all unique hostnames with tls: true, paired with the first
    /// resolver name we see for each. If two entrypoints share a hostname
    /// with different resolvers, the second one is dropped with a warning —
    /// we want one cert per hostname, not duplicate ACME orders.
    fn collect_tls_certs(&self) -> Vec<(String, Option<String>)> {
        let storage = match self.storage.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!(
                    "internal state corrupted (configuration store), restart required: {}",
                    e
                );
                return Vec::new();
            }
        };

        let mut certs: Vec<(String, Option<String>)> = Vec::new();
        for entrypoint in storage.values() {
            if !entrypoint.config.tls {
                continue;
            }
            let resolver_name = entrypoint.config.acme.as_ref().map(|a| a.resolver.clone());
            for hostname in &entrypoint.config.hostnames {
                if let Some((_, existing)) = certs.iter().find(|(h, _)| h == hostname) {
                    if existing != &resolver_name {
                        warn!(
                            "Hostname {} is claimed by multiple entrypoints with different resolvers ({:?} vs {:?}); keeping the first",
                            hostname, existing, resolver_name
                        );
                    }
                    continue;
                }
                certs.push((hostname.clone(), resolver_name.clone()));
            }
        }
        certs
    }

    /// Validate that a hostname is safe to use as a directory name (no path traversal).
    /// Wildcards (`*.foo.com`) are accepted; the wildcard label must be the leftmost one.
    fn validate_hostname(hostname: &str) -> anyhow::Result<()> {
        let trailing = hostname.strip_prefix("*.").unwrap_or(hostname);
        if trailing.is_empty()
            || trailing.contains('*')
            || trailing.contains('/')
            || trailing.contains('\\')
            || trailing.contains('\0')
            || trailing == "."
            || trailing == ".."
            || trailing.contains("..")
        {
            anyhow::bail!("Invalid hostname for certificate storage: {}", hostname);
        }
        Ok(())
    }

    /// Check if a hostname needs a new certificate (missing, or past the
    /// lifetime-ratio renewal point).
    ///
    /// Renewal triggers once the remaining lifetime drops below one third of the
    /// certificate's total lifetime, capped at [`RENEWAL_FLOOR_DAYS`] so a
    /// long-lived cert isn't reissued months early. For Let's Encrypt's classic
    /// 90-day profile this is the 30-days-left mark — identical to the previous
    /// fixed threshold — while short-lived profiles (7-day, 45-day) no longer
    /// renew on every poll the moment they're issued.
    async fn needs_certificate(&self, hostname: &str) -> bool {
        if Self::validate_hostname(hostname).is_err() {
            warn!("Skipping invalid hostname: {}", hostname);
            return false;
        }
        let cert_path = self.certs_dir.join(path_safe(hostname)).join("cert.pem");
        if !cert_path.exists() {
            return true;
        }

        // Read and parse existing cert to check expiration
        match tokio::fs::read_to_string(&cert_path).await {
            Ok(pem_data) => cheti::needs_renewal_ratio_checked(&pem_data, RENEWAL_FLOOR_DAYS)
                .unwrap_or_else(|e| {
                    warn!(
                        "Could not parse certificate expiry, assuming renewal needed: {}",
                        e
                    );
                    true
                }),
            Err(_) => true,
        }
    }

    /// Provision a certificate for `hostname` using the resolver named by
    /// the entrypoint (or the legacy HTTP-01 fallback if none).
    async fn provision_certificate(
        &self,
        hostname: &str,
        resolver_name: Option<&str>,
    ) -> anyhow::Result<()> {
        Self::validate_hostname(hostname)?;

        let resolver = build_resolver(resolver_name, &self.config)?;

        if is_wildcard(hostname) && !resolver.as_ref().is_some_and(Resolver::supports_wildcard) {
            anyhow::bail!(
                "wildcard hostname `{}` requires a DNS-01 resolver; assign one via `acme.resolver` on the entrypoint",
                hostname
            );
        }

        // Ensure rustls has a crypto provider installed (needed by instant-acme/reqwest)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let server_url = if self.config.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        let account = self.get_or_create_account(server_url).await?;
        let identifiers = vec![Identifier::Dns(hostname.to_string())];
        let order = account.new_order(&NewOrder::new(&identifiers)).await?;

        let (cert_chain_pem, key_pem) = match resolver {
            Some(Resolver::Dns01(provider)) => self.solve_dns01(order, provider).await?,
            Some(Resolver::Http01) | None => self.solve_http01(order, hostname).await?,
        };

        self.save_certificate(hostname, &cert_chain_pem, &key_pem)
            .await?;

        let (cert_pem, chain) = split_pem_chain(&cert_chain_pem);
        self.cert_tx
            .send(CertCommand {
                hostname: hostname.to_string(),
                cert_pem,
                key_pem,
                chain,
            })
            .await?;

        info!("Certificate for {} provisioned successfully", hostname);
        Ok(())
    }

    /// HTTP-01 challenge flow: stash key auth in shared state, let
    /// `challenge_server` answer the ACME validation request, then finalize.
    async fn solve_http01(
        &self,
        mut order: Order,
        hostname: &str,
    ) -> anyhow::Result<(String, String)> {
        let mut challenge_tokens: Vec<String> = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut auth_handle = result?;
            let mut challenge = auth_handle
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found"))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();

            {
                let mut challenges = self.challenges.write().map_err(|e| {
                    anyhow::anyhow!(
                        "internal state corrupted (ACME challenges), restart required: {}",
                        e
                    )
                })?;
                challenges.insert(token.clone(), key_auth.as_str().to_string());
            }

            debug!("Challenge token stored: {} (type: HTTP-01)", token);
            challenge_tokens.push(token);
            challenge.set_ready().await?;
        }
        let _ = authorizations;

        let ready_result = Self::poll_order_ready(&mut order).await;
        self.cleanup_challenge_tokens(&challenge_tokens);
        ready_result?;
        info!("Order for {} is ready", hostname);

        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key_pair)?;

        order.finalize_csr(csr.der()).await?;
        let cert_chain_pem = Self::poll_certificate(&mut order).await?;
        let key_pem = key_pair.serialize_pem();
        Ok((cert_chain_pem, key_pem))
    }

    /// DNS-01 challenge flow: hand the order off to cheti, which drives
    /// provider TXT records + propagation polling + finalize.
    async fn solve_dns01(
        &self,
        order: Order,
        provider: Box<dyn cheti::DnsProvider>,
    ) -> anyhow::Result<(String, String)> {
        Dns01Solver::new(provider)
            .solve_and_finalize(order)
            .await
            .map_err(|e| anyhow::anyhow!("DNS-01 challenge failed: {e}"))
    }

    /// Get or create an ACME account, persisted via cheti's FileAccountStore.
    async fn get_or_create_account(&self, server_url: &str) -> anyhow::Result<Account> {
        let store = FileAccountStore::new(self.certs_dir.join("account_credentials.json"));

        match store.load() {
            Ok(Some(credentials)) => {
                match Account::builder()?.from_credentials(credentials).await {
                    Ok(account) => {
                        info!("Loaded existing ACME account");
                        return Ok(account);
                    }
                    Err(e) => warn!("Failed to restore ACME account, creating new one: {}", e),
                }
            }
            Ok(None) => {}
            Err(e) => warn!(
                "Failed to load account credentials, creating new one: {}",
                e
            ),
        }

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

        store
            .save(&credentials)
            .map_err(|e| anyhow::anyhow!("persist ACME account credentials: {e}"))?;
        info!("Created new ACME account");

        Ok(account)
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
                error!(
                    "internal state corrupted (ACME challenges), restart required: {}",
                    e
                );
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
        let cert_dir = self.certs_dir.join(path_safe(hostname));
        tokio::fs::create_dir_all(&cert_dir).await?;

        tokio::fs::write(cert_dir.join("cert.pem"), cert_chain_pem).await?;
        write_with_restricted_permissions(&cert_dir.join("key.pem"), key_pem.as_bytes()).await?;

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

            let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Skip account credentials file
            if dir_name == "account_credentials.json" {
                continue;
            }

            let hostname = hostname_from_path(&dir_name);

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
            if cheti::needs_renewal(&cert_pem, 0) {
                warn!("Certificate for {} is expired, skipping load", hostname);
                continue;
            }

            let (cert, chain) = split_pem_chain(&cert_pem);
            if let Err(e) = self
                .cert_tx
                .send(CertCommand {
                    hostname: hostname.clone(),
                    cert_pem: cert,
                    key_pem,
                    chain,
                })
                .await
            {
                error!("Failed to send cert command for {}: {}", hostname, e);
            } else {
                info!("Loaded existing certificate for {}", hostname);
            }
        }
    }
}

/// Write data to a file with 0600 permissions (owner read/write only)
async fn write_with_restricted_permissions(
    path: &std::path::Path,
    data: &[u8],
) -> anyhow::Result<()> {
    tokio::fs::write(path, data).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(path, perms).await?;
    }
    Ok(())
}

fn is_wildcard(hostname: &str) -> bool {
    hostname.starts_with("*.")
}

/// Translate a hostname into a filesystem-safe directory name. `*` is not
/// portable across tools, so wildcard hostnames are stored under
/// `_wildcard_.{rest}`. Inverse of `hostname_from_path`.
fn path_safe(hostname: &str) -> String {
    if let Some(rest) = hostname.strip_prefix("*.") {
        format!("_wildcard_.{rest}")
    } else {
        hostname.to_string()
    }
}

/// Inverse of `path_safe`: recover the wildcard hostname stored under a
/// `_wildcard_.{rest}` directory.
fn hostname_from_path(dir_name: &str) -> String {
    if let Some(rest) = dir_name.strip_prefix("_wildcard_.") {
        format!("*.{rest}")
    } else {
        dir_name.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_wildcard_detects_leading_star_dot() {
        assert!(is_wildcard("*.example.com"));
        assert!(!is_wildcard("example.com"));
        assert!(!is_wildcard("api.*.example.com"));
        assert!(!is_wildcard("*example.com"));
    }

    #[test]
    fn path_safe_round_trips_wildcard() {
        assert_eq!(path_safe("*.example.com"), "_wildcard_.example.com");
        assert_eq!(
            hostname_from_path("_wildcard_.example.com"),
            "*.example.com"
        );
        assert_eq!(
            hostname_from_path(&path_safe("*.deep.sub.example.com")),
            "*.deep.sub.example.com"
        );
    }

    #[test]
    fn path_safe_passes_plain_hostnames_through() {
        assert_eq!(path_safe("example.com"), "example.com");
        assert_eq!(hostname_from_path("example.com"), "example.com");
    }

    #[test]
    fn validate_hostname_accepts_wildcards_and_plain() {
        AcmeManager::validate_hostname("example.com").unwrap();
        AcmeManager::validate_hostname("*.example.com").unwrap();
        AcmeManager::validate_hostname("*.deep.sub.example.com").unwrap();
    }

    #[test]
    fn validate_hostname_rejects_path_traversal() {
        assert!(AcmeManager::validate_hostname("../etc/passwd").is_err());
        assert!(AcmeManager::validate_hostname("a/b").is_err());
        assert!(AcmeManager::validate_hostname("").is_err());
        assert!(AcmeManager::validate_hostname(".").is_err());
    }

    #[test]
    fn validate_hostname_rejects_misplaced_wildcards() {
        // Only the leftmost label may be a wildcard.
        assert!(AcmeManager::validate_hostname("api.*.example.com").is_err());
        assert!(AcmeManager::validate_hostname("*.*.example.com").is_err());
        // Bare `*.` is also invalid (no apex).
        assert!(AcmeManager::validate_hostname("*.").is_err());
    }
}
