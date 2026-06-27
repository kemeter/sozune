pub mod challenge_server;
pub mod inventory;
pub mod resolver;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use cheti::{AccountStore, Dns01Solver, FileAccountStore};
use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder, Order, OrderStatus};
use rcgen::{CertificateParams, KeyPair};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::{AcmeConfig, ResolverConfig};
use crate::model::Entrypoint;

use self::challenge_server::ChallengeState;
use self::resolver::{Resolver, build_resolver};

/// Upper bound, in days, on how early a certificate may be renewed before
/// expiry. The renewal trigger is `min(total_lifetime / 3, RENEWAL_FLOOR_DAYS)`:
/// the ratio adapts to short-lived certs, and this floor stops a long-lived cert
/// from being reissued months ahead of time. Set to 30 so the common 90-day
/// Let's Encrypt profile keeps renewing at the 30-days-left mark.
const RENEWAL_FLOOR_DAYS: u32 = 30;

/// Per-hostname backoff schedule applied after a failed provisioning attempt,
/// indexed by the count of consecutive failures (1st failure -> 60s, etc.).
/// A permanently broken hostname (e.g. missing DNS) settles at the last value
/// instead of being retried every cycle, which would otherwise pile up
/// Let's Encrypt authorization failures and rate-limit the whole account.
const BACKOFF_SCHEDULE: [Duration; 5] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
];

/// Tracks when a hostname may next be attempted after one or more failures.
struct BackoffState {
    next_attempt_at: Instant,
    consecutive_failures: u32,
}

/// Per-hostname backoff tracker. Keeps failing hostnames from being retried
/// every cycle (which would pile up Let's Encrypt authorization failures and
/// rate-limit the whole account) while letting healthy hostnames through.
#[derive(Default)]
struct Backoff {
    failures: RwLock<HashMap<String, BackoffState>>,
}

impl Backoff {
    /// Remaining backoff for a hostname, or `None` if it may be attempted now.
    fn remaining(&self, hostname: &str) -> Option<Duration> {
        let failures = self.failures.read().ok()?;
        let state = failures.get(hostname)?;
        state.next_attempt_at.checked_duration_since(Instant::now())
    }

    /// Clear any backoff state for a hostname after a successful provisioning.
    fn record_success(&self, hostname: &str) {
        if let Ok(mut failures) = self.failures.write() {
            failures.remove(hostname);
        }
    }

    /// Record a failed attempt and schedule the next one. When a `retry after`
    /// instant is present (Let's Encrypt rate limiting), honor it: the next
    /// attempt is deferred until at least that time, even if the backoff
    /// schedule would have been shorter.
    fn record_failure(&self, hostname: &str, retry_after_secs: Option<u64>) {
        let Ok(mut failures) = self.failures.write() else {
            return;
        };
        let now = Instant::now();
        let entry = failures
            .entry(hostname.to_string())
            .or_insert(BackoffState {
                next_attempt_at: now,
                consecutive_failures: 0,
            });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);

        let idx = (entry.consecutive_failures as usize - 1).min(BACKOFF_SCHEDULE.len() - 1);
        let mut delay = BACKOFF_SCHEDULE[idx];

        if let Some(retry_after) = retry_after_secs {
            delay = delay.max(Duration::from_secs(retry_after));
        }

        entry.next_attempt_at = now + delay;
    }
}

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
    /// Per-hostname backoff after failed provisioning attempts.
    backoff: Backoff,
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
            backoff: Backoff::default(),
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
                    // A hostname that keeps failing (e.g. missing DNS) stays in
                    // backoff so it is not retried every cycle — that would keep
                    // the Let's Encrypt account rate-limited and starve healthy
                    // hostnames of provisioning.
                    if let Some(remaining) = self.backoff.remaining(hostname) {
                        debug!(
                            "Skipping {}: in backoff for another {}s after a prior failure",
                            hostname,
                            remaining.as_secs()
                        );
                        continue;
                    }

                    info!("Requesting certificate for {}", hostname);
                    match self
                        .provision_certificate(hostname, resolver_name.as_deref())
                        .await
                    {
                        Ok(()) => self.backoff.record_success(hostname),
                        Err(e) => {
                            let retry_after = parse_retry_after_secs(&e.to_string());
                            self.backoff.record_failure(hostname, retry_after);
                            error!("Failed to provision certificate for {}: {}", hostname, e);
                        }
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

        // Resolver-managed domains first: a resolver can declare `domains`
        // (e.g. a wildcard) it provisions on its own, with no entrypoint. They
        // take precedence so that an entrypoint reusing the same hostname does
        // not override the resolver binding for it.
        let mut certs = collect_resolver_managed_domains(&self.config.resolvers);

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

        // A resolver may pin its own ACME directory URL (Traefik's `caServer`),
        // which overrides the global staging/prod default — so a staging and a
        // production resolver can coexist.
        let resolver_ca = resolver_name
            .and_then(|name| self.config.resolvers.get(name))
            .and_then(|r| r.ca_server());
        let server_url = match resolver_ca {
            Some(url) => url,
            None if self.config.staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            None => "https://acme-v02.api.letsencrypt.org/directory",
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
    ///
    /// The account is keyed by the ACME directory URL: each CA (production,
    /// staging, a third-party ACME) has its own credentials file, so switching
    /// or mixing CAs never reuses an account that belongs to a different
    /// server. The production Let's Encrypt URL keeps the historical filename
    /// (`account_credentials.json`) for backwards compatibility.
    async fn get_or_create_account(&self, server_url: &str) -> anyhow::Result<Account> {
        let store = FileAccountStore::new(self.certs_dir.join(account_file_for(server_url)));

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

            // Skip ACME account credential files (one per CA directory URL:
            // `account_credentials.json` plus any `account_<slug>.json`).
            if dir_name.starts_with("account_") && dir_name.ends_with(".json") {
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

/// Credentials filename for an ACME account, derived from the directory URL so
/// each CA (production, staging, a third-party ACME) gets its own account file
/// and they never collide. The URL is reduced to a stable, filesystem-safe
/// slug.
fn account_file_for(server_url: &str) -> String {
    let slug: String = server_url
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("account_{slug}.json")
}

/// Flatten the `domains` declared on each resolver into `(hostname, resolver)`
/// pairs, deduplicating by hostname (first resolver wins). These are the certs
/// a resolver provisions on its own, with no entrypoint — typically a wildcard.
fn collect_resolver_managed_domains(
    resolvers: &HashMap<String, ResolverConfig>,
) -> Vec<(String, Option<String>)> {
    let mut certs: Vec<(String, Option<String>)> = Vec::new();
    for (resolver_name, resolver) in resolvers {
        for hostname in resolver.managed_domains() {
            if certs.iter().any(|(h, _)| h == hostname) {
                continue;
            }
            certs.push((hostname.clone(), Some(resolver_name.clone())));
        }
    }
    certs
}

/// Extract the seconds remaining until the `retry after` instant carried by a
/// Let's Encrypt `rateLimited` error message, e.g.
/// `... retry after 2026-06-27 15:48:27 UTC: see ...`.
/// Returns `None` when no such timestamp is present or it is already in the past.
///
/// The timestamp has a `YYYY-MM-DD HH:MM:SS UTC` shape, so it is parsed by hand
/// to avoid pulling a date-parsing crate into the production build (`time` is a
/// dev-dependency only, and without its `parsing` feature anyway).
fn parse_retry_after_secs(message: &str) -> Option<u64> {
    let after = message.split("retry after ").nth(1)?;
    // The instant is followed by `: see <url>` in real messages. Cut at that
    // separator instead of assuming a fixed offset, so a longer year, a missing
    // suffix, or extra surrounding text doesn't silently truncate the stamp.
    let stamp = after.split(": ").next()?.trim();
    let retry_epoch = parse_utc_stamp_to_epoch(stamp)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;

    let remaining = retry_epoch - now;
    if remaining > 0 {
        Some(remaining as u64)
    } else {
        None
    }
}

/// Parse a `YYYY-MM-DD HH:MM:SS UTC` string into a Unix epoch (seconds).
fn parse_utc_stamp_to_epoch(stamp: &str) -> Option<i64> {
    let stamp = stamp.strip_suffix(" UTC")?;
    let (date, time) = stamp.split_once(' ')?;

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    // Reject any trailing field, e.g. "2026-06-27-01".
    if date_parts.next().is_some() {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    // Days since the Unix epoch via the civil-date algorithm (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    Some(days * 86400 + hour * 3600 + minute * 60 + second)
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

    #[test]
    fn parse_utc_stamp_matches_known_epochs() {
        // Reference values cross-checked against the Unix epoch.
        assert_eq!(parse_utc_stamp_to_epoch("1970-01-01 00:00:00 UTC"), Some(0));
        assert_eq!(
            parse_utc_stamp_to_epoch("2000-01-01 00:00:00 UTC"),
            Some(946_684_800)
        );
        assert_eq!(
            parse_utc_stamp_to_epoch("2026-06-27 15:48:27 UTC"),
            Some(1_782_575_307)
        );
        // Leap second is accepted (60s).
        assert_eq!(
            parse_utc_stamp_to_epoch("2016-12-31 23:59:60 UTC"),
            Some(1_483_228_800)
        );
        // Malformed input is rejected, not panicked on.
        assert_eq!(parse_utc_stamp_to_epoch("not a date"), None);
        assert_eq!(parse_utc_stamp_to_epoch("2026-13-01 00:00:00 UTC"), None);
        // Out-of-range time fields are rejected.
        assert_eq!(parse_utc_stamp_to_epoch("2026-06-27 24:00:00 UTC"), None);
        assert_eq!(parse_utc_stamp_to_epoch("2026-06-27 15:60:00 UTC"), None);
        // Extra trailing fields are rejected, not silently ignored.
        assert_eq!(parse_utc_stamp_to_epoch("2026-06-27-01 15:48:27 UTC"), None);
        assert_eq!(parse_utc_stamp_to_epoch("2026-06-27 15:48:27:99 UTC"), None);
        // Missing UTC suffix is rejected.
        assert_eq!(parse_utc_stamp_to_epoch("2026-06-27 15:48:27"), None);
    }

    #[test]
    fn parse_retry_after_is_robust_to_message_shape() {
        // Five-digit year would overflow a fixed 23-char slice; the separator
        // cut handles it (epoch far in the future -> large positive remaining).
        let secs = parse_retry_after_secs("retry after 10000-01-01 00:00:00 UTC: see x")
            .expect("five-digit year must still parse");
        assert!(secs > 0);

        // No trailing `: see ...`, just the stamp.
        assert!(parse_retry_after_secs("retry after 2099-01-01 00:00:00 UTC").is_some());

        // Surrounding whitespace around the stamp is tolerated.
        assert!(parse_retry_after_secs("retry after  2099-01-01 00:00:00 UTC : see x").is_some());

        // Garbage after the marker yields None, not a panic or bogus instant.
        assert_eq!(parse_retry_after_secs("retry after soon-ish: see x"), None);
    }

    #[test]
    fn parse_retry_after_reads_letsencrypt_rate_limit_message() {
        // A timestamp far in the future yields a large positive remaining.
        let msg = "API error: too many failed authorizations (5) for \"x.example.com\" in the \
             last 1h0m0s, retry after 2099-01-01 00:00:00 UTC: see \
             https://letsencrypt.org/docs/rate-limits/";
        let secs = parse_retry_after_secs(msg).expect("should parse a future retry-after");
        assert!(secs > 0, "expected positive remaining, got {secs}");
    }

    #[test]
    fn parse_retry_after_none_when_absent_or_past() {
        assert_eq!(parse_retry_after_secs("Order became invalid"), None);
        assert_eq!(
            parse_retry_after_secs("retry after 2000-01-01 00:00:00 UTC: see ..."),
            None
        );
    }

    #[test]
    fn backoff_schedule_progresses_and_caps() {
        // The index used in record_failure: (consecutive_failures - 1) clamped.
        let pick = |failures: u32| {
            let idx = (failures as usize - 1).min(BACKOFF_SCHEDULE.len() - 1);
            BACKOFF_SCHEDULE[idx]
        };
        assert_eq!(pick(1), Duration::from_secs(60));
        assert_eq!(pick(2), Duration::from_secs(5 * 60));
        assert_eq!(pick(5), Duration::from_secs(6 * 60 * 60));
        // Beyond the schedule length it stays capped at the last value.
        assert_eq!(pick(99), Duration::from_secs(6 * 60 * 60));
    }

    #[test]
    fn backoff_isolates_hostnames_so_a_broken_one_does_not_starve_others() {
        let backoff = Backoff::default();

        // One hostname fails; it goes into backoff.
        backoff.record_failure("broken.example.com", None);
        assert!(
            backoff.remaining("broken.example.com").is_some(),
            "a failed hostname must be in backoff"
        );

        // A sibling hostname that never failed is not affected: it may be
        // attempted right away, so it is still provisioned this cycle.
        assert_eq!(
            backoff.remaining("healthy.example.com"),
            None,
            "an unrelated hostname must not inherit a sibling's backoff"
        );
    }

    #[test]
    fn backoff_records_failure_then_clears_on_success() {
        let backoff = Backoff::default();

        backoff.record_failure("host.example.com", None);
        assert!(backoff.remaining("host.example.com").is_some());

        // A successful provisioning clears the backoff entry entirely.
        backoff.record_success("host.example.com");
        assert_eq!(backoff.remaining("host.example.com"), None);
    }

    #[test]
    fn backoff_honors_retry_after_over_the_schedule() {
        let backoff = Backoff::default();

        // First failure would normally back off 60s; a far-future retry-after
        // must win, deferring the next attempt well beyond the schedule value.
        let one_day = 24 * 60 * 60;
        backoff.record_failure("host.example.com", Some(one_day));
        let remaining = backoff
            .remaining("host.example.com")
            .expect("host should be in backoff");
        assert!(
            remaining > BACKOFF_SCHEDULE[0],
            "retry-after must override the shorter schedule delay, got {remaining:?}"
        );
    }

    fn dns01(domains: &[&str]) -> ResolverConfig {
        ResolverConfig::Dns01 {
            provider: crate::config::ProviderConfig::Gandi {
                personal_access_token_env: "X".to_string(),
            },
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ca_server: None,
        }
    }

    #[test]
    fn resolver_domains_are_collected_with_their_resolver() {
        let mut resolvers = HashMap::new();
        resolvers.insert("gandi".to_string(), dns01(&["*.kemeter.app"]));

        let certs = collect_resolver_managed_domains(&resolvers);
        assert_eq!(
            certs,
            vec![("*.kemeter.app".to_string(), Some("gandi".to_string()))]
        );
    }

    #[test]
    fn resolver_without_domains_contributes_nothing() {
        let mut resolvers = HashMap::new();
        resolvers.insert("gandi".to_string(), dns01(&[]));
        resolvers.insert(
            "legacy".to_string(),
            ResolverConfig::Http01 { ca_server: None },
        );

        assert!(collect_resolver_managed_domains(&resolvers).is_empty());
    }

    #[test]
    fn http01_resolver_domains_are_ignored() {
        // Http01 has no `domains` field, so it can never manage a domain on its
        // own — managed_domains() is empty regardless.
        let mut resolvers = HashMap::new();
        resolvers.insert(
            "legacy".to_string(),
            ResolverConfig::Http01 { ca_server: None },
        );

        assert!(collect_resolver_managed_domains(&resolvers).is_empty());
    }

    #[test]
    fn duplicate_domain_across_resolvers_keeps_one() {
        // Same hostname declared on two resolvers: only one pairing is kept so
        // we never open two competing ACME orders for it.
        let mut resolvers = HashMap::new();
        resolvers.insert("a".to_string(), dns01(&["*.kemeter.app"]));
        resolvers.insert("b".to_string(), dns01(&["*.kemeter.app"]));

        let certs = collect_resolver_managed_domains(&resolvers);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].0, "*.kemeter.app");
    }

    #[test]
    fn multiple_resolvers_each_contribute_their_domains() {
        let mut resolvers = HashMap::new();
        resolvers.insert("gandi".to_string(), dns01(&["*.kemeter.app"]));
        resolvers.insert("cf".to_string(), dns01(&["*.example.com"]));

        let mut hosts: Vec<String> = collect_resolver_managed_domains(&resolvers)
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        hosts.sort();
        assert_eq!(hosts, vec!["*.example.com", "*.kemeter.app"]);
    }

    #[test]
    fn account_file_is_distinct_per_ca() {
        // Staging and prod must map to different account files so a switch or a
        // mix of CAs never reuses an account that belongs to another server.
        let prod = account_file_for("https://acme-v02.api.letsencrypt.org/directory");
        let staging = account_file_for("https://acme-staging-v02.api.letsencrypt.org/directory");
        assert_ne!(prod, staging);
        // Same URL is stable across calls.
        assert_eq!(
            prod,
            account_file_for("https://acme-v02.api.letsencrypt.org/directory")
        );
    }

    #[test]
    fn account_file_is_filesystem_safe() {
        // No slashes, colons or other path-significant characters survive.
        let name = account_file_for("https://acme-v02.api.letsencrypt.org/directory");
        assert!(name.starts_with("account_"));
        assert!(name.ends_with(".json"));
        assert!(!name.contains('/'));
        assert!(!name.contains(':'));
    }

    #[test]
    fn ca_server_override_is_read_from_resolver() {
        let staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
        let resolver = ResolverConfig::Dns01 {
            provider: crate::config::ProviderConfig::Gandi {
                personal_access_token_env: "X".to_string(),
            },
            domains: vec![],
            ca_server: Some(staging.to_string()),
        };
        assert_eq!(resolver.ca_server(), Some(staging));

        // Absent ca_server -> None (caller falls back to the global default).
        assert_eq!(dns01(&[]).ca_server(), None);
        assert_eq!(ResolverConfig::Http01 { ca_server: None }.ca_server(), None);
    }
}
