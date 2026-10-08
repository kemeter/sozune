//! Read-only inventory of the certificates Sōzune serves.
//!
//! Walks `certs_dir` (the same layout [`super::AcmeManager`] writes: one
//! `{path_safe(hostname)}/cert.pem` per host) and reports identity and expiry
//! metadata for each certificate, so the API can list them without the proxy
//! having to track certs in memory. Certificates loaded from files
//! (`proxy.https.tls.certificates`) are listed next to them, from the material
//! read at startup.

use std::path::Path;

use serde::Serialize;
use tracing::warn;

use super::{RENEWAL_FLOOR_DAYS, hostname_from_path, split_pem_chain};
use crate::manual_certs::{ManualCertificate, covered};

/// Lifecycle bucket for a certificate, mirroring the renewal decision so the
/// dashboard's "expiring soon" badge and the ACME renewal trigger never
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertStatus {
    /// Comfortably within its lifetime.
    Valid,
    /// Past the lifetime-ratio renewal point but not yet expired.
    Expiring,
    /// `not_after` is in the past.
    Expired,
}

/// Where a certificate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertSource {
    /// Issued by ACME and stored under `certs_dir`.
    Acme,
    /// Supplied by the operator under `proxy.https.tls.certificates`.
    File,
}

/// One certificate, with the metadata the API surfaces.
///
/// `subject_cn` and `sans` come straight from the leaf certificate, so they
/// reflect what the cert actually covers rather than the directory name.
/// Timestamps are Unix seconds; `total_days` / `remaining_days` are whole days.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    /// Hostname recovered from the storage directory (wildcards restored).
    pub hostname: String,
    /// Subject Common Name, if the certificate carries one.
    pub subject_cn: Option<String>,
    /// DNS names from the Subject Alternative Name extension.
    pub sans: Vec<String>,
    /// `notBefore` as Unix seconds.
    pub not_before: i64,
    /// `notAfter` as Unix seconds.
    pub not_after: i64,
    /// Full lifetime in whole days.
    pub total_days: i64,
    /// Whole days until expiry; negative once expired.
    pub remaining_days: i64,
    /// Lifecycle bucket derived from the lifetime ratio.
    pub status: CertStatus,
    pub source: CertSource,
    /// The `cert_file` of a certificate loaded from a file.
    pub file: Option<String>,
    /// The `cert_file` on disk no longer holds the certificate being served
    /// — typically renewed by certbot. Files are read at startup only, so the
    /// new one is served after a restart.
    pub file_replaced: bool,
}

/// Scan `certs_dir` and return one [`CertificateInfo`] per readable
/// certificate, sorted by hostname for stable output.
///
/// Unreadable or unparseable certificates are logged and skipped rather than
/// failing the whole listing — one bad cert on disk shouldn't blank the API.
/// Returns an empty vec if the directory doesn't exist.
pub async fn scan_certificates(certs_dir: &Path) -> Vec<CertificateInfo> {
    let mut certs = Vec::new();

    if !certs_dir.exists() {
        return certs;
    }

    let mut entries = match tokio::fs::read_dir(certs_dir).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read certs directory: {}", e);
            return certs;
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

        // Without its key the manager does not load it: nothing serves it.
        let cert_path = path.join("cert.pem");
        if !cert_path.exists() || !path.join("key.pem").exists() {
            continue;
        }

        let pem = match tokio::fs::read_to_string(&cert_path).await {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to read cert at {}: {}", cert_path.display(), e);
                continue;
            }
        };

        let hostname = hostname_from_path(&dir_name);
        if let Some(info) = certificate_info(hostname, &pem, CertSource::Acme) {
            certs.push(info);
        }
    }

    certs.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    certs
}

/// List what the HTTPS worker serves: the certificates loaded from files at
/// startup, and the ACME certificates under `certs_dir` (`None` when ACME is
/// off)
/// minus those a file certificate covers — ACME does not load those, so
/// listing them would show a certificate nobody is served.
pub async fn list_served(
    certs_dir: Option<&Path>,
    files: &[ManualCertificate],
) -> Vec<CertificateInfo> {
    let manual_names: Vec<String> = files.iter().flat_map(|c| c.names.clone()).collect();
    let mut certs = match certs_dir {
        Some(dir) => scan_certificates(dir).await,
        None => Vec::new(),
    };
    certs.retain(|c| !covered(&manual_names, &c.hostname));

    for file in files {
        let Some(mut info) =
            certificate_info(file.names[0].clone(), &file.cert_pem, CertSource::File)
        else {
            continue;
        };
        info.file = Some(file.cert_file.clone());
        info.file_replaced = file_replaced(file).await;
        certs.push(info);
    }

    certs.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    certs
}

/// Whether `cert_file` now holds another chain than the one being served —
/// a new leaf, or the same leaf with other intermediates. An unreadable file
/// counts as replaced: what is served is no longer on disk.
async fn file_replaced(file: &ManualCertificate) -> bool {
    let Ok(pem) = tokio::fs::read_to_string(&file.cert_file).await else {
        return true;
    };
    let (leaf, chain) = split_pem_chain(&pem);
    let trimmed = |pems: &[String]| {
        pems.iter()
            .map(|p| p.trim().to_string())
            .collect::<Vec<_>>()
    };
    leaf.trim() != file.cert_pem.trim() || trimmed(&chain) != trimmed(&file.chain)
}

/// Build a [`CertificateInfo`] for `hostname` from its leaf PEM. Returns
/// `None` (with a warning) if the PEM can't be parsed.
fn certificate_info(hostname: String, pem: &str, source: CertSource) -> Option<CertificateInfo> {
    let life = match cheti::cert_lifetime(pem) {
        Ok(life) => life,
        Err(e) => {
            warn!("Skipping unparseable certificate for {}: {}", hostname, e);
            return None;
        }
    };

    // Exact timestamps: `remaining_days` is truncated to whole days, so it
    // still reads 0 for a certificate that expired hours ago.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let status = if life.not_after < now {
        CertStatus::Expired
    } else if cheti::needs_renewal_ratio(pem, RENEWAL_FLOOR_DAYS) {
        CertStatus::Expiring
    } else {
        CertStatus::Valid
    };

    Some(CertificateInfo {
        hostname,
        subject_cn: life.subject_cn,
        sans: life.sans,
        not_before: life.not_before,
        not_after: life.not_after,
        total_days: life.total_days,
        remaining_days: life.remaining_days,
        status,
        source,
        file: None,
        file_replaced: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::path::PathBuf;
    use time::{Duration, OffsetDateTime};

    /// Write `{dir}/{cert_subdir}/cert.pem` for a self-signed cert that is
    /// `lifetime_days` long and expires `expires_in_days` from now (negative ⇒
    /// already expired). Returns nothing; the caller scans the parent dir.
    fn write_cert(
        dir: &std::path::Path,
        cert_subdir: &str,
        cn: &str,
        sans: &[&str],
        lifetime_days: i64,
        expires_in_days: i64,
    ) {
        let not_after = OffsetDateTime::now_utc() + Duration::days(expires_in_days);
        let not_before = not_after - Duration::days(lifetime_days);

        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName(s.to_string().try_into().unwrap()))
            .collect();

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let host_dir: PathBuf = dir.join(cert_subdir);
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::write(host_dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(host_dir.join("key.pem"), key.serialize_pem()).unwrap();
    }

    #[tokio::test]
    async fn scan_returns_empty_for_missing_dir() {
        let missing = std::env::temp_dir().join("sozune-no-such-certs-dir-xyz");
        assert!(scan_certificates(&missing).await.is_empty());
    }

    #[tokio::test]
    async fn scan_reports_identity_and_sorts_by_hostname() {
        let tmp = tempfile::tempdir().unwrap();
        // Classic 90-day cert with 60 days left → valid.
        write_cert(
            tmp.path(),
            "shop.example.com",
            "shop.example.com",
            &["shop.example.com", "www.example.com"],
            90,
            60,
        );
        write_cert(
            tmp.path(),
            "api.example.com",
            "api.example.com",
            &["api.example.com"],
            90,
            60,
        );

        let certs = scan_certificates(tmp.path()).await;
        assert_eq!(certs.len(), 2);
        // Sorted by hostname: api before shop.
        assert_eq!(certs[0].hostname, "api.example.com");
        assert_eq!(certs[1].hostname, "shop.example.com");

        let shop = &certs[1];
        assert_eq!(shop.subject_cn.as_deref(), Some("shop.example.com"));
        assert_eq!(shop.sans, vec!["shop.example.com", "www.example.com"]);
        assert_eq!(shop.total_days, 90);
        assert_eq!(shop.status, CertStatus::Valid);
    }

    #[tokio::test]
    async fn status_valid_expiring_expired_track_the_ratio() {
        let tmp = tempfile::tempdir().unwrap();
        // 90-day cert, 60 days left → above the 30-day floor → valid.
        write_cert(
            tmp.path(),
            "valid.example",
            "valid.example",
            &["valid.example"],
            90,
            60,
        );
        // 90-day cert, 20 days left → below 30-day floor → expiring.
        write_cert(
            tmp.path(),
            "soon.example",
            "soon.example",
            &["soon.example"],
            90,
            20,
        );
        // 7-day cert freshly issued (6 days left) → ratio trigger ~2.3d → still valid,
        // which is the whole point of the ratio fix (fixed-30 would say expiring).
        write_cert(
            tmp.path(),
            "short.example",
            "short.example",
            &["short.example"],
            7,
            6,
        );
        // Expired cert (1 day past not_after).
        write_cert(
            tmp.path(),
            "dead.example",
            "dead.example",
            &["dead.example"],
            90,
            -1,
        );

        let certs = scan_certificates(tmp.path()).await;
        let by_host = |h: &str| {
            certs
                .iter()
                .find(|c| c.hostname == h)
                .unwrap_or_else(|| panic!("missing {h}"))
                .status
        };

        assert_eq!(by_host("valid.example"), CertStatus::Valid);
        assert_eq!(by_host("soon.example"), CertStatus::Expiring);
        assert_eq!(by_host("short.example"), CertStatus::Valid);
        assert_eq!(by_host("dead.example"), CertStatus::Expired);
    }

    #[tokio::test]
    async fn wildcard_hostname_is_restored_from_dir_name() {
        let tmp = tempfile::tempdir().unwrap();
        write_cert(
            tmp.path(),
            "_wildcard_.example.com",
            "*.example.com",
            &["*.example.com"],
            90,
            60,
        );

        let certs = scan_certificates(tmp.path()).await;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hostname, "*.example.com");
    }

    fn file_certificate(dir: &std::path::Path, names: &[&str]) -> ManualCertificate {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        let cert_file = dir.join("fullchain.pem");
        std::fs::write(&cert_file, &pem).unwrap();
        ManualCertificate {
            cert_file: cert_file.to_string_lossy().into_owned(),
            names: names.iter().map(|n| n.to_string()).collect(),
            cert_pem: pem,
            chain: vec![],
            key_pem: String::new(),
        }
    }

    #[tokio::test]
    async fn file_certificates_are_listed_with_their_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = file_certificate(tmp.path(), &["*.example.com", "example.com"]);

        let certs = list_served(None, std::slice::from_ref(&file)).await;

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hostname, "*.example.com");
        assert_eq!(certs[0].source, CertSource::File);
        assert_eq!(certs[0].file.as_deref(), Some(file.cert_file.as_str()));
        assert!(!certs[0].file_replaced);
    }

    #[tokio::test]
    async fn acme_certificates_a_file_covers_are_not_listed() {
        let acme_dir = tempfile::tempdir().unwrap();
        write_cert(
            acme_dir.path(),
            "app.example.com",
            "app.example.com",
            &["app.example.com"],
            90,
            60,
        );
        write_cert(
            acme_dir.path(),
            "other.org",
            "other.org",
            &["other.org"],
            90,
            60,
        );
        let files_dir = tempfile::tempdir().unwrap();
        let file = file_certificate(files_dir.path(), &["*.example.com"]);

        let certs = list_served(Some(acme_dir.path()), &[file]).await;

        let listed: Vec<_> = certs
            .iter()
            .map(|c| (c.hostname.as_str(), c.source))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("*.example.com", CertSource::File),
                ("other.org", CertSource::Acme)
            ]
        );
    }

    #[tokio::test]
    async fn a_file_renewed_on_disk_is_flagged_as_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let served = file_certificate(tmp.path(), &["example.com"]);
        // certbot renews: same path, new certificate.
        file_certificate(tmp.path(), &["example.com"]);

        let certs = list_served(None, &[served]).await;

        assert!(certs[0].file_replaced);
    }

    #[tokio::test]
    async fn same_leaf_with_another_chain_is_flagged_as_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let served = file_certificate(tmp.path(), &["example.com"]);
        let intermediate_dir = tempfile::tempdir().unwrap();
        let intermediate = file_certificate(intermediate_dir.path(), &["ca.example"]);
        std::fs::write(
            &served.cert_file,
            format!("{}{}", served.cert_pem, intermediate.cert_pem),
        )
        .unwrap();

        let certs = list_served(None, &[served]).await;

        assert!(certs[0].file_replaced);
    }

    #[tokio::test]
    async fn a_certificate_without_its_key_is_not_listed() {
        let tmp = tempfile::tempdir().unwrap();
        write_cert(tmp.path(), "a.example", "a.example", &["a.example"], 90, 60);
        std::fs::remove_file(tmp.path().join("a.example/key.pem")).unwrap();

        assert!(scan_certificates(tmp.path()).await.is_empty());
    }

    #[tokio::test]
    async fn a_certificate_expired_hours_ago_is_expired() {
        let tmp = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["late.example".to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(90);
        params.not_after = now - Duration::hours(2);
        let dir = tmp.path().join("late.example");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("cert.pem"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();

        let certs = scan_certificates(tmp.path()).await;

        assert_eq!(certs[0].status, CertStatus::Expired);
    }

    #[tokio::test]
    async fn unparseable_cert_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        write_cert(
            tmp.path(),
            "good.example",
            "good.example",
            &["good.example"],
            90,
            60,
        );
        // A directory with garbage instead of a real PEM.
        let bad = tmp.path().join("bad.example");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("cert.pem"), "not a certificate").unwrap();
        std::fs::write(bad.join("key.pem"), "key").unwrap();

        let certs = scan_certificates(tmp.path()).await;
        // The bad one is dropped; the good one still lists.
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hostname, "good.example");
    }
}
