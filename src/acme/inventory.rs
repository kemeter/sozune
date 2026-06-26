//! Read-only inventory of the certificates Sōzune has on disk.
//!
//! Walks `certs_dir` (the same layout [`super::AcmeManager`] writes: one
//! `{path_safe(hostname)}/cert.pem` per host) and reports identity and expiry
//! metadata for each certificate, so the API can list them without the proxy
//! having to track certs in memory.

use std::path::Path;

use serde::Serialize;
use tracing::warn;

use super::{RENEWAL_FLOOR_DAYS, hostname_from_path};

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

/// One certificate on disk, with the metadata the API surfaces.
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

        let cert_path = path.join("cert.pem");
        if !cert_path.exists() {
            continue;
        }

        let pem = match tokio::fs::read_to_string(&cert_path).await {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to read cert at {}: {}", cert_path.display(), e);
                continue;
            }
        };

        if let Some(info) = certificate_info(&dir_name, &pem) {
            certs.push(info);
        }
    }

    certs.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    certs
}

/// Build a [`CertificateInfo`] from a storage directory name and its leaf PEM.
/// Returns `None` (with a warning) if the PEM can't be parsed.
fn certificate_info(dir_name: &str, pem: &str) -> Option<CertificateInfo> {
    let life = match cheti::cert_lifetime(pem) {
        Ok(life) => life,
        Err(e) => {
            warn!("Skipping unparseable certificate for {}: {}", dir_name, e);
            return None;
        }
    };

    let status = if life.remaining_days < 0 {
        CertStatus::Expired
    } else if cheti::needs_renewal_ratio(pem, RENEWAL_FLOOR_DAYS) {
        CertStatus::Expiring
    } else {
        CertStatus::Valid
    };

    Some(CertificateInfo {
        hostname: hostname_from_path(dir_name),
        subject_cn: life.subject_cn,
        sans: life.sans,
        not_before: life.not_before,
        not_after: life.not_after,
        total_days: life.total_days,
        remaining_days: life.remaining_days,
        status,
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

        let certs = scan_certificates(tmp.path()).await;
        // The bad one is dropped; the good one still lists.
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hostname, "good.example");
    }
}
