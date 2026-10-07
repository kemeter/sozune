//! Certificates supplied by the operator as files, outside ACME.
//!
//! Each `proxy.https.tls.certificates` entry points at a PEM certificate chain
//! and its private key — a wildcard issued by certbot, a purchased certificate,
//! an internal PKI. They are read and checked once at startup, then handed to
//! the HTTPS worker like an ACME certificate. Sōzu picks the certificate by the
//! SNI of each handshake, so no route references them: a `tls=true` route whose
//! hostname they cover is served with them, and ACME leaves that hostname alone.
//!
//! Every problem is fatal: a path that cannot be read, a key that does not
//! belong to the certificate or an expired certificate would otherwise leave
//! the hostname failing its handshakes with nothing in the logs saying why.

use std::path::Path;

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::sign::CertifiedKey;

use crate::acme::{CertCommand, split_pem_chain};
use crate::config::CertificateFile;

/// A certificate read from disk and checked, ready for the HTTPS worker.
#[derive(Debug, Clone)]
pub struct ManualCertificate {
    /// The `cert_file` it was read from, for log lines.
    pub cert_file: String,
    /// DNS names the certificate covers (its SANs, or its CN without SANs).
    pub names: Vec<String>,
    pub cert_pem: String,
    pub chain: Vec<String>,
    pub key_pem: String,
}

impl ManualCertificate {
    pub fn to_command(&self) -> CertCommand {
        CertCommand {
            names: self.names.clone(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            chain: self.chain.clone(),
            accepted: None,
        }
    }
}

/// Read and check every configured certificate, failing on the first problem.
pub fn load_all(entries: &[CertificateFile]) -> anyhow::Result<Vec<ManualCertificate>> {
    entries.iter().map(load).collect()
}

fn load(entry: &CertificateFile) -> anyhow::Result<ManualCertificate> {
    let cert_chain_pem = read(&entry.cert_file, "cert_file")?;
    let key_pem = read(&entry.key_file, "key_file")?;

    let names = check(&cert_chain_pem, &key_pem).with_context(|| {
        format!(
            "invalid certificate in proxy.https.tls.certificates ({})",
            entry.cert_file
        )
    })?;

    let (cert_pem, chain) = split_pem_chain(&cert_chain_pem);
    Ok(ManualCertificate {
        cert_file: entry.cert_file.clone(),
        names,
        cert_pem,
        chain,
        key_pem,
    })
}

fn read(path: &str, field: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("could not read {field} `{path}` in proxy.https.tls.certificates"))
}

/// Check that the certificate parses, is not expired, names at least one host
/// and matches the key. Returns the names it covers.
fn check(cert_chain_pem: &str, key_pem: &str) -> anyhow::Result<Vec<String>> {
    let life = cheti::cert_lifetime(cert_chain_pem)
        .map_err(|e| anyhow::anyhow!("cannot parse the certificate: {e}"))?;

    // Exact timestamps: `remaining_days` is truncated to whole days, so it
    // still reads 0 for a certificate that expired hours ago.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    if life.not_after < now {
        anyhow::bail!("the certificate has expired");
    }
    if life.not_before > now {
        anyhow::bail!("the certificate is not valid yet");
    }

    // Lowercased: Sōzu looks names up bytewise, while SNI and hostnames are
    // compared case-insensitively — `App.Example.com` must still serve
    // `app.example.com`.
    let names: Vec<String> = if life.sans.is_empty() {
        life.subject_cn.into_iter().collect()
    } else {
        life.sans
    }
    .into_iter()
    .map(|name| name.to_ascii_lowercase())
    .collect();
    if names.is_empty() {
        anyhow::bail!("the certificate names no host (no DNS SAN and no CN)");
    }

    let chain = CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("cannot parse the certificate chain: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot parse the private key: {e}"))?;
    CertifiedKey::from_der(chain, key, &rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|e| anyhow::anyhow!("the private key does not match the certificate: {e}"))?;

    Ok(names)
}

/// Whether any of `names` covers `hostname`.
pub fn covered(names: &[String], hostname: &str) -> bool {
    names.iter().any(|name| covers(name, hostname))
}

/// Whether a certificate name covers `hostname`: an exact match, or a `*.`
/// wildcard over exactly one label. A wildcard hostname is only covered by the
/// same wildcard. Case-insensitive, as DNS names are.
pub fn covers(name: &str, hostname: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    if name == hostname {
        return true;
    }

    let Some(suffix) = name.strip_prefix("*.") else {
        return false;
    };
    match hostname.split_once('.') {
        Some((label, rest)) => !label.is_empty() && label != "*" && rest == suffix,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn self_signed(names: &[&str]) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write_pair(dir: &Path, cert: &str, key: &str) -> CertificateFile {
        let cert_file = dir.join("fullchain.pem");
        let key_file = dir.join("privkey.pem");
        std::fs::write(&cert_file, cert).unwrap();
        std::fs::write(&key_file, key).unwrap();
        CertificateFile {
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
        }
    }

    #[test]
    fn a_valid_pair_is_loaded_with_its_sans() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = self_signed(&["*.example.com", "example.com"]);
        let entry = write_pair(dir.path(), &cert, &key);

        let loaded = load_all(&[entry]).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].names, vec!["*.example.com", "example.com"]);
        assert!(loaded[0].chain.is_empty());
    }

    #[test]
    fn names_are_lowercased_for_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = self_signed(&["App.Example.com"]);
        let entry = write_pair(dir.path(), &cert, &key);

        let loaded = load_all(&[entry]).unwrap();

        assert_eq!(loaded[0].names, vec!["app.example.com"]);
    }

    #[test]
    fn a_key_from_another_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = self_signed(&["example.com"]);
        let (_, other_key) = self_signed(&["example.com"]);
        let entry = write_pair(dir.path(), &cert, &other_key);

        let err = format!("{:#}", load_all(&[entry]).unwrap_err());

        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let entry = write_pair(dir.path(), &cert.pem(), &key.serialize_pem());

        let err = format!("{:#}", load_all(&[entry]).unwrap_err());

        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn a_certificate_expired_within_the_last_day_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(30);
        params.not_after = now - time::Duration::hours(1);
        let cert = params.self_signed(&key).unwrap();
        let entry = write_pair(dir.path(), &cert.pem(), &key.serialize_pem());

        let err = format!("{:#}", load_all(&[entry]).unwrap_err());

        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn a_certificate_not_valid_yet_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::days(1);
        params.not_after = now + time::Duration::days(90);
        let cert = params.self_signed(&key).unwrap();
        let entry = write_pair(dir.path(), &cert.pem(), &key.serialize_pem());

        let err = format!("{:#}", load_all(&[entry]).unwrap_err());

        assert!(err.contains("not valid yet"), "{err}");
    }

    #[test]
    fn a_missing_file_names_the_field_and_path() {
        let entry = CertificateFile {
            cert_file: "/nonexistent/fullchain.pem".to_string(),
            key_file: "/nonexistent/privkey.pem".to_string(),
        };

        let err = format!("{:#}", load_all(&[entry]).unwrap_err());

        assert!(
            err.contains("cert_file `/nonexistent/fullchain.pem`"),
            "{err}"
        );
    }

    #[test]
    fn a_file_without_a_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = self_signed(&["example.com"]);
        let entry = write_pair(dir.path(), "not a certificate", &key);

        assert!(load_all(&[entry]).is_err());
    }

    #[test]
    fn exact_names_cover_themselves_case_insensitively() {
        assert!(covers("app.example.com", "app.example.com"));
        assert!(covers("App.Example.com", "app.example.COM"));
        assert!(!covers("app.example.com", "api.example.com"));
    }

    #[test]
    fn a_wildcard_covers_one_label() {
        assert!(covers("*.example.com", "app.example.com"));
        assert!(covers("*.example.com", "*.example.com"));
        assert!(!covers("*.example.com", "example.com"));
        assert!(!covers("*.example.com", "a.b.example.com"));
        assert!(!covers("*.example.com", "app.example.org"));
    }

    #[test]
    fn a_plain_name_does_not_cover_a_wildcard_hostname() {
        assert!(!covers("app.example.com", "*.example.com"));
    }
}
