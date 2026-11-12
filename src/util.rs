//! Small cross-module helpers (fuzzy matching, debug-mode flag, HTTP client).

pub mod fuzzy {
    /// Find the closest match in `haystack` for `needle`. Returns `None` if
    /// nothing is close enough. Substring containment in either direction is
    /// treated as distance 1 so cases like `timeout` → `backendTimeout` work
    /// even though raw Levenshtein distance is large.
    pub fn closest_match<'a>(
        needle: &str,
        haystack: &'a [&'a str],
        max_distance: usize,
    ) -> Option<&'a str> {
        let needle_lower = needle.to_lowercase();
        let mut best: Option<(&str, usize)> = None;
        for &candidate in haystack {
            let candidate_lower = candidate.to_lowercase();
            let d = if candidate_lower.contains(&needle_lower)
                || needle_lower.contains(&candidate_lower)
            {
                1
            } else {
                levenshtein(&needle_lower, &candidate_lower)
            };
            if d <= max_distance && best.is_none_or(|(_, bd)| d < bd) {
                best = Some((candidate, d));
            }
        }
        best.map(|(s, _)| s)
    }

    pub fn levenshtein(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let (n, m) = (a.len(), b.len());
        if n == 0 {
            return m;
        }
        if m == 0 {
            return n;
        }
        let mut prev: Vec<usize> = (0..=m).collect();
        let mut curr = vec![0usize; m + 1];
        for i in 1..=n {
            curr[0] = i;
            for j in 1..=m {
                let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
                curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }
        prev[m]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn levenshtein_basics() {
            assert_eq!(levenshtein("", ""), 0);
            assert_eq!(levenshtein("abc", ""), 3);
            assert_eq!(levenshtein("", "abc"), 3);
            assert_eq!(levenshtein("abc", "abc"), 0);
            assert_eq!(levenshtein("abc", "abd"), 1);
            assert_eq!(levenshtein("kitten", "sitting"), 3);
        }

        #[test]
        fn closest_uses_substring_for_long_candidates() {
            let opts = ["backendTimeout", "port"];
            assert_eq!(closest_match("timeout", &opts, 2), Some("backendTimeout"));
        }

        #[test]
        fn closest_returns_none_when_far_off() {
            let opts = ["port", "host"];
            assert!(closest_match("xyzzy", &opts, 2).is_none());
        }

        #[test]
        fn closest_picks_shortest_distance() {
            let opts = ["port", "host", "path"];
            assert_eq!(closest_match("prt", &opts, 2), Some("port"));
        }
    }
}

/// Returns `true` when `SOZUNE_DEBUG` is on, read as any boolean variable.
/// Used to gate verbose runtime diagnostics that may leak configured hostnames
/// or backend addresses.
pub fn debug_enabled() -> bool {
    crate::config::env_bool("SOZUNE_DEBUG").unwrap_or(false)
}

/// The files of a client TLS setup: a CA to trust and a client certificate.
pub mod client_tls {
    use crate::config::ClientTlsFiles;
    use anyhow::Context as _;

    /// The client certificate and key, when both are set.
    pub fn client_identity(tls: &ClientTlsFiles) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
        match (&tls.cert, &tls.key) {
            (Some(cert), Some(key)) => Ok(Some((read(cert, "tls.cert")?, read(key, "tls.key")?))),
            (None, None) => Ok(None),
            _ => anyhow::bail!("tls.cert and tls.key must be set together"),
        }
    }

    fn read(path: &str, field: &str) -> anyhow::Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("could not read {field} at {path}"))
    }

    /// `tls.ca`, which must hold at least one certificate, all usable as trust
    /// roots: the clients skip an invalid one silently, which would leave the
    /// server's CA untrusted and every connection failing.
    pub fn read_ca(path: &str) -> anyhow::Result<Vec<u8>> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let pem = read(path, "tls.ca")?;
        let certs = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("invalid PEM in tls.ca at {path}"))?;
        if certs.is_empty() {
            anyhow::bail!("tls.ca at {path} holds no PEM certificate");
        }
        let (_, ignored) = rustls::RootCertStore::empty().add_parsable_certificates(certs);
        if ignored > 0 {
            anyhow::bail!("tls.ca at {path} holds a certificate that is not a valid CA");
        }
        Ok(pem)
    }
}

pub mod http_client {
    use std::sync::OnceLock;

    /// A `reqwest` client builder that works on a host without CA
    /// certificates.
    ///
    /// `reqwest` verifies certificates against the system store and refuses
    /// to build a client when that store is empty (a minimal image without
    /// `ca-certificates`), even a client that only speaks plain HTTP. When the
    /// store is empty, this builder trusts the bundled Mozilla roots instead,
    /// so the client builds and public HTTPS endpoints still verify. Every
    /// `reqwest` client of Sōzune starts from here.
    pub fn builder() -> reqwest::ClientBuilder {
        let builder = reqwest::Client::builder();
        if system_store_is_empty() {
            builder.tls_certs_only(bundled_roots())
        } else {
            builder
        }
    }

    /// Same as [`builder`], for a blocking client.
    pub fn blocking_builder() -> reqwest::blocking::ClientBuilder {
        let builder = reqwest::blocking::Client::builder();
        if system_store_is_empty() {
            builder.tls_certs_only(bundled_roots())
        } else {
            builder
        }
    }

    /// Whether the system has no CA certificate. Read once and logged once:
    /// clients are built at startup and on reloads.
    pub fn system_store_is_empty() -> bool {
        static EMPTY: OnceLock<bool> = OnceLock::new();
        *EMPTY.get_or_init(|| {
            let empty = rustls_native_certs::load_native_certs().certs.is_empty();
            if empty {
                tracing::warn!(
                    "no CA certificates found on the system, trusting the bundled Mozilla roots for outgoing HTTPS"
                );
            }
            empty
        })
    }

    /// The bundled Mozilla roots, for a `rustls` client.
    pub fn bundled_root_store() -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        roots
    }

    fn bundled_roots() -> Vec<reqwest::Certificate> {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|der| reqwest::Certificate::from_der(der).ok())
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bundled_roots_parse() {
            assert!(bundled_roots().len() > 100);
        }

        #[test]
        fn bundled_root_store_is_not_empty() {
            assert!(bundled_root_store().len() > 100);
        }

        #[test]
        fn client_with_only_the_bundled_roots_builds() {
            let client = reqwest::Client::builder()
                .tls_certs_only(bundled_roots())
                .build();
            assert!(client.is_ok(), "{:?}", client.err());
        }
    }
}
