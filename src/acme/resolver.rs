//! Build cheti DNS providers from `AcmeConfig` resolver entries.

use cheti::DnsProvider;

use crate::config::{AcmeConfig, ProviderConfig, ResolverConfig};

/// What kind of ACME challenge to run for a given hostname.
pub enum Resolver {
    Http01,
    Dns01(Box<dyn DnsProvider>),
    /// TLS-ALPN-01 (RFC 8737): answered over the TLS handshake on 443. The
    /// challenge certificate is served by the shared responder the ACME
    /// manager holds, so this variant carries no state of its own.
    TlsAlpn01,
}

/// Resolve a resolver name from `AcmeConfig.resolvers` and build it.
/// Returns `Ok(None)` if `name` is `None` (caller will fall back to the
/// legacy HTTP-01 challenge port).
pub fn build_resolver(name: Option<&str>, acme: &AcmeConfig) -> anyhow::Result<Option<Resolver>> {
    let Some(name) = name else {
        return Ok(None);
    };

    let Some(cfg) = acme.resolvers.get(name) else {
        anyhow::bail!("unknown ACME resolver `{}`", name);
    };

    match cfg {
        ResolverConfig::Http01 { .. } => Ok(Some(Resolver::Http01)),
        ResolverConfig::Dns01 { provider, .. } => {
            Ok(Some(Resolver::Dns01(build_provider(provider)?)))
        }
        ResolverConfig::TlsAlpn01 { .. } => Ok(Some(Resolver::TlsAlpn01)),
    }
}

/// Build every DNS-01 resolver once, and return those that cannot be built,
/// sorted by name. A resolver is otherwise only built when a certificate is
/// ordered through it: a missing env var or an invalid field would then fail
/// each order in turn, long after startup. Building opens no connection.
pub fn unusable_resolvers(acme: &AcmeConfig) -> Vec<(String, anyhow::Error)> {
    let mut unusable: Vec<(String, anyhow::Error)> = acme
        .resolvers
        .iter()
        .filter_map(|(name, cfg)| match cfg {
            ResolverConfig::Dns01 { provider, .. } => {
                build_provider(provider).err().map(|e| (name.clone(), e))
            }
            ResolverConfig::Http01 { .. } | ResolverConfig::TlsAlpn01 { .. } => None,
        })
        .collect();
    unusable.sort_by(|a, b| a.0.cmp(&b.0));
    unusable
}

/// A warning for each DNS-01 resolver written in the `type:` form, sorted
/// by resolver: it still works, as the `name:` and `env:` form it stands
/// for.
pub fn deprecated_providers(acme: &AcmeConfig) -> Vec<String> {
    let mut warnings: Vec<String> = acme
        .resolvers
        .iter()
        .filter_map(|(name, cfg)| match cfg {
            ResolverConfig::Dns01 { provider, .. } if provider.legacy => Some(format!(
                "acme.resolvers.{name}.provider is written in the `type:` form, deprecated since 0.17: write `provider: {}`, with an `env:` map for the variables named otherwise (see UPGRADE.md)",
                provider.name
            )),
            _ => None,
        })
        .collect();
    warnings.sort();
    warnings
}

/// The provider `cfg` names, built by cheti from its variables: cheti's
/// and lego's names for them, or those `cfg.env` names.
fn build_provider(cfg: &ProviderConfig) -> anyhow::Result<Box<dyn DnsProvider>> {
    cheti::providers::from_env_with(&cfg.name, |var| cfg.lookup(var)).map_err(|e| {
        // The variables the config names, rather than the provider's own
        // names for them, are what to set.
        let unset: Vec<&str> = cfg
            .env
            .values()
            .filter(|var| {
                std::env::var(var).is_err() && std::env::var(format!("{var}_FILE")).is_err()
            })
            .map(String::as_str)
            .collect();
        if unset.is_empty() {
            anyhow::anyhow!("build {} provider: {e}", cfg.name)
        } else {
            anyhow::anyhow!(
                "build {} provider: required environment variable `{}` is not set",
                cfg.name,
                unset.join("`, `")
            )
        }
    })
}

impl Resolver {
    /// True if this resolver can validate wildcard hostnames (`*.example.com`).
    pub fn supports_wildcard(&self) -> bool {
        matches!(self, Resolver::Dns01(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, ProviderConfig, ResolverConfig};
    use crate::test_env::ENV_LOCK;
    use std::collections::HashMap;

    struct EnvGuard {
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        fn new(vars: &[(&'static str, &str)]) -> Self {
            let keys = vars.iter().map(|(k, _)| *k).collect();
            unsafe {
                for (k, v) in vars {
                    std::env::set_var(k, v);
                }
            }
            Self { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                for k in &self.keys {
                    std::env::remove_var(k);
                }
            }
        }
    }

    fn empty_acme() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            email: String::new(),
            certs_dir: String::from("/tmp"),
            staging: true,
            challenge_port: 80,
            tls_alpn_port: 3038,
            resolvers: HashMap::new(),
        }
    }

    #[test]
    fn unusable_resolvers_names_each_broken_dns01_resolver() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("TEST_DNS_TOKEN", "token")]);
        let mut acme = empty_acme();
        for (name, yaml) in [
            ("good", "type: desec\ntoken_env: TEST_DNS_TOKEN"),
            ("no-env", "type: hetzner\napi_token_env: TEST_DNS_UNSET_VAR"),
            (
                "bad-endpoint",
                "type: ovh\nendpoint: ovh-asia\napplication_key_env: TEST_DNS_TOKEN\napplication_secret_env: TEST_DNS_TOKEN\nconsumer_key_env: TEST_DNS_TOKEN",
            ),
        ] {
            acme.resolvers.insert(
                name.to_string(),
                ResolverConfig::Dns01 {
                    provider: serde_yaml::from_str(yaml).unwrap(),
                    domains: vec![],
                    ca_server: None,
                },
            );
        }
        acme.resolvers.insert(
            "http".to_string(),
            ResolverConfig::Http01 { ca_server: None },
        );

        let unusable = unusable_resolvers(&acme);

        let names: Vec<&str> = unusable.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["bad-endpoint", "no-env"]);
        assert!(unusable[1].1.to_string().contains("TEST_DNS_UNSET_VAR"));
    }

    #[test]
    fn returns_none_when_name_is_none() {
        let acme = empty_acme();
        assert!(build_resolver(None, &acme).unwrap().is_none());
    }

    #[test]
    fn fails_when_resolver_name_unknown() {
        let acme = empty_acme();
        let err = match build_resolver(Some("nope"), &acme) {
            Ok(_) => panic!("expected error for unknown resolver"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("unknown ACME resolver"));
    }

    #[test]
    fn http01_resolver_does_not_support_wildcard() {
        let mut acme = empty_acme();
        acme.resolvers.insert(
            "legacy".to_string(),
            ResolverConfig::Http01 { ca_server: None },
        );
        let resolver = build_resolver(Some("legacy"), &acme).unwrap().unwrap();
        assert!(!resolver.supports_wildcard());
        assert!(matches!(resolver, Resolver::Http01));
    }

    fn dns01_from_yaml(yaml: &str) -> AcmeConfig {
        let provider: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
        let mut acme = empty_acme();
        acme.resolvers.insert(
            "dns".to_string(),
            ResolverConfig::Dns01 {
                provider,
                domains: vec![],
                ca_server: None,
            },
        );
        acme
    }

    fn built(yaml: &str) -> anyhow::Result<Option<Resolver>> {
        build_resolver(Some("dns"), &dns01_from_yaml(yaml))
    }

    /// Every provider, by its name, its variables under names of the
    /// config's.
    #[test]
    fn providers_build_by_name() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("TEST_DNS_TOKEN", "token"),
            ("TEST_DNS_SECRET", "c2VjcmV0LWtleS1mb3ItdHNpZw=="),
            ("TEST_DNS_URL", "https://pdns.example.com"),
        ]);
        for yaml in [
            "name: cloudflare\nenv: { CLOUDFLARE_API_TOKEN: TEST_DNS_TOKEN }",
            "name: route53\nenv: { AWS_ACCESS_KEY_ID: TEST_DNS_TOKEN, AWS_SECRET_ACCESS_KEY: TEST_DNS_SECRET }",
            "name: bunny\nenv: { BUNNY_API_KEY: TEST_DNS_TOKEN }",
            "name: pdns\nenv: { PDNS_API_URL: TEST_DNS_URL, PDNS_API_KEY: TEST_DNS_TOKEN }",
            "name: scaleway\nenv: { SCW_SECRET_KEY: TEST_DNS_TOKEN }",
            "name: gandiv5\nenv: { GANDIV5_PERSONAL_ACCESS_TOKEN: TEST_DNS_TOKEN }",
        ] {
            match built(yaml) {
                Ok(Some(resolver)) => assert!(resolver.supports_wildcard(), "{yaml}"),
                Ok(None) => panic!("no resolver for {yaml}"),
                Err(e) => panic!("{yaml}: {e:#}"),
            }
        }
    }

    /// A name alone reads the provider's standard variables.
    #[test]
    fn a_name_alone_reads_the_standard_variables() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("DESEC_TOKEN", "token")]);
        assert!(built("desec").unwrap().is_some());
    }

    /// With `env`, a variable left unset is not taken under the provider's
    /// standard name: that may be another account's.
    #[test]
    fn with_env_the_standard_names_are_not_read() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("TEST_DNS_UNSET") };
        let _env = EnvGuard::new(&[("DESEC_TOKEN", "another-accounts-token")]);
        let err = match built("name: desec\nenv: { DESEC_TOKEN: TEST_DNS_UNSET }") {
            Ok(_) => panic!("expected an error for an unset variable"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("TEST_DNS_UNSET"), "{err}");
    }

    #[test]
    fn an_unknown_provider_name_is_refused_with_the_known_ones() {
        let err = serde_yaml::from_str::<ProviderConfig>("azure").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("unknown DNS provider `azure`"),
            "{message}"
        );
        assert!(message.contains("route53"), "{message}");
    }

    /// The `type:` form of before 0.17 still builds, each provider as it
    /// did, and is told deprecated.
    #[test]
    fn the_type_form_still_builds() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("TEST_DNS_TOKEN", "token"),
            ("TEST_DNS_SECRET", "c2VjcmV0LWtleS1mb3ItdHNpZw=="),
        ]);

        for yaml in [
            "type: cloudflare\napi_token_env: TEST_DNS_TOKEN",
            "type: ovh\napplication_key_env: TEST_DNS_TOKEN\napplication_secret_env: TEST_DNS_TOKEN\nconsumer_key_env: TEST_DNS_TOKEN\nendpoint: ovh-ca",
            "type: gandi\npersonal_access_token_env: TEST_DNS_TOKEN",
            "type: scaleway\nsecret_key_env: TEST_DNS_TOKEN",
            "type: desec\ntoken_env: TEST_DNS_TOKEN",
            "type: digitalocean\ntoken_env: TEST_DNS_TOKEN",
            "type: hetzner\napi_token_env: TEST_DNS_TOKEN",
            "type: infomaniak\naccess_token_env: TEST_DNS_TOKEN",
            "type: porkbun\napi_key_env: TEST_DNS_TOKEN\nsecret_api_key_env: TEST_DNS_SECRET",
            "type: rfc2136\nnameserver: 192.0.2.53\ntsig_key: acme-update\ntsig_secret_env: TEST_DNS_SECRET",
            "type: rfc2136\nnameserver: ns.example.com:5353\ntsig_key: acme-update\ntsig_secret_env: TEST_DNS_SECRET\ntsig_algorithm: hmac-sha512\nzone: example.com",
        ] {
            let acme = dns01_from_yaml(yaml);
            let resolver = match build_resolver(Some("dns"), &acme) {
                Ok(Some(resolver)) => resolver,
                Ok(None) => panic!("no resolver for {yaml}"),
                Err(e) => panic!("{yaml}: {e:#}"),
            };
            assert!(resolver.supports_wildcard(), "{yaml}");
            let warnings = deprecated_providers(&acme);
            assert_eq!(warnings.len(), 1, "{yaml}");
            assert!(
                warnings[0].contains("acme.resolvers.dns.provider"),
                "{yaml}"
            );
        }
        assert!(deprecated_providers(&dns01_from_yaml("desec")).is_empty());
    }

    #[test]
    fn rfc2136_rejects_an_unknown_algorithm() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("TEST_DNS_SECRET", "c2VjcmV0LWtleS1mb3ItdHNpZw==")]);
        let err = match built(
            "type: rfc2136\nnameserver: 192.0.2.53\ntsig_key: acme-update\ntsig_secret_env: TEST_DNS_SECRET\ntsig_algorithm: hmac-md5",
        ) {
            Ok(_) => panic!("expected an error for hmac-md5"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("hmac-md5"), "{err}");
    }

    #[test]
    fn unknown_ovh_endpoint_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("TEST_DNS_TOKEN", "token")]);
        let err = match built(
            "type: ovh\nendpoint: ovh-asia\napplication_key_env: TEST_DNS_TOKEN\napplication_secret_env: TEST_DNS_TOKEN\nconsumer_key_env: TEST_DNS_TOKEN",
        ) {
            Ok(_) => panic!("expected an error for ovh-asia"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("unknown OVH endpoint `ovh-asia`"),
            "{err}"
        );
    }

    #[test]
    fn dns01_resolver_fails_when_env_missing() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("TEST_CF_TOKEN_MISSING") };
        let err = match built("type: cloudflare\napi_token_env: TEST_CF_TOKEN_MISSING") {
            Ok(_) => panic!("expected error when env var missing"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("TEST_CF_TOKEN_MISSING"),
            "error should name the missing env var, got: {err}"
        );
    }
}
