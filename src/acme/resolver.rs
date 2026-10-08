//! Build cheti DNS providers from `AcmeConfig` resolver entries.

use cheti::{
    CloudflareConfig, CloudflareProvider, DesecConfig, DesecProvider, DigitalOceanConfig,
    DigitalOceanProvider, DnsProvider, GandiConfig, GandiProvider, HetznerConfig, HetznerProvider,
    InfomaniakConfig, InfomaniakProvider, OvhConfig, OvhProvider, PorkbunConfig, PorkbunProvider,
    Rfc2136Config, Rfc2136Provider, ScalewayConfig, ScalewayProvider, TsigAlgorithm,
};

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

fn build_provider(cfg: &ProviderConfig) -> anyhow::Result<Box<dyn DnsProvider>> {
    match cfg {
        ProviderConfig::Cloudflare { api_token_env } => {
            let token = read_env(api_token_env)?;
            let provider = CloudflareProvider::new(CloudflareConfig::new(token))
                .map_err(|e| anyhow::anyhow!("build Cloudflare provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Ovh {
            endpoint,
            application_key_env,
            application_secret_env,
            consumer_key_env,
        } => {
            let api_base = ovh_api_base(endpoint)?;
            let app_key = read_env(application_key_env)?;
            let app_secret = read_env(application_secret_env)?;
            let consumer_key = read_env(consumer_key_env)?;
            let config = OvhConfig::new(app_key, app_secret, consumer_key)
                .with_api_base(api_base)
                .map_err(|e| anyhow::anyhow!("OVH endpoint `{endpoint}`: {e}"))?;
            let provider =
                OvhProvider::new(config).map_err(|e| anyhow::anyhow!("build OVH provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Gandi {
            personal_access_token_env,
        } => {
            let pat = read_env(personal_access_token_env)?;
            let provider = GandiProvider::new(GandiConfig::new(pat))
                .map_err(|e| anyhow::anyhow!("build Gandi provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Scaleway { secret_key_env } => {
            let key = read_env(secret_key_env)?;
            let provider = ScalewayProvider::new(ScalewayConfig::new(key))
                .map_err(|e| anyhow::anyhow!("build Scaleway provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Desec { token_env } => {
            let token = read_env(token_env)?;
            let provider = DesecProvider::new(DesecConfig::new(token))
                .map_err(|e| anyhow::anyhow!("build deSEC provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::DigitalOcean { token_env } => {
            let token = read_env(token_env)?;
            let provider = DigitalOceanProvider::new(DigitalOceanConfig::new(token))
                .map_err(|e| anyhow::anyhow!("build DigitalOcean provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Hetzner { api_token_env } => {
            let token = read_env(api_token_env)?;
            let provider = HetznerProvider::new(HetznerConfig::new(token))
                .map_err(|e| anyhow::anyhow!("build Hetzner provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Infomaniak { access_token_env } => {
            let token = read_env(access_token_env)?;
            let provider = InfomaniakProvider::new(InfomaniakConfig::new(token))
                .map_err(|e| anyhow::anyhow!("build Infomaniak provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Porkbun {
            api_key_env,
            secret_api_key_env,
        } => {
            let api_key = read_env(api_key_env)?;
            let secret_api_key = read_env(secret_api_key_env)?;
            let provider = PorkbunProvider::new(PorkbunConfig::new(api_key, secret_api_key))
                .map_err(|e| anyhow::anyhow!("build Porkbun provider: {e}"))?;
            Ok(Box::new(provider))
        }
        ProviderConfig::Rfc2136 {
            nameserver,
            tsig_key,
            tsig_secret_env,
            tsig_algorithm,
            zone,
        } => {
            let secret = read_env(tsig_secret_env)?;
            let mut config = Rfc2136Config::new(nameserver, tsig_key, secret);
            if let Some(algorithm) = tsig_algorithm {
                let algorithm: TsigAlgorithm = algorithm
                    .parse()
                    .map_err(|e| anyhow::anyhow!("RFC 2136 tsig_algorithm `{algorithm}`: {e}"))?;
                config = config.with_algorithm(algorithm);
            }
            if let Some(zone) = zone {
                config = config
                    .with_zone(zone)
                    .map_err(|e| anyhow::anyhow!("RFC 2136 zone `{zone}`: {e}"))?;
            }
            let provider = Rfc2136Provider::new(config)
                .map_err(|e| anyhow::anyhow!("build RFC 2136 provider: {e}"))?;
            Ok(Box::new(provider))
        }
    }
}

/// API base of an OVHcloud region, named as in OVH's own SDKs. Credentials
/// belong to one region, so the wrong base fails every call.
fn ovh_api_base(endpoint: &str) -> anyhow::Result<&'static str> {
    match endpoint {
        "ovh-eu" => Ok("https://eu.api.ovh.com/1.0"),
        "ovh-ca" => Ok("https://ca.api.ovh.com/1.0"),
        "ovh-us" => Ok("https://api.us.ovhcloud.com/1.0"),
        other => {
            anyhow::bail!("unknown OVH endpoint `{other}`: expected `ovh-eu`, `ovh-ca` or `ovh-us`")
        }
    }
}

fn read_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable `{}` is not set", name))
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

    #[test]
    fn every_new_provider_type_parses_and_builds() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("TEST_DNS_TOKEN", "token"),
            ("TEST_DNS_SECRET", "c2VjcmV0LWtleS1mb3ItdHNpZw=="),
        ]);

        for yaml in [
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
                Err(e) => panic!("{yaml}: {e}"),
            };
            assert!(resolver.supports_wildcard(), "{yaml}");
        }
    }

    #[test]
    fn rfc2136_rejects_an_unknown_algorithm() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("TEST_DNS_SECRET", "c2VjcmV0LWtleS1mb3ItdHNpZw==")]);
        let acme = dns01_from_yaml(
            "type: rfc2136\nnameserver: 192.0.2.53\ntsig_key: acme-update\ntsig_secret_env: TEST_DNS_SECRET\ntsig_algorithm: hmac-md5",
        );

        let err = match build_resolver(Some("dns"), &acme) {
            Ok(_) => panic!("expected an error for hmac-md5"),
            Err(e) => e,
        };

        assert!(
            err.to_string().contains("tsig_algorithm `hmac-md5`"),
            "{err}"
        );
    }

    #[test]
    fn ovh_endpoints_map_to_their_region() {
        assert_eq!(
            ovh_api_base("ovh-eu").unwrap(),
            "https://eu.api.ovh.com/1.0"
        );
        assert_eq!(
            ovh_api_base("ovh-ca").unwrap(),
            "https://ca.api.ovh.com/1.0"
        );
        assert_eq!(
            ovh_api_base("ovh-us").unwrap(),
            "https://api.us.ovhcloud.com/1.0"
        );
    }

    #[test]
    fn unknown_ovh_endpoint_is_refused() {
        let mut acme = empty_acme();
        acme.resolvers.insert(
            "ovh".to_string(),
            ResolverConfig::Dns01 {
                provider: ProviderConfig::Ovh {
                    endpoint: "ovh-asia".to_string(),
                    application_key_env: "TEST_OVH_KEY".to_string(),
                    application_secret_env: "TEST_OVH_SECRET".to_string(),
                    consumer_key_env: "TEST_OVH_CONSUMER".to_string(),
                },
                domains: vec![],
                ca_server: None,
            },
        );

        let err = match build_resolver(Some("ovh"), &acme) {
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
        // Ensure the var is absent for this test.
        unsafe { std::env::remove_var("TEST_CF_TOKEN_MISSING") };

        let mut acme = empty_acme();
        acme.resolvers.insert(
            "cf".to_string(),
            ResolverConfig::Dns01 {
                provider: ProviderConfig::Cloudflare {
                    api_token_env: "TEST_CF_TOKEN_MISSING".to_string(),
                },
                domains: vec![],
                ca_server: None,
            },
        );
        let err = match build_resolver(Some("cf"), &acme) {
            Ok(_) => panic!("expected error when env var missing"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("TEST_CF_TOKEN_MISSING"),
            "error should name the missing env var, got: {err}"
        );
    }

    #[test]
    fn dns01_cloudflare_builds_when_env_present() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[("TEST_CF_TOKEN_PRESENT", "dummy-token")]);

        let mut acme = empty_acme();
        acme.resolvers.insert(
            "cf".to_string(),
            ResolverConfig::Dns01 {
                provider: ProviderConfig::Cloudflare {
                    api_token_env: "TEST_CF_TOKEN_PRESENT".to_string(),
                },
                domains: vec![],
                ca_server: None,
            },
        );
        let resolver = build_resolver(Some("cf"), &acme).unwrap().unwrap();
        assert!(resolver.supports_wildcard());
        assert!(matches!(resolver, Resolver::Dns01(_)));
    }
}
