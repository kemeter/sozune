//! Build cheti DNS providers from `AcmeConfig` resolver entries.

use cheti::{
    CloudflareConfig, CloudflareProvider, DnsProvider, GandiConfig, GandiProvider, OvhConfig,
    OvhProvider, ScalewayConfig, ScalewayProvider,
};

use crate::config::{AcmeConfig, ProviderConfig, ResolverConfig};

/// What kind of ACME challenge to run for a given hostname.
pub enum Resolver {
    Http01,
    Dns01(Box<dyn DnsProvider>),
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
    }
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
            endpoint: _,
            application_key_env,
            application_secret_env,
            consumer_key_env,
        } => {
            let app_key = read_env(application_key_env)?;
            let app_secret = read_env(application_secret_env)?;
            let consumer_key = read_env(consumer_key_env)?;
            let provider = OvhProvider::new(OvhConfig::new(app_key, app_secret, consumer_key))
                .map_err(|e| anyhow::anyhow!("build OVH provider: {e}"))?;
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
            resolvers: HashMap::new(),
        }
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
