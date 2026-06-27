//! `GET /config` — read-only view of the running configuration.
//!
//! Returns the parts of `AppConfig` that operators want to introspect from
//! the dashboard: listener ports, ACME settings, providers, the dashboard
//! listener. Carefully avoids leaking:
//!
//! - `api.users[].hash` — even SHA-256 of a weak password can be brute-forced
//!   offline. We don't expose the user list at all.
//! - Resolver credentials — only the *names* of the env vars referenced by
//!   ACME resolvers travel; the values stay on the process.
//!
//! The view is its own struct (not a re-export of `AppConfig`) so a new
//! sensitive field added to the config doesn't silently cascade into the
//! response payload.

use crate::api::server::AppState;
use crate::config::{
    AcmeConfig, ApiConfig, AppConfig, ProvidersConfig, ProxyConfig, ResolverConfig,
};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct ConfigView {
    pub version: &'static str,
    pub listeners: ListenersView,
    pub acme: Option<AcmeView>,
    pub providers: ProvidersView,
    pub dashboard: DashboardView,
    pub api: ApiView,
}

#[derive(Debug, Serialize)]
pub struct ListenersView {
    pub http: PortView,
    pub https: PortView,
}

#[derive(Debug, Serialize)]
pub struct PortView {
    pub port: u16,
}

#[derive(Debug, Serialize)]
pub struct AcmeView {
    pub enabled: bool,
    pub email: String,
    pub staging: bool,
    pub challenge_port: u16,
    /// Resolver names → safe summary (challenge type + which env vars are
    /// required). Never the env values themselves.
    pub resolvers: HashMap<String, ResolverView>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "challenge", rename_all = "kebab-case")]
pub enum ResolverView {
    Http01 {
        ca_server: Option<String>,
    },
    Dns01 {
        provider: &'static str,
        required_env: Vec<&'static str>,
        domains: Vec<String>,
        ca_server: Option<String>,
    },
}

#[derive(Debug, Serialize)]
pub struct ProvidersView {
    pub docker: Option<DockerView>,
    pub podman: Option<DockerView>,
    pub swarm: Option<DockerView>,
    pub kubernetes: Option<ToggleView>,
    pub nomad: Option<ToggleView>,
    pub consul: Option<ToggleView>,
    pub config_file: Option<ConfigFileView>,
    pub http: Option<HttpProviderView>,
}

#[derive(Debug, Serialize)]
pub struct DockerView {
    pub enabled: bool,
    pub endpoint: String,
    pub expose_by_default: bool,
}

#[derive(Debug, Serialize)]
pub struct ToggleView {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ConfigFileView {
    pub enabled: bool,
    pub path: String,
    pub watch: bool,
}

#[derive(Debug, Serialize)]
pub struct HttpProviderView {
    pub enabled: bool,
    pub url: String,
    pub poll_interval: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardView {
    pub enabled: bool,
    pub listen_address: String,
}

/// `api.users` is deliberately absent from this view — even a hashed user
/// list lets an attacker do an offline dictionary attack. We only expose
/// the listen address and CORS origins.
#[derive(Debug, Serialize)]
pub struct ApiView {
    pub enabled: bool,
    pub listen_address: String,
    pub cors_origins: Vec<String>,
}

impl ConfigView {
    pub fn from_app_config(cfg: &AppConfig) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            listeners: listeners_view(&cfg.proxy),
            acme: cfg.acme.as_ref().map(acme_view),
            providers: providers_view(&cfg.providers),
            dashboard: DashboardView {
                enabled: cfg.dashboard.enabled,
                listen_address: cfg.dashboard.listen_address.clone(),
            },
            api: api_view(&cfg.api),
        }
    }
}

fn listeners_view(proxy: &ProxyConfig) -> ListenersView {
    ListenersView {
        http: PortView {
            port: proxy.http.listen_address,
        },
        https: PortView {
            port: proxy.https.listen_address,
        },
    }
}

fn acme_view(acme: &AcmeConfig) -> AcmeView {
    let resolvers = acme
        .resolvers
        .iter()
        .map(|(name, r)| (name.clone(), resolver_view(r)))
        .collect();
    AcmeView {
        enabled: acme.enabled,
        email: acme.email.clone(),
        staging: acme.staging,
        challenge_port: acme.challenge_port,
        resolvers,
    }
}

fn resolver_view(r: &ResolverConfig) -> ResolverView {
    use crate::config::ProviderConfig::*;
    match r {
        ResolverConfig::Http01 { ca_server } => ResolverView::Http01 {
            ca_server: ca_server.clone(),
        },
        ResolverConfig::Dns01 {
            provider,
            domains,
            ca_server,
        } => {
            let (name, required_env) = match provider {
                Cloudflare { .. } => ("cloudflare", vec!["CLOUDFLARE_API_TOKEN (configurable)"]),
                Ovh { .. } => (
                    "ovh",
                    vec![
                        "OVH_APPLICATION_KEY (configurable)",
                        "OVH_APPLICATION_SECRET (configurable)",
                        "OVH_CONSUMER_KEY (configurable)",
                    ],
                ),
                Gandi { .. } => ("gandi", vec!["GANDI_PAT (configurable)"]),
                Scaleway { .. } => ("scaleway", vec!["SCALEWAY_SECRET (configurable)"]),
            };
            ResolverView::Dns01 {
                provider: name,
                required_env,
                domains: domains.clone(),
                ca_server: ca_server.clone(),
            }
        }
    }
}

fn providers_view(p: &ProvidersConfig) -> ProvidersView {
    ProvidersView {
        docker: p.docker.as_ref().map(|d| DockerView {
            enabled: d.enabled,
            endpoint: d.endpoint.clone(),
            expose_by_default: d.expose_by_default,
        }),
        podman: p.podman.as_ref().map(|d| DockerView {
            enabled: d.enabled,
            endpoint: d.endpoint.clone(),
            expose_by_default: d.expose_by_default,
        }),
        swarm: p.swarm.as_ref().map(|d| DockerView {
            enabled: d.enabled,
            endpoint: d.endpoint.clone(),
            expose_by_default: d.expose_by_default,
        }),
        kubernetes: p
            .kubernetes
            .as_ref()
            .map(|k| ToggleView { enabled: k.enabled }),
        nomad: p.nomad.as_ref().map(|n| ToggleView { enabled: n.enabled }),
        consul: p.consul.as_ref().map(|c| ToggleView { enabled: c.enabled }),
        config_file: p.config_file.as_ref().map(|f| ConfigFileView {
            enabled: f.enabled,
            path: f.path.clone(),
            watch: f.watch,
        }),
        http: p.http.as_ref().map(|h| HttpProviderView {
            enabled: h.enabled,
            url: h.url.clone(),
            poll_interval: h.poll_interval,
        }),
    }
}

fn api_view(api: &ApiConfig) -> ApiView {
    ApiView {
        enabled: api.enabled,
        listen_address: api.listen_address.clone(),
        cors_origins: api.cors_origins.clone(),
    }
}

pub async fn config(State(state): State<AppState>) -> (StatusCode, Json<ConfigView>) {
    (
        StatusCode::OK,
        Json(ConfigView::from_app_config(&state.config)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::collections::HashMap;

    fn sample_app_config() -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.providers.docker = Some(DockerConfig {
            enabled: true,
            endpoint: "unix:///var/run/docker.sock".into(),
            expose_by_default: false,
        });
        cfg.providers.config_file = Some(ConfigFileConfig {
            enabled: true,
            path: "/etc/sozune/entrypoints.yaml".into(),
            watch: true,
        });
        cfg.api.enabled = true;
        cfg.api.listen_address = "0.0.0.0:3035".into();
        cfg.api.users = vec![ApiUser {
            name: "admin".into(),
            hash: "very-secret-hash-DO-NOT-LEAK".into(),
            role: Role::Admin,
        }];
        cfg.api.cors_origins = vec!["https://dashboard.example.com".into()];
        cfg.proxy.http.listen_address = 80;
        cfg.proxy.https.listen_address = 443;
        cfg.acme = Some(AcmeConfig {
            enabled: true,
            email: "ops@example.com".into(),
            certs_dir: "/var/lib/sozune/certs".into(),
            staging: true,
            challenge_port: 8080,
            resolvers: HashMap::new(),
        });
        cfg.dashboard.enabled = true;
        cfg.dashboard.listen_address = "0.0.0.0:3038".into();
        cfg
    }

    #[test]
    fn view_does_not_leak_user_hashes() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        let json = serde_json::to_string(&view).unwrap();
        // The hash must never appear in the serialized payload, no matter how
        // the view evolves.
        assert!(
            !json.contains("very-secret-hash-DO-NOT-LEAK"),
            "user hash leaked to /config payload: {json}"
        );
        assert!(
            !json.contains("\"users\""),
            "user list must not be in /config payload"
        );
    }

    #[test]
    fn view_exposes_listener_ports() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        assert_eq!(view.listeners.http.port, 80);
        assert_eq!(view.listeners.https.port, 443);
    }

    #[test]
    fn view_exposes_provider_endpoints() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        let docker = view.providers.docker.expect("docker should be present");
        assert_eq!(docker.endpoint, "unix:///var/run/docker.sock");
        assert!(docker.enabled);
    }

    #[test]
    fn view_carries_running_version() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        assert_eq!(view.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn view_includes_acme_when_configured() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        let acme = view.acme.expect("acme should be exposed");
        assert!(acme.enabled);
        assert_eq!(acme.email, "ops@example.com");
        assert!(acme.staging);
    }

    #[test]
    fn view_omits_acme_when_not_configured() {
        let mut cfg = sample_app_config();
        cfg.acme = None;
        let view = ConfigView::from_app_config(&cfg);
        assert!(view.acme.is_none());
    }

    #[test]
    fn view_exposes_dashboard_listener_but_not_credentials() {
        let cfg = sample_app_config();
        let view = ConfigView::from_app_config(&cfg);
        assert!(view.dashboard.enabled);
        assert_eq!(view.dashboard.listen_address, "0.0.0.0:3038");
        // API listener IS in the view (operators need to know it), but no
        // user list, no hash.
        assert_eq!(view.api.listen_address, "0.0.0.0:3035");
        let json = serde_json::to_string(&view.api).unwrap();
        assert!(!json.contains("hash"));
        assert!(!json.contains("password"));
    }
}
