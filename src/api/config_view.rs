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
//! - Credentials in the HTTP provider URL — its user name, password and
//!   query string are masked, and its auth header value is not part of the
//!   view.
//!
//! The view is its own struct (not a re-export of `AppConfig`) so a new
//! sensitive field added to the config doesn't silently cascade into the
//! response payload.

use crate::api::server::AppState;
use crate::config::{
    AcmeConfig, ApiConfig, AppConfig, ProvidersConfig, ProxyConfig, ProxyTimeouts, ResolverConfig,
    TlsOptions,
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
    pub tls: TlsView,
    pub acme: Option<AcmeView>,
    pub providers: ProvidersView,
    pub dashboard: DashboardView,
    pub api: ApiView,
}

#[derive(Debug, Serialize)]
pub struct ListenersView {
    pub http: PortView,
    pub https: PortView,
    /// Timeouts of the HTTP and HTTPS listeners, in seconds, Sōzu's defaults
    /// filled in for the fields `proxy.timeouts` leaves out.
    pub timeouts: TimeoutsView,
    pub tcp: Vec<TcpListenerView>,
    pub udp: Vec<UdpListenerView>,
}

#[derive(Debug, Serialize)]
pub struct TimeoutsView {
    pub client_idle: u32,
    pub backend_idle: u32,
    pub backend_connect: u32,
    pub request: u32,
}

#[derive(Debug, Serialize)]
pub struct TcpListenerView {
    pub name: String,
    pub port: u16,
    pub ip_allow_list: Vec<String>,
    pub rate_limit: Option<TcpRateLimitView>,
    pub idle_timeout: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct TcpRateLimitView {
    pub max_conns: u32,
    pub per_seconds: u32,
    pub exempt: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UdpListenerView {
    pub name: String,
    pub port: u16,
}

/// TLS settings of the HTTPS listener. `None` means Sōzu's default applies.
/// Certificates are listed by their certificate file only.
#[derive(Debug, Serialize)]
pub struct TlsView {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub ciphers: Option<Vec<String>>,
    pub certificates: Vec<String>,
    /// Client certificate authentication; `None` when it is not configured.
    pub client_auth: Option<ClientAuthView>,
}

/// CA and CRL files are public material, listed by path.
#[derive(Debug, Serialize)]
pub struct ClientAuthView {
    pub mode: &'static str,
    pub ca_files: Vec<String>,
    pub crl_files: Vec<String>,
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
        /// The env vars the resolver reads its credentials from, as named
        /// in the config. Their values never travel.
        required_env: Vec<String>,
        domains: Vec<String>,
        ca_server: Option<String>,
    },
    TlsAlpn01 {
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
    pub ring: Option<ToggleView>,
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
            tls: tls_view(&cfg.proxy.https.tls),
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
        timeouts: timeouts_view(&proxy.timeouts),
        tcp: proxy
            .tcp
            .iter()
            .map(|l| TcpListenerView {
                name: l.name.clone(),
                port: l.listen,
                ip_allow_list: l.ip_allow_list.clone(),
                rate_limit: l.rate_limit.as_ref().map(|r| TcpRateLimitView {
                    max_conns: r.max_conns,
                    per_seconds: r.per_seconds,
                    exempt: r.exempt.clone(),
                }),
                idle_timeout: l.idle_timeout,
            })
            .collect(),
        udp: proxy
            .udp
            .iter()
            .map(|l| UdpListenerView {
                name: l.name.clone(),
                port: l.listen,
            })
            .collect(),
    }
}

fn timeouts_view(timeouts: &ProxyTimeouts) -> TimeoutsView {
    use sozu_command_lib::config::{
        DEFAULT_BACK_TIMEOUT, DEFAULT_CONNECT_TIMEOUT, DEFAULT_FRONT_TIMEOUT,
        DEFAULT_REQUEST_TIMEOUT,
    };
    TimeoutsView {
        client_idle: timeouts.client_idle.unwrap_or(DEFAULT_FRONT_TIMEOUT),
        backend_idle: timeouts.backend_idle.unwrap_or(DEFAULT_BACK_TIMEOUT),
        backend_connect: timeouts.backend_connect.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
        request: timeouts.request.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
    }
}

fn tls_view(tls: &TlsOptions) -> TlsView {
    TlsView {
        min_version: tls.min_version.clone(),
        max_version: tls.max_version.clone(),
        ciphers: tls.ciphers.clone(),
        certificates: tls
            .certificates
            .iter()
            .map(|c| c.cert_file.clone())
            .collect(),
        client_auth: tls.client_auth.as_ref().map(|c| ClientAuthView {
            mode: c.mode.as_str(),
            ca_files: c.ca_files.clone(),
            crl_files: c.crl_files.clone(),
        }),
    }
}

/// Mask what a URL can carry as credentials: the user name (often a token on
/// its own), the password and the query string, whole — a bare `?token` is
/// as much a secret as `?token=value`. A URL that does not parse is masked whole, since nothing tells
/// which part of it is secret.
fn redact_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return "***".to_string();
    };
    if !url.username().is_empty() {
        let _ = url.set_username("***");
    }
    if url.password().is_some() {
        let _ = url.set_password(Some("***"));
    }
    if url.query().is_some() {
        url.set_query(Some("***"));
    }
    url.to_string()
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
            let (name, required_env): (&'static str, Vec<&String>) = match provider {
                Cloudflare { api_token_env } => ("cloudflare", vec![api_token_env]),
                Ovh {
                    application_key_env,
                    application_secret_env,
                    consumer_key_env,
                    ..
                } => (
                    "ovh",
                    vec![
                        application_key_env,
                        application_secret_env,
                        consumer_key_env,
                    ],
                ),
                Gandi {
                    personal_access_token_env,
                } => ("gandi", vec![personal_access_token_env]),
                Scaleway { secret_key_env } => ("scaleway", vec![secret_key_env]),
                Desec { token_env } => ("desec", vec![token_env]),
                DigitalOcean { token_env } => ("digitalocean", vec![token_env]),
                Hetzner { api_token_env } => ("hetzner", vec![api_token_env]),
                Infomaniak { access_token_env } => ("infomaniak", vec![access_token_env]),
                Porkbun {
                    api_key_env,
                    secret_api_key_env,
                } => ("porkbun", vec![api_key_env, secret_api_key_env]),
                Rfc2136 {
                    tsig_secret_env, ..
                } => ("rfc2136", vec![tsig_secret_env]),
            };
            let required_env = required_env.into_iter().cloned().collect();
            ResolverView::Dns01 {
                provider: name,
                required_env,
                domains: domains.clone(),
                ca_server: ca_server.clone(),
            }
        }
        ResolverConfig::TlsAlpn01 { ca_server } => ResolverView::TlsAlpn01 {
            ca_server: ca_server.clone(),
        },
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
        ring: p.ring.as_ref().map(|r| ToggleView { enabled: r.enabled }),
        config_file: p.config_file.as_ref().map(|f| ConfigFileView {
            enabled: f.enabled,
            path: f.path.clone(),
            watch: f.watch,
        }),
        http: p.http.as_ref().map(|h| HttpProviderView {
            enabled: h.enabled,
            url: redact_url(&h.url),
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
            tls_alpn_port: 8443,
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
    fn http_provider_url_credentials_are_masked() {
        let mut cfg = sample_app_config();
        cfg.providers.http = Some(HttpProviderConfig {
            enabled: true,
            url: "https://user:s3cret@config.example.com/entrypoints?token=abc&env=prod".into(),
            poll_interval: 10,
            auth_header: "Authorization".into(),
            auth_value: "Bearer header-secret".into(),
        });
        let view = ConfigView::from_app_config(&cfg);
        let url = &view.providers.http.as_ref().unwrap().url;
        assert_eq!(url, "https://***:***@config.example.com/entrypoints?***");
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("user:"));
        assert!(!json.contains("s3cret"));
        assert!(!json.contains("abc"));
        assert!(!json.contains("header-secret"));
    }

    #[test]
    fn token_as_url_user_name_is_masked() {
        assert_eq!(
            redact_url("https://tok3n@config.example.com/entrypoints"),
            "https://***@config.example.com/entrypoints"
        );
    }

    #[test]
    fn bare_query_token_is_masked() {
        assert_eq!(
            redact_url("https://config.example.com/entrypoints?s3cret"),
            "https://config.example.com/entrypoints?***"
        );
    }

    #[test]
    fn plain_http_provider_url_is_kept() {
        assert_eq!(
            redact_url("https://config.example.com/entrypoints"),
            "https://config.example.com/entrypoints"
        );
    }

    #[test]
    fn unparseable_http_provider_url_is_masked_whole() {
        assert_eq!(redact_url("not a url with s3cret"), "***");
    }

    #[test]
    fn view_exposes_tcp_and_udp_listeners() {
        let mut cfg = sample_app_config();
        cfg.proxy.tcp = vec![TcpListenerConfig {
            name: "postgres".into(),
            listen: 5432,
            ip_allow_list: vec!["10.0.0.0/8".into()],
            rate_limit: Some(TcpRateLimit {
                max_conns: 20,
                per_seconds: 1,
                exempt: vec!["172.16.0.0/12".into()],
            }),
            sni_preread_timeout: None,
            sni_preread_max_bytes: None,
            idle_timeout: Some(3600),
        }];
        cfg.proxy.udp = vec![UdpListenerConfig {
            name: "dns".into(),
            listen: 53,
        }];
        let view = ConfigView::from_app_config(&cfg);
        let tcp = &view.listeners.tcp[0];
        assert_eq!((tcp.name.as_str(), tcp.port), ("postgres", 5432));
        assert_eq!(tcp.ip_allow_list, vec!["10.0.0.0/8"]);
        let rate_limit = tcp.rate_limit.as_ref().unwrap();
        assert_eq!(rate_limit.max_conns, 20);
        assert_eq!(rate_limit.exempt, vec!["172.16.0.0/12"]);
        assert_eq!(tcp.idle_timeout, Some(3600));
        assert_eq!(view.listeners.udp[0].port, 53);
    }

    #[test]
    fn view_fills_unset_timeouts_with_sozu_defaults() {
        let mut cfg = sample_app_config();
        cfg.proxy.timeouts.backend_idle = Some(120);
        let view = ConfigView::from_app_config(&cfg);
        let timeouts = &view.listeners.timeouts;
        assert_eq!(timeouts.backend_idle, 120);
        assert_eq!(
            timeouts.client_idle,
            sozu_command_lib::config::DEFAULT_FRONT_TIMEOUT
        );
    }

    #[test]
    fn view_exposes_client_auth() {
        let mut cfg = sample_app_config();
        cfg.proxy.https.tls.client_auth = Some(ClientAuth {
            mode: ClientAuthMode::Required,
            ca_files: vec!["/certs/client-ca.pem".into()],
            crl_files: Vec::new(),
        });
        let view = ConfigView::from_app_config(&cfg);
        let client_auth = view.tls.client_auth.unwrap();
        assert_eq!(client_auth.mode, "required");
        assert_eq!(client_auth.ca_files, vec!["/certs/client-ca.pem"]);
    }

    #[test]
    fn view_exposes_tls_options_without_key_files() {
        let mut cfg = sample_app_config();
        cfg.proxy.https.tls = TlsOptions {
            min_version: Some("1.3".into()),
            max_version: None,
            ciphers: Some(vec!["TLS13_AES_256_GCM_SHA384".into()]),
            certificates: vec![CertificateFile {
                cert_file: "/certs/fullchain.pem".into(),
                key_file: "/certs/privkey.pem".into(),
            }],
            client_auth: None,
        };
        let view = ConfigView::from_app_config(&cfg);
        assert_eq!(view.tls.min_version.as_deref(), Some("1.3"));
        assert_eq!(view.tls.certificates, vec!["/certs/fullchain.pem"]);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("privkey.pem"));
    }

    #[test]
    fn resolver_view_names_the_configured_env_vars() {
        let resolver = ResolverConfig::Dns01 {
            provider: ProviderConfig::Porkbun {
                api_key_env: "PB_KEY".into(),
                secret_api_key_env: "PB_SECRET".into(),
            },
            domains: vec![],
            ca_server: None,
        };

        match resolver_view(&resolver) {
            ResolverView::Dns01 {
                provider,
                required_env,
                ..
            } => {
                assert_eq!(provider, "porkbun");
                assert_eq!(required_env, vec!["PB_KEY", "PB_SECRET"]);
            }
            other => panic!("expected a DNS-01 view, got {other:?}"),
        }
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
