use std::collections::HashMap;

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, Debug, Clone, Default)]
pub struct AppConfig {
    pub providers: ProvidersConfig,
    pub api: ApiConfig,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    #[serde(default)]
    pub middleware: MiddlewareConfig,
    #[serde(default)]
    pub dashboard: DashboardConfig,
    /// Dedicated `/metrics` listener, independent of the API. Disabled by default.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Logging output configuration (text vs JSON).
    #[serde(default)]
    pub log: LogConfig,
    /// Distributed tracing (OpenTelemetry OTLP export). Disabled by default.
    #[serde(default)]
    pub tracing: TracingConfig,
    /// WASM plugins declared by name. Each entry points at an http-wasm guest
    /// `.wasm`; entrypoints reference these by name to run them as middleware.
    #[serde(default)]
    pub plugins: HashMap<String, PluginConfig>,
}

/// Distributed-tracing configuration. When `enabled`, every proxied request
/// opens an OpenTelemetry span, the incoming W3C `traceparent` is honoured as
/// the parent, an outgoing `traceparent` is injected toward the backend, and
/// spans are exported over OTLP to a collector (Jaeger, Tempo, Zipkin, …).
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TracingConfig {
    /// Master switch. Off by default — no spans, no exporter, zero overhead.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/gRPC collector endpoint, e.g. `http://collector:4317`.
    #[serde(default = "default_tracing_endpoint")]
    pub endpoint: String,
    /// `service.name` reported on every span.
    #[serde(default = "default_tracing_service_name")]
    pub service_name: String,
    /// Sampler. `parent_based_always_on` (default) follows the upstream
    /// decision and otherwise samples everything; `ratio:<0..1>` samples a
    /// fraction (still parent-based), e.g. `ratio:0.1`; `always_on` /
    /// `always_off` force the decision.
    #[serde(default = "default_tracing_sampler")]
    pub sampler: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_tracing_endpoint(),
            service_name: default_tracing_service_name(),
            sampler: default_tracing_sampler(),
        }
    }
}

fn default_tracing_endpoint() -> String {
    "http://127.0.0.1:4317".to_string()
}

fn default_tracing_service_name() -> String {
    "sozune".to_string()
}

fn default_tracing_sampler() -> String {
    "parent_based_always_on".to_string()
}

/// Logging output configuration. Controls the formatter used by the global
/// tracing subscriber — this affects *all* logs, including the per-request
/// access log (emitted on the `access` target).
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct LogConfig {
    /// `text` (default, human-readable) or `json` (one JSON object per line,
    /// machine-parseable). JSON renders structured fields like `client_ip`,
    /// `status`, and `duration_ms` as top-level keys.
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Declaration of one WASM plugin artifact. The `config` blob is opaque to
/// Sōzune and handed to the guest verbatim via the http-wasm `get_config` ABI.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct PluginConfig {
    /// Filesystem path to the http-wasm guest `.wasm`.
    pub path: String,
    /// Guest-specific configuration, passed through unchanged. Serialized to
    /// JSON bytes before handing it to the guest.
    #[serde(default)]
    pub config: serde_json::Value,
    /// Hosts the plugin is allowed to reach via the outbound-HTTP extension
    /// (`http_fetch`). Empty disables network access for the plugin. Listing
    /// hosts opts the plugin into the non-standard fetch extension.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AcmeConfig {
    #[serde(default, deserialize_with = "deserialize_acme_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_acme_email_with_env")]
    pub email: String,
    #[serde(
        default = "default_acme_certs_dir",
        deserialize_with = "deserialize_acme_certs_dir_with_env"
    )]
    pub certs_dir: String,
    #[serde(
        default = "default_acme_staging",
        deserialize_with = "deserialize_acme_staging_with_env"
    )]
    pub staging: bool,
    #[serde(
        default = "default_acme_challenge_port",
        deserialize_with = "deserialize_acme_challenge_port_with_env"
    )]
    pub challenge_port: u16,
    #[serde(default)]
    pub resolvers: HashMap<String, ResolverConfig>,
}

/// One named ACME challenge resolver. Entrypoints reference these by name.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "challenge", rename_all = "kebab-case")]
pub enum ResolverConfig {
    #[serde(rename = "http-01")]
    Http01 {
        /// ACME directory URL for this resolver (Traefik's `caServer`). When
        /// set, it overrides the global `staging` flag, so a staging resolver
        /// and a production resolver can coexist. Each distinct CA keeps its
        /// own ACME account on disk. Defaults to the global staging/prod URL.
        #[serde(default)]
        ca_server: Option<String>,
    },
    #[serde(rename = "dns-01")]
    Dns01 {
        provider: ProviderConfig,
        /// Hostnames the resolver provisions on its own, independently of any
        /// entrypoint. This is how a wildcard (`*.example.com`) gets issued
        /// without a placeholder route: the cert is then served by SNI for
        /// every matching subdomain. Each entry is treated exactly like an
        /// entrypoint hostname bound to this resolver.
        #[serde(default)]
        domains: Vec<String>,
        /// ACME directory URL for this resolver (Traefik's `caServer`). See
        /// the `http-01` variant for semantics.
        #[serde(default)]
        ca_server: Option<String>,
    },
}

impl ResolverConfig {
    /// Hostnames this resolver provisions on its own (DNS-01 `domains`).
    /// Empty for HTTP-01 or a DNS-01 resolver without `domains`.
    pub fn managed_domains(&self) -> &[String] {
        match self {
            ResolverConfig::Dns01 { domains, .. } => domains,
            ResolverConfig::Http01 { .. } => &[],
        }
    }

    /// Explicit ACME directory URL for this resolver, if any. `None` means
    /// fall back to the global staging/prod URL.
    pub fn ca_server(&self) -> Option<&str> {
        match self {
            ResolverConfig::Http01 { ca_server } | ResolverConfig::Dns01 { ca_server, .. } => {
                ca_server.as_deref()
            }
        }
    }
}

/// DNS-01 provider configuration. Credentials are referenced by env var name,
/// never inlined in YAML.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProviderConfig {
    Cloudflare {
        api_token_env: String,
    },
    Ovh {
        #[serde(default = "default_ovh_endpoint")]
        endpoint: String,
        application_key_env: String,
        application_secret_env: String,
        consumer_key_env: String,
    },
    Gandi {
        personal_access_token_env: String,
    },
    Scaleway {
        secret_key_env: String,
    },
}

fn default_ovh_endpoint() -> String {
    "ovh-eu".to_string()
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct ProvidersConfig {
    pub docker: Option<DockerConfig>,
    pub podman: Option<PodmanConfig>,
    pub swarm: Option<SwarmConfig>,
    pub kubernetes: Option<KubernetesConfig>,
    pub nomad: Option<NomadConfig>,
    pub consul: Option<ConsulConfig>,
    pub ring: Option<RingConfig>,
    pub config_file: Option<ConfigFileConfig>,
    pub http: Option<HttpProviderConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DockerConfig {
    #[serde(default, deserialize_with = "deserialize_docker_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_docker_endpoint_with_env")]
    pub endpoint: String,
    #[serde(
        default,
        deserialize_with = "deserialize_docker_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PodmanConfig {
    #[serde(default, deserialize_with = "deserialize_podman_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_podman_endpoint_with_env")]
    pub endpoint: String,
    #[serde(
        default,
        deserialize_with = "deserialize_podman_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SwarmConfig {
    #[serde(default, deserialize_with = "deserialize_swarm_enabled_with_env")]
    pub enabled: bool,
    #[serde(
        default = "default_swarm_endpoint",
        deserialize_with = "deserialize_swarm_endpoint_with_env"
    )]
    pub endpoint: String,
    #[serde(
        default,
        deserialize_with = "deserialize_swarm_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
    #[serde(default, deserialize_with = "deserialize_swarm_network_with_env")]
    pub network: String,
    #[serde(
        default = "default_swarm_refresh_interval",
        deserialize_with = "deserialize_swarm_refresh_interval_with_env"
    )]
    pub refresh_interval: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct KubernetesConfig {
    #[serde(default, deserialize_with = "deserialize_kubernetes_enabled_with_env")]
    pub enabled: bool,
    /// Path to a kubeconfig file. Empty string means in-cluster (ServiceAccount).
    #[serde(
        default,
        deserialize_with = "deserialize_kubernetes_kubeconfig_with_env"
    )]
    pub kubeconfig: String,
    /// Restrict discovery to a single namespace. Empty string means all namespaces.
    #[serde(
        default,
        deserialize_with = "deserialize_kubernetes_namespace_with_env"
    )]
    pub namespace: String,
    /// Ingress class name to filter on (only Ingresses with this class are picked up).
    #[serde(
        default = "default_kubernetes_ingress_class",
        deserialize_with = "deserialize_kubernetes_ingress_class_with_env"
    )]
    pub ingress_class: String,
    #[serde(
        default,
        deserialize_with = "deserialize_kubernetes_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct NomadConfig {
    #[serde(default, deserialize_with = "deserialize_nomad_enabled_with_env")]
    pub enabled: bool,
    /// Nomad HTTP API endpoint (e.g. `http://127.0.0.1:4646`).
    #[serde(
        default = "default_nomad_endpoint",
        deserialize_with = "deserialize_nomad_endpoint_with_env"
    )]
    pub endpoint: String,
    /// Optional ACL token sent as the `X-Nomad-Token` header.
    #[serde(default, deserialize_with = "deserialize_nomad_token_with_env")]
    pub token: String,
    /// Restrict discovery to a single namespace. Empty means cluster-wide.
    #[serde(default, deserialize_with = "deserialize_nomad_namespace_with_env")]
    pub namespace: String,
    /// Polling interval, in seconds.
    #[serde(
        default = "default_nomad_poll_interval",
        deserialize_with = "deserialize_nomad_poll_interval_with_env"
    )]
    pub poll_interval: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_nomad_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
}

/// Ring provider configuration. Discovers services from a Ring cluster's
/// `GET /deployments` API and routes to each running instance's guest address.
#[derive(Deserialize, Debug, Clone)]
pub struct RingConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Ring HTTP API endpoint (e.g. `http://127.0.0.1:3030`).
    #[serde(default = "default_ring_endpoint")]
    pub endpoint: String,
    /// Optional PAT (scope `deployments:read`), sent as `Authorization: Bearer`.
    #[serde(default)]
    pub token: String,
    /// Polling interval, in seconds (Ring has no blocking-query mechanism).
    #[serde(default = "default_ring_poll_interval")]
    pub poll_interval: u64,
    /// Expose every running deployment even without `sozune.enable=true`.
    #[serde(default)]
    pub expose_by_default: bool,
}

fn default_ring_endpoint() -> String {
    "http://127.0.0.1:3030".to_string()
}

fn default_ring_poll_interval() -> u64 {
    10
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_ring_endpoint(),
            token: String::new(),
            poll_interval: default_ring_poll_interval(),
            expose_by_default: false,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConsulConfig {
    #[serde(default, deserialize_with = "deserialize_consul_enabled_with_env")]
    pub enabled: bool,
    /// Consul HTTP API endpoint (e.g. `http://127.0.0.1:8500`).
    #[serde(
        default = "default_consul_endpoint",
        deserialize_with = "deserialize_consul_endpoint_with_env"
    )]
    pub endpoint: String,
    /// Optional ACL token sent as the `X-Consul-Token` header.
    #[serde(default, deserialize_with = "deserialize_consul_token_with_env")]
    pub token: String,
    /// Restrict discovery to a single datacenter (`?dc=`). Empty means the
    /// agent's default datacenter.
    #[serde(default, deserialize_with = "deserialize_consul_datacenter_with_env")]
    pub datacenter: String,
    /// Polling interval, in seconds. Used as the `wait` bound for blocking
    /// queries.
    #[serde(
        default = "default_consul_poll_interval",
        deserialize_with = "deserialize_consul_poll_interval_with_env"
    )]
    pub poll_interval: u64,
    /// Which Consul health-check states are allowed to receive traffic.
    /// Defaults to `["passing", "warning"]` — only `critical` instances are
    /// excluded. Mirrors Traefik's `strictChecks`.
    #[serde(default = "default_consul_strict_checks")]
    pub strict_checks: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_consul_expose_by_default_with_env"
    )]
    pub expose_by_default: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiConfig {
    #[serde(default, deserialize_with = "deserialize_api_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_api_listen_address_with_env")]
    pub listen_address: String,
    #[serde(default)]
    pub users: Vec<ApiUser>,
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiUser {
    pub name: String,
    pub hash: String,
    #[serde(default)]
    pub role: Role,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    #[default]
    Admin,
    ReadOnly,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HttpProviderConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_http_provider_enabled_with_env"
    )]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_http_provider_url_with_env")]
    pub url: String,
    #[serde(
        default = "default_http_provider_poll_interval",
        deserialize_with = "deserialize_http_provider_poll_interval_with_env"
    )]
    pub poll_interval: u64,
    /// Optional HTTP header sent on every poll request — e.g. for bearer
    /// tokens or shared secrets. Empty means no header is sent.
    #[serde(
        default,
        deserialize_with = "deserialize_http_provider_auth_header_with_env"
    )]
    pub auth_header: String,
    /// Value paired with `auth_header`. Empty means no header is sent.
    #[serde(
        default,
        deserialize_with = "deserialize_http_provider_auth_value_with_env"
    )]
    pub auth_value: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConfigFileConfig {
    #[serde(default, deserialize_with = "deserialize_config_file_enabled_with_env")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_config_file_path_with_env")]
    pub path: String,
    #[serde(default, deserialize_with = "deserialize_config_file_watch_with_env")]
    pub watch: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub http: HttpConfig,
    pub https: HttpsConfig,
    #[serde(default)]
    pub tcp: Vec<TcpListenerConfig>,
    #[serde(default)]
    pub udp: Vec<UdpListenerConfig>,
    #[serde(
        default = "default_max_buffers",
        deserialize_with = "deserialize_max_buffers_with_env"
    )]
    pub max_buffers: usize,
    #[serde(
        default = "default_buffer_size",
        deserialize_with = "deserialize_buffer_size_with_env"
    )]
    pub buffer_size: usize,
    #[serde(
        default = "default_startup_delay_ms",
        deserialize_with = "deserialize_startup_delay_ms_with_env"
    )]
    pub startup_delay_ms: u64,
    #[serde(
        default = "default_cluster_setup_delay_ms",
        deserialize_with = "deserialize_cluster_setup_delay_ms_with_env"
    )]
    pub cluster_setup_delay_ms: u64,
    /// Debounce window, in milliseconds, applied to reload signals. The reload
    /// is only triggered after this many ms of silence on the reload channel,
    /// each new signal resetting the timer. Coalesces bursts of container
    /// start/stop events into a single reload. Mirrors Traefik's
    /// `providersThrottleDuration` (default there: 2 s; we default to 500 ms).
    #[serde(
        default = "default_reload_debounce_ms",
        deserialize_with = "deserialize_reload_debounce_ms_with_env"
    )]
    pub reload_debounce_ms: u64,
    /// Per-worker deadline, in milliseconds, for a metrics poll round-trip. The
    /// poll runs inside the same loop that accepts traffic and applies
    /// certificates, and reads the worker reply with a *blocking* wait — so this
    /// deadline is the longest that one worker's metrics query can monopolize
    /// that loop. A silent or overwhelmed worker (e.g. a metrics reply that
    /// overflows the command channel's back buffer) would otherwise block here;
    /// keep this short so a metrics hiccup can never freeze proxying. Defaults
    /// to 200 ms (a healthy worker answers in single-digit ms).
    #[serde(
        default = "default_metrics_poll_timeout_ms",
        deserialize_with = "deserialize_metrics_poll_timeout_ms_with_env"
    )]
    pub metrics_poll_timeout_ms: u64,
    /// Maximum size, in bytes, the Sōzu command channel back buffer may grow to.
    /// The channel carries config commands and worker replies (including the
    /// metrics reply); a single frame larger than this ceiling is rejected with
    /// a "too large for back buffer capacity" error and never reaches the peer.
    /// The production incident hit the old 10000-byte ceiling once the metrics
    /// reply grew past it. Defaults to 65536, well above any realistic command
    /// or metrics frame, while still bounding memory per channel.
    #[serde(
        default = "default_command_buffer_max_bytes",
        deserialize_with = "deserialize_command_buffer_max_bytes_with_env"
    )]
    pub command_buffer_max_bytes: u64,
    /// CIDRs of reverse-proxies that sit in front of Sōzune and are trusted
    /// to set `X-Forwarded-For`. **Empty by default** — when no entry is
    /// configured, Sōzune ignores `X-Forwarded-For` entirely and treats the
    /// direct TCP peer as the client. This is the only safe default when the
    /// proxy is exposed to the internet, since `X-Forwarded-For` is
    /// attacker-controllable otherwise. Entries may be bare IPs (auto-promoted
    /// to /32 or /128) or CIDR blocks.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HttpConfig {
    #[serde(
        default = "default_http_port",
        deserialize_with = "deserialize_port_with_env"
    )]
    pub listen_address: u16,
    /// Listener-wide custom HTTP answer templates, keyed by status code.
    /// Values may be inline bodies or `file://<path>` references; both are
    /// resolved by Sōzu at listener-build time. Overridden per cluster
    /// via `EntrypointConfig.error_pages`.
    #[serde(
        default,
        deserialize_with = "crate::error_pages::deserialize_error_pages"
    )]
    pub error_pages: BTreeMap<String, String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HttpsConfig {
    #[serde(
        default = "default_https_port",
        deserialize_with = "deserialize_https_port_with_env"
    )]
    pub listen_address: u16,
    /// See [`HttpConfig::error_pages`]. Applies to the HTTPS listener only.
    #[serde(
        default,
        deserialize_with = "crate::error_pages::deserialize_error_pages"
    )]
    pub error_pages: BTreeMap<String, String>,
    /// HTTP/2 negotiation on the TLS listener.
    #[serde(default)]
    pub http2: Http2Config,
}

/// HTTP/2 listener settings. Both fields default to `None`, which leaves
/// Sōzu's own defaults untouched (ALPN `["h2", "http/1.1"]`, HTTP/1.1 enabled).
#[derive(Deserialize, Debug, Clone, Default)]
pub struct Http2Config {
    /// ALPN protocols advertised on the TLS listener. `None` keeps Sōzu's
    /// default `["h2", "http/1.1"]`. Valid values: `"h2"`, `"http/1.1"`.
    #[serde(default)]
    pub alpn_protocols: Option<Vec<String>>,
    /// Disable HTTP/1.1 on the listener (h2-only). `None` keeps it enabled.
    /// Incompatible with `alpn_protocols` containing `"http/1.1"`.
    #[serde(default)]
    pub disable_http11: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TcpListenerConfig {
    pub name: String,
    pub listen: u16,
    /// CIDRs / bare IPs allowed to connect to this listener, checked at
    /// `accept()` by the pre-accept forwarder. Empty = allow all. A bare IP is
    /// promoted to `/32` (or `/128`). Note: this is an application-level filter
    /// — for a database exposed to the internet, a kernel firewall (nftables)
    /// in front is the more robust choice; see the TCP routing docs.
    #[serde(default)]
    pub ip_allow_list: Vec<String>,
    /// Per-source connection-rate limit (anti-flood), enforced by the
    /// pre-accept forwarder. Absent = no limit.
    #[serde(default)]
    pub rate_limit: Option<TcpRateLimit>,
}

/// Per-source connection-rate limit for a TCP listener. A token bucket: a burst
/// of `max_conns` is absorbed at once, then refills at `max_conns / per_seconds`
/// per second. Sources matching `exempt` (CIDRs / bare IPs) are never limited —
/// e.g. internal Docker ranges that open startup connection bursts.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TcpRateLimit {
    pub max_conns: u32,
    pub per_seconds: u32,
    #[serde(default)]
    pub exempt: Vec<String>,
}

/// A static UDP listener. Like `TcpListenerConfig`, it is referenced by name
/// from a `udp` entrypoint's `entrypoint` field; one Sōzu worker binds one
/// listener. Datagram services (DNS, syslog, NTP, …) attach as backends.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct UdpListenerConfig {
    pub name: String,
    pub listen: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DashboardConfig {
    #[serde(default, deserialize_with = "deserialize_dashboard_enabled_with_env")]
    pub enabled: bool,
    #[serde(
        default = "default_dashboard_listen_address",
        deserialize_with = "deserialize_dashboard_listen_address_with_env"
    )]
    pub listen_address: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_dashboard_listen_address(),
        }
    }
}

fn default_dashboard_listen_address() -> String {
    "127.0.0.1:3038".to_string()
}

/// Dedicated `/metrics` listener, independent of the API.
///
/// `/metrics` is also served by the API listener when the API is enabled, but
/// that couples scraping to running (and exposing) the admin API. This lets an
/// operator expose only Prometheus metrics — its own port, its own `enabled`
/// flag — without turning on the rest of the API.
#[derive(Deserialize, Debug, Clone)]
pub struct MetricsConfig {
    #[serde(default, deserialize_with = "deserialize_metrics_enabled_with_env")]
    pub enabled: bool,
    #[serde(
        default = "default_metrics_listen_address",
        deserialize_with = "deserialize_metrics_listen_address_with_env"
    )]
    pub listen_address: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_metrics_listen_address(),
        }
    }
}

fn default_metrics_listen_address() -> String {
    // 3035 API, 3036 ACME challenge, 3037 middleware, 3038 dashboard → 3039.
    "127.0.0.1:3039".to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct MiddlewareConfig {
    #[serde(
        default = "default_middleware_port",
        deserialize_with = "deserialize_middleware_port_with_env"
    )]
    pub port: u16,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        Self {
            port: default_middleware_port(),
        }
    }
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "/var/run/docker.sock".to_string(),
            expose_by_default: false,
        }
    }
}

impl Default for PodmanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_podman_endpoint(),
            expose_by_default: false,
        }
    }
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "/var/run/docker.sock".to_string(),
            expose_by_default: false,
            network: String::new(),
            refresh_interval: default_swarm_refresh_interval(),
        }
    }
}

fn default_swarm_refresh_interval() -> u64 {
    15
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kubeconfig: String::new(),
            namespace: String::new(),
            ingress_class: default_kubernetes_ingress_class(),
            expose_by_default: false,
        }
    }
}

fn default_kubernetes_ingress_class() -> String {
    "sozune".to_string()
}

impl Default for NomadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_nomad_endpoint(),
            token: String::new(),
            namespace: String::new(),
            poll_interval: default_nomad_poll_interval(),
            expose_by_default: false,
        }
    }
}

fn default_nomad_endpoint() -> String {
    "http://127.0.0.1:4646".to_string()
}

fn default_nomad_poll_interval() -> u64 {
    15
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_consul_endpoint(),
            token: String::new(),
            datacenter: String::new(),
            poll_interval: default_consul_poll_interval(),
            strict_checks: default_consul_strict_checks(),
            expose_by_default: false,
        }
    }
}

fn default_consul_endpoint() -> String {
    "http://127.0.0.1:8500".to_string()
}

fn default_consul_poll_interval() -> u64 {
    15
}

fn default_consul_strict_checks() -> Vec<String> {
    vec!["passing".to_string(), "warning".to_string()]
}

fn default_swarm_endpoint() -> String {
    "/var/run/docker.sock".to_string()
}

fn default_podman_endpoint() -> String {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{runtime_dir}/podman/podman.sock")
    } else {
        "/run/podman/podman.sock".to_string()
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_api_listen_address(),
            users: Vec::new(),
            cors_origins: Vec::new(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen_address: default_http_port(),
            error_pages: BTreeMap::new(),
        }
    }
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            listen_address: default_https_port(),
            error_pages: BTreeMap::new(),
            http2: Http2Config::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            http: Default::default(),
            https: Default::default(),
            tcp: Vec::new(),
            udp: Vec::new(),
            max_buffers: default_max_buffers(),
            buffer_size: default_buffer_size(),
            startup_delay_ms: default_startup_delay_ms(),
            cluster_setup_delay_ms: default_cluster_setup_delay_ms(),
            reload_debounce_ms: default_reload_debounce_ms(),
            metrics_poll_timeout_ms: default_metrics_poll_timeout_ms(),
            command_buffer_max_bytes: default_command_buffer_max_bytes(),
            trusted_proxies: Vec::new(),
        }
    }
}

fn default_max_buffers() -> usize {
    500
}

fn default_buffer_size() -> usize {
    16384
}

fn default_startup_delay_ms() -> u64 {
    1000
}

fn default_cluster_setup_delay_ms() -> u64 {
    500
}

fn default_reload_debounce_ms() -> u64 {
    500
}

pub(crate) fn default_metrics_poll_timeout_ms() -> u64 {
    200
}

pub(crate) fn default_command_buffer_max_bytes() -> u64 {
    65536
}

fn default_api_listen_address() -> String {
    "127.0.0.1:3035".to_string()
}

fn default_acme_certs_dir() -> String {
    "/etc/sozune/certs".to_string()
}

fn default_acme_staging() -> bool {
    true
}

fn default_acme_challenge_port() -> u16 {
    3036
}

fn default_middleware_port() -> u16 {
    3037
}

fn default_http_provider_poll_interval() -> u64 {
    30
}

fn default_http_port() -> u16 {
    80
}

fn default_https_port() -> u16 {
    443
}

fn get_env_port<T: std::str::FromStr>(var: &str, default: T) -> T {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

// Macro pour générer les fonctions de désérialisation
macro_rules! deserialize_with_env {
    ($fn_name:ident, $env_var:expr, $type:ty, $default_fn:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = <$type>::deserialize(deserializer).unwrap_or_else(|_| $default_fn());
            Ok(get_env_port($env_var, value))
        }
    };
    ($fn_name:ident, $env_var:expr, $type:ty, $default_value:expr, literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = <$type>::deserialize(deserializer).unwrap_or($default_value);
            Ok(get_env_port($env_var, value))
        }
    };
}

deserialize_with_env!(
    deserialize_port_with_env,
    "SOZUNE_HTTP_PORT",
    u16,
    default_http_port
);
deserialize_with_env!(
    deserialize_https_port_with_env,
    "SOZUNE_HTTPS_PORT",
    u16,
    default_https_port
);

// Fonction spécialisée pour les booléens
fn get_env_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .ok()
        .and_then(|v| match v.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

// Fonction spécialisée pour les String
fn get_env_string(var: &str, default: String) -> String {
    std::env::var(var).unwrap_or(default)
}

// Macro spécialisée pour les booléens
macro_rules! deserialize_bool_with_env {
    ($fn_name:ident, $env_var:expr, $default_value:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<bool, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = bool::deserialize(deserializer).unwrap_or($default_value);
            Ok(get_env_bool($env_var, value))
        }
    };
}

// Macro spécialisée pour les String
macro_rules! deserialize_string_with_env {
    ($fn_name:ident, $env_var:expr, $default_fn:expr) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer).unwrap_or_else(|_| $default_fn());
            Ok(get_env_string($env_var, value))
        }
    };
    ($fn_name:ident, $env_var:expr, $default_value:expr, literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value =
                String::deserialize(deserializer).unwrap_or_else(|_| $default_value.to_string());
            Ok(get_env_string($env_var, value))
        }
    };
}

// Génération de toutes les fonctions avec les macros
deserialize_bool_with_env!(
    deserialize_docker_enabled_with_env,
    "SOZUNE_PROVIDER_DOCKER_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_docker_endpoint_with_env,
    "SOZUNE_PROVIDER_DOCKER_ENDPOINT",
    "/var/run/docker.sock",
    literal
);
deserialize_bool_with_env!(
    deserialize_docker_expose_by_default_with_env,
    "SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT",
    false
);

deserialize_bool_with_env!(
    deserialize_podman_enabled_with_env,
    "SOZUNE_PROVIDER_PODMAN_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_podman_endpoint_with_env,
    "SOZUNE_PROVIDER_PODMAN_ENDPOINT",
    default_podman_endpoint
);
deserialize_bool_with_env!(
    deserialize_podman_expose_by_default_with_env,
    "SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT",
    false
);

deserialize_bool_with_env!(
    deserialize_swarm_enabled_with_env,
    "SOZUNE_PROVIDER_SWARM_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_swarm_endpoint_with_env,
    "SOZUNE_PROVIDER_SWARM_ENDPOINT",
    "/var/run/docker.sock",
    literal
);
deserialize_bool_with_env!(
    deserialize_swarm_expose_by_default_with_env,
    "SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT",
    false
);
deserialize_string_with_env!(
    deserialize_swarm_network_with_env,
    "SOZUNE_PROVIDER_SWARM_NETWORK",
    "",
    literal
);
deserialize_with_env!(
    deserialize_swarm_refresh_interval_with_env,
    "SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL",
    u64,
    default_swarm_refresh_interval
);

deserialize_bool_with_env!(
    deserialize_kubernetes_enabled_with_env,
    "SOZUNE_PROVIDER_KUBERNETES_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_kubernetes_kubeconfig_with_env,
    "SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_kubernetes_namespace_with_env,
    "SOZUNE_PROVIDER_KUBERNETES_NAMESPACE",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_kubernetes_ingress_class_with_env,
    "SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS",
    default_kubernetes_ingress_class
);
deserialize_bool_with_env!(
    deserialize_kubernetes_expose_by_default_with_env,
    "SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT",
    false
);

deserialize_bool_with_env!(
    deserialize_nomad_enabled_with_env,
    "SOZUNE_PROVIDER_NOMAD_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_nomad_endpoint_with_env,
    "SOZUNE_PROVIDER_NOMAD_ENDPOINT",
    default_nomad_endpoint
);
deserialize_string_with_env!(
    deserialize_nomad_token_with_env,
    "SOZUNE_PROVIDER_NOMAD_TOKEN",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_nomad_namespace_with_env,
    "SOZUNE_PROVIDER_NOMAD_NAMESPACE",
    "",
    literal
);
deserialize_with_env!(
    deserialize_nomad_poll_interval_with_env,
    "SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL",
    u64,
    default_nomad_poll_interval
);
deserialize_bool_with_env!(
    deserialize_nomad_expose_by_default_with_env,
    "SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT",
    false
);

deserialize_bool_with_env!(
    deserialize_consul_enabled_with_env,
    "SOZUNE_PROVIDER_CONSUL_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_consul_endpoint_with_env,
    "SOZUNE_PROVIDER_CONSUL_ENDPOINT",
    default_consul_endpoint
);
deserialize_string_with_env!(
    deserialize_consul_token_with_env,
    "SOZUNE_PROVIDER_CONSUL_TOKEN",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_consul_datacenter_with_env,
    "SOZUNE_PROVIDER_CONSUL_DATACENTER",
    "",
    literal
);
deserialize_with_env!(
    deserialize_consul_poll_interval_with_env,
    "SOZUNE_PROVIDER_CONSUL_POLL_INTERVAL",
    u64,
    default_consul_poll_interval
);
deserialize_bool_with_env!(
    deserialize_consul_expose_by_default_with_env,
    "SOZUNE_PROVIDER_CONSUL_EXPOSE_BY_DEFAULT",
    false
);

deserialize_bool_with_env!(
    deserialize_config_file_enabled_with_env,
    "SOZUNE_PROVIDER_CONFIG_FILE_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_config_file_path_with_env,
    "SOZUNE_PROVIDER_CONFIG_FILE_PATH",
    "/etc/sozune/config.yaml",
    literal
);
deserialize_bool_with_env!(
    deserialize_config_file_watch_with_env,
    "SOZUNE_PROVIDER_CONFIG_FILE_WATCH",
    true
);

deserialize_bool_with_env!(
    deserialize_api_enabled_with_env,
    "SOZUNE_API_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_api_listen_address_with_env,
    "SOZUNE_API_LISTEN_ADDRESS",
    default_api_listen_address
);

deserialize_with_env!(
    deserialize_max_buffers_with_env,
    "SOZUNE_PROXY_MAX_BUFFERS",
    usize,
    default_max_buffers
);
deserialize_with_env!(
    deserialize_buffer_size_with_env,
    "SOZUNE_PROXY_BUFFER_SIZE",
    usize,
    default_buffer_size
);
deserialize_with_env!(
    deserialize_startup_delay_ms_with_env,
    "SOZUNE_PROXY_STARTUP_DELAY_MS",
    u64,
    default_startup_delay_ms
);
deserialize_with_env!(
    deserialize_cluster_setup_delay_ms_with_env,
    "SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS",
    u64,
    default_cluster_setup_delay_ms
);
deserialize_with_env!(
    deserialize_reload_debounce_ms_with_env,
    "SOZUNE_PROXY_RELOAD_DEBOUNCE_MS",
    u64,
    default_reload_debounce_ms
);
deserialize_with_env!(
    deserialize_metrics_poll_timeout_ms_with_env,
    "SOZUNE_PROXY_METRICS_POLL_TIMEOUT_MS",
    u64,
    default_metrics_poll_timeout_ms
);
deserialize_with_env!(
    deserialize_command_buffer_max_bytes_with_env,
    "SOZUNE_PROXY_COMMAND_BUFFER_MAX_BYTES",
    u64,
    default_command_buffer_max_bytes
);

deserialize_bool_with_env!(
    deserialize_acme_enabled_with_env,
    "SOZUNE_ACME_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_acme_email_with_env,
    "SOZUNE_ACME_EMAIL",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_acme_certs_dir_with_env,
    "SOZUNE_ACME_CERTS_DIR",
    default_acme_certs_dir
);
deserialize_bool_with_env!(
    deserialize_acme_staging_with_env,
    "SOZUNE_ACME_STAGING",
    true
);
deserialize_with_env!(
    deserialize_acme_challenge_port_with_env,
    "SOZUNE_ACME_CHALLENGE_PORT",
    u16,
    default_acme_challenge_port
);
deserialize_with_env!(
    deserialize_middleware_port_with_env,
    "SOZUNE_MIDDLEWARE_PORT",
    u16,
    default_middleware_port
);

deserialize_bool_with_env!(
    deserialize_http_provider_enabled_with_env,
    "SOZUNE_PROVIDER_HTTP_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_http_provider_url_with_env,
    "SOZUNE_PROVIDER_HTTP_URL",
    "",
    literal
);
deserialize_with_env!(
    deserialize_http_provider_poll_interval_with_env,
    "SOZUNE_PROVIDER_HTTP_POLL_INTERVAL",
    u64,
    default_http_provider_poll_interval
);
deserialize_string_with_env!(
    deserialize_http_provider_auth_header_with_env,
    "SOZUNE_PROVIDER_HTTP_AUTH_HEADER",
    "",
    literal
);
deserialize_string_with_env!(
    deserialize_http_provider_auth_value_with_env,
    "SOZUNE_PROVIDER_HTTP_AUTH_VALUE",
    "",
    literal
);

deserialize_bool_with_env!(
    deserialize_dashboard_enabled_with_env,
    "SOZUNE_DASHBOARD_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_dashboard_listen_address_with_env,
    "SOZUNE_DASHBOARD_LISTEN_ADDRESS",
    default_dashboard_listen_address
);
deserialize_bool_with_env!(
    deserialize_metrics_enabled_with_env,
    "SOZUNE_METRICS_ENABLED",
    false
);
deserialize_string_with_env!(
    deserialize_metrics_listen_address_with_env,
    "SOZUNE_METRICS_LISTEN_ADDRESS",
    default_metrics_listen_address
);

fn env_bool(var: &str) -> Option<bool> {
    std::env::var(var)
        .ok()
        .and_then(|v| match v.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn env_string(var: &str) -> Option<String> {
    std::env::var(var).ok()
}

fn env_parse<T: std::str::FromStr>(var: &str) -> Option<T> {
    std::env::var(var).ok().and_then(|v| v.parse::<T>().ok())
}

impl AppConfig {
    /// Apply `SOZUNE_*` environment variable overrides on top of the current
    /// config. Required for the path where no YAML file is present: the serde
    /// deserializers that normally consume env vars are bypassed entirely when
    /// `AppConfig::default()` is used directly.
    pub fn apply_env_overrides(&mut self) {
        self.providers.apply_env_overrides();
        self.api.apply_env_overrides();
        self.proxy.apply_env_overrides();
        self.middleware.apply_env_overrides();
        self.dashboard.apply_env_overrides();
        self.metrics.apply_env_overrides();
        self.log.apply_env_overrides();
        self.tracing.apply_env_overrides();

        let acme_env_present = std::env::var("SOZUNE_ACME_ENABLED").is_ok()
            || std::env::var("SOZUNE_ACME_EMAIL").is_ok()
            || std::env::var("SOZUNE_ACME_CERTS_DIR").is_ok()
            || std::env::var("SOZUNE_ACME_STAGING").is_ok()
            || std::env::var("SOZUNE_ACME_CHALLENGE_PORT").is_ok();
        if acme_env_present || self.acme.is_some() {
            let acme = self.acme.get_or_insert_with(|| AcmeConfig {
                enabled: false,
                email: String::new(),
                certs_dir: default_acme_certs_dir(),
                staging: default_acme_staging(),
                challenge_port: default_acme_challenge_port(),
                resolvers: HashMap::new(),
            });
            acme.apply_env_overrides();
        }
    }
}

impl ProvidersConfig {
    fn apply_env_overrides(&mut self) {
        let docker_env = std::env::var("SOZUNE_PROVIDER_DOCKER_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_DOCKER_ENDPOINT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT").is_ok();
        if docker_env || self.docker.is_some() {
            self.docker
                .get_or_insert_with(DockerConfig::default)
                .apply_env_overrides();
        }

        let podman_env = std::env::var("SOZUNE_PROVIDER_PODMAN_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_PODMAN_ENDPOINT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT").is_ok();
        if podman_env || self.podman.is_some() {
            self.podman
                .get_or_insert_with(PodmanConfig::default)
                .apply_env_overrides();
        }

        let swarm_env = std::env::var("SOZUNE_PROVIDER_SWARM_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_SWARM_ENDPOINT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_SWARM_NETWORK").is_ok()
            || std::env::var("SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL").is_ok();
        if swarm_env || self.swarm.is_some() {
            self.swarm
                .get_or_insert_with(SwarmConfig::default)
                .apply_env_overrides();
        }

        let kubernetes_env = std::env::var("SOZUNE_PROVIDER_KUBERNETES_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG").is_ok()
            || std::env::var("SOZUNE_PROVIDER_KUBERNETES_NAMESPACE").is_ok()
            || std::env::var("SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS").is_ok()
            || std::env::var("SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT").is_ok();
        if kubernetes_env || self.kubernetes.is_some() {
            self.kubernetes
                .get_or_insert_with(KubernetesConfig::default)
                .apply_env_overrides();
        }

        let nomad_env = std::env::var("SOZUNE_PROVIDER_NOMAD_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_NOMAD_ENDPOINT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_NOMAD_TOKEN").is_ok()
            || std::env::var("SOZUNE_PROVIDER_NOMAD_NAMESPACE").is_ok()
            || std::env::var("SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL").is_ok()
            || std::env::var("SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT").is_ok();
        if nomad_env || self.nomad.is_some() {
            self.nomad
                .get_or_insert_with(NomadConfig::default)
                .apply_env_overrides();
        }

        let ring_env = std::env::var("SOZUNE_PROVIDER_RING_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_RING_ENDPOINT").is_ok()
            || std::env::var("SOZUNE_PROVIDER_RING_TOKEN").is_ok()
            || std::env::var("SOZUNE_PROVIDER_RING_POLL_INTERVAL").is_ok()
            || std::env::var("SOZUNE_PROVIDER_RING_EXPOSE_BY_DEFAULT").is_ok();
        if ring_env || self.ring.is_some() {
            self.ring
                .get_or_insert_with(RingConfig::default)
                .apply_env_overrides();
        }

        let config_file_env = std::env::var("SOZUNE_PROVIDER_CONFIG_FILE_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_CONFIG_FILE_PATH").is_ok()
            || std::env::var("SOZUNE_PROVIDER_CONFIG_FILE_WATCH").is_ok();
        if config_file_env || self.config_file.is_some() {
            self.config_file
                .get_or_insert_with(|| ConfigFileConfig {
                    enabled: false,
                    path: String::new(),
                    watch: true,
                })
                .apply_env_overrides();
        }

        let http_env = std::env::var("SOZUNE_PROVIDER_HTTP_ENABLED").is_ok()
            || std::env::var("SOZUNE_PROVIDER_HTTP_URL").is_ok()
            || std::env::var("SOZUNE_PROVIDER_HTTP_POLL_INTERVAL").is_ok()
            || std::env::var("SOZUNE_PROVIDER_HTTP_AUTH_HEADER").is_ok()
            || std::env::var("SOZUNE_PROVIDER_HTTP_AUTH_VALUE").is_ok();
        if http_env || self.http.is_some() {
            self.http
                .get_or_insert_with(|| HttpProviderConfig {
                    enabled: false,
                    url: String::new(),
                    poll_interval: default_http_provider_poll_interval(),
                    auth_header: String::new(),
                    auth_value: String::new(),
                })
                .apply_env_overrides();
        }
    }
}

impl DockerConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_DOCKER_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_DOCKER_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
    }
}

impl PodmanConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_PODMAN_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_PODMAN_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
    }
}

impl SwarmConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_SWARM_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_SWARM_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_SWARM_NETWORK") {
            self.network = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL") {
            self.refresh_interval = v;
        }
    }
}

impl KubernetesConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_KUBERNETES_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG") {
            self.kubeconfig = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_KUBERNETES_NAMESPACE") {
            self.namespace = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS") {
            self.ingress_class = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
    }
}

impl NomadConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_NOMAD_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_NOMAD_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_NOMAD_TOKEN") {
            self.token = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_NOMAD_NAMESPACE") {
            self.namespace = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL") {
            self.poll_interval = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
    }
}

impl RingConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_RING_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_RING_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_RING_TOKEN") {
            self.token = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROVIDER_RING_POLL_INTERVAL") {
            self.poll_interval = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_RING_EXPOSE_BY_DEFAULT") {
            self.expose_by_default = v;
        }
    }
}

impl ConfigFileConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_CONFIG_FILE_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_CONFIG_FILE_PATH") {
            self.path = v;
        }
        if let Some(v) = env_bool("SOZUNE_PROVIDER_CONFIG_FILE_WATCH") {
            self.watch = v;
        }
    }
}

impl HttpProviderConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_PROVIDER_HTTP_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_HTTP_URL") {
            self.url = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROVIDER_HTTP_POLL_INTERVAL") {
            self.poll_interval = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_HTTP_AUTH_HEADER") {
            self.auth_header = v;
        }
        if let Some(v) = env_string("SOZUNE_PROVIDER_HTTP_AUTH_VALUE") {
            self.auth_value = v;
        }
    }
}

impl ApiConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_API_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_API_LISTEN_ADDRESS") {
            self.listen_address = v;
        }
    }
}

impl ProxyConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_parse::<u16>("SOZUNE_HTTP_PORT") {
            self.http.listen_address = v;
        }
        if let Some(v) = env_parse::<u16>("SOZUNE_HTTPS_PORT") {
            self.https.listen_address = v;
        }
        if let Some(v) = env_parse::<usize>("SOZUNE_PROXY_MAX_BUFFERS") {
            self.max_buffers = v;
        }
        if let Some(v) = env_parse::<usize>("SOZUNE_PROXY_BUFFER_SIZE") {
            self.buffer_size = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROXY_STARTUP_DELAY_MS") {
            self.startup_delay_ms = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS") {
            self.cluster_setup_delay_ms = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROXY_RELOAD_DEBOUNCE_MS") {
            self.reload_debounce_ms = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROXY_METRICS_POLL_TIMEOUT_MS") {
            self.metrics_poll_timeout_ms = v;
        }
        if let Some(v) = env_parse::<u64>("SOZUNE_PROXY_COMMAND_BUFFER_MAX_BYTES") {
            self.command_buffer_max_bytes = v;
        }
    }
}

impl MiddlewareConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_parse::<u16>("SOZUNE_MIDDLEWARE_PORT") {
            self.port = v;
        }
    }
}

impl LogConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_string("SOZUNE_LOG_FORMAT") {
            match v.trim().to_ascii_lowercase().as_str() {
                "json" => self.format = LogFormat::Json,
                "text" => self.format = LogFormat::Text,
                other => {
                    // Unknown value: keep the current format. A warning here
                    // would predate tracing init, so we stay silent and let the
                    // documented default stand.
                    let _ = other;
                }
            }
        }
    }
}

impl TracingConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_TRACING_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_TRACING_ENDPOINT") {
            self.endpoint = v;
        }
        if let Some(v) = env_string("SOZUNE_TRACING_SERVICE_NAME") {
            self.service_name = v;
        }
        if let Some(v) = env_string("SOZUNE_TRACING_SAMPLER") {
            self.sampler = v;
        }
    }
}

impl DashboardConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_DASHBOARD_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_DASHBOARD_LISTEN_ADDRESS") {
            self.listen_address = v;
        }
    }
}

impl MetricsConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_METRICS_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_METRICS_LISTEN_ADDRESS") {
            self.listen_address = v;
        }
    }
}

impl AcmeConfig {
    fn apply_env_overrides(&mut self) {
        if let Some(v) = env_bool("SOZUNE_ACME_ENABLED") {
            self.enabled = v;
        }
        if let Some(v) = env_string("SOZUNE_ACME_EMAIL") {
            self.email = v;
        }
        if let Some(v) = env_string("SOZUNE_ACME_CERTS_DIR") {
            self.certs_dir = v;
        }
        if let Some(v) = env_bool("SOZUNE_ACME_STAGING") {
            self.staging = v;
        }
        if let Some(v) = env_parse::<u16>("SOZUNE_ACME_CHALLENGE_PORT") {
            self.challenge_port = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ENV_LOCK;

    /// RAII helper: sets `SOZUNE_*` vars on construction, removes them on drop.
    /// Use together with `ENV_LOCK` to keep tests isolated.
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

    #[test]
    fn apply_env_overrides_on_default_config_populates_optional_providers() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("SOZUNE_PROVIDER_DOCKER_ENABLED", "true"),
            ("SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT", "false"),
            ("SOZUNE_PROVIDER_CONFIG_FILE_ENABLED", "true"),
            (
                "SOZUNE_PROVIDER_CONFIG_FILE_PATH",
                "/etc/sozune/entrypoints.yaml",
            ),
            ("SOZUNE_PROVIDER_CONFIG_FILE_WATCH", "true"),
            ("SOZUNE_HTTP_PORT", "8080"),
            ("SOZUNE_HTTPS_PORT", "8443"),
            ("SOZUNE_ACME_ENABLED", "true"),
            ("SOZUNE_ACME_EMAIL", "ops@example.com"),
            ("SOZUNE_ACME_STAGING", "false"),
            ("SOZUNE_ACME_CERTS_DIR", "/certs"),
            ("SOZUNE_API_ENABLED", "false"),
            ("SOZUNE_DASHBOARD_ENABLED", "false"),
        ]);

        let mut config = AppConfig::default();
        config.apply_env_overrides();

        let docker = config
            .providers
            .docker
            .expect("docker provider should be materialised");
        assert!(docker.enabled);
        assert!(!docker.expose_by_default);

        let cfg_file = config
            .providers
            .config_file
            .expect("config_file provider should be materialised");
        assert!(cfg_file.enabled);
        assert_eq!(cfg_file.path, "/etc/sozune/entrypoints.yaml");
        assert!(cfg_file.watch);

        assert_eq!(config.proxy.http.listen_address, 8080);
        assert_eq!(config.proxy.https.listen_address, 8443);

        let acme = config
            .acme
            .expect("acme should be materialised when SOZUNE_ACME_* is set");
        assert!(acme.enabled);
        assert_eq!(acme.email, "ops@example.com");
        assert!(!acme.staging);
        assert_eq!(acme.certs_dir, "/certs");

        assert!(!config.api.enabled);
        assert!(!config.dashboard.enabled);
    }

    #[test]
    fn apply_env_overrides_without_env_keeps_defaults() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Defensively clear anything a previous test might have leaked.
        unsafe {
            for k in [
                "SOZUNE_PROVIDER_DOCKER_ENABLED",
                "SOZUNE_PROVIDER_DOCKER_ENDPOINT",
                "SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT",
                "SOZUNE_PROVIDER_CONFIG_FILE_ENABLED",
                "SOZUNE_PROVIDER_CONFIG_FILE_PATH",
                "SOZUNE_PROVIDER_CONFIG_FILE_WATCH",
                "SOZUNE_PROVIDER_HTTP_ENABLED",
                "SOZUNE_PROVIDER_HTTP_URL",
                "SOZUNE_PROVIDER_HTTP_POLL_INTERVAL",
                "SOZUNE_HTTP_PORT",
                "SOZUNE_HTTPS_PORT",
                "SOZUNE_ACME_ENABLED",
                "SOZUNE_ACME_EMAIL",
                "SOZUNE_ACME_STAGING",
                "SOZUNE_ACME_CERTS_DIR",
                "SOZUNE_ACME_CHALLENGE_PORT",
                "SOZUNE_API_ENABLED",
                "SOZUNE_DASHBOARD_ENABLED",
            ] {
                std::env::remove_var(k);
            }
        }

        let mut config = AppConfig::default();
        config.apply_env_overrides();

        assert!(config.providers.docker.is_none());
        assert!(config.providers.config_file.is_none());
        assert!(config.providers.http.is_none());
        assert!(config.acme.is_none());
        assert_eq!(config.proxy.http.listen_address, 80);
        assert_eq!(config.proxy.https.listen_address, 443);
    }

    #[test]
    fn apply_env_overrides_overrides_yaml_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("SOZUNE_HTTP_PORT", "8080"),
            ("SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT", "true"),
            ("SOZUNE_ACME_EMAIL", "override@example.com"),
        ]);

        let yaml = r#"
providers:
  docker:
    enabled: true
    expose_by_default: false
api:
  enabled: false
  listen_address: "127.0.0.1:3035"
proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
acme:
  enabled: true
  email: yaml@example.com
"#;
        let mut config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        config.apply_env_overrides();

        let docker = config.providers.docker.expect("docker present in YAML");
        assert!(docker.enabled, "yaml value preserved when no env override");
        assert!(
            docker.expose_by_default,
            "env should override yaml false → true"
        );

        assert_eq!(
            config.proxy.http.listen_address, 8080,
            "env overrides yaml port"
        );
        assert_eq!(
            config.proxy.https.listen_address, 443,
            "yaml preserved when no env"
        );

        let acme = config.acme.expect("acme present in YAML");
        assert_eq!(acme.email, "override@example.com");
        assert!(acme.enabled, "yaml-only fields untouched");
    }

    #[test]
    fn apply_env_overrides_enables_metrics_listener_without_yaml() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::new(&[
            ("SOZUNE_METRICS_ENABLED", "true"),
            ("SOZUNE_METRICS_LISTEN_ADDRESS", "0.0.0.0:9100"),
        ]);

        // Env-only deployment: no config file, so `apply_env_overrides` is the
        // only path that can turn the metrics listener on.
        let mut config = AppConfig::default();
        assert!(!config.metrics.enabled, "disabled by default");
        config.apply_env_overrides();

        assert!(config.metrics.enabled, "env enables the metrics listener");
        assert_eq!(config.metrics.listen_address, "0.0.0.0:9100");
    }

    #[test]
    fn test_default_values() {
        assert_eq!(default_http_port(), 80);
        assert_eq!(default_https_port(), 443);
        assert_eq!(default_max_buffers(), 500);
        assert_eq!(default_buffer_size(), 16384);
        assert_eq!(default_startup_delay_ms(), 1000);
        assert_eq!(default_cluster_setup_delay_ms(), 500);
        assert_eq!(default_reload_debounce_ms(), 500);
        assert_eq!(default_metrics_poll_timeout_ms(), 200);
        assert_eq!(default_command_buffer_max_bytes(), 65536);
    }

    #[test]
    fn test_get_env_port_with_valid_env() {
        unsafe {
            std::env::set_var("TEST_PORT", "9000");
            let result = get_env_port("TEST_PORT", 8080);
            assert_eq!(result, 9000);
            std::env::remove_var("TEST_PORT");
        }
    }

    #[test]
    fn test_get_env_port_with_invalid_env() {
        unsafe {
            std::env::set_var("TEST_PORT_INVALID", "not_a_number");
            let result = get_env_port("TEST_PORT_INVALID", 8080);
            assert_eq!(result, 8080);
            std::env::remove_var("TEST_PORT_INVALID");
        }
    }

    #[test]
    fn test_get_env_port_no_env() {
        let result = get_env_port("NON_EXISTENT_PORT", 3000);
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_proxy_config_deserialization() {
        // Take ENV_LOCK to avoid seeing env vars set by sibling tests; the
        // serde deserializers honour SOZUNE_* env vars even on a YAML-only path.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            for k in [
                "SOZUNE_HTTP_PORT",
                "SOZUNE_HTTPS_PORT",
                "SOZUNE_PROXY_MAX_BUFFERS",
                "SOZUNE_PROXY_BUFFER_SIZE",
                "SOZUNE_PROXY_STARTUP_DELAY_MS",
                "SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS",
                "SOZUNE_PROXY_RELOAD_DEBOUNCE_MS",
                "SOZUNE_PROXY_METRICS_POLL_TIMEOUT_MS",
                "SOZUNE_PROXY_COMMAND_BUFFER_MAX_BYTES",
            ] {
                std::env::remove_var(k);
            }
        }

        let yaml = r#"
http:
  listen_address: 9080
https:
  listen_address: 9443
max_buffers: 1000
buffer_size: 32768
startup_delay_ms: 2000
cluster_setup_delay_ms: 1000
reload_debounce_ms: 750
metrics_poll_timeout_ms: 250
command_buffer_max_bytes: 131072
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.http.listen_address, 9080);
        assert_eq!(config.https.listen_address, 9443);
        assert_eq!(config.max_buffers, 1000);
        assert_eq!(config.buffer_size, 32768);
        assert_eq!(config.startup_delay_ms, 2000);
        assert_eq!(config.cluster_setup_delay_ms, 1000);
        assert_eq!(config.reload_debounce_ms, 750);
        assert_eq!(config.metrics_poll_timeout_ms, 250);
        assert_eq!(config.command_buffer_max_bytes, 131072);
    }

    #[test]
    fn test_udp_listeners_deserialization() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
udp:
  - name: dns
    listen: 53
  - name: syslog
    listen: 514
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.udp.len(), 2);
        assert_eq!(config.udp[0].name, "dns");
        assert_eq!(config.udp[0].listen, 53);
        assert_eq!(config.udp[1].name, "syslog");
        assert_eq!(config.udp[1].listen, 514);
    }

    #[test]
    fn test_tcp_ip_allow_list_deserialization() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
tcp:
  - name: postgres
    listen: 5432
    ip_allow_list: ["94.23.3.96", "172.16.0.0/12"]
  - name: redis
    listen: 6379
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tcp.len(), 2);
        assert_eq!(
            config.tcp[0].ip_allow_list,
            vec!["94.23.3.96".to_string(), "172.16.0.0/12".to_string()]
        );
        // Absent ip_allow_list defaults to empty (allow all).
        assert!(config.tcp[1].ip_allow_list.is_empty());
    }

    #[test]
    fn test_tcp_rate_limit_deserialization() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
tcp:
  - name: postgres
    listen: 5432
    rate_limit:
      max_conns: 10
      per_seconds: 3
      exempt: ["172.16.0.0/12"]
  - name: redis
    listen: 6379
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let rl = config.tcp[0]
            .rate_limit
            .as_ref()
            .expect("rate_limit present");
        assert_eq!(rl.max_conns, 10);
        assert_eq!(rl.per_seconds, 3);
        assert_eq!(rl.exempt, vec!["172.16.0.0/12".to_string()]);
        // Absent rate_limit stays None (no limit).
        assert!(config.tcp[1].rate_limit.is_none());
    }

    #[test]
    fn test_udp_defaults_to_empty() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.udp.is_empty());
    }

    #[test]
    fn test_podman_config_deserialization() {
        let yaml = r#"
enabled: true
endpoint: /run/podman/podman.sock
expose_by_default: true
"#;
        let config: PodmanConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/run/podman/podman.sock");
        assert!(config.expose_by_default);
    }

    #[test]
    fn test_podman_config_defaults() {
        let config = PodmanConfig::default();
        assert!(!config.enabled);
        assert!(!config.expose_by_default);
        assert!(config.endpoint.ends_with("podman.sock"));
    }

    #[test]
    fn test_kubernetes_config_deserialization() {
        let yaml = r#"
enabled: true
kubeconfig: /home/user/.kube/config
namespace: default
ingress_class: sozune
expose_by_default: false
"#;
        let config: KubernetesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.kubeconfig, "/home/user/.kube/config");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.ingress_class, "sozune");
        assert!(!config.expose_by_default);
    }

    #[test]
    fn test_kubernetes_config_defaults() {
        let config = KubernetesConfig::default();
        assert!(!config.enabled);
        assert!(config.kubeconfig.is_empty());
        assert!(config.namespace.is_empty());
        assert_eq!(config.ingress_class, "sozune");
        assert!(!config.expose_by_default);
    }

    #[test]
    fn test_swarm_config_deserialization() {
        let yaml = r#"
enabled: true
endpoint: /var/run/docker.sock
expose_by_default: true
network: traefik-public
refresh_interval: 30
"#;
        let config: SwarmConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/var/run/docker.sock");
        assert!(config.expose_by_default);
        assert_eq!(config.network, "traefik-public");
        assert_eq!(config.refresh_interval, 30);
    }

    #[test]
    fn test_swarm_config_defaults() {
        let config = SwarmConfig::default();
        assert!(!config.enabled);
        assert!(!config.expose_by_default);
        assert_eq!(config.endpoint, "/var/run/docker.sock");
        assert!(config.network.is_empty());
        assert_eq!(config.refresh_interval, 15);
    }

    #[test]
    fn test_swarm_config_partial_yaml_uses_defaults() {
        let yaml = r#"
enabled: true
"#;
        let config: SwarmConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/var/run/docker.sock");
        assert!(!config.expose_by_default);
        assert!(config.network.is_empty());
        assert_eq!(config.refresh_interval, 15);
    }

    #[test]
    fn test_proxy_config_with_defaults() {
        // ProxyConfig deserializers read SOZUNE_* env vars; hold the shared
        // lock so a sibling test setting those vars can't bleed in here.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let yaml = r#"
http:
  listen_address: 9080
https:
  listen_address: 9443
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.http.listen_address, 9080);
        assert_eq!(config.https.listen_address, 9443);
        // Vérifier que les valeurs par défaut sont utilisées
        assert_eq!(config.max_buffers, 500);
        assert_eq!(config.buffer_size, 16384);
        assert_eq!(config.startup_delay_ms, 1000);
        assert_eq!(config.cluster_setup_delay_ms, 500);
        assert_eq!(config.reload_debounce_ms, 500);
        assert_eq!(config.metrics_poll_timeout_ms, 200);
        assert_eq!(config.command_buffer_max_bytes, 65536);
    }

    #[test]
    fn test_proxy_config_tcp_listeners() {
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
tcp:
  - name: postgres
    listen: 5432
  - name: mysql
    listen: 3306
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tcp.len(), 2);
        assert_eq!(config.tcp[0].name, "postgres");
        assert_eq!(config.tcp[0].listen, 5432);
        assert_eq!(config.tcp[1].name, "mysql");
        assert_eq!(config.tcp[1].listen, 3306);
    }

    #[test]
    fn test_proxy_config_tcp_defaults_to_empty() {
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.tcp.is_empty());
    }

    #[test]
    fn https_http2_defaults_to_unset() {
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.https.http2.alpn_protocols.is_none());
        assert!(config.https.http2.disable_http11.is_none());
    }

    #[test]
    fn https_http2_block_is_parsed() {
        let yaml = r#"
http:
  listen_address: 80
https:
  listen_address: 443
  http2:
    alpn_protocols: ["http/1.1"]
    disable_http11: false
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.https.http2.alpn_protocols,
            Some(vec!["http/1.1".to_string()])
        );
        assert_eq!(config.https.http2.disable_http11, Some(false));
    }

    #[test]
    fn log_format_defaults_to_text() {
        assert_eq!(LogConfig::default().format, LogFormat::Text);
        // An AppConfig with no `log:` block also defaults to text.
        let cfg: AppConfig = serde_yaml::from_str("{}").unwrap_or_default();
        assert_eq!(cfg.log.format, LogFormat::Text);
    }

    #[test]
    fn log_format_parses_json_from_yaml() {
        let cfg: LogConfig = serde_yaml::from_str("format: json").unwrap();
        assert_eq!(cfg.format, LogFormat::Json);
        let cfg: LogConfig = serde_yaml::from_str("format: text").unwrap();
        assert_eq!(cfg.format, LogFormat::Text);
    }

    #[test]
    fn log_format_env_override_wins() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = LogConfig::default();
        {
            let _env = EnvGuard::new(&[("SOZUNE_LOG_FORMAT", "json")]);
            cfg.apply_env_overrides();
        }
        assert_eq!(cfg.format, LogFormat::Json);
    }

    #[test]
    fn log_format_env_unknown_value_keeps_current() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = LogConfig {
            format: LogFormat::Json,
        };
        {
            let _env = EnvGuard::new(&[("SOZUNE_LOG_FORMAT", "garbage")]);
            cfg.apply_env_overrides();
        }
        // Unknown value must not silently flip the format.
        assert_eq!(cfg.format, LogFormat::Json);
    }
}
