use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct Entrypoint {
    pub id: String,
    pub backends: Vec<Backend>,
    pub name: String,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
    #[serde(default)]
    pub source: Option<String>,
}

/// One backend instance: an address (IP or hostname), the port it listens
/// on, and an optional load-balancing weight (defaults to 100).
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Backend {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    100
}

impl Backend {
    pub fn new(address: impl Into<String>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            weight: default_weight(),
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum Protocol {
    Http,
    Tcp,
    Udp,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct EntrypointConfig {
    pub hostnames: Vec<String>,
    pub path: Option<PathConfig>,
    pub tls: bool,
    pub strip_prefix: bool,
    #[serde(default)]
    pub add_prefix: Option<String>,
    #[serde(default)]
    pub https_redirect: bool,
    #[serde(default)]
    pub https_redirect_port: Option<u16>,
    #[serde(default)]
    pub redirect: Option<RedirectPolicy>,
    #[serde(default)]
    pub redirect_scheme: Option<RedirectScheme>,
    #[serde(default)]
    pub redirect_template: Option<String>,
    #[serde(default)]
    pub www_authenticate: Option<String>,
    pub priority: i32,
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub forward_auth: Option<ForwardAuthConfig>,
    #[serde(default)]
    pub headers: Vec<HeaderConfig>,
    #[serde(default)]
    pub backend_timeout: Option<u64>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub sticky_session: bool,
    #[serde(default)]
    pub compress: bool,
    #[serde(default)]
    pub entrypoint: Option<String>,
    /// HTTP methods this entrypoint matches. Empty means any method.
    /// Methods are uppercased and validated against the standard verbs
    /// (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Per-entrypoint ACME settings. When `tls: true` and this is `None`,
    /// the legacy HTTP-01 fallback on `acme.challenge_port` is used.
    #[serde(default)]
    pub acme: Option<EntrypointAcmeConfig>,
    /// Names of WASM plugins (declared in `AppConfig.plugins`) to run as
    /// middleware on this entrypoint, in order.
    #[serde(default)]
    pub plugins: Vec<String>,
    /// Cluster-scoped custom HTTP answer templates, keyed by status code.
    /// Values may be inline bodies or `file://<path>` references when set
    /// from static YAML; when populated from provider labels, `file://` is
    /// refused and dropped via `error_pages::sanitize_provider_error_pages`.
    /// Overrides the listener-level defaults for this entrypoint only.
    #[serde(default)]
    pub error_pages: BTreeMap<String, String>,
}

/// Selects which ACME resolver (from `acme.resolvers`) issues certs for this
/// entrypoint. Wildcard hostnames require a `dns-01` resolver.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct EntrypointAcmeConfig {
    pub resolver: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct HeaderConfig {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub direction: HeaderDirection,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HeaderDirection {
    #[default]
    Request,
    Response,
    Both,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    Forward,
    Permanent,
    Unauthorized,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RedirectScheme {
    UseSame,
    UseHttp,
    UseHttps,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct RateLimitConfig {
    pub average: u64,
    pub burst: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct PathConfig {
    pub rule_type: PathRuleType,
    pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum PathRuleType {
    Prefix,
    Regex,
    Exact,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct AuthConfig {
    pub basic: Option<Vec<BasicAuthUser>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BasicAuthUser {
    pub username: String,
    pub password_hash: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct ForwardAuthConfig {
    pub address: String,
    #[serde(default)]
    pub response_headers: Vec<String>,
    #[serde(default)]
    pub trust_forward_header: bool,
}
