use serde::{Deserialize, Serialize};

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
