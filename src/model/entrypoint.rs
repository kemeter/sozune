use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct Entrypoint {
    pub id: String,
    pub backends: Vec<String>,
    pub name: String,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub backend_weights: HashMap<String, u32>,
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
    pub port: u16,
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
