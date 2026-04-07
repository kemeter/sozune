use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Entrypoint {
    pub id: String,
    pub backends: Vec<String>,
    pub name: String,
    pub protocol: Protocol,
    pub config: EntrypointConfig,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Protocol {
    Http,
    Tcp,
    Udp,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EntrypointConfig {
    pub hostnames: Vec<String>,
    pub port: u16,
    pub path: Option<PathConfig>,
    pub tls: bool,
    pub strip_prefix: bool,
    #[serde(default)]
    pub https_redirect: bool,
    pub priority: i32,
    pub auth: Option<AuthConfig>,
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub backend_timeout: Option<u64>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
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
    Exact,
    Prefix,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthConfig {
    pub basic: Option<Vec<BasicAuthUser>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BasicAuthUser {
    pub username: String,
    pub password_hash: String,
}

