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
    /// Host to write into a permanent redirect's `Location`, overriding the
    /// request host. Maps to Sōzu's `rewrite_host`. A literal value (no
    /// `$HOST[n]` / `$PATH[n]` capture) is a fixed authority.
    #[serde(default)]
    pub rewrite_host: Option<String>,
    /// Path to write into a permanent redirect's `Location`, overriding the
    /// request path. Maps to Sōzu's `rewrite_path`, same template grammar.
    #[serde(default)]
    pub rewrite_path: Option<String>,
    /// Transparent URL rewrite applied to the forwarded request (Gateway API
    /// `urlRewrite` filter). Unlike `rewrite_host` / `rewrite_path` above —
    /// which only shape a permanent redirect's `Location` — this rewrites the
    /// request the backend receives, with no redirect to the client. When
    /// set, it takes precedence over `strip_prefix` / `add_prefix`. Maps onto
    /// Sōzu's native frontend `rewrite_path` / `rewrite_host`.
    #[serde(default)]
    pub rewrite: Option<UrlRewrite>,
    /// Port to write into a permanent redirect's `Location`. Maps to Sōzu's
    /// `rewrite_port`.
    #[serde(default)]
    pub rewrite_port: Option<u16>,
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
    /// Active HTTP health check. When set, the health checker issues a
    /// `GET <path>` against each backend and judges health on the status code
    /// instead of a bare TCP connect. `None` (default) keeps the TCP probe.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Retry a failed forward to the backend (connection error or timeout)
    /// up to N attempts. `None` (default) disables retries.
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Per-route circuit breaker. When set, a backend that fails too often is
    /// short-circuited with `503` until it recovers. `None` (default) disables.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Maximum number of concurrent in-flight requests per client IP for this
    /// route. When the limit is reached, further requests from that IP are
    /// rejected with `503 Service Unavailable` until an in-flight request
    /// completes. `None` (default) disables the limiter.
    #[serde(default)]
    pub in_flight_req: Option<u64>,
    /// Load-balancing algorithm across this entrypoint's backends. Defaults to
    /// round-robin. Maps to Sōzu's `LoadBalancingAlgorithms`.
    #[serde(default)]
    pub load_balancer: LoadBalancer,
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
    /// IP allow-list — list of IPs / CIDR ranges (IPv4 or IPv6). When
    /// non-empty, a request whose resolved client IP matches none of the
    /// entries is rejected with `403 Forbidden` before reaching auth,
    /// rate-limit, or the backend. Empty (default) disables the filter.
    /// See `ProxyConfig::trusted_proxies` for how the client IP is resolved.
    #[serde(default)]
    pub ip_allow_list: Vec<String>,
    /// Request header match conditions. When non-empty, a request is served by
    /// this entrypoint only if every listed header is present with the given
    /// value. Sōzu routes on host/path/method only, so this is enforced by a
    /// middleware that returns `404` when a condition fails.
    #[serde(default)]
    pub match_headers: Vec<MatchCondition>,
    /// Query-parameter match conditions. Same semantics as `match_headers`,
    /// against the request's query string.
    #[serde(default)]
    pub match_query: Vec<MatchCondition>,
    /// Client-IP route matcher — list of IPs / CIDR ranges (IPv4 or IPv6).
    /// When non-empty, this entrypoint serves a request only if its resolved
    /// client IP matches one of the entries; otherwise the request is rejected
    /// with `404 Not Found`, as if the route didn't match. This is a *routing*
    /// matcher (distinct from `ip_allow_list`, which is an access filter that
    /// returns `403`). The client IP is resolved exactly like the allow-list —
    /// see `ProxyConfig::trusted_proxies`.
    #[serde(default)]
    pub match_client_ip: Vec<String>,
}

/// One key/value match condition used by header and query matching. An empty
/// `value` matches on key presence alone.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct MatchCondition {
    pub key: String,
    #[serde(default)]
    pub value: String,
}

/// Load-balancing algorithm across an entrypoint's backends. Mirrors the
/// algorithms Sōzu's worker supports; `RoundRobin` is the default.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancer {
    /// Cycle through backends in order (default).
    #[default]
    RoundRobin,
    /// Pick a backend at random.
    Random,
    /// Power-of-two-choices: sample two backends, pick the less loaded.
    PowerOfTwo,
    /// Send to the backend with the fewest active connections.
    LeastConnections,
}

/// Active HTTP health-check parameters for an entrypoint's backends.
///
/// When present, the health checker sends `GET <path>` to each backend (over
/// plain HTTP to `host:port`) and considers it healthy when the response status
/// is accepted. With `status = None`, any `2xx`/`3xx` is healthy (the Traefik
/// default); with `status = Some(code)`, only that exact code is.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct HealthCheckConfig {
    /// Request path, e.g. `/health`. Leading slash recommended; the checker
    /// prefixes one if missing.
    pub path: String,
    /// Exact status code required for "healthy". `None` accepts any 2xx/3xx.
    #[serde(default)]
    pub status: Option<u16>,
    /// Per-check request timeout in milliseconds. `None` falls back to the
    /// checker's global default (5s). Lets a deliberately slow `/health`
    /// endpoint avoid being marked down at the global cutoff.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Retry policy for forwarding a request to a backend.
///
/// Retries cover **connection-level failures and timeouts** — the backend
/// never produced a response. A response that arrives (even a 5xx) is *not*
/// retried: the backend acted on the request, so a blind replay could double a
/// side effect. This matches Traefik's default retry semantics.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct RetryConfig {
    /// Total number of attempts (the first try plus retries). `2` means one
    /// retry. Values `<= 1` are treated as "no retry" by the parser.
    pub attempts: u32,
}

/// Per-route circuit-breaker tunables. The breaker trips when the recent
/// failure ratio (responses `>= 500` or transport errors) reaches `threshold`
/// over a window of at least `min_requests`, stays open for `cooldown_secs`,
/// then half-opens to probe recovery. Mirrors Traefik's defaults (50% / 10s).
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
pub struct CircuitBreakerConfig {
    /// Failure ratio in `(0.0, 1.0]` that trips the breaker.
    pub threshold: f64,
    /// Minimum recent observations before the ratio is evaluated.
    pub min_requests: u32,
    /// Seconds the breaker stays open before probing again.
    pub cooldown_secs: u64,
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

/// Transparent URL rewrite, mapped from the Gateway API `urlRewrite` filter.
/// Either field (or both) may be set; an all-`None` value is a no-op.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct UrlRewrite {
    /// Path rewrite — full-path replacement or prefix replacement.
    #[serde(default)]
    pub path: Option<PathRewrite>,
    /// Replacement value for the request's `Host` header (literal authority).
    #[serde(default)]
    pub hostname: Option<String>,
}

/// How the request path is rewritten before it reaches the backend.
///
/// - `ReplaceFullPath(new)` — the whole path becomes `new`, regardless of the
///   request's trailing segments.
/// - `ReplacePrefixMatch(new)` — the route's matched prefix is swapped for
///   `new`, keeping any trailing segments (`/api/users` with `from=/api`,
///   `new=/v2` → `/v2/users`). The matched (old) prefix comes from the
///   entrypoint's `path` at build time; this carries only the replacement.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum PathRewrite {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
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
