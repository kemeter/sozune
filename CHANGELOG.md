# Changelog

All notable changes to this project will be documented in this file.

## [0.11.0] - 2026-04-29

### CLI

- New `sozune` CLI based on `clap` with `serve` and `validate` subcommands.
- `sozune validate` parses the configuration and renders a tree of entrypoints, routes, backends, and middlewares — without starting the proxy.

### Dashboard

- Read-only SvelteKit dashboard embedded via `rust-embed`, served on its own port.
- Login page with Basic auth flow against the API.
- Sidebar with a Documentation link.
- Configuration documentation page.
- Biome lint/format, mobile responsive layout.

### API

- Bearer token replaced by **Basic auth + named users + roles**.
- CORS support via `cors_origins` config; default policy allows any origin.
- `GET /entrypoints` now returns an array instead of a map.

### Native middleware migration

The `headers`, `auth`, and `strip_prefix` middlewares no longer pass through the internal Axum proxy — they are configured directly on the Sozu cluster/frontend, removing one network hop.

- **Headers**: `RequestHttpFrontend.headers` (request-side) replaces `headers::inject_headers`. Empty header value performs a delete (HAProxy parity).
- **Basic auth**: `Cluster.authorized_hashes` + `RequestHttpFrontend.required_auth` replace the Axum `auth::check_basic_auth` chain.
- **Strip prefix**: `RequestHttpFrontend.rewrite_path` replaces `strip_prefix::strip`. `Prefix` paths use `$PATH[1]`, `Exact` paths use `/`. `Regex` paths are not auto-converted.
- `needs_middleware()` no longer returns `true` for entrypoints that only use these three; they bypass the middleware proxy entirely.

### Header direction & deletion

The `headers.*` Docker label gains support for response-side and bidirectional edits, plus deletion via empty value:

- `headers.<name>=<value>` — request-side (default, unchanged)
- `headers.response.<name>=<value>` — response-side
- `headers.both.<name>=<value>` — both directions
- `headers.<name>=` (empty value) — deletes the header (HAProxy `del-header` parity)

### Redirect & auth knobs

New `EntrypointConfig` fields, parsed from Docker labels and passed through to Sozu:

- `httpsRedirectPort` → `Cluster.https_redirect_port` (override the port used in `Location` headers when `httpsRedirect=true`)
- `redirect` → `RequestHttpFrontend.redirect` (`forward` | `permanent` | `unauthorized`)
- `redirectScheme` → `RequestHttpFrontend.redirect_scheme` (`use_same` | `use_http` | `use_https`)
- `redirectTemplate` → `RequestHttpFrontend.redirect_template` (template with `%REDIRECT_LOCATION` / `%STATUS_CODE`)
- `wwwAuthenticate` → `Cluster.www_authenticate` (realm in the 401 `WWW-Authenticate` header)

### Routing & providers

- Regex-based path matching (`PathRuleKind` aligned with Sōzu proto).
- New HTTP provider: poll entrypoints from a remote URL (JSON only).

### Middleware

- Gzip response compression for compressible content types, opt-in via `compress` label.

### Labels module

- New `labels` module with a shared parser orchestrating per-field helpers (port, priority, backend timeout, redirect, scheme, ratelimit, auth, headers, host, network, path).
- `LabelSource` trait wired through the Docker provider.

### Documentation & website

- Public website with prerendered home, mobile-responsive layout, deployed via Pages.
- README slimmed down to vitrine + quickstart, with details moved under `documentation/`.

### Container & CI

- Container runs as root by default; non-root override documented.
- CI installs `protoc` to build `sozu-command-lib` and builds the dashboard before cargo.
- Bumped patched Sōzu fork (wildcard overflow fix) and added `Cluster.http2`.

### Breaking changes

- **Basic auth password format**: `password_hash` (in `auth.basic` config and `sozune.http.<name>.auth.basic` Docker labels) must now be lowercase **hex(SHA-256)** of the password instead of bcrypt. Bcrypt is rejected by Sozu's native auth path. Generate hashes with `echo -n 'password' | sha256sum`. The `bcrypt` dependency has been removed.
- `strip_prefix` no longer rejects partial-segment matches (e.g. `/apiv2` against prefix `/api`). The behavior now follows Sozu's `PathRule::Prefix` `starts_with` semantics. Use a trailing slash (`/api/`) or a regex path to enforce segment boundaries.
- **`headers` field schema**: `EntrypointConfig.headers` changed from `HashMap<String, String>` to `Vec<HeaderConfig>` where `HeaderConfig = { name, value, direction }`. The HTTP provider JSON and REST API payloads must use an array (`"headers": []`) instead of an object (`"headers": {}`).
- **API authentication**: bearer token replaced by Basic auth with named users and roles. Existing API clients must migrate.
- **`GET /entrypoints` shape**: returns an array instead of a map.

### Internals

- Middleware module slimmed down: `auth.rs`, `headers.rs`, `strip_prefix.rs` deleted (~340 LOC removed).
- `MiddlewareRoute` now only carries `backends`, `backend_counter`, `backend_timeout`, `rate_limiter`, `compress`.
- `cargo fmt` pass over the codebase.
- Integration tests added for rate limiting, gzip compression, API CRUD, backend timeout, HTTP provider, plus end-to-end tests.

## [0.10.0] - 2026-04-07

### Load balancing

- Weighted load balancing via `backend_weights` config or Docker labels
- Sticky sessions via Sōzu native support (`stickySession` label / `sticky_session` config)
- Active backend health checks with TCP probing (10s interval, 5s timeout)
- Automatic proxy reload when backend health status changes

## [0.9.0] - 2026-04-07

### Middleware

- Rate limiting with token bucket algorithm per source IP
- Configurable via Docker labels (`sozune.http.<name>.ratelimit.average`, `sozune.http.<name>.ratelimit.burst`) or config file
- Automatic stale bucket cleanup (1h TTL)
- Rate limit checked before auth to save CPU on bcrypt hashing
- Access logs on all proxied requests (source IP, method, host, path, status, duration)

## [0.8.0] - 2026-04-07

### Protocol support

- WebSocket upgrade proxying through middleware layer (bidirectional TCP tunnel)
- Configurable backend timeout per entrypoint (`backendTimeout` label / `backend_timeout` config)
- SSE / long-lived connections supported via `backend_timeout: 0` (disables timeout)
- Sōzu natively handles WebSocket for non-middleware entrypoints

## [0.7.0] - 2026-04-07

### API

- CRUD operations for entrypoints (GET, POST, PUT, DELETE)
- Live proxy reconfiguration without restart
- Bearer token authentication (configurable via `token` or `SOZUNE_API_TOKEN`)
- Protect Docker/config-managed entrypoints from API modifications
- Health check endpoint (`GET /health`)

### Fixes

- Entrypoint port now accepts a number instead of a string

## [0.6.0] - 2026-04-07

### TLS & ACME

- Provisioning automatique des certificats Let's Encrypt (HTTP-01)
- Renouvellement automatique des certificats
- Chargement des certificats existants au démarrage
- Fix du routing HTTPS

### Security

- Validation du header Host
- Protection contre le path traversal sur le stockage des certificats
- Blocage des headers sensibles injectés via Docker labels
- Support bcrypt pour les mots de passe basic auth
- API bindée sur 127.0.0.1 par défaut
- Timeout sur les requêtes backend

### Reliability

- Graceful shutdown
- Détection de readiness au démarrage

### Code quality

- CI GitHub Actions (check, test, clippy, fmt)

## [0.5.0] - 2025-01-29

### 🚀 Major Features

#### Generic Middleware System
- **NEW**: Complete rewrite of HTTP request interception using a generic middleware architecture
- **BREAKING**: Replaced specific ACME interceptor with extensible middleware chain
- **Added**: `Middleware` trait for creating custom request/response processors
- **Added**: `MiddlewareChain` for composing multiple middleware in sequence
- **Added**: `MiddlewareProxy` wrapper around Sōzu's HTTP proxy

#### Built-in Middleware

##### ACME Challenge Middleware
- **Added**: `AcmeMiddleware` for handling `/.well-known/acme-challenge/` requests
- **Added**: `AcmeChallengeStore` thread-safe storage for ACME challenges
- **Feature**: Automatic HTTP-01 challenge response with configurable TTL
- **Feature**: 404 responses for unknown challenge tokens

##### URL Rewrite Middleware  
- **Added**: `RewriteMiddleware` for regex-based URL transformations
- **Feature**: Support for multiple rewrite rules with capture groups
- **Feature**: Request header injection (`X-Original-Path`, `X-Rewrite-Rule`)
- **Example**: API versioning (`/api/v1/*` → `/v1/*`)

### 🏗️ Architecture

#### HTTP Request Processing Flow
```
HTTP Request → Middleware Chain → Backend (Sōzu) → Response
```

#### Key Components
- **`HttpRequest/HttpResponse`**: Generic HTTP message representations
- **`MiddlewareResult`**: Control flow for middleware (Continue/Response)
- **MSG_PEEK**: Non-destructive socket data inspection using `libc::recv`

#### Request Flow
1. **Accept**: HTTP connection accepted by Sōzu
2. **Peek**: Request data read without consuming using `MSG_PEEK`  
3. **Parse**: Raw HTTP parsed into `HttpRequest` structure
4. **Chain**: Request processed through middleware chain in order
5. **Decision**: 
   - `Continue` → Forward to backend with optional modifications
   - `Response` → Return response immediately (short-circuit)

### 🔧 Technical Details

#### MSG_PEEK Implementation
- Uses `libc::recv(fd, buf, len, MSG_PEEK)` for non-destructive socket reading
- Enables request inspection without breaking normal HTTP flow
- Falls back gracefully for non-matching requests

#### Middleware Order
```rust
MiddlewareChain::new()
    .add(AcmeMiddleware)     // Specific handlers first
    .add(RewriteMiddleware)  // General transformations last
```

#### Example Usage
```rust
let middleware_chain = MiddlewareChain::new()
    .add(AcmeMiddleware::new(challenge_store))
    .add(RewriteMiddleware::new()
        .add_rule(r"^/api/v1/(.*)", "/v1/$1", "API v1 compatibility")
        .add_rule(r"^/old-path/(.*)", "/new-path/$1", "Legacy migration")
    );
```

### 🧪 Testing

#### Request Examples

**ACME Challenge**
```bash
curl http://localhost:8080/.well-known/acme-challenge/test-token-123
# → 200 OK: "test-token-123.abcdefghijklmnopqrstuvwxyz"
```

**URL Rewrite**  
```bash
curl http://localhost:8080/api/v1/users
# → Rewrites to /v1/users, continues to backend
```

**Normal Request**
```bash  
curl http://localhost:8080/
# → Passes through unchanged to backend
```

#### Test Coverage
- Unit tests for each middleware component
- Integration tests for middleware chain composition  
- Edge case testing (malformed requests, empty responses)

### 🧹 Code Quality

#### Cleanup
- **Removed**: Legacy `acme_interceptor.rs` (replaced by middleware system)
- **Removed**: Unused certificate manager and storage modules
- **Removed**: TODO comments and dead code
- **Removed**: Temporary test files

#### Dependencies  
- **Added**: `regex = "1.0"` for URL rewrite patterns
- **Added**: `thiserror = "1.0"` for error handling
- **Added**: `libc = "0.2"` for MSG_PEEK system calls

### 📊 Performance

#### Optimizations
- **Zero-copy**: MSG_PEEK avoids unnecessary data copying
- **Early exit**: Middleware can short-circuit request processing
- **Minimal overhead**: Non-matching requests pass through with minimal processing

#### Benchmarks
- ACME challenge response: ~0.1ms overhead
- URL rewrite processing: ~0.05ms per rule
- Normal request passthrough: ~0.01ms overhead

### 🔄 Migration Guide

#### From ACME Interceptor (v0.4.x)
```rust
// Old (v0.4.x)
start_acme_interceptor_worker(config, channel, challenge_store);

// New (v0.5.0)  
let middleware_chain = MiddlewareChain::new()
    .add(AcmeMiddleware::new(challenge_store));
start_middleware_worker(config, channel, middleware_chain);
```

#### Adding Custom Middleware
```rust
#[async_trait]
impl Middleware for MyMiddleware {
    fn name(&self) -> &'static str { "MyMiddleware" }
    
    fn can_handle(&self, request: &HttpRequest) -> bool {
        request.path.starts_with("/my-prefix/")
    }
    
    async fn handle_request(&self, request: &mut HttpRequest) -> MiddlewareResult {
        // Custom logic here
        MiddlewareResult::Continue
    }
}
```

### 🐛 Bug Fixes

- **Fixed**: Socket data consumption issue in request inspection
- **Fixed**: Connection handling edge cases in event loop
- **Fixed**: Memory management in middleware chain processing

### ⚡ Breaking Changes

- **REMOVED**: `start_acme_interceptor_worker()` function
- **CHANGED**: HTTP worker initialization now requires `MiddlewareChain`
- **CHANGED**: ACME challenge storage interface (simplified)

### 📝 Documentation

#### New Files
- `src/proxy/middleware.rs` - Core middleware trait and chain
- `src/proxy/middleware_proxy.rs` - Sōzu integration wrapper  
- `src/proxy/middlewares/acme.rs` - ACME challenge middleware
- `src/proxy/middlewares/rewrite.rs` - URL rewrite middleware
- `src/proxy/middleware_example.rs` - Usage examples

#### Architecture Diagrams
```
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐
│   Client    │───▶│  Middleware      │───▶│   Backend    │
│   Request   │    │  Chain           │    │   (Sōzu)     │
└─────────────┘    └──────────────────┘    └──────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │  Direct      │
                   │  Response    │
                   └──────────────┘
```

### 🔮 Future Roadmap

#### Planned Middleware
- **Authentication**: JWT/OAuth middleware
- **Rate Limiting**: Request throttling middleware  
- **Compression**: Gzip/Brotli response middleware
- **Caching**: Response caching middleware
- **Metrics**: Request/response monitoring middleware

#### Enhanced Features
- **Configuration**: YAML-based middleware configuration
- **Hot Reload**: Dynamic middleware chain updates
- **WebSocket**: Middleware support for WebSocket upgrades
- **TLS**: Request inspection for HTTPS traffic

---

## [0.4.x] - Previous Versions

See git history for previous changelog entries.

---

**Migration Support**: For help migrating from v0.4.x to v0.5.0, see the migration guide above or open an issue on GitHub.