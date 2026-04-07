# Changelog

All notable changes to this project will be documented in this file.

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