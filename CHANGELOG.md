# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.14.0-dev]

### TLS / ACME

- DNS-01 challenge support via named resolvers — declare `acme.resolvers` with `challenge: dns-01` and a provider (Cloudflare, OVH, Gandi, Scaleway), then point an entrypoint at it with `acme.resolver: <name>`. Provider credentials are read from environment variables, never inlined in YAML. DNS-01 solving is delegated to [cheti](https://github.com/kemeter/cheti).
- Wildcard certificates — `*.example.com` can now be issued through a DNS-01 resolver. Attempting a wildcard on an HTTP-01 resolver fails loudly. Wildcard certs are stored under `_wildcard_.example.com/` on disk.
- Entrypoints with `tls: true` but no `acme.resolver` keep the existing HTTP-01 behaviour on `challenge_port` — no migration needed.
- ACME account persistence and certificate renewal checks now use cheti (`FileAccountStore`, `needs_renewal`), replacing the in-tree X.509 parser. Storage layout is unchanged (`certs_dir/account_credentials.json`).
- HTTP/2 listener tuning — `proxy.https.http2.alpn_protocols` and `http2.disable_http11` let you control ALPN on the TLS listener (force HTTP/1.1-only, or h2-only). Both default to unset, keeping the existing behaviour (ALPN `["h2", "http/1.1"]`, HTTP/2 negotiated by default).

### Routing

- `addPrefix` middleware — prepend a fixed path prefix to incoming requests before forwarding to the backend. Counterpart of `stripPrefix`, useful for serving a sub-path of an existing app under a dedicated subdomain (e.g. `expats.example.com` → backend receives `/foo`). Available via Docker/Swarm/Podman/Nomad labels (`sozune.http.<svc>.addPrefix=/foo`), the HTTP provider, the YAML config file, and the REST API.
- UDP load balancing — UDP listeners now load-balance datagrams across backends with flow affinity: datagrams from the same source IP form a virtual flow pinned to one backend. Two flow-affine algorithms are available, set per service via `sozune.udp.<svc>.loadBalancer`: `hrw` (Highest-Random-Weight / rendezvous hashing, stable under backend churn, recommended) and `maglev` (consistent hashing with O(1) lookup, for large backend sets). `round_robin`, `random`, `power_of_two`, and `least_connections` are also accepted. Requesting `hrw`/`maglev` on an HTTP or TCP service emits `W022` and falls back to round-robin. See [UDP routing docs](documentation/routing/udp.md#load-balancing).
- Source-IP allow-list on TCP listeners — restrict which source IPs may connect to a TCP listener with `ip_allow_list` (CIDRs or bare IPs), checked at `accept()` on the public port. Empty (default) allows all. See [TCP routing docs](documentation/routing/tcp.md#source-ip-allow-list).
- Per-source connection-rate anti-flood on TCP listeners — cap how fast a single source IP may open new connections with `rate_limit` (`max_conns` per `per_seconds`) on a `proxy.tcp` listener; excess connections are dropped before `accept()`. See [TCP routing docs](documentation/routing/tcp.md#anti-flood-per-source-connection-rate).

### Middleware

- Custom error pages — serve a custom body when Sōzune returns `404`, `503` or any of the 12 statuses Sōzu can template (`301, 400, 401, 404, 408, 413, 421, 429, 502, 503, 504, 507`). Two scopes compose: listener-level defaults (`proxy.http.error_pages` / `proxy.https.error_pages`) and entrypoint-level overrides (`entrypoints[*].error_pages`). Three value shapes are accepted — inline body (wrapped into a valid HTTP/1.1 response on your behalf), full HTTP/1.1 response (passed through), or `file://path` (loaded from disk). Available via Docker/Swarm/Podman/Nomad labels (`sozune.http.<svc>.errorPages.<code>=<body>`, inline only — `file://` is refused from provider labels for security), the HTTP provider, the YAML config file, and the REST API. See [Error pages docs](documentation/middleware/error-pages.md).
- `forwardAuth` — delegate authentication to an external service (e.g. Authelia, Authentik). The proxy issues a sub-request to the auth service before each protected request and forwards selected response headers (`Remote-User`, `Remote-Email`, `Remote-Groups`) to the backend. Supports `address`, `responseHeaders` (comma-separated), and `trustForwardHeader`. See [Forward auth docs](documentation/middleware/forward-auth.md).
- `inFlightReq` — cap the number of concurrent in-flight requests per client IP on a route; excess requests get `503`. Available via Docker/Swarm/Podman/Nomad labels (`sozune.http.<svc>.inFlightReq=N`), the HTTP provider, the YAML config file, and the REST API. See [In-flight request docs](documentation/middleware/in-flight-req.md).
- Circuit breaker — stop forwarding to a backend whose recent failure rate crosses a threshold: the breaker opens, answers `503` immediately for a cooldown, then probes once and closes when healthy. Per route, configured with `circuitBreaker.threshold` (default `0.5`), `circuitBreaker.minRequests` (default `20`), and `circuitBreaker.cooldown` seconds (default `10`); `5xx` and connection errors count as failures, `4xx` does not. Available via Docker/Swarm/Podman/Nomad labels, the HTTP provider, the YAML config file, and the REST API. See [Circuit breaker docs](documentation/middleware/circuit-breaker.md).
- Retry on backend failure — retry a request when forwarding fails before any response (connection refused/reset, or backend timeout). `sozune.http.<svc>.retry.attempts` is the total number of tries (`3` = up to two retries); responses that arrive — even `5xx` — are never retried, so non-idempotent side effects aren't replayed. Available via Docker/Swarm/Podman/Nomad labels, the HTTP provider, the YAML config file, and the REST API. See [Retry docs](documentation/middleware/retry.md).

### Docker provider

- HEALTHCHECK gating — when a container declares a Docker `HEALTHCHECK`, sōzune now treats it as a readiness probe and gates routing on `State.Health.Status`: `starting`/`unhealthy` containers are kept out of the backend pool, `healthy` ones routed, and transitions are tracked via `health_status: healthy`/`unhealthy` Docker events. No opt-out: containers without a HEALTHCHECK keep the old "route as soon as running" behaviour. See [Docker provider docs](documentation/providers/docker.md#readiness--docker-healthcheck).

### HTTP provider

- Optional auth header on outgoing fetches — `providers.http.auth.header` and `auth.value` send an arbitrary header (typically `Authorization: Bearer <token>`) with every poll. Useful when the upstream config service sits behind its own auth layer.

### Observability

- Dedicated `/metrics` listener — scrape Prometheus metrics without enabling (or exposing) the admin API. Enable with `metrics.enabled: true` (or `SOZUNE_METRICS_ENABLED=true`); binds `127.0.0.1:3039` by default (`metrics.listen_address` / `SOZUNE_METRICS_LISTEN_ADDRESS`). Off by default. When the API is also enabled, `/metrics` keeps being served there too, unchanged. See [Observability docs](documentation/advanced/observability.md#the-metrics-endpoint).

### Providers

- Ring provider — discover entrypoints from a [Ring](https://github.com/kemeter/ring) cluster (a lightweight container / microVM orchestrator). Enable with `providers.ring` (`endpoint`, optional `token`, `poll_interval`, `expose_by_default`); Sōzune polls Ring's `GET /deployments` HTTP API, turns each deployment's `sozune.*` labels into routes, and fans a multi-replica deployment out to one backend per running instance. Discovery is interval-based and only triggers a reload when the Ring-sourced view changes. See [Ring provider docs](documentation/providers/ring.md).

### Fixes

- Environment variable overrides (e.g. `SOZUNE_PROXY_HTTP_LISTEN_ADDRESS`) now apply when `config.yaml` is absent, instead of silently using defaults.
- Docker provider: `send_to_worker` now returns an error on Sōzu worker ack timeout instead of `Ok(())`, so configuration desync becomes visible in the logs.
- Proxy backend addresses: IPv6 (bracketed or bare literal) is now supported in addition to IPv4. Previously IPv6 backends were dropped with a `bail!`.

### Kubernetes Gateway API

- HTTPRoute support — Sōzune watches `gateway.networking.k8s.io/v1` `GatewayClass`, `Gateway`, and `HTTPRoute` resources alongside Ingress when the Kubernetes provider is enabled and the CRDs are installed. Hostnames, `PathPrefix`/`Exact` path matches (multiple per rule, OR'd), multiple backendRefs (with weights), cross-namespace backends, and live apply/delete are wired in.
- Multi-controller scoping via `controllerName: kemeter.io/sozune` — sōzune only serves routes whose `parentRefs → Gateway → GatewayClass` chain ends at a class it owns, so it coexists with Traefik, Envoy Gateway, NGINX Gateway, and friends without hijacking their routes.
- Service backendRefs are resolved to ready pod IPs through the existing EndpointSlice cache; Sōzu requires `IpAddr` backends, so routes targeting a Service with no ready endpoints retry every 2 seconds until pods come up. Routes also re-resolve the moment a matching Gateway appears or disappears.
- HTTPRoute `requestRedirect` filter — mapped onto Sōzu's native frontend redirect (scheme, hostname, port, full-path replacement). `302` and `replacePrefixMatch` forms remain dropped with `Accepted=False reason=UnsupportedValue`.
- HTTPRoute `requestHeaderModifier` / `responseHeaderModifier` filters — set and remove request/response headers via Gateway API filters, mapped onto Sōzu's native frontend header edits. `add` is applied as `set` (Sōzu has no frontend append-without-replace) and logged.
- HTTPRoute `urlRewrite` filter — transparent path and hostname rewriting via `ReplaceFullPath`, `ReplacePrefixMatch` (suffix preserved) and `hostname`, mapped onto Sōzu's native frontend rewrite (no redirect). `requestMirror` and `extensionRef` remain unsupported; combining `urlRewrite` with `requestRedirect` on one rule is rejected.
- Status conditions — sōzune writes the standard `Accepted` and `ResolvedRefs` conditions to `status.parents[]` for every parentRef it owns, so users see `Accepted=True` / `ResolvedRefs=BackendNotFound` / `Accepted=False reason=UnsupportedValue` directly in `kubectl describe httproute`. Other controllers' entries are preserved untouched. Requires the new `httproutes/status` `update;patch` RBAC.
- Listener-driven port binding, `parentRef.sectionName`/`port`, the `requestMirror`/`extensionRef` HTTPRoute filters, and GRPCRoute/TCPRoute are not yet implemented — see [Kubernetes provider docs](documentation/providers/kubernetes.md#gateway-api-httproute) for the full support matrix.

## [0.13.0] - 2026-05-04

UX overhaul. Diagnostics become a first-class surface — visible in the CLI, the API, and the dashboard — and the dashboard gains the filters and drill-down to make them actionable.

### CLI

- `sozune explain <CODE>` — detailed cause / effect / fix / example for every diagnostic code (E001-E005, W001-W018, I001-I002).
- `sozune doctor [--offline]` — environment health-check: config readability, port bindability, provider sockets, ACME directory writability, privileges (CAP_NET_BIND_SERVICE detection).

### Routing

- Method-based routing via `sozune.http.<svc>.methods=GET,POST,...` (case-insensitive, dedup, one Sōzu frontend per method).

### Diagnostics

New diagnostic codes surfaced by `sozune validate`:

- `W014` invalid HTTP method in `methods=...`
- `W015` ACME enabled but no entrypoint declares `tls=true`
- `W016` `httpsRedirect=true` without `tls=true`
- `W017` `rate_limit.burst < average` (burst window disabled)
- `W018` route collision: same `(host, path)` declared by multiple candidates

### API

- New `GET /diagnostics` endpoint returning a snapshot grouped per candidate, plus a top-level `global` array for cross-cutting lints (e.g. `W015`).
- `GET /entrypoints` and `GET /entrypoints/{id}` payloads gain a `diagnostics` field, populated from a runtime store the providers write to as they parse labels.
- `W018` collisions are computed on the fly against live storage; `W015` is recomputed from `acme.enabled` and the live TLS entrypoints.
- Diagnostics serialize their severity (derived from the code prefix) so clients don't have to know the convention.
- 15 new tests covering the endpoint, the per-entrypoint field, severity derivation, and the runtime collision/global lints.

### Dashboard

- Per-entrypoint diagnostic badges (`⚠ N` / `✗ N`) on the entrypoints list, with a styled popover (replaces the native tooltip) and click-outside dismiss.
- New `/diagnostics` page in the sidebar with a warning icon and a live count badge that polls the API.
- "Diagnostics" stat-card on the entrypoints page (errors + warnings).
- Detail page (`/entrypoints/{id}`) shows a Diagnostics section when the entrypoint has any.
- Banner above the entrypoints table for global diagnostics (`W015` etc.).
- New filters on the entrypoints page: source / TLS / health / diagnostics, with a result counter and a one-click reset.
- New filters on the diagnostics page: free-text search, code dropdown.
- Drill-down: each candidate group on `/diagnostics` lists the affected entrypoints as clickable chips that link to the detail page.

### Runtime errors

- HTTP error responses in the middleware reverse-proxy now carry an `X-Sozune-Diagnostic` header on every 4xx/5xx (no more empty 502/504 bodies). Helpers cover `backend-unreachable`, `backend-timeout`, `forwarding-failed`, `internal-error`, `bad-request`, `rate-limited`, in addition to the existing `no-route-for-host` / `no-healthy-backend`.

### Logs

- Default log filter silences `sozu_lib`, `sozu_command_lib`, `mio`, `h2`, `kube`, `tower`, `hyper_util`. Override via `RUST_LOG`.
- 47 internal-jargon log messages reformulated into user-facing language (no more `Storage lock poisoned`, `Failed to send reload signal`, `Challenge state lock poisoned`, …).
- Reformulated `E001` and `E004` parser messages from "candidate is …" jargon to user-facing wording (`workload`, actionable hints).

### Config errors

- YAML parse failures report the file path and `line:column`.
- Provider errors in `validate` include actionable hints (Docker socket perms, Podman API socket, Nomad endpoint).
- ACME warning suggests setting `acme.email` instead of just stating it is missing.

### Docker provider

- Detect service-name collisions instead of merging silently. When two unrelated containers share a `sozune.<protocol>.<service-name>` segment but expose different hostnames or paths, the second one is now stored under a disambiguated key (`<key>_<short-container-id>`) instead of being absorbed into the first cluster. A loud warning explains how to silence it (rename the service-name segment).
- New e2e suite covering the collision case end-to-end.

## [0.12.0] - 2026-05-03

Multi-orchestrator release. New providers (Podman, Swarm, Nomad, Kubernetes), TCP entrypoints, brotli/zstd compression, dashboard health surface.

### Providers

- **Podman provider**: Docker-API-compatible socket (delegates to the Docker provider internals).
- **Swarm provider**: config block, full implementation with VIP discovery and event stream, wired into the provider factory, manager verification at startup, e2e suite, documentation.
- **Nomad provider**: blocking-query discovery, services API polling, tag→label mapping, port synthesis.
- **Kubernetes provider**: scaffold, cluster connect on startup, Service discovery via annotations and watch stream, EndpointSlice ready-pod IP resolution, Ingress routing with class filtering, per-slice attribution to drop stale endpoints on shrink, run as in-cluster Pod with `hostNetwork` for e2e (4/4 passing), Ingress e2e suite scaffold.
- Provider factory spawns the Docker provider so other providers can start in parallel.

### Routing & backends

- TCP entrypoints: listener config block, label parsing, Sōzu TCP worker wiring, e2e suite, documentation.
- Per-backend port and weight on `Backend` (replaces `config.port` and `backend_weights`); dashboard adapted accordingly.
- Skip unchanged entrypoints when applying Sōzu routing config (avoid noisy reloads).
- Diff full `Entrypoint` on reload to flush stale middleware state.

### Compression

- Brotli response compression (opt-in via `compress` label).
- Zstd response compression.

### CLI

- `--config` flag overrides `CONFIG_PATH` env var.

### Dashboard

- Surface unhealthy backends.
- Hero subtitle and taglines updated to mention Swarm, Kubernetes and Nomad.
- Dashboard entrypoints screenshot in README and docs index.
- Dashboard deps upgraded: vite 8, plugin-svelte 7, typescript 6 (CVE-2026-39365).

### Reliability

- Reload signals are debounced to coalesce container start bursts.
- HTTP provider avoids write-lock contention on unchanged polls.
- Filter config-file watcher events to the watched file only.
- Signal reload after the initial config-file load.
- E2E suites wait for all routes to be live simultaneously before running.
- Tightened e2e suites: real backend timeout, SSE octal fix.
- New SSE e2e suite + documented SSE pattern through Sozune.
- New API tests for payload validation, backend serialization, source guards.

### Defaults

- Restored production defaults: HTTP `:80`, HTTPS `:443`, dashboard `:3038`.

### Vendor

- Sōzu pinned to `282bb93` (TLS chain dedup, 302/308 redirects, 30 commits upstream).
- Earlier in the cycle: bumped Sōzu to `41b69cc` and upgraded other Rust dependencies; clippy fixes across the codebase.

### Repo

- `.dockerignore` skips `target/`, `node_modules`, dev junk (Docker build context: 8.8 GB → 439 MB).
- Documentation regrouped under `/providers` with a pinned sidebar order.

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

- **Headers**: `RequestHttpFrontend.headers` (request-side) replaces `headers::inject_headers`. Empty header value performs a delete.
- **Basic auth**: `Cluster.authorized_hashes` + `RequestHttpFrontend.required_auth` replace the Axum `auth::check_basic_auth` chain.
- **Strip prefix**: `RequestHttpFrontend.rewrite_path` replaces `strip_prefix::strip`. `Prefix` paths use `$PATH[1]`, `Exact` paths use `/`. `Regex` paths are not auto-converted.
- `needs_middleware()` no longer returns `true` for entrypoints that only use these three; they bypass the middleware proxy entirely.

### Header direction & deletion

The `headers.*` Docker label gains support for response-side and bidirectional edits, plus deletion via empty value:

- `headers.<name>=<value>` — request-side (default, unchanged)
- `headers.response.<name>=<value>` — response-side
- `headers.both.<name>=<value>` — both directions
- `headers.<name>=` (empty value) — deletes the header

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

---

## [0.4.x] - Previous Versions

See git history for previous changelog entries.

---

**Migration Support**: For help migrating from v0.4.x to v0.5.0, see the migration guide above or open an issue on GitHub.