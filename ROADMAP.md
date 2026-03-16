# Roadmap

## Enforce already parsed features

- [x] Apply custom headers injection (via middleware layer)
- [x] Implement strip prefix / path rewriting (via middleware layer)
- [x] Apply route priority ordering (currently all routes use `RulePosition::Pre`)
- [x] Enforce basic authentication (via middleware layer)
- [x] HTTPS redirect (via Sozu native `Cluster.https_redirect`)
- [ ] Implement TCP proxying via Sozu TCP worker
- [ ] Implement UDP proxying

## Sozu proxy reliability

- [x] Clean up stale routes on reload (diff-based removal of old clusters/frontends/backends)
- [x] Read worker responses after sending commands (detect actual failures vs "already exists")
- [x] Use `Handle::current()` instead of creating a nested Tokio runtime in reload handler
- [x] Implement graceful shutdown via `shutdown_rx` (currently unused, relies on `process::exit`)
- [x] Replace startup `thread::sleep` with proper worker readiness detection

## TLS & Certificates

- [x] Let's Encrypt / ACME automatic certificate provisioning
- [ ] SNI-based certificate selection
- [x] Certificate hot-reload without restart

## Observability

- [ ] Health check endpoint (`GET /health`)
- [ ] Backend health checks (active probing)
- [ ] Prometheus metrics endpoint (`GET /metrics`)
- [ ] Request/response timing metrics
- [ ] Error rate tracking

## API

- [ ] CRUD operations on entrypoints (POST, PUT, DELETE)
- [ ] Live reconfiguration without file reload
- [ ] API authentication

## Load balancing

- [ ] Weighted load balancing
- [ ] Least-connections algorithm
- [ ] Session affinity / sticky sessions
- [ ] Health-based routing (remove unhealthy backends)

## Advanced routing

- [ ] Regex-based path matching
- [ ] Method-based routing (GET, POST, etc.)
- [ ] Request/response header rewriting
- [ ] IPv6 support

## Protocol support

- [ ] WebSocket upgrade handling
- [ ] gRPC proxying
- [ ] HTTP/2 support

## Administration

- [ ] Dashboard UI
- [ ] Request tracing / debug mode
- [ ] Configuration validation command (`sozune validate`)

## Code quality

- [ ] Fix clippy warnings
- [ ] Remove dead code (`Provider::name()`, `should_reload_for_container()`)
- [ ] Increase test coverage (Docker event handling, proxy configuration)
