# Roadmap

## P2 — Features différenciantes

### Middleware

- [ ] Response caching

### Advanced routing

- [ ] Regex-based path matching
- [ ] Method-based routing (GET, POST, etc.)
- [ ] Request/response header rewriting

### Administration

- [ ] Configuration validation command (`sozune validate`)

## P3 — Backlog

### Protocol support

- [ ] gRPC proxying
- [ ] HTTP/2 support
- [ ] TCP proxying via Sozu TCP worker
- [ ] UDP proxying

### Advanced routing

- [ ] IPv6 support

### Load balancing

- [ ] Least-connections algorithm

### Administration

- [ ] Dashboard UI
- [ ] Request tracing / debug mode

### Observability

- [ ] Prometheus metrics endpoint (`GET /metrics`)
- [ ] Request/response timing metrics
- [ ] Error rate tracking

## Done

- [x] Custom headers injection (middleware)
- [x] Strip prefix / path rewriting (middleware)
- [x] Basic authentication with bcrypt (middleware)
- [x] HTTPS redirect (Sozu native)
- [x] Route priority ordering
- [x] Stale route cleanup on reload
- [x] Worker response reading
- [x] Shared Tokio runtime
- [x] Graceful shutdown
- [x] Startup readiness detection
- [x] Let's Encrypt / ACME automatic certificate provisioning
- [x] Certificate hot-reload without restart
- [x] API CRUD entrypoints with live reconfiguration
- [x] API bearer token authentication
- [x] Health check endpoint (`GET /health`)
- [x] Rate limiting (token bucket, per IP)
- [x] Access logs
- [x] WebSocket upgrade proxying
- [x] Configurable backend timeout (SSE/long-lived connections)
- [x] Gzip response compression (opt-in)
- [x] Weighted load balancing
- [x] Sticky sessions
- [x] Backend health checks (active TCP probing)
- [x] SNI-based certificate selection (Sōzu native)
