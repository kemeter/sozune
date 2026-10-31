# Docker labels

When run against the Docker provider, Sōzune discovers your services through container labels. Each label has the form:

```
sozune.<protocol>.<service>.<key>=<value>
```

Where `<protocol>` is `http`, `tcp` or `udp`, and `<service>` is your own identifier — it groups labels for the same logical service. Containers sharing the same `<service>` name are merged as backends of one cluster.

## Configuration

```yaml
providers:
  docker:
    enabled: true
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Docker provider |
| `endpoint` | `/var/run/docker.sock` | Docker socket, as a path or a `unix://` URL. Only Unix sockets are supported: any other value falls back to `DOCKER_HOST` when it is a `unix://` URL, else to `/var/run/docker.sock`. |
| `expose_by_default` | `false` | If `true`, every running container is a candidate even without `sozune.enable=true` |

Env var overrides: `SOZUNE_PROVIDER_DOCKER_ENABLED`, `SOZUNE_PROVIDER_DOCKER_ENDPOINT`, `SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT` (since 0.6).

## Activation

| Label | Description |
|---|---|
| `sozune.enable=true` | Enables discovery for the container. Required unless `expose_by_default` is set on the Docker provider |
| `sozune.network=<name>` | Docker network used for routing (when the container is on multiple networks) |

## Readiness — Docker HEALTHCHECK

> Since 0.14

When a container declares a Docker `HEALTHCHECK` (via `HEALTHCHECK` in the Dockerfile or `healthcheck:` in compose), Sōzune treats it as the container's readiness probe and gates routing on its status:

| `State.Health.Status` | Routed? |
|---|---|
| (no HEALTHCHECK declared) | Yes — as soon as the container is `running` |
| `starting` | No |
| `healthy` | Yes |
| `unhealthy` | No (backend removed; re-added when status returns to `healthy`) |

There is no label or flag to opt out: declaring a `HEALTHCHECK` is itself the opt-in to the readiness contract. If you want traffic during warmup, drop the `HEALTHCHECK` or use `--health-start-period` to delay the first probe.

## Routing — HTTP

| Label | Example | Reference |
|---|---|---|
| `sozune.http.<svc>.host` | `app.example.com` | [Hostnames](/documentation/routing/hostnames) |
| `sozune.http.<svc>.port` | `8080` | Backend port (default `80`) |
| `sozune.http.<svc>.path` | `/api` | [Path matching](/documentation/routing/path-matching) |
| `sozune.http.<svc>.prefix` | `/api` | Alias for `path` |
| `sozune.http.<svc>.pathRegex` | `/users/[0-9]+` | [Path matching](/documentation/routing/path-matching) (since 0.11) |
| `sozune.http.<svc>.priority` | `100` | Higher wins when multiple rules match (default `0`) |
| `sozune.http.<svc>.methods` | `GET,POST` | Restrict the route to these HTTP methods (comma-separated; default: any) (since 0.13) |
| `sozune.http.<svc>.matchHeaders` | `X-Canary:true` | [Header & query matching](/documentation/routing/header-query-matching) — comma-separated `key:value` conditions on request headers (since 0.14) |
| `sozune.http.<svc>.matchQuery` | `version:2` | [Header & query matching](/documentation/routing/header-query-matching) — same, on query parameters (since 0.14) |
| `sozune.http.<svc>.matchHeadersRegex.<name>` | `v[0-9]+` | [Header & query matching](/documentation/routing/header-query-matching#regular-expressions) — the header must match the regex whole (since 0.16) |
| `sozune.http.<svc>.matchQueryRegex.<name>` | `[0-9]+` | [Header & query matching](/documentation/routing/header-query-matching#regular-expressions) — same, on a query parameter (since 0.16) |
| `sozune.http.<svc>.matchClientIP` | `10.0.0.0/8` | [Client-IP matching](/documentation/routing/client-ip-matching) — comma-separated IPs/CIDRs; others get `404` (since 0.14) |
| `sozune.http.<svc>.mirrorOf` | `app` | [Mirroring](/documentation/routing/mirroring) — copy the requests of service `app` to this one, which serves no host of its own (since 0.16) |
| `sozune.http.<svc>.loadBalancer` | `least_connections` | [Load balancing](/documentation/routing/load-balancing#choosing-the-algorithm) (default `round_robin`) (since 0.14) |
| `sozune.http.<svc>.weight` | `90` | [Weighted load balancing](/documentation/routing/load-balancing#weighted-load-balancing) — this container's weight (default `100`) (since 0.14) |
| `sozune.http.<svc>.tls` | `true` | Enables TLS termination (provisions an ACME cert) |
| `sozune.http.<svc>.acme.resolver` | `cloudflare` | Names the [ACME resolver](/documentation/tls/acme) that issues the certificate. Absent: HTTP-01 on `challenge_port` (since 0.15) |

## Health checks

> Since 0.14

| Label | Reference |
|---|---|
| `sozune.http.<svc>.healthCheck.path` | [Health checks](/documentation/advanced/health-checks#http-health-checks) — probe path; enables the HTTP probe |
| `sozune.http.<svc>.healthCheck.status` | [Health checks](/documentation/advanced/health-checks#http-health-checks) — exact status required (default: any `2xx`/`3xx`) |
| `sozune.http.<svc>.healthCheck.timeout` | [Health checks](/documentation/advanced/health-checks#settings) — per-probe timeout, in milliseconds |
| `sozune.http.<svc>.healthCheck.interval` | [Health checks](/documentation/advanced/health-checks#settings) — milliseconds between probes (since 0.16) |
| `sozune.http.<svc>.healthCheck.port` | [Health checks](/documentation/advanced/health-checks#settings) — port to probe instead of the backend's (since 0.16) |
| `sozune.http.<svc>.healthCheck.unhealthyThreshold` | [Health checks](/documentation/advanced/health-checks#settings) — failed probes in a row before a backend leaves (since 0.16) |
| `sozune.http.<svc>.healthCheck.healthyThreshold` | [Health checks](/documentation/advanced/health-checks#settings) — successful probes in a row before it comes back (since 0.16) |
| `sozune.http.<svc>.healthCheck.headers.<name>` | [Health checks](/documentation/advanced/health-checks#http-health-checks) — a header the probe sends (since 0.16) |

## Middleware

| Label | Reference |
|---|---|
| `sozune.http.<svc>.auth.basic` | [Basic auth](/documentation/middleware/auth) (since 0.6) |
| `sozune.http.<svc>.forwardAuth.address` | [Forward auth](/documentation/middleware/forward-auth) — required to enable (since 0.14) |
| `sozune.http.<svc>.forwardAuth.responseHeaders` | [Forward auth](/documentation/middleware/forward-auth) — comma-separated headers to copy from auth response onto the request (since 0.14) |
| `sozune.http.<svc>.forwardAuth.trustForwardHeader` | [Forward auth](/documentation/middleware/forward-auth) — keep client `X-Forwarded-*` headers when calling the auth service (since 0.14) |
| `sozune.http.<svc>.headers.<name>` | [Custom headers](/documentation/middleware/headers) — request-side by default (since 0.6) |
| `sozune.http.<svc>.headers.response.<name>` | [Custom headers](/documentation/middleware/headers) — response-side (since 0.11) |
| `sozune.http.<svc>.headers.both.<name>` | [Custom headers](/documentation/middleware/headers) — both directions (since 0.11) |
| `sozune.http.<svc>.stripPrefix` | [Strip prefix](/documentation/middleware/strip-prefix) (since 0.6) |
| `sozune.http.<svc>.addPrefix` | [Add prefix](/documentation/middleware/add-prefix) (since 0.14) |
| `sozune.http.<svc>.httpsRedirect` | [Redirects](/documentation/middleware/redirects) (since 0.6) |
| `sozune.http.<svc>.httpsRedirectPort` | [Redirects](/documentation/middleware/redirects) (since 0.11) |
| `sozune.http.<svc>.redirect` | [Redirects](/documentation/middleware/redirects#redirect-policy) (since 0.11) |
| `sozune.http.<svc>.redirectScheme` | [Redirects](/documentation/middleware/redirects) (since 0.11) |
| `sozune.http.<svc>.redirectTemplate` | [Redirects](/documentation/middleware/redirects) (since 0.11) |
| `sozune.http.<svc>.redirectHost` | [Redirects](/documentation/middleware/redirects#redirecthost) — permanent redirect to another host (since 0.16) |
| `sozune.http.<svc>.wwwAuthenticate` | [Basic auth](/documentation/middleware/auth) (since 0.11) |
| `sozune.http.<svc>.ratelimit.average` | [Rate limit](/documentation/middleware/rate-limit) (since 0.9) |
| `sozune.http.<svc>.ratelimit.burst` | [Rate limit](/documentation/middleware/rate-limit) (since 0.9) |
| `sozune.http.<svc>.inFlightReq` | [In-flight requests](/documentation/middleware/in-flight-req) — concurrent requests per client IP (since 0.14) |
| `sozune.http.<svc>.ipAllowList` | [IP allow-list](/documentation/middleware/ip-allow-list) — comma-separated IPs/CIDRs; others get `403` (since 0.14) |
| `sozune.http.<svc>.compress` | [Response compression](/documentation/middleware/compress) (zstd, br, gzip) (since 0.11) |
| `sozune.http.<svc>.backendTimeout` | [Backend timeout](/documentation/middleware/backend-timeout) (since 0.8) |
| `sozune.http.<svc>.retry.attempts` | [Retry](/documentation/middleware/retry) — total tries, first one included (since 0.14) |
| `sozune.http.<svc>.circuitBreaker.threshold` | [Circuit breaker](/documentation/middleware/circuit-breaker) — failure ratio that trips it (since 0.14) |
| `sozune.http.<svc>.circuitBreaker.minRequests` | [Circuit breaker](/documentation/middleware/circuit-breaker) — requests before the ratio counts (since 0.14) |
| `sozune.http.<svc>.circuitBreaker.cooldown` | [Circuit breaker](/documentation/middleware/circuit-breaker) — seconds open before probing again (since 0.14) |
| `sozune.http.<svc>.errorPages.<code>` | [Error pages](/documentation/middleware/error-pages) — inline body for that status (since 0.14) |
| `sozune.http.<svc>.plugins` | [WASM plugins](/documentation/middleware/wasm-plugins) — comma-separated plugin names, run in order (since 0.14) |
| `sozune.http.<svc>.plugins.<name>.<key>` | [WASM plugins](/documentation/middleware/wasm-plugins#per-route-config) — per-route plugin config (since 0.14) |
| `sozune.http.<svc>.stickySession` | [Sticky sessions](/documentation/routing/load-balancing#sticky-sessions) (since 0.10) |

## Routing — TCP

> Since 0.12

TCP routing requires a listener declared under `proxy.tcp` in the main config. Labels then attach a backend to that listener by name. See [TCP routing](/documentation/routing/tcp) for the full picture.

| Label | Example | Description |
|---|---|---|
| `sozune.tcp.<svc>.entrypoint` | `postgres` | Listener name declared under `proxy.tcp`. **Required** (`E005`). |
| `sozune.tcp.<svc>.port` | `5432` | Backend port on the container. Defaults to `8080` (`I002`). |
| `sozune.tcp.<svc>.sni` | `db.example.com` | Route TLS connections by the name in the ClientHello, without terminating TLS. See [Route by SNI](/documentation/routing/tcp#route-by-sni-tls-passthrough). (since 0.15) |
| `sozune.tcp.<svc>.loadBalancer` | `least_connections` | [Load balancing](/documentation/routing/load-balancing#choosing-the-algorithm) (since 0.14) |
| `sozune.tcp.<svc>.weight` | `90` | This container's [weight](/documentation/routing/load-balancing#weighted-load-balancing) (since 0.14) |
| `sozune.tcp.<svc>.priority` | `100` | A listener without `sni` serves one service: when several name it, the highest priority. See [One route per listener](/documentation/routing/tcp#one-route-per-listener). (since 0.16) |

## Routing — UDP

> Since 0.14

UDP routing requires a listener declared under `proxy.udp` in the main config. See [UDP routing](/documentation/routing/udp).

| Label | Example | Description |
|---|---|---|
| `sozune.udp.<svc>.entrypoint` | `dns` | Listener name declared under `proxy.udp`. **Required** (`E005`). |
| `sozune.udp.<svc>.port` | `53` | Backend port on the container. **Required** — no default for datagram services (`E006`). |
| `sozune.udp.<svc>.loadBalancer` | `hrw` | [Load balancing](/documentation/routing/udp#load-balancing), including the flow-affine `hrw` and `maglev` |
| `sozune.udp.<svc>.weight` | `90` | This container's [weight](/documentation/routing/load-balancing#weighted-load-balancing) |
| `sozune.udp.<svc>.priority` | `100` | A listener serves one service: when several name it, the highest priority. (since 0.16) |

## Full example

```yaml
services:
  api:
    image: my-api
    labels:
      - "sozune.enable=true"
      - "sozune.http.api.host=api.example.com"
      - "sozune.http.api.port=8080"
      - "sozune.http.api.tls=true"
      - "sozune.http.api.httpsRedirect=true"
      - "sozune.http.api.path=/v1"
      - "sozune.http.api.stripPrefix=true"
      - "sozune.http.api.ratelimit.average=100"
      - "sozune.http.api.ratelimit.burst=50"
      - "sozune.http.api.headers.X-Powered-By=sozune"

  db:
    image: postgres:16
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.db.entrypoint=postgres"
      - "sozune.tcp.db.port=5432"
```
