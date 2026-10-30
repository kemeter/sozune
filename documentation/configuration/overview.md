# Configuration overview

Sōzune reads its main configuration from a YAML file. Path: `config.yaml` in the working directory by default, overridable through the `CONFIG_PATH` environment variable or the `--config` flag (since 0.12), which wins over it.

If the file is missing, Sōzune falls back to a built-in default configuration (everything disabled, both listeners on default ports).

`providers`, `api` and `proxy`, with `proxy.http` and `proxy.https`, must be present, even empty (`api: {}`): without one of them the file is refused with `missing field`. Every other section, and every key inside a section, is optional and takes the default listed below.

## Example

```yaml
providers:
  docker:
    enabled: true
    expose_by_default: false

api:
  enabled: true
  listen_address: "127.0.0.1:3035"
  users:
    - name: admin
      hash: "<sha256 hex of password>"
      role: admin
  cors_origins: []

acme:
  enabled: false
  email: "you@example.com"
  certs_dir: "/etc/sozune/certs"
  staging: true
  challenge_port: 3036

proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
  tcp:
    - name: postgres
      listen: 5432
  max_buffers: 500
  buffer_size: 16384
  startup_delay_ms: 1000
  cluster_setup_delay_ms: 500

middleware:
  port: 3037
```

## Sections

| Section | Purpose |
|---|---|
| `providers` | Sources for entrypoint discovery: Docker, Podman, Swarm, Kubernetes, Nomad, Consul, Ring, HTTP polling, or a YAML file. Required. |
| `api` | REST API for live entrypoint management. Required, `{}` to leave it off. |
| `acme` | ACME (Let's Encrypt) provisioning. |
| `proxy` | Sōzu listeners and runtime tuning. Required. |
| `middleware` | Internal middleware proxy port. |
| `dashboard` | Web dashboard listener. Off by default. See [Dashboard](/documentation/configuration/dashboard). (since 0.11) |
| `metrics` | Dedicated Prometheus `/metrics` listener, independent of the API. Off by default. See [Observability](../advanced/observability.md#the-metrics-endpoint). (since 0.14) |
| `log` | Log output format (`text` or `json`). (since 0.14) |
| `tracing` | OpenTelemetry distributed tracing (OTLP export). Off by default. See [Observability](../advanced/observability.md#distributed-tracing-opentelemetry). (since 0.14) |
| `plugins` | WASM plugins, declared by name. See [WASM plugins](/documentation/middleware/wasm-plugins). (since 0.14) |

## Providers

```yaml
providers:
  docker:
    enabled: true
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
  swarm:
    enabled: false
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
    # network: sozune-public   # optional: only consider VIPs on this overlay
    refresh_interval: 15
  http:
    enabled: false
    url: "https://config.example.com/entrypoints"
    poll_interval: 30
  config_file:
    enabled: false
    path: "/etc/sozune/config.yaml"
    watch: true
```

| Field | Default | Description |
|---|---|---|
| `docker.enabled` | `false` | Enables Docker label discovery |
| `docker.endpoint` | `/var/run/docker.sock` | Docker socket path |
| `docker.expose_by_default` | `false` | If true, every container is candidate without `sozune.enable=true` |
| `swarm.enabled` | `false` | Enables Docker Swarm service discovery (must point to a manager) (since 0.12) |
| `swarm.endpoint` | `/var/run/docker.sock` | Docker socket on a Swarm manager (since 0.12) |
| `swarm.expose_by_default` | `false` | If true, every service is candidate without `sozune.enable=true` (since 0.12) |
| `swarm.network` | `""` | Optional overlay network filter (since 0.12) |
| `swarm.refresh_interval` | `15` | Periodic poll interval, in seconds (safety net behind the event stream) (since 0.12) |
| `http.enabled` | `false` | Enables polling a remote URL for JSON entrypoints (since 0.11) |
| `http.url` | — | URL to poll (since 0.11) |
| `http.poll_interval` | `30` | Polling interval, in seconds (since 0.11) |
| `http.auth_header` / `http.auth_value` | `""` | Header sent on every poll, e.g. `Authorization` / `Bearer …`. Not sent while either is empty. (since 0.14) |
| `config_file.enabled` | `false` | Enables a static YAML file as a source |
| `config_file.path` | — | Path to the entrypoints file |
| `config_file.watch` | `true` | Hot-reload on file change |

The other providers have their own page: [Podman](/documentation/providers/podman) (since 0.12), [Kubernetes](/documentation/providers/kubernetes) (since 0.12), [Nomad](/documentation/providers/nomad) (since 0.12), [Consul](/documentation/providers/consul) (since 0.14) and [Ring](/documentation/providers/ring) (since 0.14).

## API

| Field | Default | Description |
|---|---|---|
| `api.enabled` | `false` | Enables the REST API |
| `api.listen_address` | `127.0.0.1:3035` | Bind address |
| `api.users` | `[]` | List of API users. Each entry has `name`, `hash` (hex sha256 of the password) and `role` (`admin`, the default, or `read-only`). The API refuses to start if this list is empty when `api.enabled: true`. (since 0.11) |
| `api.cors_origins` | `[]` | Allowed origins for CORS (since 0.11) |

## Dashboard

> Since 0.11

| Field | Default | Description |
|---|---|---|
| `dashboard.enabled` | `false` | Serves the web dashboard |
| `dashboard.listen_address` | `127.0.0.1:3038` | Bind address |

See [Dashboard](/documentation/configuration/dashboard).

## Metrics

> Since 0.14

Dedicated Prometheus `/metrics` listener, independent of the API — lets you
scrape metrics without enabling the admin API. When the API is also enabled,
`/metrics` is served on both listeners.

| Field | Default | Description |
|---|---|---|
| `metrics.enabled` | `false` | Enables the dedicated `/metrics` listener (`SOZUNE_METRICS_ENABLED`) |
| `metrics.listen_address` | `127.0.0.1:3039` | Bind address (`SOZUNE_METRICS_LISTEN_ADDRESS`); keep on loopback or restrict with an ACL |

## Proxy

| Field | Default | Description |
|---|---|---|
| `proxy.http.listen_address` | `80` | Port for the HTTP listener |
| `proxy.https.listen_address` | `443` | Port for the HTTPS listener |
| `proxy.http.error_pages` / `proxy.https.error_pages` | `{}` | Pages for the errors Sōzune answers itself, by status. See [Error pages](/documentation/middleware/error-pages). (since 0.14) |
| `proxy.https.http2` | — | ALPN protocols offered on the HTTPS listener. See [HTTP/2](/documentation/tls/overview#http2). (since 0.14) |
| `proxy.https.tls` | — | TLS versions, ciphers, certificates from files and client certificates. See [TLS](/documentation/tls/overview). (since 0.15) |
| `proxy.https.passthrough` | `false` | Also serve TLS passthrough on the HTTPS port: a connection whose SNI names a route of the `https-passthrough` TCP listener (a Kubernetes TLSRoute on a `TLS` listener of this port, or a Docker TCP route) is forwarded undecrypted, the others are served over HTTPS. Sōzune then reads each ClientHello first. See [Passthrough on the HTTPS port](/documentation/routing/tcp#passthrough-on-the-https-port). (since 0.16) |
| `proxy.tcp` | `[]` | List of TCP listeners. Each entry has `name` (referenced by labels) and `listen` (port), plus optional `ip_allow_list`, `rate_limit`, `idle_timeout`, `sni_preread_timeout` and `sni_preread_max_bytes`. See [TCP routing](/documentation/routing/tcp). (since 0.12) |
| `proxy.udp` | `[]` | List of UDP listeners, each with `name` and `listen`. See [UDP routing](/documentation/routing/udp). (since 0.14) |
| `proxy.gateway_ports.tcp` | `[]` | Ports a Kubernetes Gateway `TLS` or `TCP` listener may open when no `proxy.tcp` entry declares them: ports (`5432`) or inclusive ranges (`"9000-9099"`). Opened while a route is served on them. See [Kubernetes](/documentation/providers/kubernetes#which-ports-a-gateway-is-served-on). (since 0.16) |
| `proxy.gateway_ports.udp` | `[]` | The same, for `UDP` listeners and `proxy.udp`. (since 0.16) |
| `proxy.gateway_ports.http` | `[]` | Ports a Kubernetes Gateway `HTTP` listener is served on, instead of `proxy.http.listen_address`. Opened while a route is served on them. See [Kubernetes](/documentation/providers/kubernetes#http-listeners-on-their-own-port). (since 0.16) |
| `proxy.gateway_ports.https` | `[]` | The same, for `HTTPS` listeners and `proxy.https.listen_address`. See [Kubernetes](/documentation/providers/kubernetes#https-listeners-on-their-own-port). (since 0.16) |
| `proxy.max_buffers` | `500` | Max number of buffers in the Sōzu pool |
| `proxy.buffer_size` | `16384` | Buffer size, in bytes |
| `proxy.startup_delay_ms` | `1000` | Delay before applying the initial config (gives Sōzu workers time to boot) |
| `proxy.cluster_setup_delay_ms` | `500` | Delay between cluster setup commands |
| `proxy.reload_debounce_ms` | `500` | Debounce window, in ms, applied to reload signals. A reload runs only after this many ms of silence, coalescing bursts of container start/stop events into one reload (since 0.12) |
| `proxy.metrics_poll_timeout_ms` | `200` | Per-worker deadline, in ms, for a metrics poll round-trip. Keep it short: the poll shares the loop that accepts traffic and applies certificates, so a slow or silent worker must not be allowed to block proxying (since 0.14) |
| `proxy.trusted_proxies` | `[]` | IPs or CIDRs of proxies in front of Sōzune whose `X-Forwarded-For` is trusted to find the client IP. See [Client-IP resolution](/documentation/middleware/ip-allow-list#client-ip-resolution). (since 0.14) |
| `proxy.timeouts.client_idle` | `60` | Seconds a client connection may stay silent before it is closed, waiting for a slow response included (since 0.15) |
| `proxy.timeouts.backend_idle` | `30` | Seconds a backend connection may stay silent, waiting for the response included. Raise it for long-polling, slow reports or quiet SSE streams (since 0.15) |
| `proxy.timeouts.backend_connect` | `3` | Seconds allowed to connect to a backend (since 0.15) |
| `proxy.timeouts.request` | `10` | Seconds a client may take to send a complete request (since 0.15) |
| `proxy.command_buffer_max_bytes` | `65536` | Maximum size, in bytes, the Sōzu command channel back buffer may grow to. A single command or worker reply larger than this is rejected; raise it if you have a very large number of entrypoints (since 0.14) |

## Middleware

> Since 0.6

| Field | Default | Description |
|---|---|---|
| `middleware.port` | `3037` | Port the internal middleware proxy listens on, on loopback. Routes with a middleware Sōzu cannot run itself (rate limit, compression, backend timeout, forward auth, IP allow-list, retry, circuit breaker, WASM plugins…) go through it. Basic auth, headers, strip prefix and redirects run natively in Sōzu and do not pass through this port. |

## Log

> Since 0.14

| Field | Default | Description |
|---|---|---|
| `log.format` | `text` | `text` or `json` (one JSON object per line). Applies to every log line, access log included. See [Access logs](/documentation/advanced/access-logs). |

The verbosity is set with `RUST_LOG`, see [Configuring log verbosity](/documentation/advanced/access-logs#configuring-log-verbosity).

## Tracing

> Since 0.14

| Field | Default | Description |
|---|---|---|
| `tracing.enabled` | `false` | Exports a span per proxied request over OTLP/gRPC |
| `tracing.endpoint` | `http://127.0.0.1:4317` | OTLP/gRPC collector |
| `tracing.service_name` | `sozune` | `service.name` of every span |
| `tracing.sampler` | `parent_based_always_on` | See [Sampling](/documentation/advanced/observability#sampling) |

## ACME

> Since 0.6

See [ACME / Let's Encrypt](/documentation/tls/acme).

## Environment variable overrides

> Since 0.6

The fields below can be set through an environment variable, which wins over the YAML value. Lists and maps (`api.users`, `proxy.tcp`, `proxy.trusted_proxies`, `acme.resolvers`, `plugins`…) and the fields not listed have no environment variable.

| Field | Env var |
|---|---|
| `proxy.http.listen_address` | `SOZUNE_HTTP_PORT` |
| `proxy.https.listen_address` | `SOZUNE_HTTPS_PORT` |
| `proxy.max_buffers` | `SOZUNE_PROXY_MAX_BUFFERS` |
| `proxy.buffer_size` | `SOZUNE_PROXY_BUFFER_SIZE` |
| `proxy.startup_delay_ms` | `SOZUNE_PROXY_STARTUP_DELAY_MS` |
| `proxy.cluster_setup_delay_ms` | `SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS` |
| `proxy.reload_debounce_ms` | `SOZUNE_PROXY_RELOAD_DEBOUNCE_MS` (since 0.12) |
| `proxy.metrics_poll_timeout_ms` | `SOZUNE_PROXY_METRICS_POLL_TIMEOUT_MS` (since 0.14) |
| `proxy.command_buffer_max_bytes` | `SOZUNE_PROXY_COMMAND_BUFFER_MAX_BYTES` (since 0.14) |
| `proxy.timeouts.client_idle` | `SOZUNE_PROXY_TIMEOUT_CLIENT_IDLE` (since 0.15) |
| `proxy.timeouts.backend_idle` | `SOZUNE_PROXY_TIMEOUT_BACKEND_IDLE` (since 0.15) |
| `proxy.timeouts.backend_connect` | `SOZUNE_PROXY_TIMEOUT_BACKEND_CONNECT` (since 0.15) |
| `proxy.timeouts.request` | `SOZUNE_PROXY_TIMEOUT_REQUEST` (since 0.15) |
| `api.enabled` | `SOZUNE_API_ENABLED` |
| `api.listen_address` | `SOZUNE_API_LISTEN_ADDRESS` |
| `dashboard.enabled` | `SOZUNE_DASHBOARD_ENABLED` (since 0.11) |
| `dashboard.listen_address` | `SOZUNE_DASHBOARD_LISTEN_ADDRESS` (since 0.11) |
| `metrics.enabled` | `SOZUNE_METRICS_ENABLED` (since 0.14) |
| `metrics.listen_address` | `SOZUNE_METRICS_LISTEN_ADDRESS` (since 0.14) |
| `providers.docker.enabled` | `SOZUNE_PROVIDER_DOCKER_ENABLED` |
| `providers.docker.endpoint` | `SOZUNE_PROVIDER_DOCKER_ENDPOINT` |
| `providers.docker.expose_by_default` | `SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT` |
| `providers.podman.enabled` | `SOZUNE_PROVIDER_PODMAN_ENABLED` (since 0.12) |
| `providers.podman.endpoint` | `SOZUNE_PROVIDER_PODMAN_ENDPOINT` (since 0.12) |
| `providers.podman.expose_by_default` | `SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT` (since 0.12) |
| `providers.swarm.enabled` | `SOZUNE_PROVIDER_SWARM_ENABLED` (since 0.12) |
| `providers.swarm.endpoint` | `SOZUNE_PROVIDER_SWARM_ENDPOINT` (since 0.12) |
| `providers.swarm.expose_by_default` | `SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT` (since 0.12) |
| `providers.swarm.network` | `SOZUNE_PROVIDER_SWARM_NETWORK` (since 0.12) |
| `providers.swarm.refresh_interval` | `SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL` (since 0.12) |
| `providers.kubernetes.enabled` | `SOZUNE_PROVIDER_KUBERNETES_ENABLED` (since 0.12) |
| `providers.kubernetes.kubeconfig` | `SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG` (since 0.12) |
| `providers.kubernetes.namespace` | `SOZUNE_PROVIDER_KUBERNETES_NAMESPACE` (since 0.12) |
| `providers.kubernetes.ingress_class` | `SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS` (since 0.12) |
| `providers.kubernetes.expose_by_default` | `SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT` (since 0.12) |
| `providers.kubernetes.publish_service` | `SOZUNE_PROVIDER_KUBERNETES_PUBLISH_SERVICE` (since 0.16) |
| `providers.nomad.enabled` | `SOZUNE_PROVIDER_NOMAD_ENABLED` (since 0.12) |
| `providers.nomad.endpoint` | `SOZUNE_PROVIDER_NOMAD_ENDPOINT` (since 0.12) |
| `providers.nomad.token` | `SOZUNE_PROVIDER_NOMAD_TOKEN` (since 0.12) |
| `providers.nomad.namespace` | `SOZUNE_PROVIDER_NOMAD_NAMESPACE` (since 0.12) |
| `providers.nomad.poll_interval` | `SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL` (since 0.12) |
| `providers.nomad.expose_by_default` | `SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT` (since 0.12) |
| `providers.consul.enabled` | `SOZUNE_PROVIDER_CONSUL_ENABLED` (since 0.14) |
| `providers.consul.endpoint` | `SOZUNE_PROVIDER_CONSUL_ENDPOINT` (since 0.14) |
| `providers.consul.token` | `SOZUNE_PROVIDER_CONSUL_TOKEN` (since 0.14) |
| `providers.consul.datacenter` | `SOZUNE_PROVIDER_CONSUL_DATACENTER` (since 0.14) |
| `providers.consul.poll_interval` | `SOZUNE_PROVIDER_CONSUL_POLL_INTERVAL` (since 0.14) |
| `providers.consul.expose_by_default` | `SOZUNE_PROVIDER_CONSUL_EXPOSE_BY_DEFAULT` (since 0.14) |
| `providers.ring.enabled` | `SOZUNE_PROVIDER_RING_ENABLED` (since 0.14) |
| `providers.ring.endpoint` | `SOZUNE_PROVIDER_RING_ENDPOINT` (since 0.14) |
| `providers.ring.token` | `SOZUNE_PROVIDER_RING_TOKEN` (since 0.14) |
| `providers.ring.poll_interval` | `SOZUNE_PROVIDER_RING_POLL_INTERVAL` (since 0.14) |
| `providers.ring.expose_by_default` | `SOZUNE_PROVIDER_RING_EXPOSE_BY_DEFAULT` (since 0.14) |
| `providers.http.enabled` | `SOZUNE_PROVIDER_HTTP_ENABLED` (since 0.11) |
| `providers.http.url` | `SOZUNE_PROVIDER_HTTP_URL` (since 0.11) |
| `providers.http.poll_interval` | `SOZUNE_PROVIDER_HTTP_POLL_INTERVAL` (since 0.11) |
| `providers.http.auth_header` | `SOZUNE_PROVIDER_HTTP_AUTH_HEADER` (since 0.14) |
| `providers.http.auth_value` | `SOZUNE_PROVIDER_HTTP_AUTH_VALUE` (since 0.14) |
| `providers.config_file.enabled` | `SOZUNE_PROVIDER_CONFIG_FILE_ENABLED` |
| `providers.config_file.path` | `SOZUNE_PROVIDER_CONFIG_FILE_PATH` |
| `providers.config_file.watch` | `SOZUNE_PROVIDER_CONFIG_FILE_WATCH` |
| `acme.enabled` | `SOZUNE_ACME_ENABLED` |
| `acme.email` | `SOZUNE_ACME_EMAIL` |
| `acme.certs_dir` | `SOZUNE_ACME_CERTS_DIR` |
| `acme.staging` | `SOZUNE_ACME_STAGING` |
| `acme.challenge_port` | `SOZUNE_ACME_CHALLENGE_PORT` |
| `middleware.port` | `SOZUNE_MIDDLEWARE_PORT` |
| `log.format` | `SOZUNE_LOG_FORMAT` (since 0.14) |
| `tracing.enabled` | `SOZUNE_TRACING_ENABLED` (since 0.14) |
| `tracing.endpoint` | `SOZUNE_TRACING_ENDPOINT` (since 0.14) |
| `tracing.service_name` | `SOZUNE_TRACING_SERVICE_NAME` (since 0.14) |
| `tracing.sampler` | `SOZUNE_TRACING_SAMPLER` (since 0.14) |

Booleans accept `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`.

### Standalone variables

These have no YAML counterpart:

| Env var | Effect |
|---|---|
| `CONFIG_PATH` | Path to the YAML config file (default: `config.yaml`). `--config` wins over it. |
| `SOZUNE_DEBUG` | When `true` or `1`, routing failures (`502`) include a body listing configured hosts/backends and a did-you-mean suggestion. Off by default to avoid leaking topology. See [Debugging](/documentation/advanced/debugging). (since 0.12) |
| `RUST_LOG` | Log verbosity filter. See [Configuring log verbosity](/documentation/advanced/access-logs#configuring-log-verbosity). |
| `SOZUNE_API_USER` / `SOZUNE_API_PASSWORD` | Credentials `sozune route` uses to call the API. See [Debugging](/documentation/advanced/debugging). (since 0.15) |
