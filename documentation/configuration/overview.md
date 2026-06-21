# Configuration overview

Sōzune reads its main configuration from a YAML file. Path: `config.yaml` in the working directory by default, overridable through the `CONFIG_PATH` environment variable.

If the file is missing, Sōzune falls back to a built-in default configuration (everything disabled, both listeners on default ports).

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
| `providers` | Sources for entrypoint discovery: Docker, Podman, Swarm, Kubernetes, Nomad, HTTP polling, or a YAML file. |
| `api` | REST API for live entrypoint management. |
| `acme` | Let's Encrypt provisioning. |
| `proxy` | Sōzu listeners and runtime tuning. |
| `middleware` | Internal middleware proxy port. |
| `log` | Log output format (`text` or `json`). |
| `tracing` | OpenTelemetry distributed tracing (OTLP export). Off by default. See [Observability](../advanced/observability.md#distributed-tracing-opentelemetry). |

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
| `swarm.enabled` | `false` | Enables Docker Swarm service discovery (must point to a manager) |
| `swarm.endpoint` | `/var/run/docker.sock` | Docker socket on a Swarm manager |
| `swarm.expose_by_default` | `false` | If true, every service is candidate without `sozune.enable=true` |
| `swarm.network` | `""` | Optional overlay network filter |
| `swarm.refresh_interval` | `15` | Periodic poll interval, in seconds (safety net behind the event stream) |
| `http.enabled` | `false` | Enables polling a remote URL for JSON entrypoints |
| `http.url` | — | URL to poll |
| `http.poll_interval` | `30` | Polling interval, in seconds |
| `config_file.enabled` | `false` | Enables a static YAML file as a source |
| `config_file.path` | — | Path to the entrypoints file |
| `config_file.watch` | `true` | Hot-reload on file change |

## API

| Field | Default | Description |
|---|---|---|
| `api.enabled` | `false` | Enables the REST API |
| `api.listen_address` | `127.0.0.1:3035` | Bind address |
| `api.users` | `[]` | List of API users. Each entry has `name`, `hash` (hex sha256 of the password) and `role` (`admin` or `read-only`). The API refuses to start if this list is empty when `api.enabled: true`. |
| `api.cors_origins` | `[]` | Allowed origins for CORS |

## Proxy

| Field | Default | Description |
|---|---|---|
| `proxy.http.listen_address` | `80` | Port for the HTTP listener |
| `proxy.https.listen_address` | `443` | Port for the HTTPS listener |
| `proxy.tcp` | `[]` | List of TCP listeners. Each entry has `name` (referenced by labels) and `listen` (port). See [TCP routing](/documentation/routing/tcp). |
| `proxy.max_buffers` | `500` | Max number of buffers in the Sōzu pool |
| `proxy.buffer_size` | `16384` | Buffer size, in bytes |
| `proxy.startup_delay_ms` | `1000` | Delay before applying the initial config (gives Sōzu workers time to boot) |
| `proxy.cluster_setup_delay_ms` | `500` | Delay between cluster setup commands |
| `proxy.reload_debounce_ms` | `500` | Debounce window, in ms, applied to reload signals. A reload runs only after this many ms of silence, coalescing bursts of container start/stop events into one reload |
| `proxy.metrics_poll_timeout_ms` | `200` | Per-worker deadline, in ms, for a metrics poll round-trip. Keep it short: the poll shares the loop that accepts traffic and applies certificates, so a slow or silent worker must not be allowed to block proxying |
| `proxy.command_buffer_max_bytes` | `65536` | Maximum size, in bytes, the Sōzu command channel back buffer may grow to. A single command or worker reply larger than this is rejected; raise it if you have a very large number of entrypoints |

## Middleware

| Field | Default | Description |
|---|---|---|
| `middleware.port` | `3037` | Port the internal middleware proxy listens on (rate limit, gzip, backend timeout). Auth, headers, strip prefix and redirects run natively in Sōzu and do not pass through this port. |

## ACME

See [ACME / Let's Encrypt](/documentation/tls/acme).

## Environment variable overrides

Every field above can be overridden through an environment variable. The env var wins over the YAML value.

| Field | Env var |
|---|---|
| `proxy.http.listen_address` | `SOZUNE_HTTP_PORT` |
| `proxy.https.listen_address` | `SOZUNE_HTTPS_PORT` |
| `proxy.max_buffers` | `SOZUNE_PROXY_MAX_BUFFERS` |
| `proxy.buffer_size` | `SOZUNE_PROXY_BUFFER_SIZE` |
| `proxy.startup_delay_ms` | `SOZUNE_PROXY_STARTUP_DELAY_MS` |
| `proxy.cluster_setup_delay_ms` | `SOZUNE_PROXY_CLUSTER_SETUP_DELAY_MS` |
| `proxy.reload_debounce_ms` | `SOZUNE_PROXY_RELOAD_DEBOUNCE_MS` |
| `proxy.metrics_poll_timeout_ms` | `SOZUNE_PROXY_METRICS_POLL_TIMEOUT_MS` |
| `proxy.command_buffer_max_bytes` | `SOZUNE_PROXY_COMMAND_BUFFER_MAX_BYTES` |
| `api.enabled` | `SOZUNE_API_ENABLED` |
| `api.listen_address` | `SOZUNE_API_LISTEN_ADDRESS` |
| `dashboard.enabled` | `SOZUNE_DASHBOARD_ENABLED` |
| `dashboard.listen_address` | `SOZUNE_DASHBOARD_LISTEN_ADDRESS` |
| `providers.docker.enabled` | `SOZUNE_PROVIDER_DOCKER_ENABLED` |
| `providers.docker.endpoint` | `SOZUNE_PROVIDER_DOCKER_ENDPOINT` |
| `providers.docker.expose_by_default` | `SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT` |
| `providers.podman.enabled` | `SOZUNE_PROVIDER_PODMAN_ENABLED` |
| `providers.podman.endpoint` | `SOZUNE_PROVIDER_PODMAN_ENDPOINT` |
| `providers.podman.expose_by_default` | `SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT` |
| `providers.swarm.enabled` | `SOZUNE_PROVIDER_SWARM_ENABLED` |
| `providers.swarm.endpoint` | `SOZUNE_PROVIDER_SWARM_ENDPOINT` |
| `providers.swarm.expose_by_default` | `SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT` |
| `providers.swarm.network` | `SOZUNE_PROVIDER_SWARM_NETWORK` |
| `providers.swarm.refresh_interval` | `SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL` |
| `providers.kubernetes.enabled` | `SOZUNE_PROVIDER_KUBERNETES_ENABLED` |
| `providers.kubernetes.kubeconfig` | `SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG` |
| `providers.kubernetes.namespace` | `SOZUNE_PROVIDER_KUBERNETES_NAMESPACE` |
| `providers.kubernetes.ingress_class` | `SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS` |
| `providers.kubernetes.expose_by_default` | `SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT` |
| `providers.http.enabled` | `SOZUNE_PROVIDER_HTTP_ENABLED` |
| `providers.http.url` | `SOZUNE_PROVIDER_HTTP_URL` |
| `providers.http.poll_interval` | `SOZUNE_PROVIDER_HTTP_POLL_INTERVAL` |
| `providers.http.auth_header` | `SOZUNE_PROVIDER_HTTP_AUTH_HEADER` |
| `providers.http.auth_value` | `SOZUNE_PROVIDER_HTTP_AUTH_VALUE` |
| `providers.config_file.enabled` | `SOZUNE_PROVIDER_CONFIG_FILE_ENABLED` |
| `providers.config_file.path` | `SOZUNE_PROVIDER_CONFIG_FILE_PATH` |
| `providers.config_file.watch` | `SOZUNE_PROVIDER_CONFIG_FILE_WATCH` |
| `acme.enabled` | `SOZUNE_ACME_ENABLED` |
| `acme.email` | `SOZUNE_ACME_EMAIL` |
| `acme.certs_dir` | `SOZUNE_ACME_CERTS_DIR` |
| `acme.staging` | `SOZUNE_ACME_STAGING` |
| `acme.challenge_port` | `SOZUNE_ACME_CHALLENGE_PORT` |
| `middleware.port` | `SOZUNE_MIDDLEWARE_PORT` |
| `log.format` | `SOZUNE_LOG_FORMAT` |
| `tracing.enabled` | `SOZUNE_TRACING_ENABLED` |
| `tracing.endpoint` | `SOZUNE_TRACING_ENDPOINT` |
| `tracing.service_name` | `SOZUNE_TRACING_SERVICE_NAME` |
| `tracing.sampler` | `SOZUNE_TRACING_SAMPLER` |

Booleans accept `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`.

### Standalone variables

These have no YAML counterpart:

| Env var | Effect |
|---|---|
| `CONFIG_PATH` | Path to the YAML config file (default: `config.yaml`) |
| `SOZUNE_DEBUG` | When `true`, routing failures (`502`) include a body listing configured hosts/backends and a did-you-mean suggestion. Off by default to avoid leaking topology. See [Debugging](/documentation/advanced/debugging). |
