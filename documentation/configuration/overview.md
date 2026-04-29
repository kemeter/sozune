# Configuration overview

Sozune reads its main configuration from a YAML file. Path: `config.yaml` in the working directory by default, overridable through the `CONFIG_PATH` environment variable.

If the file is missing, Sozune falls back to a built-in default configuration (everything disabled, both listeners on default ports).

## Example

```yaml
providers:
  docker:
    enabled: true
    expose_by_default: false

api:
  enabled: true
  listen_address: "127.0.0.1:3035"
  token: "your-secret-token"
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
| `providers` | Sources for entrypoint discovery: Docker, HTTP polling, file. |
| `api` | REST API for live entrypoint management. |
| `acme` | Let's Encrypt provisioning. |
| `proxy` | Sōzu listeners and runtime tuning. |
| `middleware` | Internal middleware proxy port. |

## Providers

```yaml
providers:
  docker:
    enabled: true
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
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
| `api.token` | none | Bearer token. **If absent, the API runs without authentication** — every route is publicly reachable on `listen_address`. |
| `api.cors_origins` | `[]` | Allowed origins for CORS |

## Proxy

| Field | Default | Description |
|---|---|---|
| `proxy.http.listen_address` | `80` | Port for the HTTP listener |
| `proxy.https.listen_address` | `443` | Port for the HTTPS listener |
| `proxy.max_buffers` | `500` | Max number of buffers in the Sōzu pool |
| `proxy.buffer_size` | `16384` | Buffer size, in bytes |
| `proxy.startup_delay_ms` | `1000` | Delay before applying the initial config (gives Sōzu workers time to boot) |
| `proxy.cluster_setup_delay_ms` | `500` | Delay between cluster setup commands |

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
| `api.enabled` | `SOZUNE_API_ENABLED` |
| `api.listen_address` | `SOZUNE_API_LISTEN_ADDRESS` |
| `api.token` | `SOZUNE_API_TOKEN` |
| `providers.docker.enabled` | `SOZUNE_PROVIDER_DOCKER_ENABLED` |
| `providers.docker.endpoint` | `SOZUNE_PROVIDER_DOCKER_ENDPOINT` |
| `providers.docker.expose_by_default` | `SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT` |
| `providers.http.enabled` | `SOZUNE_PROVIDER_HTTP_ENABLED` |
| `providers.http.url` | `SOZUNE_PROVIDER_HTTP_URL` |
| `providers.http.poll_interval` | `SOZUNE_PROVIDER_HTTP_POLL_INTERVAL` |
| `providers.config_file.enabled` | `SOZUNE_PROVIDER_CONFIG_FILE_ENABLED` |
| `providers.config_file.path` | `SOZUNE_PROVIDER_CONFIG_FILE_PATH` |
| `providers.config_file.watch` | `SOZUNE_PROVIDER_CONFIG_FILE_WATCH` |
| `acme.enabled` | `SOZUNE_ACME_ENABLED` |
| `acme.email` | `SOZUNE_ACME_EMAIL` |
| `acme.certs_dir` | `SOZUNE_ACME_CERTS_DIR` |
| `acme.staging` | `SOZUNE_ACME_STAGING` |
| `acme.challenge_port` | `SOZUNE_ACME_CHALLENGE_PORT` |
| `middleware.port` | `SOZUNE_MIDDLEWARE_PORT` |

Booleans accept `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`.

### Standalone variables

These have no YAML counterpart:

| Env var | Effect |
|---|---|
| `CONFIG_PATH` | Path to the YAML config file (default: `config.yaml`) |
| `SOZUNE_DEBUG` | When `true`, routing failures (`502`) include a body listing configured hosts/backends and a did-you-mean suggestion. Off by default to avoid leaking topology. See [Debugging](../advanced/debugging.md). |
