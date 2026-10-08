# REST API

Sōzune exposes a REST API to manage entrypoints on the fly, without restarting. The API also surfaces real-time diagnostics, backend health, and the identity of the currently authenticated user — everything the dashboard needs to drive an interactive UI.

## Configuration

`config.yaml`:

```yaml
api:
  enabled: true
  listen_address: "127.0.0.1:3035"
  users:
    - name: admin
      hash: "b630f5d579dfef28c45ddf5e3c7a65f09ebca4d5b064a70c4203578c8667fdeb"
      role: admin
    - name: dashboard
      hash: "7d4cab0d7c8a5e9eef83b7d306b4cb6dad27b3aaf7df9e0db18f78f9efb1ee43"
      role: read-only
  cors_origins:
    - "https://dashboard.example.com"
```

The API refuses to start when `users` is empty. There is no anonymous mode.

## Authentication

The API uses HTTP Basic. Each user has a `name`, a `hash` (hex of `sha256(password)`), and a `role`.

Generate a hash with:

```bash
echo -n "your-password" | sha256sum
```

Then call the API with the password — sōzune hashes it on receive and compares in constant time:

```bash
curl -u admin:your-password http://localhost:3035/entrypoints
```

The hash format matches what sōzune accepts in route-level basic auth (`sozune.http.<svc>.auth.basic`), so the same generation step works on both sides.

## Roles

| Role | GET / HEAD / OPTIONS | POST / PUT / DELETE |
|---|---|---|
| `admin` (default) | yes | yes |
| `read-only` | yes | `403 Forbidden`, except `POST /routes/resolve` |

`role` can be omitted in `config.yaml`; it defaults to `admin`.

Read-only users can still read every endpoint, including `/diagnostics` and `/me`, and resolve a route: `POST /routes/resolve` only reads. Write attempts return `403` with a JSON error body:

```json
{ "error": "read-only role cannot perform this operation" }
```

## Securing the API on a network

> **HTTP Basic over plaintext HTTP sends the password in the clear on every request.** It is only safe when the connection is encrypted.

The default `listen_address: "127.0.0.1:3035"` keeps the API local-only — fine for CLI use from the same host, never expose it on `0.0.0.0` without TLS in front.

To expose it remotely, put it behind TLS:

- **Behind sōzune itself** — declare an entrypoint that points at `127.0.0.1:3035` with `tls: true` and an ACME-issued certificate.
- **Behind another reverse proxy** that already terminates TLS (nginx, Caddy, an ingress controller).

## CORS

When `cors_origins` is empty, the API responds with `Access-Control-Allow-Origin: *` (every origin allowed). Set `cors_origins` to a list of explicit origins to restrict the browser-side calls — useful when the dashboard is served from a different domain than the API.

Allowed methods are `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`. Allowed headers: `Authorization`, `Content-Type`, `Accept`.

## Common error responses

Every error response body is JSON with an `error` field:

| Status | When |
|---|---|
| `400 Bad Request` | Malformed JSON in the request body |
| `401 Unauthorized` | Missing or invalid `Authorization: Basic ...` header. Response includes `WWW-Authenticate: Basic realm="sozune"`. |
| `403 Forbidden` | Authenticated but the role doesn't permit the operation (read-only writes, or attempting to mutate a provider-owned entrypoint) |
| `404 Not Found` | Unknown entrypoint id |
| `415 Unsupported Media Type` | `Content-Type` is missing or not `application/json` on a write |
| `422 Unprocessable Entity` | JSON parsed but required fields are missing or the wrong type |
| `500 Internal Server Error` | Internal state lock poisoned (unrecoverable; sōzune needs a restart) |

## Endpoints

### `GET /health`

Liveness probe. No auth required.

```bash
curl http://localhost:3035/health
```

```json
{ "status": "ok", "service": "sozune" }
```

Returns `200 OK` as long as the API server can answer. It does not validate downstream state (worker reachability, provider connectivity). `service` tells sozune apart from another process answering on the same port; `sozune doctor` relies on it to detect a running instance.

### `GET /me`

Returns the authenticated user's identity. The dashboard hits this on login to validate credentials and learn its role.

```bash
curl -u dashboard:your-password http://localhost:3035/me
```

```json
{
  "name": "dashboard",
  "role": "read-only"
}
```

`role` is either `"admin"` or `"read-only"`.

### `GET /entrypoints`

Lists every entrypoint sōzune currently routes — from every provider (Docker, Podman, Swarm, Nomad, Kubernetes Ingress/Gateway API, HTTP, config file) plus those created through this API. Available to both roles.

```bash
curl -u admin:your-password http://localhost:3035/entrypoints
```

Response: a JSON array of entrypoint objects (see [Entrypoint schema](#entrypoint-schema) below). Each item also carries:

- `unhealthy_backends`: array of objects describing the backends the health checker has marked unhealthy for this entrypoint. Each object has:
    - `address` — `"<host>:<port>"` of the failing backend
    - `kind` — failure classification: `connection_refused`, `no_route_to_host`, `network_unreachable`, `host_unreachable`, `timeout`, `dns_failure`, or `other`
    - `message` — raw error message from the last probe attempt
    - `since` — Unix epoch (seconds) the backend was first marked down
    - `last_checked` — Unix epoch (seconds) of the last probe attempt
- `diagnostics`: list of [Diagnostic objects](#diagnostic-schema) associated with this entrypoint, including runtime collision lints (W018)

### `GET /entrypoints/{id}`

Fetches a single entrypoint by its id. Returns `404` if unknown. Available to both roles.

```bash
curl -u admin:your-password http://localhost:3035/entrypoints/http_api
```

Response shape identical to one element of `GET /entrypoints` — entrypoint object plus `unhealthy_backends` and `diagnostics`.

### `POST /entrypoints`

Creates an entrypoint through the API. **Admin only.**

```bash
curl -X POST http://localhost:3035/entrypoints \
  -u admin:your-password \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-api",
    "backends": [
      { "address": "10.0.0.5", "port": 8080, "weight": 100 }
    ],
    "protocol": "Http",
    "config": {
      "hostnames": ["api.example.com"],
      "tls": true,
      "https_redirect": true,
      "priority": 0
    }
  }'
```

Required fields: `name`, `backends`, `protocol`, `config`. See [CreateEntrypointRequest schema](#createentrypointrequest-schema) for the full field list.

Response: `201 Created` with the created entrypoint in the body. The `id` is generated by sōzune; the entrypoint's `source` is `"api"`.

### `PUT /entrypoints/{id}`

Replaces an existing entrypoint created through the API. **Admin only.**

```bash
curl -X PUT http://localhost:3035/entrypoints/http_my-api \
  -u admin:your-password \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-api",
    "backends": [{ "address": "10.0.0.6", "port": 8080, "weight": 100 }],
    "protocol": "Http",
    "config": { "hostnames": ["api.example.com"], "tls": true, "priority": 0 }
  }'
```

Response: `200 OK` with the updated entrypoint.

Returns `403 Forbidden` if the entrypoint was discovered from a provider (Docker, Kubernetes, etc.) — those are read-only through the API. To change them, edit the source (container labels, Ingress/HTTPRoute spec, Nomad service tags…).

### `DELETE /entrypoints/{id}`

Deletes an entrypoint. **Admin only.** Returns `204 No Content` on success.

```bash
curl -X DELETE -u admin:your-password http://localhost:3035/entrypoints/http_my-api
```

Same `403 Forbidden` rule as `PUT`: provider-owned entrypoints cannot be deleted through the API.

### `GET /providers`

Snapshot of every provider sōzune knows about, with its `enabled` flag and the number of entrypoints it currently owns in the storage. Useful for a dashboard "what's wired up?" overview. Available to both roles.

```bash
curl -u admin:your-password http://localhost:3035/providers
```

```json
{
  "providers": [
    { "name": "docker",     "enabled": true,  "configured": true,  "entrypoint_count": 5 },
    { "name": "podman",     "enabled": false, "configured": false, "entrypoint_count": 0 },
    { "name": "swarm",      "enabled": false, "configured": false, "entrypoint_count": 0 },
    { "name": "kubernetes", "enabled": true,  "configured": true,  "entrypoint_count": 12 },
    { "name": "nomad",      "enabled": false, "configured": false, "entrypoint_count": 0 },
    { "name": "http",       "enabled": false, "configured": false, "entrypoint_count": 0 },
    { "name": "config",     "enabled": true,  "configured": true,  "entrypoint_count": 2 }
  ]
}
```

- `name`: identifier matching `entrypoint.source` for entrypoints emitted by this provider
- `configured`: the provider block exists in `config.yaml` (truthy when `providers.<name>` is present, regardless of `enabled`)
- `enabled`: the provider's `enabled` flag from `config.yaml` — only enabled providers are actually running and contributing entrypoints
- `entrypoint_count`: live count of entrypoints in storage whose `source` matches this provider name

The list always contains every known provider, even when not configured, so the dashboard can render "configure me" rows next to inactive providers.

### `GET /certificates`

Lists the TLS certificates sōzune serves, with the identity and expiry of each: those ACME stored under `acme.certs_dir` when ACME is enabled, and those [loaded from files](/documentation/tls/overview#certificates-from-files). An ACME certificate for a hostname a file certificate covers is left out, since it is not served. **Admin only.**

```bash
curl -u admin:your-password http://localhost:3035/certificates
```

```json
{
  "certificates": [
    {
      "hostname": "shop.example.com",
      "subject_cn": "shop.example.com",
      "sans": ["shop.example.com", "www.example.com"],
      "not_before": 1750000000,
      "not_after": 1757776000,
      "total_days": 90,
      "remaining_days": 47,
      "status": "valid",
      "source": "acme",
      "file": null,
      "file_replaced": false
    }
  ]
}
```

- `hostname`: for ACME, the host the certificate is stored under (wildcards are restored from the on-disk directory name, e.g. `*.example.com`); for a file, the first name the certificate carries
- `subject_cn`: the certificate's subject Common Name, or `null` if it has none
- `sans`: the `dNSName` entries from the Subject Alternative Name extension
- `not_before` / `not_after`: validity window as Unix epoch seconds
- `total_days`: the certificate's full lifetime in whole days
- `remaining_days`: whole days until expiry; negative once expired
- `status`: lifecycle bucket — `valid`, `expiring`, or `expired`
- `source`: `acme`, or `file` for a certificate from `proxy.https.tls.certificates`
- `file`: the `cert_file` of a certificate from a file, `null` otherwise
- `file_replaced`: `true` when `cert_file` no longer holds the certificate being served — renewed by certbot, or missing. Files are read at startup only: check them with `sozune doctor` first, since a missing or broken file stops startup, then restart sōzune to serve the new one

The `status` is derived from the same lifetime-ratio rule that drives ACME renewal: a certificate is `expiring` once its remaining lifetime drops below one third of its total lifetime (capped at 30 days), so short-lived certificates (7-day, 45-day profiles) aren't flagged the moment they're issued, and the dashboard badge never disagrees with when sōzune actually renews.

### `GET /config`

Read-only snapshot of the running configuration: listeners (HTTP, HTTPS, TCP, UDP), TLS options, ACME settings, providers, the dashboard listener, and the API listener (without the user list). Available to both roles.

```bash
curl -u admin:your-password http://localhost:3035/config
```

Sample response:

```jsonc
{
  "version": "0.13.0",
  "listeners": {
    "http":  { "port": 80 },
    "https": { "port": 443 },
    "tcp": [
      { "name": "postgres", "port": 5432, "ip_allow_list": ["10.0.0.0/8"], "rate_limit": { "max_conns": 20, "per_seconds": 1, "exempt": [] }, "idle_timeout": 3600 }
    ],
    "udp": [{ "name": "dns", "port": 53 }]
  },
  "tls": {
    "min_version": "1.3",
    "max_version": null,
    "ciphers": null,
    "certificates": ["/etc/sozune/certs/fullchain.pem"]
  },
  "acme": {
    "enabled": true,
    "email": "ops@example.com",
    "staging": true,
    "challenge_port": 8080,
    "resolvers": {
      "le-prod": { "challenge": "http-01" },
      "le-cf":   { "challenge": "dns-01", "provider": "cloudflare", "required_env": ["CF_DNS_API_TOKEN"] }
    }
  },
  "providers": {
    "docker": { "enabled": true, "endpoint": "unix:///var/run/docker.sock", "expose_by_default": false },
    "config_file": { "enabled": true, "path": "/etc/sozune/entrypoints.yaml", "watch": true }
    "http": { "enabled": true, "url": "https://config.example.com/entrypoints?***", "poll_interval": 10 }
    // ... podman, swarm, kubernetes, nomad, consul, ring: null when not configured
  },
  "dashboard": {
    "enabled": true,
    "listen_address": "0.0.0.0:3038"
  },
  "api": {
    "enabled": true,
    "listen_address": "0.0.0.0:3035",
    "cors_origins": ["https://dashboard.example.com"]
  }
}
```

**Never exposed:**
- `api.users` — neither the names nor the password hashes. Even hashed credentials enable offline brute-force attacks.
- DNS-01 resolver secrets — only the *names* of the env vars referenced by ACME resolvers travel (`required_env`, as configured); their values stay on the process.
- HTTP provider credentials — the URL's user name, password and query string are replaced by `***`, and `auth_value` is left out.
- Private key paths of the TLS certificate files — only the certificate file is listed.

### `GET /diagnostics`

Snapshot of every diagnostic sōzune has computed: per-candidate diagnostics from the parser, plus global lints (e.g. `W015` ACME enabled but no `tls=true`) and runtime collision lints (`W018`). Available to both roles.

```bash
curl -u admin:your-password http://localhost:3035/diagnostics
```

```json
{
  "total": 3,
  "global": [
    {
      "code": "W015",
      "severity": "warn",
      "message": "ACME enabled but no entrypoint declares tls=true",
      "hint": "set tls=true on at least one HTTP entrypoint to enable certificate provisioning"
    }
  ],
  "items": [
    {
      "candidate_id": "/sozune-test-app",
      "diagnostics": [
        {
          "code": "W001",
          "severity": "warn",
          "label": "sozune.http.app.port",
          "value": "abc",
          "message": "invalid port value, falling back to default",
          "hint": "use a positive integer between 1 and 65535"
        }
      ]
    }
  ]
}
```

- `total`: number of diagnostics across `global` + every `items[*].diagnostics`
- `global`: cross-cutting diagnostics not tied to a single candidate
- `items`: per-candidate diagnostics, sorted by `candidate_id` for stable ordering

The full diagnostic code reference is documented at [`sozune explain <CODE>`](/documentation/configuration/diagnostics).

### `POST /routes/resolve`

Which route serves a request, and why — without sending it. Sōzune answers from its live routing state, with Sōzu's own router and the middleware chain the route really runs. Available to both roles.

```bash
curl -u admin:your-password -X POST http://localhost:3035/routes/resolve \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://app.example.com/api/users", "method": "GET", "headers": {"X-Tenant": "acme"}, "client_ip": "203.0.113.7"}'
```

Only `url` is required. `method` defaults to `GET`. Without `client_ip`, rules on the client address (IP allow-list, client-IP matching) are reported as not evaluated.

```json
{
  "outcome": "proxied",
  "status": null,
  "summary": "proxied by route `api`",
  "route": { "id": "http_api", "name": "api", "source": "docker", "priority": 10 },
  "candidates": [
    {
      "id": "http_web", "name": "web", "priority": 0,
      "verdict": "shadowed",
      "reason": "matches too, but `api` has a higher priority (10 > 0)"
    }
  ],
  "pipeline": [
    { "name": "ip-allow-list", "verdict": "pass", "detail": null },
    { "name": "rate-limit", "verdict": "applies", "detail": "depends on the client's recent requests" }
  ],
  "backends": [
    { "address": "10.0.0.4:8080", "healthy": true, "reason": null },
    { "address": "10.0.0.5:8080", "healthy": false, "reason": "connection refused" }
  ]
}
```

- `outcome`: `proxied` (sent to a backend), `redirected`, `rejected` (a route matched but sōzune answers with an error, see `status`), `acme_challenge`, or `no_route`.
- `status`: the status sōzune answers with itself; `null` when a backend answers.
- `candidates`: the other routes whose hostname matches, each with a `verdict` — `shadowed` (would match, but a route tried before it matches first), `rejected` (its path, method or TLS setting does not match), or `refused` (Sōzu refused it, so it is not live).
- `pipeline`: the route's middlewares in the order they run. `pass` and `blocked` are decided on the request; `applies` depends on live state (rate-limit buckets, in-flight requests, the forward-auth server) and is not decided; `not_evaluated` needs `client_ip`, comes after a blocking step, or is `basic-auth`: credentials are never checked by this endpoint, so a route protected by basic auth is reported as proxied *if the credentials are valid*, and as a `401` when the request carries none.
- `backends`: the route's backends and their health-check state.

The answer reflects the routes the last reload installed in Sōzu. While a reload is being applied, a route that just started answering can still be missing from it for a moment.

A malformed `url`, a scheme other than `http`/`https`, or a method or header that is not valid HTTP returns `400`.

## Entrypoint schema

The canonical shape of an entrypoint as returned by `GET /entrypoints`, `GET /entrypoints/{id}`, `POST`, and `PUT`:

```jsonc
{
  "id": "http_my-api",                  // sōzune-generated, stable across reloads
  "name": "my-api",                     // user-supplied, used as the cluster name
  "protocol": "Http",                   // "Http" | "Tcp" | "Udp"
  "backends": [
    { "address": "10.0.0.5", "port": 8080, "weight": 100 }
  ],
  "source": "api",                      // "api" | "docker" | "swarm" | "kubernetes" | "nomad" | "http" | "config"
  "config": {
    "hostnames": ["api.example.com"],   // exact, wildcard (*.example.com), or regex (/[a-z]+.example.com/)
    "path": {                           // optional path matcher
      "rule_type": "Prefix",            // "Prefix" | "Exact" | "Regex"
      "value": "/v1"
    },
    "tls": true,                        // enable TLS termination (provisions an ACME cert)
    "strip_prefix": false,
    "add_prefix": null,                 // string, mutually exclusive with strip_prefix
    "https_redirect": true,
    "https_redirect_port": null,        // override 443
    "redirect": null,                   // "forward" | "permanent" | "unauthorized"
    "redirect_scheme": null,            // "use_same" | "use_http" | "use_https"
    "redirect_template": null,
    "www_authenticate": null,
    "priority": 0,                      // higher wins on rule collision
    "auth": null,                       // see below
    "forward_auth": null,               // see below
    "headers": [],                      // see below
    "backend_timeout": null,            // milliseconds
    "rate_limit": null,                 // see below
    "sticky_session": false,
    "compress": false,                  // zstd/br/gzip negotiated via Accept-Encoding
    "entrypoint": null,                 // TCP listener name (required for protocol=Tcp)
    "methods": []                       // ["GET", "POST", ...]; empty = any method
  },
  "unhealthy_backends": [],             // only on GET responses (array of objects, see "GET /entrypoints")
  "diagnostics": []                     // only on GET responses
}
```

### Sub-schemas

`auth` (basic auth on this route):

```jsonc
{
  "basic": [
    { "username": "alice", "password_hash": "<sha256-hex>" }
  ]
}
```

`forward_auth`:

```jsonc
{
  "address": "http://authelia:9091/api/verify",
  "response_headers": ["Remote-User", "Remote-Email", "Remote-Groups"],
  "trust_forward_header": false
}
```

`headers` (each item adds or replaces one header on the request, response, or both):

```jsonc
[
  { "name": "X-Powered-By", "value": "sozune", "direction": "response" }
]
```

`direction` is `"request"`, `"response"`, or `"both"`. Defaults to `"request"`.

`rate_limit`:

```jsonc
{ "average": 100, "burst": 50 }
```

`average` is requests per second; `burst` is the bucket size. `burst < average` disables the burst window.

## `CreateEntrypointRequest` schema

POST and PUT accept the same body shape — the four required top-level fields:

| Field | Type | Description |
|---|---|---|
| `name` | string | Logical service name. Becomes part of the generated `id`. |
| `backends` | array of `Backend` | At least one backend; each has `address` (IPv4, IPv6, or hostname), `port`, and optional `weight` (defaults to `100`) |
| `protocol` | `"Http"` \| `"Tcp"` \| `"Udp"` | Routing protocol. UDP is parsed but not yet wired in. |
| `config` | `EntrypointConfig` | All routing options. See [Entrypoint schema](#entrypoint-schema). Every field except `hostnames` and `priority` is optional and defaults to its zero value. |

`id` and `source` are ignored if present in the request — sōzune assigns them.

## Diagnostic schema

```jsonc
{
  "code": "W001",
  "severity": "error" | "warn" | "info",
  "message": "invalid port value, falling back to default",
  "label": "sozune.http.app.port",   // optional: the offending label name
  "value": "abc",                    // optional: the offending value
  "hint": "use a positive integer between 1 and 65535"  // optional remediation hint
}
```

Run `sozune explain <CODE>` for the full cause / effect / fix / example of each code.

## Note on provider-owned entrypoints

Entrypoints discovered from a provider (Docker labels, Kubernetes Ingress/HTTPRoute, Nomad service tags, Swarm service labels, HTTP poll, config file) are **read-only through the API**. `PUT` and `DELETE` against them return `403 Forbidden`. To change them, edit the source.

The `source` field on each entrypoint indicates which provider owns it — useful when the dashboard wants to render "edit through Docker" vs "edit through API" affordances.
