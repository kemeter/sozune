# HTTP provider

> Since 0.11

The HTTP provider polls a remote URL for entrypoint definitions in JSON. Useful when you don't run on Docker, or when an external control plane needs to push routes to Sōzune.

## Configuration

```yaml
providers:
  http:
    enabled: true
    url: "https://config.example.com/entrypoints"
    poll_interval: 30
    auth_header: "X-Sozune-Token"
    auth_value: "shared-secret"
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the HTTP provider |
| `url` | — | URL to poll |
| `poll_interval` | `30` | Polling interval, in seconds |
| `auth_header` | `""` | Header name to send on every poll request. See [Authentication](#authentication). (since 0.14) |
| `auth_value` | `""` | Header value to send. Both `auth_header` and `auth_value` must be non-empty for any header to be sent. (since 0.14) |

Env var overrides: `SOZUNE_PROVIDER_HTTP_ENABLED`, `SOZUNE_PROVIDER_HTTP_URL`, `SOZUNE_PROVIDER_HTTP_POLL_INTERVAL`, `SOZUNE_PROVIDER_HTTP_AUTH_HEADER`, `SOZUNE_PROVIDER_HTTP_AUTH_VALUE`.

## Authentication

> Since 0.14

When the upstream config endpoint is reachable from the public internet, you typically don't want anonymous callers to be able to enumerate your topology. Sōzune supports a simple shared-secret scheme: a single fixed HTTP header sent on every poll.

### How it works

- If both `auth_header` and `auth_value` are set, Sōzune adds `<auth_header>: <auth_value>` to every GET request to `url`.
- If either is empty, no header is sent — the request is anonymous.
- The pair is sent verbatim: Sōzune does not prepend `Bearer `, base64-encode, or otherwise transform the value. If you want `Authorization: Bearer abc123`, set `auth_header: "Authorization"` and `auth_value: "Bearer abc123"`.
- The header is sent on every poll. There is no rotation, no refresh, no challenge/response. Treat the value as a long-lived shared secret.

### Recommended patterns

- **`Authorization: Bearer <token>`** — works with most off-the-shelf auth middleware.
- **`X-Sozune-Token: <secret>`** — a custom header makes intent explicit and keeps the endpoint outside generic auth chains.

### Example: protecting a Symfony control plane

The control plane checks the header before serving the entrypoint list:

```php
#[Route('/.well-known/sozune', methods: ['GET'])]
public function __invoke(Request $request): JsonResponse
{
    if ($request->headers->get('X-Sozune-Token') !== $this->expectedToken) {
        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }
    return new JsonResponse($this->buildEntrypoints());
}
```

Sōzune side:

```yaml
providers:
  http:
    enabled: true
    url: "https://control-plane.example.com/.well-known/sozune"
    poll_interval: 30
    auth_header: "X-Sozune-Token"
    # auth_value left out: set SOZUNE_PROVIDER_HTTP_AUTH_VALUE in the environment
```

### Storing the secret

Prefer the env var override (`SOZUNE_PROVIDER_HTTP_AUTH_VALUE`) over committing the value to YAML. The env var wins if both are set. The config file does not expand `${VAR}` references: such a value is sent as written.

### Defence in depth

A single static header is a low bar. For sensitive control planes, layer it with one or more of:

- **Network ACLs** restricting the endpoint to Sōzune's source IP.
- **TLS** on the upstream URL (Sōzune verifies certificates by default via `rustls`).
- **mTLS** terminated by an upstream reverse proxy in front of the control plane (Sōzune itself does not currently load client certificates).

## Expected response

A JSON array of entrypoints with the same schema as the [REST API](/documentation/configuration/api), `id` included:

```json
[
  {
    "id": "my-api",
    "name": "my-api",
    "protocol": "Http",
    "backends": [
      { "address": "10.0.0.5", "port": 8080, "weight": 100 }
    ],
    "config": {
      "hostnames": ["api.example.com"],
      "path": null,
      "tls": true,
      "strip_prefix": false,
      "https_redirect": true,
      "priority": 0,
      "auth": null
    }
  }
]
```

Each backend carries its own `port` (and an optional `weight`, default `100`); there is no route-level port. Of `config`, `hostnames`, `tls`, `strip_prefix` and `priority` are required; every other field is optional and takes its default when left out. An entry that does not match the schema fails the whole poll.

## Behaviour

- **JSON only.** The body is parsed as JSON whatever its `Content-Type`; YAML or anything else fails the poll.
- **Polling cadence:** a first poll at startup, then every `poll_interval` seconds.
- **Reload trigger:** Sōzune compares the new payload with the routes it holds. Any difference — an entrypoint added or removed, or any field of one changed (backends, hostnames, path, conditions, TLS, middleware…) — replaces them and triggers a reload. An identical payload does nothing. A change to an existing entrypoint other than its `backends` or `hostnames` is applied too (since 0.16).
- **Failure handling:** a network error, a non-2xx response or a body that is not a valid entrypoint array is logged as a warning (`HTTP provider fetch failed`). The previous routes are kept as they are; the next poll tries again.
- **Empty list:** `[]` is a valid answer: it removes every route of the HTTP provider.
- **Invalid entries:** an entrypoint with a hostname Sōzune refuses — a bare `*`, an empty label such as `example..com`, a malformed `/regex/` — is dropped with a warning, the others applied (since 0.15). So is one whose `match_headers` or `match_query` regex does not compile (since 0.16).
- **Source tag:** entrypoints from the HTTP provider are tagged with `source: "http"` internally. This isolates them from the other providers' and API-managed entrypoints — the HTTP provider replaces only its own subset on each successful poll.

## Coexistence with other providers

The HTTP provider, the other providers, and the REST API can run together. Each manages its own slice of the entrypoint storage, identified by `source`:

- Docker, Podman, Swarm, Kubernetes, Nomad, Consul, Ring providers: `source: "docker"`, `"podman"`, `"swarm"`, `"kubernetes"`, `"nomad"`, `"consul"`, `"ring"`
- Config file provider: `source: "config"`
- HTTP provider: `source: "http"`
- REST API entrypoints: `source: "api"`

A poll only deletes entrypoints with `source: "http"` — the others are untouched. Give the HTTP provider's entrypoints `id`s no other source uses: one with the same `id` as another source's entrypoint replaces it.

## Limitations

- **No retry/backoff.** A failed fetch waits the full `poll_interval` before retrying.
- **Auth is a single static header.** No token rotation, OAuth flow, or mTLS client certs — see [Authentication](#authentication) for the trade-offs and recommended layered patterns.
