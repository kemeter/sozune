# HTTP provider

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
| `auth_header` | `""` | Header name to send on every poll request. See [Authentication](#authentication). |
| `auth_value` | `""` | Header value to send. Both `auth_header` and `auth_value` must be non-empty for any header to be sent. |

Env var overrides: `SOZUNE_PROVIDER_HTTP_ENABLED`, `SOZUNE_PROVIDER_HTTP_URL`, `SOZUNE_PROVIDER_HTTP_POLL_INTERVAL`, `SOZUNE_PROVIDER_HTTP_AUTH_HEADER`, `SOZUNE_PROVIDER_HTTP_AUTH_VALUE`.

## Authentication

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
    auth_value: "${SOZUNE_HTTP_PROVIDER_TOKEN}"  # or use the env var override
```

### Storing the secret

Prefer the env var override (`SOZUNE_PROVIDER_HTTP_AUTH_VALUE`) over committing the value to YAML. The env var wins if both are set.

### Defence in depth

A single static header is a low bar. For sensitive control planes, layer it with one or more of:

- **Network ACLs** restricting the endpoint to Sōzune's source IP.
- **TLS** on the upstream URL (Sōzune verifies certificates by default via `rustls`).
- **mTLS** terminated by an upstream reverse proxy in front of the control plane (Sōzune itself does not currently load client certificates).

## Expected response

A JSON array of entrypoints with the same schema as the [REST API](/documentation/configuration/api):

```json
[
  {
    "id": "my-api",
    "name": "my-api",
    "backends": ["10.0.0.5:8080"],
    "protocol": "Http",
    "config": {
      "hostnames": ["api.example.com"],
      "port": 8080,
      "path": null,
      "tls": true,
      "strip_prefix": false,
      "add_prefix": null,
      "https_redirect": true,
      "https_redirect_port": null,
      "redirect": null,
      "redirect_scheme": null,
      "redirect_template": null,
      "www_authenticate": null,
      "priority": 0,
      "headers": [],
      "auth": null,
      "backend_timeout": null,
      "rate_limit": null,
      "sticky_session": false,
      "compress": false
    }
  }
]
```

## Behaviour

- **JSON only.** YAML is rejected — Sōzune only parses `application/json`-compatible bodies.
- **Polling cadence:** every `poll_interval` seconds.
- **Reload trigger:** Sōzune diffs the new payload against the current state. A reload is triggered only when **at least one** of `backends`, `hostnames`, `port` changes for any entrypoint, or when entrypoints are added/removed.
- **Failure handling:** a non-2xx response or unparseable JSON is logged as a warning. The previous state is preserved; no entrypoints are removed on failure.
- **Source tag:** entrypoints from the HTTP provider are tagged with `source: "http"` internally. This isolates them from Docker-discovered or API-managed entrypoints — the HTTP provider replaces only its own subset on each successful poll.

## Coexistence with other providers

The HTTP provider, Docker provider, and REST API can run together. Each manages its own slice of the entrypoint storage, identified by `source`:

- Docker provider: `source: "docker"`
- HTTP provider: `source: "http"`
- REST API entrypoints: `source: "api"`

A poll only deletes entrypoints with `source: "http"` — Docker and API ones are untouched.

## Limitations

- **No retry/backoff.** A failed fetch waits the full `poll_interval` before retrying.
- **No diff granularity below entrypoint-level fields.** A change in middleware config (auth, headers, rate limit) is currently not detected by the diff and won't trigger a reload until one of `backends`/`hostnames`/`port` changes too.
- **Auth is a single static header.** No token rotation, OAuth flow, or mTLS client certs — see [Authentication](#authentication) for the trade-offs and recommended layered patterns.
