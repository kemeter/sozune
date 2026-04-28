# HTTP provider

The HTTP provider polls a remote URL for entrypoint definitions in JSON. Useful when you don't run on Docker, or when an external control plane needs to push routes to Sozune.

## Configuration

```yaml
providers:
  http:
    enabled: true
    url: "https://config.example.com/entrypoints"
    poll_interval: 30
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the HTTP provider |
| `url` | — | URL to poll |
| `poll_interval` | `30` | Polling interval, in seconds |

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
      "https_redirect": true,
      "priority": 0,
      "headers": {},
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

- **JSON only.** YAML is rejected — Sozune only parses `application/json`-compatible bodies.
- **Polling cadence:** every `poll_interval` seconds.
- **Reload trigger:** Sozune diffs the new payload against the current state. A reload is triggered only when **at least one** of `backends`, `hostnames`, `port` changes for any entrypoint, or when entrypoints are added/removed.
- **Failure handling:** a non-2xx response or unparseable JSON is logged as a warning. The previous state is preserved; no entrypoints are removed on failure.
- **Source tag:** entrypoints from the HTTP provider are tagged with `source: "http"` internally. This isolates them from Docker-discovered or API-managed entrypoints — the HTTP provider replaces only its own subset on each successful poll.

## Coexistence with other providers

The HTTP provider, Docker provider, and REST API can run together. Each manages its own slice of the entrypoint storage, identified by `source`:

- Docker provider: `source: "docker"`
- HTTP provider: `source: "http"`
- REST API entrypoints: `source: "api"`

A poll only deletes entrypoints with `source: "http"` — Docker and API ones are untouched.

## Limitations

- **No authentication.** The polling client doesn't send any header to the upstream URL. Protect your config endpoint via network ACLs or run it on localhost.
- **No retry/backoff.** A failed fetch waits the full `poll_interval` before retrying.
- **No diff granularity below entrypoint-level fields.** A change in middleware config (auth, headers, rate limit) is currently not detected by the diff and won't trigger a reload until one of `backends`/`hostnames`/`port` changes too.
