# Backend health checks

Sōzune actively probes every backend in the background and reconfigures Sōzu when their status changes. This runs automatically — no configuration needed.

## How it works

Every **10 seconds**, Sōzune probes each backend. By default this is a **TCP connect** to `<backend-host>:<backend-port>` with a **5-second timeout**; declaring a health-check path upgrades that backend to an **HTTP probe** (see below).

| Result | Action |
|---|---|
| TCP connect succeeds (TCP mode) | Backend marked healthy |
| HTTP status accepted (HTTP mode) | Backend marked healthy |
| Connect refused / request failed | Backend marked unhealthy |
| Timeout | Backend marked unhealthy |
| HTTP status not accepted | Backend marked unhealthy (`bad_status`) |

When a backend transitions between healthy and unhealthy, Sōzune triggers a Sōzu reload. Unhealthy backends are removed from rotation; they come back as soon as the probe succeeds again.

## HTTP health checks

A bare TCP connect only proves the port is open — a backend that accepts connections but returns `503` to every request still looks healthy. To check at the application layer, point the health check at a path:

```yaml
labels:
  - "sozune.http.api.healthCheck.path=/health"     # enables the HTTP probe
  - "sozune.http.api.healthCheck.status=200"       # optional: exact status required
  - "sozune.http.api.healthCheck.timeout=2000"     # optional: per-check timeout (ms)
```

| Label | Description |
|---|---|
| `healthCheck.path` | Request path. Presence enables the HTTP probe. A leading `/` is added if missing. |
| `healthCheck.status` | Exact status code required for "healthy". **Omit to accept any `2xx`/`3xx`** (the Traefik default). |
| `healthCheck.timeout` | Per-check request timeout in milliseconds. Falls back to the global 5s when unset — useful for a deliberately slow `/health`. |

The probe sends `GET http://<backend-host>:<backend-port><path>` and does **not** follow redirects (a `3xx` is judged as-is). A backend that fails the status check is marked unhealthy with kind `bad_status`; a transport failure is `http_error`. Both surface in `GET /entrypoints` and the dashboard like any other failure reason.

Without `healthCheck.path`, the backend keeps the plain TCP probe — fully backward compatible.

## What it does not do

- **No per-service interval.** The probe interval (10s) is global and hardcoded; only the per-check HTTP `timeout` is configurable so far.
- **No threshold logic.** A single failed probe marks the backend unhealthy. There is no "fail N times before evicting" debouncing.
- **No gRPC / custom method / custom headers** on the HTTP probe yet — it is a plain `GET`.

## Combined with Docker

When a Docker container goes down, the Docker provider removes its IP from the entrypoint's `backends` list — usually faster than the health check picks it up. Health checks are a safety net for cases where the container is still running but unresponsive.
