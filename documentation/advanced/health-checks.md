# Backend health checks

Sōzune actively probes every backend in the background, takes the unhealthy ones out of rotation and reports why. This runs automatically — no configuration needed.

## How it works

Every **10 seconds** by default, Sōzune probes each backend. Without a health-check path this is a **TCP connect** to `<backend-host>:<backend-port>` with a **5-second timeout**; declaring a path upgrades it to an **HTTP probe** (see below). The interval, the timeout, the port and how many probes it takes to change a backend's status can be set per route — see [Settings](#settings).

| Result | Action |
|---|---|
| TCP connect succeeds (TCP mode) | Backend marked healthy |
| HTTP status accepted (HTTP mode) | Backend marked healthy |
| Connect refused / request failed | Backend marked unhealthy |
| Timeout | Backend marked unhealthy |
| HTTP status not accepted | Backend marked unhealthy (`bad_status`) |

When a backend turns unhealthy, Sōzune takes it out of its route: Sōzu and the Sōzune middleware stop sending it requests, and the connections Sōzu holds to it are closed. A WebSocket tunnel the middleware opened stays until one side closes it (see [When a backend leaves](/documentation/routing/load-balancing#when-a-backend-leaves)). It keeps being probed, and comes back as soon as a probe succeeds.

- **Every backend unhealthy:** none is taken out. A route with nothing left would refuse every request, and a probe can be wrong — a misconfigured `healthCheck.path` fails on every backend at once. The dashboard and `sozune route resolve` say so.
- **Backups:** a backend of [weight `0`](/documentation/routing/load-balancing#weighted-load-balancing) is a backup. When the others are unhealthy and it is not, it serves.
- **Shared backends:** a backend that several routes use is probed once per health check they declare, and each route takes it out on its own check's result.
- **UDP** backends are not probed.

The unhealthy backends show up in `GET /entrypoints` (`unhealthy_backends`, with `in_rotation` telling whether each is out), the dashboard and `sozune route resolve`.

## Settings

```yaml
labels:
  - "sozune.http.api.healthCheck.interval=5000"          # probe every 5s
  - "sozune.http.api.healthCheck.unhealthyThreshold=3"   # out after 3 failures in a row
  - "sozune.http.api.healthCheck.healthyThreshold=2"     # back after 2 successes in a row
  - "sozune.http.api.healthCheck.port=8081"              # probe an admin port
```

| Label | Description |
|---|---|
| `healthCheck.interval` | Milliseconds between two probes of a backend. Default `10000`. The checker runs every second, so shorter is not faster. |
| `healthCheck.timeout` | Per-probe timeout in milliseconds, TCP or HTTP. Default `5000`. |
| `healthCheck.port` | Port the probe dials instead of the backend's, for an application that serves its health on an admin port. |
| `healthCheck.unhealthyThreshold` | Failed probes in a row before the backend leaves the rotation. Default `1`: one failure is enough. Raise it so a single slow probe does not take a backend out. |
| `healthCheck.healthyThreshold` | Successful probes in a row before an unhealthy backend comes back. Default `1`. |

Each of these works with the TCP probe as well as the HTTP one: setting any of them without `healthCheck.path` keeps the TCP connect, on the port and at the pace given. An invalid value emits `W021` and falls back to the default.

## HTTP health checks

A bare TCP connect only proves the port is open — a backend that accepts connections but returns `503` to every request still looks healthy. To check at the application layer, point the health check at a path:

```yaml
labels:
  - "sozune.http.api.healthCheck.path=/health"     # enables the HTTP probe
  - "sozune.http.api.healthCheck.status=200"       # optional: exact status required
  - "sozune.http.api.healthCheck.timeout=2000"     # optional: per-check timeout (ms)
  - "sozune.http.api.healthCheck.headers.Authorization=Bearer s3cr3t"  # optional: request header
```

| Label | Description |
|---|---|
| `healthCheck.path` | Request path. Presence enables the HTTP probe. A leading `/` is added if missing. |
| `healthCheck.status` | Exact status code required for "healthy". **Omit to accept any `2xx`/`3xx`** (the Traefik default). |
| `healthCheck.timeout` | Per-check request timeout in milliseconds. Falls back to the global 5s when unset — useful for a deliberately slow `/health`. |
| `healthCheck.headers.<Name>` | A request header the probe sends, e.g. `Authorization` for a protected `/health`. One label per header. The API shows its name, never its value. |

The probe sends `GET http://<backend-host>:<port><path>`, `<port>` being `healthCheck.port` or the backend's, and does **not** follow redirects (a `3xx` is judged as-is). A backend that fails the status check is marked unhealthy with kind `bad_status`; a transport failure is `http_error`. Both surface in `GET /entrypoints` and the dashboard like any other failure reason.

Without `healthCheck.path`, the backend keeps the plain TCP probe — fully backward compatible. `healthCheck.status` and `healthCheck.headers.*` need a path: without one they emit `W021` and are ignored.

## Without a health check

A backend that stops answering is also left out without one, from the requests it fails. Sōzu does it for the routes it serves itself. For a route that goes through the Sōzune middleware (rate limit, auth, compression, timeouts, retries, a mirror…), a backend that gives no response to 3 requests in a row (refused connection, timeout) gets no more requests for 10 seconds, unless every backend of the route is in that state. The next request it is picked for then tries it again: an answer, whatever its status, brings it back; a failure leaves it out for 10 more seconds. A health check takes a backend out before any request fails on it; this only reacts to the failures.

## What it does not do

- **No status ranges.** `healthCheck.status` accepts one exact code; without it, any `2xx`/`3xx` is healthy.
- **No gRPC / custom method / HTTPS** on the HTTP probe yet — it is a plain-HTTP `GET`.

## Combined with Docker

When a Docker container goes down, the Docker provider removes its IP from the entrypoint's `backends` list — usually faster than the health check picks it up. Health checks are a safety net for cases where the container is still running but unresponsive.
