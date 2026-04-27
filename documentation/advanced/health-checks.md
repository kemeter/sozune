# Backend health checks

Sozune actively probes every backend in the background and reconfigures Sōzu when their status changes. This runs automatically — no configuration needed.

## How it works

Every **10 seconds**, Sozune opens a TCP connection to each backend (`<backend-host>:<backend-port>`) with a **5-second timeout**.

| Result | Action |
|---|---|
| TCP connect succeeds | Backend marked healthy |
| TCP connect refused | Backend marked unhealthy |
| Timeout | Backend marked unhealthy |

When a backend transitions between healthy and unhealthy, Sozune triggers a Sōzu reload. Unhealthy backends are removed from rotation; they come back as soon as the probe succeeds again.

## What it checks

- **Layer 4 only** (TCP). Sozune does not send an HTTP request, doesn't check status codes, doesn't follow redirects.
- The probed address is the same one used for traffic — host and port from the entrypoint config.

## What it does not do

- **No HTTP probe.** A backend that accepts TCP but returns 500 to every request is considered healthy. If you need application-level health, expose a TCP-level proxy in front (or rely on your container orchestrator's healthcheck).
- **No configuration.** The interval (10s), timeout (5s), and protocol (TCP) are hardcoded.
- **No threshold logic.** A single failed probe marks the backend unhealthy. There is no "fail N times before evicting" debouncing.

## Combined with Docker

When a Docker container goes down, the Docker provider removes its IP from the entrypoint's `backends` list — usually faster than the health check picks it up. Health checks are a safety net for cases where the container is still running but unresponsive.
