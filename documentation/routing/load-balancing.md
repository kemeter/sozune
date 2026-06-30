# Load balancing

Sōzune balances traffic across multiple backends. Round-robin is the default; other algorithms, weighted distribution, and sticky sessions are opt-in.

## Default — round-robin

Sōzu spreads requests evenly across all healthy backends of a cluster. No configuration needed; this is always on.

## Choosing the algorithm

Set `loadBalancer` to pick how requests are distributed across the backends:

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.loadBalancer=least_connections"
```

| Value | Behaviour |
|---|---|
| `round_robin` (default) | Cycle through backends in order. |
| `least_connections` | Send to the backend with the fewest active connections — good for uneven request durations. |
| `power_of_two` | Sample two backends at random, pick the less loaded. Cheaper than full least-connections at scale, nearly as good. |
| `random` | Pick a backend at random. |

Values are case-insensitive and accept hyphens or underscores (`least-connections` == `least_connections`); common aliases work too (`leastconn`, `rr`, `p2c`). An unrecognised value falls back to round-robin and raises a `W022` diagnostic. The setting applies to both HTTP and TCP entrypoints, and is also available as `load_balancer` on the REST/YAML entrypoint payload.

## Multiple backends from Docker

Several containers can serve the same Sōzune service. They are merged into a single cluster when they share the same `<service_name>` in their labels.

```yaml
services:
  app-instance-1:
    image: my-app
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"

  app-instance-2:
    image: my-app
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
```

Both containers register as backends of the `app` service (the part of `sozune.http.app.host`). Traffic for `app.example.com` is balanced between them.

The Compose service name (`app-instance-1`, `app-instance-2`) is irrelevant — only the Sōzune service name in the label matters.

## Multiple backends from the API

```json
POST /entrypoints
{
  "name": "app",
  "backends": [
    { "address": "10.0.0.5", "port": 8080, "weight": 100 },
    { "address": "10.0.0.6", "port": 8080, "weight": 100 }
  ],
  "protocol": "Http",
  "config": { "hostnames": ["app.example.com"] }
}
```

## Weighted load balancing

Weights live on each backend via the `weight` field (default `100`). Higher weight = more traffic.

```json
{
  "name": "app",
  "backends": [
    { "address": "10.0.0.5", "port": 8080, "weight": 80 },
    { "address": "10.0.0.6", "port": 8080, "weight": 20 }
  ],
  ...
}
```

From Docker (or any label source), a backend sets its own weight with the `weight` label:

```yaml
services:
  app-stable:
    image: my-app:stable
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.weight=90"
      - "sozune.http.app.loadBalancer=random"

  app-canary:
    image: my-app:canary
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.weight=10"
      - "sozune.http.app.loadBalancer=random"
```

The two containers join the same `app` service, so `app.example.com` is split roughly 90% / 10% between them — a simple canary.

> **Only `random` honours the weight.** `round_robin` (the default) and the load-based algorithms ignore it, so set `loadBalancer=random` on the service when you rely on weights. The split is statistical, not an exact ratio. A weight of `0` keeps the backend wired but excludes it from selection; a negative or non-integer value falls back to the default weight and raises a `W027` diagnostic.

## Sticky sessions

Pin a client to the same backend for the duration of its session:

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.stickySession=true"
```

When enabled, Sōzu sets a session cookie and routes subsequent requests with that cookie to the originally selected backend. If the backend disappears, the client is reassigned.

Sticky sessions are best-effort affinity, not absolute pinning.

## What's not supported

- **Custom hashing** (consistent hashing, IP hash) — not exposed by Sōzu.
- **Deterministic weighted round-robin** — weights are honoured only by the `random` balancer, so the split is statistical, not an exact request-by-request ratio.
