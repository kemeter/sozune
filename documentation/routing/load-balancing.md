# Load balancing

Sōzune balances traffic across multiple backends. Round-robin is the default; other algorithms, weighted distribution, and sticky sessions are opt-in.

## Default — round-robin

Sōzu spreads requests across all healthy backends of a cluster, evenly unless the backends carry different [weights](#weighted-load-balancing). No configuration needed; this is always on.

## Choosing the algorithm

Set `loadBalancer` to pick how requests are distributed across the backends:

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.loadBalancer=least_connections"
```

| Value | Behaviour |
|---|---|
| `round_robin` (default) | Cycle through backends in order, each in proportion to its weight. |
| `least_connections` | Send to the backend with the fewest active connections per unit of weight — good for uneven request durations. |
| `power_of_two` | Sample two backends at random, pick the one less loaded per unit of weight. Cheaper than full least-connections at scale, nearly as good. |
| `random` | Pick a backend at random, weighted by its weight. |

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

  app-canary:
    image: my-app:canary
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.weight=10"
```

The two containers join the same `app` service, so `app.example.com` is split 90% / 10% between them — a simple canary.

Every algorithm honours the weight:

- `round_robin` gives a backend of weight `w` exactly `w` requests out of every `Σw`, interleaved: weights `5`, `1`, `1` serve `a a b a c a a`, not `a a a a a b c`.
- `least_connections` and `power_of_two` compare each backend's load divided by its weight.
- `random` draws in proportion to the weights, so the split is statistical.

The weight belongs to a backend, not to a service: three replicas of `app-stable` labelled `weight=90` carry 270 shares between them.

A weight of `0` makes the backend a **backup**: it takes no traffic while another backend can serve, and takes over when none can. A negative or non-integer value falls back to the default weight and raises a `W027` diagnostic.

A route that goes through the Sōzune middleware (rate limit, compression, auth, retry…) is balanced by the middleware with the weighted round robin above, whatever `loadBalancer` says. There, a backup takes over a request no backend gave a response to: once the [retries](/documentation/middleware/retry) are spent, each backend the request has not tried yet gets one try, heaviest first, then each backup. A WebSocket upgrade, which is not retried, goes through the same order when its backend refuses it.

## When a backend leaves

When a backend leaves a route — its container stops, the service scales down, a rollout replaces it, its [health check](/documentation/advanced/health-checks) fails, or the route itself goes away — Sōzune removes it, then closes the connections still tied to it, so clients reconnect to a backend that is still there:

- an HTTP/1.1 request in flight finishes first, and the connection closes after its response;
- an HTTP/2 connection is told to stop (`GOAWAY`), finishes its open streams and closes;
- a WebSocket or TCP connection closes at once, and the client reconnects.

A route change that keeps a backend (another header, another weight) leaves its connections open, and so does a change Sōzune could not apply: the route keeps what it had. When a route is changed, its connections are closed once its new version is in place, so a client that reconnects at once is served. On a route that goes through the Sōzune middleware, connections are closed this way only when the whole route goes away: a WebSocket tunnel the middleware opened to a backend that left stays open until one side closes it.

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
