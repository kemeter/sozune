# Rate limiting

> Since 0.9

Token-bucket rate limiter, scoped per source IP. Use to protect backends from abuse or accidental traffic spikes.

## Labels

```yaml
labels:
  - "sozune.http.<svc>.ratelimit.average=<requests-per-second>"
  - "sozune.http.<svc>.ratelimit.burst=<max-burst>"
```

| Label | Description |
|---|---|
| `ratelimit.average` | Sustained rate, in requests per second per IP |
| `ratelimit.burst` | Maximum burst size. Defaults to `average` when omitted. |

If neither label is present, rate limiting is disabled for the service. A value that is not a positive integer (`0` included, since 0.16), or `burst` without `average`, raises a `W004` diagnostic and disables the limit, except an invalid `burst`, which falls back to `average` (since 0.11). A `burst` lower than `average` raises `W017` (since 0.13).

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.ratelimit.average=10"
  - "sozune.http.api.ratelimit.burst=20"
```

A client gets up to 20 requests in a burst, then steady traffic is capped at 10 req/s. New tokens are added continuously (10 per second).

## Behaviour

- Each IP gets its own token bucket; one IP being throttled does not affect another.
- A new bucket starts **full** (`burst` tokens), so the very first burst from a fresh IP goes through.
- Tokens refill linearly at `average` per second, capped at `burst`.
- When a request finds the bucket empty, Sōzune returns `429 Too Many Requests` with the header `x-sozune-diagnostic: rate-limited`. The body is empty unless `SOZUNE_DEBUG=true` (see [Debugging](/documentation/advanced/debugging)).
- The check runs in Sōzune's middleware proxy, after the [IP allow-list](ip-allow-list.md), header/query conditions, CORS and [forward auth](forward-auth.md), and before the [in-flight limit](in-flight-req.md). Basic auth is checked by Sōzu itself, before the request reaches the middleware: a request it rejects never takes a token.

## Source IP detection

The client is the address that connected to Sōzu, resolved as the [IP allow-list](ip-allow-list.md#client-ip-resolution) does: when that address is one of `proxy.trusted_proxies`, `X-Forwarded-For` is read right to left, every line of it in order, and the first entry that is not a trusted proxy is the client. An `X-Forwarded-For` entry the client wrote itself is never taken for its address.

If you run Sōzune behind another proxy or a load balancer, list it in `proxy.trusted_proxies`: otherwise every request appears to come from that proxy and shares a single bucket.

## Memory

Buckets live in memory, one per source. Once a route tracks 10,000 sources, the next new one first triggers a sweep: buckets idle for an hour are dropped, then, if the map is still full, those holding at least half of `burst` (sources not being held back), and if it is still full, all of them.

## Limitations

- **Per-IP only**. There is currently no per-route, per-cluster, or per-user (auth-keyed) rate limit.
- **Process-local**. If you run multiple Sōzune instances behind a balancer, each maintains its own buckets — the effective limit is `instances × average`.
