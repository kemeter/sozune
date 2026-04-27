# Rate limiting

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

If neither label is present, rate limiting is disabled for the service.

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
- When a request finds the bucket empty, Sozune returns `429 Too Many Requests` with body `Too Many Requests`.
- The check runs **before** basic auth, so failed-auth attempts also count against the limit (cheaper than verifying bcrypt for nothing).

## Source IP detection

Sozune extracts the client IP from:

1. The first entry of the `X-Forwarded-For` header, if present.
2. Otherwise, the `Host` header value.

If you run Sozune behind another proxy or a load balancer, ensure that proxy sets `X-Forwarded-For` correctly — otherwise every request will appear to come from the same upstream IP and share a single bucket.

## Memory

Idle buckets are evicted automatically after 1 hour of inactivity. There is no hard cap on the number of concurrent IPs tracked.

## Limitations

- **Per-IP only**. There is currently no per-route, per-cluster, or per-user (auth-keyed) rate limit.
- **Process-local**. If you run multiple Sozune instances behind a balancer, each maintains its own buckets — the effective limit is `instances × average`.
