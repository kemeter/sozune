# Circuit breaker

Stop sending traffic to a backend that is failing. When the recent failure rate crosses a threshold, the breaker **opens** and Sōzune answers `503` immediately instead of forwarding — giving the backend room to recover and failing fast for clients. After a cooldown it probes again and closes once the backend is healthy.

## Label

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.circuitBreaker.threshold=0.5"
  - "sozune.http.app.circuitBreaker.minRequests=20"
  - "sozune.http.app.circuitBreaker.cooldown=10"
```

Setting **any** `circuitBreaker.*` field enables the breaker; omitted fields use the defaults.

| Field | Meaning | Default |
|---|---|---|
| `circuitBreaker.threshold` | Failure ratio in `(0, 1]` that trips the breaker | `0.5` (50%) |
| `circuitBreaker.minRequests` | Recent requests required before the ratio is evaluated | `20` |
| `circuitBreaker.cooldown` | Seconds the breaker stays open before probing again | `10` |

An invalid value for a field raises a `W024` diagnostic and falls back to that field's default.

## How it works

Three states:

1. **Closed** (normal) — every request is forwarded. Outcomes feed a sliding window of the last `minRequests` requests. Once the window is full and the failure ratio reaches `threshold`, the breaker trips to **Open**.
2. **Open** — every request is short-circuited with `503` (diagnostic `circuit-open`) for `cooldown` seconds. The backend is left alone.
3. **Half-open** — after the cooldown, a single trial request is allowed through. If it succeeds the breaker **closes** (window reset); if it fails it re-opens for another cooldown.

## What counts as a failure

| Backend outcome | Counts as failure? |
|---|---|
| Response `>= 500` | ✅ |
| Connection error / timeout (no response) | ✅ |
| Response `2xx`/`3xx`/`4xx` | ❌ |

`4xx` is a client error, not a backend fault, so it never trips the breaker — matching Traefik's intent.

## Notes

- The breaker is **per route** and its state is shared across requests, so it persists between connections.
- Cooldown timing uses a monotonic clock, so wall-clock changes don't disturb it.
- Declaring `circuitBreaker.*` routes the entrypoint through the Sōzune middleware layer, where the breaker is enforced.
- Pairs well with [retry](./retry.md): retries handle transient blips; the breaker handles a backend that is durably down.

## REST / YAML surface

Also available on the entrypoint payload as `circuit_breaker`:

```jsonc
{
  "name": "app",
  "protocol": "Http",
  "config": {
    "hostnames": ["app.example.com"],
    "circuit_breaker": { "threshold": 0.5, "min_requests": 20, "cooldown_secs": 10 }
  }
}
```
