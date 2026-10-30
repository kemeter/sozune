# In-flight request limiting

> Since 0.14

Cap the number of requests a single client IP can have in flight (being processed) at the same time on a route. Use it to protect a backend from a single client holding open many slow or concurrent connections, independently of the request rate.

This is the concurrency counterpart to [rate limiting](rate-limit.md): rate limiting caps requests **per second**, while in-flight limiting caps requests **in parallel**.

## Labels

```yaml
labels:
  - "sozune.http.<svc>.inFlightReq=<max-concurrent-requests>"
```

| Label | Description |
|---|---|
| `inFlightReq` | Maximum number of concurrent in-flight requests per client IP. Must be a positive integer. |

If the label is absent, in-flight limiting is disabled for the service. A value that is not a positive integer raises a `W025` diagnostic and disables the limiter.

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.inFlightReq=20"
```

Any single client IP may have at most 20 requests being processed at once. A 21st concurrent request is rejected immediately; once one of the in-flight requests completes, a slot frees up and the next request from that IP is admitted.

## YAML configuration

The same limit is available in the static config file, as `in_flight_req` on the entrypoint's `config`:

```yaml
entrypoints:
  - id: file_api
    name: api
    protocol: Http
    backends:
      - address: "172.20.0.4"
        port: 8080
    config:
      hostnames: ["api.example.com"]
      tls: false
      strip_prefix: false
      priority: 0
      in_flight_req: 20
```

## REST API

The field is exposed as `in_flight_req` on the entrypoint configuration object returned and accepted by the REST API. Omit it (or set it to `null`) to disable the limiter.

## Behaviour

- A slot is taken when the request passes the limiter and released once Sōzune hands the response back (its status and headers), on **every** code path (normal response, backend error, short-circuit). The counter never leaks slots. A response body still streaming, or a WebSocket tunnel, no longer holds a slot.
- Each IP has its own counter; one IP saturating its limit does not affect another.
- When a client is already at its limit, Sōzune returns `503 Service Unavailable` with the header `x-sozune-diagnostic: too-many-in-flight`. The body is empty unless `SOZUNE_DEBUG=true`.
- The check runs in Sōzune's middleware proxy, right after rate limiting. The two are independent: a route can use either, both, or neither. A request the rate limit rejects takes no slot.

## Source IP detection

The client is resolved as for [rate limiting](rate-limit.md#source-ip-detection) and the [IP allow-list](ip-allow-list.md#client-ip-resolution): the address that connected to Sōzu or, behind proxies listed in `proxy.trusted_proxies`, the first `X-Forwarded-For` entry from the right that is not one of them. An `X-Forwarded-For` entry the client wrote itself is never taken for its address.

If you run Sōzune behind another proxy or a load balancer, list it in `proxy.trusted_proxies`: otherwise every request appears to come from that proxy and shares a single counter.

## Memory

The per-IP counter map is in memory. An IP's entry is removed as soon as its in-flight count drops back to zero, so the map only ever holds IPs with active requests.

## Limitations

- **Per-IP only**. There is no per-route-total or per-user (auth-keyed) concurrency cap.
- **Process-local**. If you run multiple Sōzune instances behind a balancer, each maintains its own counters — the effective limit is `instances × inFlightReq`.
