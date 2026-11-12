# Retry

> Since 0.14

Retry a request when forwarding it to the backend fails before any response comes back — a refused connection, a dropped connection, or a timeout. Useful for rolling restarts and transient network blips.

## Label

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.retry.attempts=3"
```

`retry.attempts` is the **total** number of tries (the first attempt plus retries). `3` means up to two retries. `1` or `0` — or omitting the label — disables retries. An invalid value disables retries and raises a `W023` diagnostic.

## What is and isn't retried

Retries cover **connection-level failures and timeouts**, where the backend produced **no response**:

| Situation | Retried? |
|---|---|
| Connection refused / reset | ✅ |
| Backend timeout (`backendTimeout`) | ✅ |
| Backend returned a response — even `500`/`502`/`503` | ❌, unless its status is in `codes` |

A response that arrives is returned to the client as-is and **never** retried: the backend already acted on the request, so replaying it could double a side effect (a payment, an order…).

A route can still retry some statuses, through the [REST / YAML surface](#rest--yaml-surface) or a Gateway API [HTTPRoute](/documentation/providers/kubernetes) `retry` (since 0.16). A response with one of its `codes` takes the next attempt, within `attempts`; the last attempt's response is returned whatever its status. Only list statuses a backend gives before acting on the request, or for requests that are safe to replay.

After all attempts fail, the client gets the usual error: `504` if the last failure was a timeout, `502` otherwise.

## Notes

- The request body is kept in memory, up to 1 MiB, so it can be sent again on each attempt, or to a backup. A larger body is streamed to one attempt instead (since 0.16; every body was kept whole before). It still goes on to the next attempt when the backend could not be reached, as none of it was sent, but not once the backend read any of it (since 0.17).
- A gRPC call (`content-type: application/grpc`) is always streamed, whatever its size: a streaming call sends its next message only once the server answered the last one, so waiting for the whole body would hold it. It is retried only when the backend could not be reached, and a status retry (`codes`) applies only to a backend that answered without reading the call (since 0.17).
- A retry goes to the heaviest backend the request has not tried yet, so with multiple backends it lands on a different one; once every backend was tried, the balancer picks again. When every attempt fails on a route with [backup](/documentation/routing/load-balancing#weighted-load-balancing) backends (weight `0`), each backend not tried yet gets one more try, heaviest first, then each backup. (since 0.16)
- Retries are attempted back-to-back, unless the route sets `backoff_ms`: each retry then waits that long first (since 0.16). A Gateway API `timeouts.request` bounds the waits too.
- A WebSocket upgrade is never retried: `retry.attempts` does not apply to it. On a route with backup backends, an upgrade no backend answered still goes to each backend not tried yet, then each backup (since 0.16).
- With a [circuit breaker](./circuit-breaker.md), a request whose every attempt failed counts as one failure.
- Declaring `retry.attempts` routes the entrypoint through the Sōzune middleware layer (where the retry loop lives), like any other middleware.

## REST / YAML surface

Also available on the entrypoint payload as `retry`:

```jsonc
{
  "name": "app",
  "protocol": "Http",
  "config": {
    "hostnames": ["app.example.com"],
    "retry": { "attempts": 3 }
  }
}
```

Two more fields, not available as labels (since 0.16):

```jsonc
"retry": {
  "attempts": 3,
  "codes": [502, 503],  // statuses retried too
  "backoff_ms": 100     // wait before each retry
}
```
