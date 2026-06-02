# Retry

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
| Backend returned a response — even `500`/`502`/`503` | ❌ |

A response that arrives is returned to the client as-is and **never** retried: the backend already acted on the request, so replaying it could double a side effect (a payment, an order…). This matches Traefik's default retry behaviour.

After all attempts fail, the client gets the usual error: `504` if the last failure was a timeout, `502` otherwise.

## Notes

- The request body is buffered in memory so it can be replayed on each attempt. Keep that in mind for very large uploads on retried routes.
- Each attempt re-runs backend selection, so with multiple backends a retry can land on a different (healthy) one.
- Retries are attempted back-to-back; there is no backoff delay between them yet.
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
