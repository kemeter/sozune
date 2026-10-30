# Backend timeout

> Since 0.8

Cap the time Sōzune waits for a backend response before giving up. Useful to avoid stuck connections from blocking workers, or — set to zero — to allow long-lived streams.

## Label

```yaml
labels:
  - "sozune.http.<svc>.backendTimeout=<milliseconds>"
```

## Defaults

| Value | Behaviour |
|---|---|
| omitted | 30 seconds (`30000`) to get the response's headers; its body is not bounded |
| `0` | **No timeout** — wait indefinitely |
| any positive integer | Timeout in milliseconds |

## Examples

Standard API, fail fast:

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.backendTimeout=10000"
```

Server-Sent Events / long-lived stream:

```yaml
labels:
  - "sozune.http.events.host=events.example.com"
  - "sozune.http.events.backendTimeout=0"
```

## Behaviour

- A `backendTimeout` you set covers each attempt: connecting to the backend, sending the request, and reading the whole response, its body included. A body still streaming past it is cut short. The default 30 seconds only bound the wait for the response's headers.
- On timeout, the client receives `504 Gateway Timeout`, or the connection is cut if the response had already started. With [`retry.attempts`](/documentation/middleware/retry), a timeout before the response is retried.
- Setting `backendTimeout` sends the route's requests through the Sōzune middleware layer, where the timeout is enforced, like any other middleware.
- On a WebSocket upgrade, the timeout covers only the handshake (connecting and getting the backend's first answer); the tunnel that follows is not bounded by it — see [WebSocket](/documentation/advanced/websocket).
- The listener's own timeouts still apply. A backend that sends nothing for longer than [`proxy.timeouts.backend_idle`](/documentation/configuration/overview#proxy) (30 s by default) is cut with a `504`, and so is a client left waiting longer than `proxy.timeouts.client_idle` (60 s), whatever `backendTimeout` says. They are listener-wide, not per route: raise them to let a route wait longer than that. `sozune validate`, `GET /diagnostics` and the dashboard flag a route whose `backendTimeout` the listener cuts short with `W030` (since 0.15).

## When to set it

- **Lower than 30s** for user-facing APIs where a slow backend should fail fast.
- **`0`** for SSE, long-polling, file uploads/downloads of unknown size, or any use case where 30s is too aggressive, together with `proxy.timeouts` when the backend can stay silent longer than 30 s.
- **Around 30s** is fine as a default for typical request/response APIs.

## Long-polling

If your client passes a `timeout` parameter expecting the server to hold the request — Matrix `/_matrix/client/v3/sync?timeout=30000`, CometD, custom JSON long-poll — the default 30 s cut lands right when the response is about to come back. Raise `backendTimeout` past the longest poll, or set it to `0`, and raise `proxy.timeouts` to match. See [Long-polling](/documentation/advanced/long-polling) for the full pattern.
