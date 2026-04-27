# Backend timeout

Cap the time Sozune waits for a backend response before giving up. Useful to avoid stuck connections from blocking workers, or — set to zero — to allow long-lived streams.

## Label

```yaml
labels:
  - "sozune.http.<svc>.backendTimeout=<seconds>"
```

## Defaults

| Value | Behaviour |
|---|---|
| omitted | 30 seconds |
| `0` | **No timeout** — wait indefinitely |
| any positive integer | Timeout in seconds |

## Examples

Standard API, fail fast:

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.backendTimeout=10"
```

Server-Sent Events / long-lived stream:

```yaml
labels:
  - "sozune.http.events.host=events.example.com"
  - "sozune.http.events.backendTimeout=0"
```

## Behaviour

- The timer covers the full request: connecting to the backend, sending the request, and reading the response.
- On timeout, the client receives `504 Gateway Timeout`.
- WebSocket upgrades are handled outside of this timeout — see [WebSocket](/documentation/websocket).

## When to set it

- **Lower than 30s** for user-facing APIs where a slow backend should fail fast.
- **`0`** for SSE, long-polling, file uploads/downloads of unknown size, or any use case where 30s is too aggressive.
- **Around 30s** is fine as a default for typical request/response APIs.
