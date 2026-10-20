# WebSocket

Sōzune proxies WebSocket upgrades transparently. No configuration is required — it's detected and handled automatically.

## How it works

When Sōzune receives a request with `Upgrade: websocket`, it:

1. Opens a raw TCP connection to the backend.
2. Forwards the HTTP upgrade request, preserving the path and headers.
3. Verifies the backend replies with `101 Switching Protocols`.
4. Establishes a bidirectional TCP tunnel between the client and the backend, copying bytes both ways until either side closes the connection.

## No timeout

Once the upgrade is accepted, the tunnel is **not subject** to the [`backendTimeout`](/documentation/middleware/backend-timeout) setting: Sōzune treats it as long-lived. Only the handshake is bounded by it, so a backend that never answers the upgrade lets the next one take it when the route has [backup](/documentation/routing/load-balancing#weighted-load-balancing) backends. Idle connections stay open until one side closes, or until their backend leaves the route: see [When a backend leaves](/documentation/routing/load-balancing#when-a-backend-leaves).

## Example

```yaml
services:
  realtime:
    image: my-websocket-server
    labels:
      - "sozune.enable=true"
      - "sozune.http.realtime.host=ws.example.com"
      - "sozune.http.realtime.tls=true"
```

A client connects with `wss://ws.example.com/...` and the upgrade flows through Sōzune to the backend.

## Limitations

- **HTTP/1.1 upgrade only.** WebSocket-over-HTTP/2 (RFC 8441) is not currently handled — the upgrade detection is based on the `Upgrade: websocket` header. If a client speaks h2 to Sōzune and tries an h2 WebSocket, the path falls back to a normal h2 request, which the backend will most likely reject.
- **No frame inspection.** Sōzune does not parse WebSocket frames; it only shuffles bytes. Subprotocols, ping/pong policies, and message size limits are entirely the backend's responsibility.
- **No graceful shutdown coordination.** If Sōzune is restarted, active WebSocket tunnels are dropped without a close frame.
