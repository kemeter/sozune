# Server-Sent Events

Sōzune proxies Server-Sent Events (`text/event-stream`) transparently. There is nothing to enable — once you set the right backend timeout, the long-lived stream flows through Sōzu chunk by chunk, in real time.

## The one knob you need

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.http.events.host=events.example.com"
  - "sozune.http.events.backendTimeout=0"
```

`backendTimeout=0` is **required** for any SSE endpoint. Without it, Sōzune cuts the connection after the default 30 s and your client reconnects on a loop without ever receiving the next event.

See [Backend timeout](/documentation/middleware/backend-timeout) for the full semantics — `0` means *no timeout*, exactly what an idle SSE stream needs.

## How it works

When the backend responds with `Content-Type: text/event-stream`:

1. Sōzu forwards the response headers immediately.
2. Each `data: ...\n\n` chunk emitted by the backend is forwarded to the client as it arrives, without waiting for the connection to close.
3. The connection stays open as long as either side keeps it open.

End-to-end latency through Sōzune for an SSE event is typically **under 100 ms** on a local backend — the e2e test in `tests/e2e/08-sse.sh` asserts this is under one second.

## Compression

Do **not** enable `sozune.http.<svc>.compress=true` on an SSE endpoint. Compression buffers chunks to fill the encoder's window, which defeats real-time delivery. Sōzune does not auto-detect SSE and skip compression for you — the choice is yours, but pick one or the other.

## Mercure example

[Mercure](https://mercure.rocks/) is a popular SSE hub. It works behind Sōzune with the standard config:

```yaml
services:
  mercure:
    image: dunglas/mercure:v0.16
    environment:
      SERVER_NAME: ":80"
      MERCURE_PUBLISHER_JWT_KEY: "your-publisher-secret"
      MERCURE_SUBSCRIBER_JWT_KEY: "your-subscriber-secret"
    labels:
      - "sozune.enable=true"
      - "sozune.http.mercure.host=mercure.example.com"
      - "sozune.http.mercure.port=80"
      - "sozune.http.mercure.tls=true"
      - "sozune.http.mercure.backendTimeout=0"
```

This setup is exercised by the e2e suite: a publish through Sōzune to the hub reaches an active subscriber (also connected through Sōzune) in tens of milliseconds.

## Limitations

- **Compression** disabled by hand, as noted above.
- **HTTP/2 and HTTP/3 SSE** work as long as the client speaks them — Sōzu serves both and forwards chunks. Polling intervals (e.g. browser auto-reconnect on `EventSource` close) are entirely client-side.
- **No SSE-specific framing.** Sōzune does not inspect `data:` / `event:` / `id:` lines; it only shuffles bytes. Subscriber lifecycle, retry policies and topic filtering are the backend's responsibility.
