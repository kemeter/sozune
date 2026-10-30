# Server-Sent Events

Sōzune proxies Server-Sent Events (`text/event-stream`) transparently. There is nothing to enable — the long-lived stream flows through Sōzu chunk by chunk, in real time, as long as no timeout cuts it.

## Timeouts

Leave `backendTimeout` unset on an SSE route, or set it to `0`:

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.http.events.host=events.example.com"
  - "sozune.http.events.backendTimeout=0"
```

A `backendTimeout` you set covers the whole response, its body included: a positive value cuts the stream once it is reached, and the client reconnects on a loop. Unset, the default 30 s only bounds the wait for the response's headers, which an SSE backend sends at once. `0` removes the timeout altogether; `sozune validate`, `GET /diagnostics` and the dashboard then report `W030`, a reminder that the listener timeouts below still apply.

See [Backend timeout](/documentation/middleware/backend-timeout) for the full semantics.

The listener still closes a backend connection that sends nothing for 30 s ([`proxy.timeouts.backend_idle`](/documentation/configuration/overview#proxy)). A stream that can stay quiet longer than that needs either a keep-alive comment from the backend (a `: ping` line every 15–20 s, which most SSE libraries can send) or a higher `backend_idle` and `client_idle` (since 0.15).

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
