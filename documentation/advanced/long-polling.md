# Long-polling

HTTP long-polling is the pattern where the client sends a request and the server holds it open — sometimes for tens of seconds — until new data is available or a server-side timeout fires. It is **not** Server-Sent Events (no `text/event-stream`) and **not** WebSocket (no `Upgrade` handshake). To Sōzune it looks like a perfectly ordinary HTTP request that happens to take a very long time to respond.

## The trap

The default backend timeout is 30 seconds. If your client asks the server to hold the connection for 30 s and the server takes a moment to respond, Sōzune cuts the connection just before the response comes back. From the client's point of view, the request fails with a reset and the long-poll loop starts again — no real-time updates ever land.

This shows up in access logs as `H2::ResetFrame` or a 504 around the timeout boundary, with the request method/path matching a known long-poll endpoint.

## The fix

Raise `backendTimeout` past the longest poll your client will request, with a small safety margin:

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.backendTimeout=60"
```

Or use the file provider if you can't add labels (e.g. existing containers you can't recreate):

```yaml
entrypoints:
  - id: file_app
    name: app
    protocol: Http
    backends:
      - address: "172.20.0.4"
        port: 8008
    config:
      hostnames:
        - app.example.com
      tls: true
      strip_prefix: false
      priority: 0
      backend_timeout: 60
```

You can also set `backendTimeout=0` (no timeout) if you don't want to think about it, but a finite cap is safer in production — a stuck backend won't pin a worker forever.

## Matrix / Synapse

Matrix clients (Element, FluffyChat, etc.) call `GET /_matrix/client/v3/sync?timeout=30000` in a loop. Synapse holds the request for up to 30 s waiting for new events. With the default `backendTimeout=30`, the cut happens right around the same time the server is about to respond, so you get a continuous stream of resets and the user sees missed messages and reconnect spinners.

Set `backendTimeout=60` (or `0`) on the Synapse entrypoint and the syncs land cleanly:

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.http.synapse.host=matrix.example.com"
  - "sozune.http.synapse.port=8008"
  - "sozune.http.synapse.tls=true"
  - "sozune.http.synapse.backendTimeout=60"
```

The Element web client itself does not long-poll (it talks to Synapse, which does), so it works fine with the default. Only the Synapse entrypoint needs the higher timeout.

## Other long-polling protocols

The same pattern applies to:

- **CometD / Bayeux** (`/cometd/connect`)
- **gRPC server-streaming over HTTP** (the stream does not use `Upgrade`, so it goes through the normal HTTP path)
- **Custom JSON long-poll endpoints** — anything where the client passes a `timeout` parameter expecting the server to hold the request

Look for client-driven `timeout` parameters in query strings or hold patterns longer than a few seconds in your access logs. Set `backendTimeout` accordingly.

## Why not always raise the default

A high default timeout would mask real backend problems. A backend stuck on a database deadlock should be cut after 30 s so the worker frees up — not held for a minute waiting for something that will never arrive. Long-polling is a deliberate pattern, opted into per route.
