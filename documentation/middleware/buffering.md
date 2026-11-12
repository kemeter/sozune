# Buffering

> Since 0.17

Reads a route's request bodies, its responses, or both, whole before passing them on, within a size. The backend gets an upload at once rather than at the client's pace, and never a body larger than it should; a client never gets a response larger than the route allows. This is Traefik's `buffering` middleware.

## Labels

```yaml
labels:
  - "sozune.http.upload.host=upload.example.com"
  - "sozune.http.upload.buffering.maxRequestBodyBytes=10485760"
  - "sozune.http.upload.buffering.maxResponseBodyBytes=2097152"
```

| Label | Description |
|---|---|
| `buffering.maxRequestBodyBytes` | The request body is read whole before the backend gets it, up to this many bytes. A larger one is answered `413`. |
| `buffering.maxResponseBodyBytes` | The response body is read whole before the client gets it, up to this many bytes. A larger one is answered `500`, as Traefik does. |

Each is optional: a route can buffer its requests alone, or its responses alone. A size that is not a positive number of bytes is dropped with `W037`, and that body is not buffered.

Traefik's `memRequestBodyBytes` and `memResponseBodyBytes`, the size past which it spills a body to disk, have no equivalent: Sōzune keeps the body in memory, up to the max, so choose the max with the memory of the concurrent requests in mind. Traefik's `retryExpression` has none either: use [`retry`](/documentation/middleware/retry). Both emit `W037`.

## What it does

- A request whose `Content-Length` is past the limit is answered `413` at once, before its body is read. Without a length (a chunked upload), the body is read until it passes the limit, then answered `413`. In both cases the backend never sees it. The answer carries `x-sozune-diagnostic: request-too-large`.
- A request read whole can be [retried](/documentation/middleware/retry), whatever its size within the limit: the 1 MiB the route keeps otherwise does not apply.
- A response whose `Content-Length` is past the limit is answered `500` at once; otherwise its body is read until it passes the limit. The answer carries `x-sozune-diagnostic: response-too-large`. A response read whole keeps its status and headers.
- A response body cut short by the route's [backend timeout](/documentation/middleware/backend-timeout) while it is read is answered `504`.
- A gRPC call (`content-type: application/grpc`) and a WebSocket upgrade are never buffered: their bodies stream for as long as they last. A [gRPC](/documentation/routing/grpc) answer is not either.
- Response buffering holds a streamed response (server-sent events, a long download) until it ends: keep it off routes that stream.

A route that buffers goes through the Sōzune middleware.

## REST / YAML surface

In static YAML and through the [API](/documentation/configuration/api), set `buffering` in the route's `config`:

```yaml
config:
  hostnames: ["upload.example.com"]
  buffering:
    max_request_body_bytes: 10485760
    max_response_body_bytes: 2097152
```
