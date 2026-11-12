# gRPC and h2c backends

> Since 0.17

gRPC servers, and some HTTP servers, only speak HTTP/2. In cleartext that is h2c, with prior knowledge: the connection opens straight on HTTP/2, with no upgrade. Sōzune reaches a route's backends over HTTP/1.1 by default. `scheme=h2c` makes it speak h2c to them instead.

## Labels

```yaml
services:
  greeter:
    image: my/grpc-greeter:1.0
    labels:
      - "sozune.enable=true"
      - "sozune.http.greeter.host=grpc.example.com"
      - "sozune.http.greeter.port=50051"
      - "sozune.http.greeter.scheme=h2c"
```

| Label | Description |
|---|---|
| `scheme` | The protocol the route's backends speak: `http` (HTTP/1.1, the default) or `h2c`. Any other value emits `W035` and keeps HTTP/1.1. |

The label works the same on every label provider (Docker, Podman, Swarm, Nomad, Consul, Ring) and as a `sozune.scheme` annotation on a Kubernetes Ingress. A Kubernetes [GRPCRoute](/documentation/providers/kubernetes#gateway-api-grpcroute) needs no label: its backends are always reached over h2c.

In static YAML and through the [API](/documentation/configuration/api), set `h2c_backends` in the route's `config`:

```yaml
entrypoints:
  - id: greeter
    name: greeter
    protocol: Http
    backends:
      - address: 10.0.0.12
        port: 50051
    config:
      hostnames: ["grpc.example.com"]
      h2c_backends: true
```

## Clients

A gRPC client speaks HTTP/2 to Sōzune too:

- **Over HTTPS**, the listener offers `h2` in its ALPN by default (see [`proxy.https.http2`](/documentation/tls/overview#http2)).
- **In cleartext**, the HTTP port takes HTTP/2 with prior knowledge once [`proxy.http.h2c: true`](/documentation/configuration/overview) is set.

```bash
grpcurl -plaintext -authority grpc.example.com -d '{"greeting":"world"}' \
  sozune.local:80 hello.HelloService/SayHello
```

An HTTP/1.1 client still reaches an h2c backend: Sōzune speaks HTTP/1.1 to the client and HTTP/2 to the backend. That is not enough for gRPC itself, which needs HTTP/2 trailers end to end.

## With middleware

A route that goes through the Sōzune middleware (headers, rate limit, auth, retry…) keeps its backends on h2c: the middleware streams bodies and passes the trailers, so gRPC calls and their streams work there too. A gRPC call is never held to be [retried](/documentation/middleware/retry#notes): it is streamed to the backend, and goes on to the next one only when the backend could not be reached. A [WASM plugin](/documentation/middleware/wasm-plugins#limits) sees a gRPC call's headers and status, not its body.

## Health checks

An [HTTP health check](/documentation/advanced/health-checks) of an h2c route is sent over h2c, with the check's path, status and headers. A TCP check is the same for both schemes.

`healthCheck.mode=grpc` calls the server's [gRPC health service](/documentation/advanced/health-checks#grpc-health-checks) instead, `grpc.health.v1.Health/Check`: the backend is healthy when it answers `SERVING`.

```yaml
labels:
  - "sozune.http.greeter.scheme=h2c"
  - "sozune.http.greeter.healthCheck.mode=grpc"
```

## Errors

> Since 0.17

When the Sōzune middleware (rate limit, auth, retry…) answers a gRPC call itself (a request with `content-type: application/grpc`), it answers the way a gRPC server would: HTTP `200`, `content-type: application/grpc`, no body, and the outcome in `grpc-status` and `grpc-message`. The message names the reason, as the `x-sozune-diagnostic` header does for an HTTP client:

```
ERROR:
  Code: Unavailable
  Message: sozune: backend-unreachable (HTTP 502)
```

| The middleware answers | `grpc-status` |
|---|---|
| No backend, circuit breaker open, backend unreachable (`502`, `503`) | `UNAVAILABLE` (14) |
| Backend or request timeout (`504`) | `DEADLINE_EXCEEDED` (4) |
| Rate limit, in-flight limit (`429`) | `RESOURCE_EXHAUSTED` (8) |
| Basic or forward auth refused (`401`) | `UNAUTHENTICATED` (16) |
| IP allow-list, forward auth forbidden (`403`) | `PERMISSION_DENIED` (7) |
| No route matches the call (`404`) | `UNIMPLEMENTED` (12) |
| Internal error (`400`, `500`) | `INTERNAL` (13) |
| Any other error | `UNKNOWN` (2) |

The codes follow the mapping gRPC clients apply to an HTTP status, except for a timeout and a limit: `DEADLINE_EXCEEDED` and `RESOURCE_EXHAUSTED` are not retried by a client's retry policy, where `UNAVAILABLE` is. A redirect, or an answer that already carries a `grpc-status` (a [WASM plugin](/documentation/middleware/wasm-plugins)'s), is left as it is, and a route's [error page](/documentation/middleware/error-pages#backend-errors) does not replace a gRPC answer.

A call the backend answered that fails mid-way ends with a status in its trailers rather than a reset stream: `DEADLINE_EXCEEDED` when the route's [`backendTimeout`](/documentation/middleware/backend-timeout) or request timeout cuts it, `UNAVAILABLE` when the backend goes away.

The answers Sōzu gives itself, before the middleware or on a route without it (no route for the host, no backend, a backend timeout), stay HTTP errors: Sōzu cannot answer `200`. gRPC clients read those with the same mapping (`503` gives `UNAVAILABLE`, `404` `UNIMPLEMENTED`), with an `unexpected HTTP status code` message.

## gRPC-Web

> Since 0.17

Browsers cannot speak gRPC: they cannot read HTTP trailers, where gRPC puts a call's status. A web page calls through [gRPC-Web](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md) instead (grpc-web, Connect, and other browser clients), over HTTP/1.1 or HTTP/2. `grpcWeb` makes Sōzune translate those calls into gRPC for the backends, and their answers back. The backend is a plain gRPC server.

```yaml
labels:
  - "sozune.http.greeter.host=api.example.com"
  - "sozune.http.greeter.port=50051"
  - "sozune.http.greeter.grpcWeb.allowOrigins=https://app.example.com"
```

| Label | Description |
|---|---|
| `grpcWeb` | `true` translates the gRPC-Web calls of the pages of the route's own origin. |
| `grpcWeb.allowOrigins` | The other origins whose pages may call the route, comma separated, `*` for any. It turns `grpcWeb` on. An explicit `grpcWeb=false` turns it off whatever the origins. |

- **The backends are reached over h2c**, whatever `scheme` says: gRPC needs HTTP/2.
- **A call is told by its content type**, `application/grpc-web` or `application/grpc-web-text` (base64), with `+proto` or another format kept for the backend. A plain gRPC client can keep calling the same route: its calls go through as they are.
- **The answer's trailers** (its `grpc-status` and `grpc-message`) come as the last message of its body, as gRPC-Web clients read them. An answer of the `-text` kind is base64 too.
- **Errors**: when the middleware answers a gRPC-Web call itself, it answers in gRPC-Web form, the status in the headers (see [Errors](#errors)).
- **CORS**: with `allowOrigins`, the route answers the preflight requests of those origins, letting them send `POST` with `content-type`, `x-grpc-web`, `x-user-agent` and `grpc-timeout`, and read `grpc-status` and `grpc-message`. A route's own [CORS policy](/documentation/middleware/cors) is kept and completed.

In static YAML and through the [API](/documentation/configuration/api), set `grpc_web` in the route's `config`, with `h2c_backends: true`:

```yaml
config:
  hostnames: ["api.example.com"]
  h2c_backends: true
  grpc_web:
    allow_origins: ["https://app.example.com"]
```

## What it does not do

- **No TLS to the backends.** `scheme=https` is refused (`W035`).
- **Sōzu's own errors stay in HTTP form.** See [Errors](#errors).
