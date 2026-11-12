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

A route that goes through the Sōzune middleware (headers, rate limit, auth, retry…) keeps its backends on h2c: the middleware streams bodies and passes the trailers, so gRPC calls and their streams work there too.

## Health checks

An [HTTP health check](/documentation/advanced/health-checks) of an h2c route is sent over h2c, with the check's path, status and headers. A TCP check is the same for both schemes.

`healthCheck.mode=grpc` calls the server's [gRPC health service](/documentation/advanced/health-checks#grpc-health-checks) instead, `grpc.health.v1.Health/Check`: the backend is healthy when it answers `SERVING`.

```yaml
labels:
  - "sozune.http.greeter.scheme=h2c"
  - "sozune.http.greeter.healthCheck.mode=grpc"
```

## What it does not do

- **No TLS to the backends.** `scheme=https` is refused (`W035`).
- **Errors in HTTP form.** When Sōzune answers a call itself (no backend, timeout, rate limit, auth), the client gets an HTTP status, not a `grpc-status`.
- **No gRPC-Web.**
