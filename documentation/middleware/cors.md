# CORS

> Since 0.17 (labels); since 0.16 through the API, static config and the Gateway API

Lets the pages of other origins call a route from a browser. Sōzune answers their preflight requests itself and marks the responses they get, whatever answered them, so the backend needs no CORS code of its own.

## Labels

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.cors.allowOrigins=https://app.example.com,https://*.example.org"
  - "sozune.http.api.cors.allowMethods=GET,POST"
  - "sozune.http.api.cors.allowHeaders=x-request-id"
  - "sozune.http.api.cors.exposeHeaders=x-total-count"
  - "sozune.http.api.cors.allowCredentials=true"
  - "sozune.http.api.cors.maxAge=3600"
```

| Label | Traefik's name (also read) | Description |
|---|---|---|
| `cors.allowOrigins` | `headers.accessControlAllowOriginList` | The origins whose pages may call the route, comma separated. Required. |
| `cors.allowMethods` | `headers.accessControlAllowMethods` | The methods they may use, `*` for any. |
| `cors.allowHeaders` | `headers.accessControlAllowHeaders` | The request headers they may send, `*` for any. |
| `cors.exposeHeaders` | `headers.accessControlExposeHeaders` | The response headers they may read beyond the safelisted ones, `*` for all. |
| `cors.allowCredentials` | `headers.accessControlAllowCredentials` | `true` lets the requests carry cookies or credentials. |
| `cors.maxAge` | `headers.accessControlMaxAge` | Seconds a browser may cache a preflight answer; `5` when unset. |

Traefik's names come from its `headers` middleware: copied as they are, they make the same policy, and they are not sent as headers. `headers.addVaryHeader` is accepted too: Sōzune always sends `Vary: Origin`. `headers.accessControlAllowOriginListRegex` has no equivalent and is dropped with `W036`: list the origins instead, a `*.` host standing for the names below it.

A value that is not an origin, a `maxAge` that is not a number or an `allowCredentials` that is neither `true` nor `false` is dropped with `W036`; a policy left with no origin is dropped whole. The labels work on every label provider and as `sozune.cors.*` annotations on a Kubernetes Ingress.

## Origins

- An origin is `scheme://host[:port]`, compared without case, a missing port being the scheme's default.
- `*` allows any origin, the `null` of a sandboxed page included.
- `https://*` allows any host over HTTPS on port 443.
- `https://*.example.org` allows any name below `example.org` (`app.example.org`, `a.b.example.org`), not `example.org` itself.

## What it does

- A preflight request (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) from an allowed origin is answered `204` by Sōzune, the backend never seeing it, with the `Access-Control-Allow-*` headers and `Access-Control-Max-Age`. It is answered before any authentication the route has: browsers send it without credentials.
- Any other request from an allowed origin goes to the backend, and its response gets `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` when credentials are allowed, and `Access-Control-Expose-Headers`. An error Sōzune answers itself (a failed authentication, an unreachable backend) is marked too, so the page can read it.
- A preflight from any other origin is answered `204` without them, so the browser refuses the request it asks about; any other request from such an origin, or with no `Origin`, goes to the backend and gets no CORS header.
- `*` in `allowMethods` or `allowHeaders` allows any; `Authorization`, which browsers want named, is added next to it when a preflight asks for it. With credentials allowed, browsers read `*` literally, so Sōzune answers with the method and headers the preflight asks for instead, with the request's own origin rather than `*`, and, for `*` in `exposeHeaders`, with the names of the headers the response carries.
- The policy is the route's alone: the backend's own `Access-Control-*` headers are replaced, or removed for an origin the policy does not allow. Every response carries `Vary: Origin`, so a cache does not serve one origin's answer to another.

A route with a CORS policy goes through the Sōzune middleware. For [gRPC-Web](/documentation/routing/grpc#grpc-web), `grpcWeb.allowOrigins` completes the policy with the headers gRPC-Web pages need.

## REST / YAML surface

In static YAML and through the [API](/documentation/configuration/api), set `cors` in the route's `config`:

```yaml
config:
  hostnames: ["api.example.com"]
  cors:
    allow_origins: ["https://app.example.com"]
    allow_methods: ["GET", "POST"]
    allow_headers: ["x-request-id"]
    expose_headers: ["x-total-count"]
    allow_credentials: true
    max_age: 3600
```

On Kubernetes, the Gateway API [`cors` filter](/documentation/providers/kubernetes#httproute-filters) of an HTTPRoute sets the same policy.
