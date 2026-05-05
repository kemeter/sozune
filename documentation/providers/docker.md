# Docker labels

When run against the Docker provider, Sōzune discovers your services through container labels. Each label has the form:

```
sozune.<protocol>.<service>.<key>=<value>
```

Where `<service>` is your own identifier — it groups labels for the same logical service. Containers sharing the same `<service>` name are merged as backends of one cluster.

## Activation

| Label | Description |
|---|---|
| `sozune.enable=true` | Enables discovery for the container. Required unless `expose_by_default` is set on the Docker provider |
| `sozune.network=<name>` | Docker network used for routing (when the container is on multiple networks) |

## Routing — HTTP

| Label | Example | Reference |
|---|---|---|
| `sozune.http.<svc>.host` | `app.example.com` | [Hostnames](/documentation/routing/hostnames) |
| `sozune.http.<svc>.port` | `8080` | Backend port (defaults: 80 for `http`, 443 for `https`, 8080 for `tcp`/`udp`) |
| `sozune.http.<svc>.path` | `/api` | [Path matching](/documentation/routing/path-matching) |
| `sozune.http.<svc>.prefix` | `/api` | Alias for `path` |
| `sozune.http.<svc>.pathRegex` | `/users/[0-9]+` | [Path matching](/documentation/routing/path-matching) |
| `sozune.http.<svc>.priority` | `100` | Higher wins when multiple rules match (default `0`) |
| `sozune.http.<svc>.tls` | `true` | Enables TLS termination (provisions an ACME cert) |

## Middleware

| Label | Reference |
|---|---|
| `sozune.http.<svc>.auth.basic` | [Basic auth](/documentation/middleware/auth) |
| `sozune.http.<svc>.headers.<name>` | [Custom headers](/documentation/middleware/headers) — request-side by default |
| `sozune.http.<svc>.headers.response.<name>` | [Custom headers](/documentation/middleware/headers) — response-side |
| `sozune.http.<svc>.headers.both.<name>` | [Custom headers](/documentation/middleware/headers) — both directions |
| `sozune.http.<svc>.stripPrefix` | [Strip prefix](/documentation/middleware/strip-prefix) |
| `sozune.http.<svc>.addPrefix` | [Add prefix](/documentation/middleware/add-prefix) |
| `sozune.http.<svc>.httpsRedirect` | [Redirects](/documentation/middleware/redirects) |
| `sozune.http.<svc>.httpsRedirectPort` | [Redirects](/documentation/middleware/redirects) |
| `sozune.http.<svc>.redirect` | [Redirects](/documentation/middleware/redirects) |
| `sozune.http.<svc>.redirectScheme` | [Redirects](/documentation/middleware/redirects) |
| `sozune.http.<svc>.redirectTemplate` | [Redirects](/documentation/middleware/redirects) |
| `sozune.http.<svc>.wwwAuthenticate` | [Basic auth](/documentation/middleware/auth) |
| `sozune.http.<svc>.ratelimit.average` | [Rate limit](/documentation/middleware/rate-limit) |
| `sozune.http.<svc>.ratelimit.burst` | [Rate limit](/documentation/middleware/rate-limit) |
| `sozune.http.<svc>.compress` | [Response compression](/documentation/middleware/compress) (zstd, br, gzip) |
| `sozune.http.<svc>.backendTimeout` | [Backend timeout](/documentation/middleware/backend-timeout) |
| `sozune.http.<svc>.stickySession` | [Sticky sessions](/documentation/routing/load-balancing) |

## Routing — TCP

TCP routing requires a listener declared under `proxy.tcp` in the main config. Labels then attach a backend to that listener by name. See [TCP routing](/documentation/routing/tcp) for the full picture.

| Label | Example | Description |
|---|---|---|
| `sozune.tcp.<svc>.entrypoint` | `postgres` | Listener name declared under `proxy.tcp`. **Required.** |
| `sozune.tcp.<svc>.port` | `5432` | Backend port on the container. |
| `sozune.tcp.<svc>.priority` | `100` | Higher wins when multiple services share the same listener (default `0`). |

## Routing — UDP

> **Note:** UDP entrypoints are recognised at the label-parsing level but are not currently proxied — the Sōzu UDP worker integration is not yet wired in.

## Full example

```yaml
services:
  api:
    image: my-api
    labels:
      - "sozune.enable=true"
      - "sozune.http.api.host=api.example.com"
      - "sozune.http.api.port=8080"
      - "sozune.http.api.tls=true"
      - "sozune.http.api.httpsRedirect=true"
      - "sozune.http.api.path=/v1"
      - "sozune.http.api.stripPrefix=true"
      - "sozune.http.api.ratelimit.average=100"
      - "sozune.http.api.ratelimit.burst=50"
      - "sozune.http.api.headers.X-Powered-By=sozune"

  db:
    image: postgres:16
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.db.entrypoint=postgres"
      - "sozune.tcp.db.port=5432"
```
