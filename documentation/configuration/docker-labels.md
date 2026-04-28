# Docker labels

Sozune discovers your services through Docker container labels. Each label has the form:

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
| `sozune.http.<svc>.headers.<name>` | [Custom headers](/documentation/middleware/headers) |
| `sozune.http.<svc>.stripPrefix` | [Strip prefix](/documentation/middleware/strip-prefix) |
| `sozune.http.<svc>.httpsRedirect` | [HTTPS redirect](/documentation/middleware/https-redirect) |
| `sozune.http.<svc>.ratelimit.average` | [Rate limit](/documentation/middleware/rate-limit) |
| `sozune.http.<svc>.ratelimit.burst` | [Rate limit](/documentation/middleware/rate-limit) |
| `sozune.http.<svc>.compress` | [Gzip compression](/documentation/middleware/compress) |
| `sozune.http.<svc>.backendTimeout` | [Backend timeout](/documentation/middleware/backend-timeout) |
| `sozune.http.<svc>.stickySession` | [Sticky sessions](/documentation/routing/load-balancing) |

## Routing — TCP / UDP

| Label | Description |
|---|---|
| `sozune.tcp.<svc>.host` | Hostname for the TCP service |
| `sozune.tcp.<svc>.port` | Backend port |
| `sozune.udp.<svc>.host` | Hostname for the UDP service |
| `sozune.udp.<svc>.port` | Backend port |

> **Note:** TCP and UDP entrypoints are recognised at the label-parsing level but are not currently proxied (the Sōzu TCP worker integration is on the [roadmap](https://github.com/kemeter/sozune/blob/main/ROADMAP.md)).

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
```
