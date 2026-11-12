# Migrating from Traefik

Sōzune reads the same kind of container labels as Traefik, with a flatter shape. This page maps the Traefik labels you most likely use to their Sōzune equivalent.

## The model in one example

Traefik splits a route into a router, a service and named middlewares, linked by name:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.api.rule=Host(`api.example.com`) && PathPrefix(`/v1`)"
  - "traefik.http.routers.api.entrypoints=websecure"
  - "traefik.http.routers.api.tls.certresolver=letsencrypt"
  - "traefik.http.routers.api.middlewares=api-strip,api-ratelimit"
  - "traefik.http.middlewares.api-strip.stripprefix.prefixes=/v1"
  - "traefik.http.middlewares.api-ratelimit.ratelimit.average=100"
  - "traefik.http.middlewares.api-ratelimit.ratelimit.burst=50"
  - "traefik.http.services.api.loadbalancer.server.port=8080"
```

Sōzune has one level: every setting of a route sits under `sozune.http.<svc>.`, middlewares included.

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.path=/v1"
  - "sozune.http.api.tls=true"
  - "sozune.http.api.acme.resolver=letsencrypt"
  - "sozune.http.api.httpsRedirect=true"
  - "sozune.http.api.stripPrefix=true"
  - "sozune.http.api.ratelimit.average=100"
  - "sozune.http.api.ratelimit.burst=50"
  - "sozune.http.api.port=8080"
```

No rule language, no middleware names to keep in sync, no entrypoint to pick for plain HTTP or HTTPS routes. The `letsencrypt` resolver has to be declared under [`acme.resolvers`](/documentation/tls/acme) in Sōzune's config, like the Traefik certificate resolver in its static config.

## Discovery

| Traefik | Sōzune |
|---|---|
| `traefik.enable=true` | `sozune.enable=true` |
| `traefik.docker.network=<name>` | `sozune.network=<name>` |
| `providers.docker.exposedByDefault` | `expose_by_default` on the provider. Traefik defaults to `true`, Sōzune to `false`: add `sozune.enable=true` to every container to expose. |
| KV providers (etcd, Redis) | The [key-value providers](/documentation/providers/key-value) read Sōzune labels, not Traefik's dynamic configuration (`traefik/http/routers/<name>/rule`…). Write each service's labels and servers instead: a router whose rule is ``Host(`app.example.com`)`` becomes `sozune/<service>/labels/sozune.http.app.host = app.example.com`, and its `loadBalancer.servers[n].url` the `sozune/<service>/servers/<n>` keys. |

## Router rules

A Traefik rule becomes one label per matcher. All the matchers of a route must match.

| Traefik matcher | Sōzune label |
|---|---|
| ``Host(`a.example.com`)`` | `host=a.example.com` |
| ``Host(`a.example.com`) \|\| Host(`b.example.com`)`` | `host=a.example.com,b.example.com` |
| ``HostRegexp(`^[^.]+\.example\.com$`)`` | `host=*.example.com` |
| ``HostRegexp(`^cdn[0-9]+\.example\.com$`)`` | `host=/cdn[0-9]+/.example.com`: the regex goes between slashes, and the domain at the end stays written out. A regex that would match any domain is refused. See [Regex hostnames](/documentation/routing/hostnames#regex). |
| ``PathPrefix(`/api`)`` | `path=/api`. Sōzune matches on segment boundaries: `/api` serves `/api/users` but not `/apiv2`, which Traefik's `PathPrefix` does. `pathRegex=^/api` keeps that broader match, but `stripPrefix` only applies to `path`. |
| ``PathRegexp(`^/users/[0-9]+`)`` | `pathRegex=^/users/[0-9]+`. Keep the `^`: without it, the regex can match anywhere in the path or in its query string. |
| ``Path(`/exact`)`` | No label. Exact paths are available through the [HTTP provider, the file provider and the API](/documentation/routing/path-matching#exact), and from a Kubernetes `Exact` path. |
| ``Method(`GET`)`` | `methods=GET` (comma-separated for several) |
| ``Header(`X-Api-Version`, `2`)`` | `matchHeaders=X-Api-Version:2` (see the note below) |
| ``Query(`beta`, `1`)`` | `matchQuery=beta:1` (see the note below) |
| ``HeaderRegexp(`X-Version`, `^v[0-9]+$`)`` | `matchHeadersRegex.X-Version=v[0-9]+`. The regex matches the whole value, where Traefik's matches anywhere in it: write `.*v[0-9]+.*` to keep that. See [Regular expressions](/documentation/routing/header-query-matching#regular-expressions). (since 0.16) |
| ``QueryRegexp(`page`, `^[0-9]+$`)`` | `matchQueryRegex.page=[0-9]+`, likewise. (since 0.16) |
| ``ClientIP(`10.0.0.0/8`)`` | `matchClientIP=10.0.0.0/8` (see the note below) |
| `routers.<r>.priority` | `priority`. Traefik ranks routes by rule length when no priority is set. At equal priority, Sōzune tries the more specific route first: exact hostname, then regex, then wildcard (longer first); exact path, then longer prefix; a route on `methods` before one on any method; more `matchHeaders` conditions first; earlier releases took the first route by id (since 0.16). Set `priority` when that order is not the one you want. See [Priority](/documentation/routing/hostnames#priority). |

`matchHeaders` chooses between routes, as `Header()` does: two routers on the same host and path that differ only by a header translate one to one, and a request without the header goes to the other route. A route whose header conditions hold comes before every route without any, whatever their priority. (since 0.16)

`matchQuery` chooses between routes too, as `Query()` does, for up to three conditions on a route without `pathRegex`, `stripPrefix` or `addPrefix` (since 0.16). `matchClientIP` filters a route, it does not choose between routes: Sōzune picks the route, then answers `404` when the client IP is not listed, without trying another route. Two Traefik routers on the same host and path that differ only by a client IP need distinct paths in Sōzune. See [Header & query matching](/documentation/routing/header-query-matching).

A rule that mixes `||` across different matcher types has no single-route equivalent: declare one service per alternative. Each of them needs a `host`, so an alternative on a path alone, on any host, cannot be expressed with labels.

## TLS and certificates

| Traefik | Sōzune |
|---|---|
| `routers.<r>.tls=true` | `tls=true` |
| `routers.<r>.tls.certresolver=<name>` | `tls=true` and `acme.resolver=<name>`. Resolvers are declared under [`acme.resolvers`](/documentation/tls/acme); without `acme.resolver`, the certificate is issued over HTTP-01. |
| `routers.<r>.entrypoints=web,websecure` | Nothing: HTTP and HTTPS listeners are global. |
| `routers.<r>.entrypoints=websecure` (HTTPS only) | `tls=true` and `httpsRedirect=true`. A `tls=true` route is still served over plain HTTP; the redirect sends those requests to HTTPS. |
| `redirectscheme.scheme=https` | `httpsRedirect=true` ([Redirects](/documentation/middleware/redirects)) |
| `redirectscheme.port=8443` | `httpsRedirectPort=8443` |
| Certificates from files (`tls.certificates`) | [`proxy.https.tls.certificates`](/documentation/tls/overview#certificates-from-files) |
| `certificatesresolvers.<name>.acme.dnsChallenge.provider=cloudflare` | `acme.resolvers.<name>.provider: cloudflare` ([Providers](/documentation/tls/acme#providers), since 0.17). The provider reads lego's variable names, so the environment of a Traefik setup works as it is. |

## Service

| Traefik | Sōzune |
|---|---|
| `services.<s>.loadbalancer.server.port` | `port` |
| `services.<s>.loadbalancer.sticky.cookie=true` | `stickySession=true` |
| `services.<s>.loadbalancer.server.scheme=h2c` | `scheme=h2c` ([gRPC and h2c backends](/documentation/routing/grpc), since 0.17). `https` has no equivalent. |
| `services.<s>.loadbalancer.healthcheck.path` | `healthCheck.path`. A backend that fails it leaves the rotation, unless every backend of the route does (since 0.16). See [Health checks](/documentation/advanced/health-checks). |
| `services.<s>.loadbalancer.healthcheck.timeout=2s` | `healthCheck.timeout=2000` (milliseconds) |
| `services.<s>.loadbalancer.healthcheck.interval=5s` | `healthCheck.interval=5000` (milliseconds) (since 0.16) |
| `services.<s>.loadbalancer.healthcheck.port` | `healthCheck.port` (since 0.16) |
| `services.<s>.loadbalancer.healthcheck.headers.<Name>` | `healthCheck.headers.<Name>` (since 0.16) |
| `services.<s>.loadbalancer.healthcheck.mode=grpc` | `healthCheck.mode=grpc`, with `healthCheck.service` for the service name (since 0.17). See [gRPC health checks](/documentation/advanced/health-checks#grpc-health-checks). |
| `services.<s>.loadbalancer.healthcheck.unhealthyInterval`, `followRedirects`, `scheme`, `hostname`, `method` | No equivalent. Thresholds instead: `healthCheck.unhealthyThreshold` / `healthyThreshold` (since 0.16). |
| `serverstransport.forwardingtimeouts.responseheadertimeout=2s` | `backendTimeout=2000` (milliseconds). It caps the whole response, not only the wait for its headers: leave room for a long or streamed body. |

Containers that declare the same `<svc>` name with the same hosts and paths are merged as backends of one route, like replicas of a Traefik service. If their hosts or paths differ, the later container gets a route of its own instead.

## Middlewares

In Sōzune, a middleware is a label on the route itself. A set of them can also be named and referenced by several routes, with `middlewares=a,b` and `sozune.middlewares.<name>.*` labels or static config's `middlewares:`: see [Named middlewares](/documentation/middleware/named-middlewares) (since 0.17).

| Traefik middleware | Sōzune label |
|---|---|
| `stripprefix.prefixes=/api` on a router with ``PathPrefix(`/api`)`` | `path=/api` + `stripPrefix=true`. `stripPrefix` removes the route's own `path`: a router that strips a prefix it does not match on has no equivalent. |
| `addprefix.prefix=/foo` | `addPrefix=/foo` |
| `replacepath.path=/foo` | `replacePath=/foo` (since 0.17) |
| `replacepathregex.regex` / `replacepathregex.replacement` | `replacePathRegex.regex` / `replacePathRegex.replacement` (since 0.17). They apply after `stripPrefix` and `addPrefix`, whatever the order of a Traefik chain. |
| `redirectregex.regex` / `.replacement` / `.permanent` | `redirectRegex.regex` / `.replacement` / `.permanent` (since 0.17) |
| `headers.customrequestheaders.X-Foo=bar` | `headers.X-Foo=bar` |
| `headers.customresponseheaders.X-Foo=bar` | `headers.response.X-Foo=bar` |
| `headers.accessControlAllowOriginList`, `accessControlAllowMethods`, `accessControlAllowHeaders`, `accessControlExposeHeaders`, `accessControlAllowCredentials`, `accessControlMaxAge` | The same labels, or `cors.allowOrigins`, `cors.allowMethods`… ([CORS](/documentation/middleware/cors), since 0.17). `accessControlAllowOriginListRegex` has no equivalent: list the origins, `https://*.example.com` for the names below a domain. |
| Empty header value (removes the header) | Same: `headers.X-Foo=` |
| `basicauth.users=user:$$apr1$$...` | `auth.basic=user:<sha256-hex>`. Sōzune does not read htpasswd hashes: [rehash each password](/documentation/middleware/auth) in SHA-256. |
| `basicauth.realm` | `wwwAuthenticate` |
| `forwardauth.address` | `forwardAuth.address` |
| `forwardauth.authResponseHeaders` | `forwardAuth.responseHeaders` |
| `forwardauth.trustForwardHeader` | `forwardAuth.trustForwardHeader` |
| `ratelimit.average` / `ratelimit.burst` | `ratelimit.average` / `ratelimit.burst` (requests per second, per client IP). Without `burst`, Traefik allows a burst of 1 and Sōzune a burst equal to `average`: set `ratelimit.burst` to keep the Traefik behaviour. |
| `inflightreq.amount` | `inFlightReq`, counted per client IP. Traefik groups by request host by default, which caps the whole route; Sōzune has no route-wide cap. |
| `ipallowlist.sourcerange` | `ipAllowList` |
| `compress=true` | `compress=true` |
| `buffering.maxRequestBodyBytes`, `buffering.maxResponseBodyBytes` | The same labels ([Buffering](/documentation/middleware/buffering), since 0.17). `memRequestBodyBytes` and `memResponseBodyBytes` have no equivalent (the body stays in memory, up to the max), nor has `retryExpression` (use `retry.*`). |
| `grpcweb.allowOrigins=https://app.example` | `grpcWeb.allowOrigins=https://app.example`, or `grpcWeb=true` for pages of the route's own origin ([gRPC-Web](/documentation/routing/grpc#grpc-web), since 0.17). The backends are reached over h2c. |
| `retry.attempts` | `retry.attempts` |
| `circuitbreaker.expression` | `circuitBreaker.threshold`, `circuitBreaker.minRequests`, `circuitBreaker.cooldown`. Sōzune trips on an error rate, not on an expression: see [Circuit breaker](/documentation/middleware/circuit-breaker). |
| `errors.status` + `errors.service` + `errors.query` | `errors.status`, and `errors.url` for the service and query together (`http://error-pages/{status}.html?from={url}`), or `errors.page` for an inline page: see [Backend errors](/documentation/middleware/error-pages#backend-errors). |
| Traefik plugins | [WASM plugins](/documentation/middleware/wasm-plugins). Traefik's Yaegi plugins do not run as is. |
| `routers.<r>.middlewares=a,b` | `sozune.http.<r>.middlewares=a,b` ([Named middlewares](/documentation/middleware/named-middlewares), since 0.17) |
| `middlewares.<name>.<type>.<option>=v` | `sozune.middlewares.<name>.<option>=v`, the option named as the route label is: `headers.customresponseheaders.X-Foo=bar` is `headers.response.X-Foo=bar`. |
| `middlewares.<name>.chain.middlewares=a,b` | `sozune.middlewares.<name>.chain=a,b` |
| `a@file`, a middleware of the file provider | A middleware of static config's `middlewares:`. |
| `a@docker` from another container | No equivalent: define it in static config. |

Not available yet: `digestauth`. `chain` is a named middleware's `chain` option: see [Named middlewares](/documentation/middleware/named-middlewares) (since 0.17). A `mirroring` service is written with a `mirrorOf` label on the mirror: see [Mirroring](/documentation/routing/mirroring) (since 0.16). A `weighted` service, a split between two versions, is written with a `serviceWeight` on the containers of each service, which their replicas share whatever their number: see [Weighted load balancing](/documentation/routing/load-balancing#service-weights) (since 0.17).

## TCP

| Traefik | Sōzune |
|---|---|
| A TCP entrypoint in the static config | A listener under [`proxy.tcp`](/documentation/routing/tcp) |
| `tcp.routers.<r>.entrypoints=postgres` | `sozune.tcp.<svc>.entrypoint=postgres` |
| ``tcp.routers.<r>.rule=HostSNI(`*`)`` | Don't set `sni`: without it, the listener sends every connection to its service. |
| ``tcp.routers.<r>.rule=HostSNI(`a.example.com`)`` + `tls.passthrough=true` | `sozune.tcp.<svc>.sni=a.example.com` |
| `tcp.services.<s>.loadbalancer.server.port` | `sozune.tcp.<svc>.port` |

## Check the result

Once the labels are rewritten, `sozune validate` reads them without starting the proxy and reports every unknown or invalid label, with a suggestion for typos. On a running instance, the dashboard's Diagnostics page shows the same, and `sozune route <url>` tells you which route a request reaches and why.
