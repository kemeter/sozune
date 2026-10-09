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

## Router rules

A Traefik rule becomes one label per matcher. All the matchers of a route must match.

| Traefik matcher | Sōzune label |
|---|---|
| ``Host(`a.example.com`)`` | `host=a.example.com` |
| ``Host(`a.example.com`) \|\| Host(`b.example.com`)`` | `host=a.example.com,b.example.com` |
| ``HostRegexp(`^[^.]+\.example\.com$`)`` | `host=*.example.com`. A wildcard covers exactly one label; other patterns need a [regex hostname](/documentation/routing/hostnames#regex), written label by label. |
| ``PathPrefix(`/api`)`` | `path=/api`. Sōzune matches on segment boundaries: `/api` serves `/api/users` but not `/apiv2`, which Traefik's `PathPrefix` does. `pathRegex=^/api` keeps that broader match, but `stripPrefix` only applies to `path`. |
| ``PathRegexp(`^/users/[0-9]+`)`` | `pathRegex=^/users/[0-9]+`. Keep the `^`: without it, the regex can match anywhere in the path. |
| ``Path(`/exact`)`` | Exact paths are only available through the [HTTP provider and the API](/documentation/routing/path-matching) |
| ``Method(`GET`)`` | `methods=GET` (comma-separated for several) |
| ``Header(`X-Api-Version`, `2`)`` | `matchHeaders=X-Api-Version:2` (see the note below) |
| ``Query(`beta`, `1`)`` | `matchQuery=beta:1` (see the note below) |
| ``ClientIP(`10.0.0.0/8`)`` | `matchClientIP=10.0.0.0/8` (see the note below) |
| `routers.<r>.priority` | `priority`. Traefik ranks routes by rule length when no priority is set. Sōzune does not: at equal priority, the first route by id wins, even over a longer path. Set `priority` on the more specific route when two routes overlap. |

`matchHeaders`, `matchQuery` and `matchClientIP` filter a route, they do not choose between routes. Sōzune picks the route on host, path and method, then answers `404` when one of these conditions fails, without trying another route. Two Traefik routers on the same host and path that differ only by a header, a query parameter or a client IP need distinct paths in Sōzune. See [Header & query matching](/documentation/routing/header-query-matching).

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

## Service

| Traefik | Sōzune |
|---|---|
| `services.<s>.loadbalancer.server.port` | `port` |
| `services.<s>.loadbalancer.sticky.cookie=true` | `stickySession=true` |
| `services.<s>.loadbalancer.healthcheck.path` | `healthCheck.path` |
| `services.<s>.loadbalancer.healthcheck.timeout=2s` | `healthCheck.timeout=2000` (milliseconds) |
| `serverstransport.forwardingtimeouts.responseheadertimeout=2s` | `backendTimeout=2000` (milliseconds). It caps the whole response, not only the wait for its headers: leave room for a long or streamed body. |

Containers that declare the same `<svc>` name with the same hosts and paths are merged as backends of one route, like replicas of a Traefik service. If their hosts or paths differ, the later container gets a route of its own instead.

## Middlewares

In Sōzune, a middleware is a label on the route itself: there is no `middlewares=` list and no shared middleware definition.

| Traefik middleware | Sōzune label |
|---|---|
| `stripprefix.prefixes=/api` on a router with ``PathPrefix(`/api`)`` | `path=/api` + `stripPrefix=true`. `stripPrefix` removes the route's own `path`: a router that strips a prefix it does not match on has no equivalent. |
| `addprefix.prefix=/foo` | `addPrefix=/foo` |
| `headers.customrequestheaders.X-Foo=bar` | `headers.X-Foo=bar` |
| `headers.customresponseheaders.X-Foo=bar` | `headers.response.X-Foo=bar` |
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
| `retry.attempts` | `retry.attempts` |
| `circuitbreaker.expression` | `circuitBreaker.threshold`, `circuitBreaker.minRequests`, `circuitBreaker.cooldown`. Sōzune trips on an error rate, not on an expression: see [Circuit breaker](/documentation/middleware/circuit-breaker). |
| `errors.status` + `errors.service` | No equivalent for errors returned by the backend. `errorPages.<status>=<html>` only replaces the errors Sōzune answers itself (no route, backend down…), with an inline page. |
| Traefik plugins | [WASM plugins](/documentation/middleware/wasm-plugins). Traefik's Yaegi plugins do not run as is. |

Not available yet: `chain`, `digestauth`, `buffering`, `redirectregex`, `replacepath`, `replacepathregex`, mirroring and weighted services.

## TCP

| Traefik | Sōzune |
|---|---|
| A TCP entrypoint in the static config | A listener under [`proxy.tcp`](/documentation/routing/tcp) |
| `tcp.routers.<r>.entrypoints=postgres` | `sozune.tcp.<svc>.entrypoint=postgres` |
| ``tcp.routers.<r>.rule=HostSNI(`*`)`` | Nothing: the listener's single backend takes every connection. |
| ``tcp.routers.<r>.rule=HostSNI(`a.example.com`)`` + `tls.passthrough=true` | `sozune.tcp.<svc>.sni=a.example.com` |
| `tcp.services.<s>.loadbalancer.server.port` | `sozune.tcp.<svc>.port` |

## Check the result

Once the labels are rewritten, `sozune validate` reads them without starting the proxy and reports every unknown or invalid label, with a suggestion for typos. On a running instance, the dashboard's Diagnostics page shows the same, and `sozune route <url>` tells you which route a request reaches and why.
