# Named middlewares

> Since 0.17

A route's middlewares are labels on the route itself (`sozune.http.<route>.compress=true`). When several routes share the same set, name it once and reference it: a named middleware is a set of route options, which the routes that reference it get. This is what Traefik's named middlewares and its `chain` do.

## Defining and referencing

A named middleware's options are route labels without their `sozune.<protocol>.<route>.` prefix. Define it on the workload itself:

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.middlewares.secure.headers.response.X-Frame-Options=DENY"
  - "sozune.middlewares.secure.headers.response.X-Content-Type-Options=nosniff"
  - "sozune.middlewares.api-limits.ratelimit.average=100"
  - "sozune.middlewares.api-limits.ratelimit.burst=50"
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.middlewares=secure,api-limits"
```

Or in static config, under `middlewares:`, where the routes of every label provider (Docker, Podman, Swarm, Nomad, Consul, Ring, and Kubernetes Ingress annotations) can reference it:

```yaml
middlewares:
  secure:
    headers.response.X-Frame-Options: DENY
    headers.response.X-Content-Type-Options: nosniff
  api-limits:
    ratelimit.average: 100
    ratelimit.burst: 50
```

| Label | Description |
|---|---|
| `sozune.http.<route>.middlewares` | The named middlewares the route gets, comma separated. Also on TCP and UDP routes, for the options they take. |
| `sozune.middlewares.<name>.<option>` | Defines middleware `<name>` on the workload, `<option>` being a route label without its prefix. |
| `sozune.middlewares.<name>.chain` | Brings middlewares into `<name>`, comma separated: Traefik's `chain`. |

## What wins

- **The route's own labels** win over its middlewares': a route referencing `secure` and setting `headers.response.X-Frame-Options=SAMEORIGIN` itself keeps `SAMEORIGIN`.
- **In the list**, a later middleware wins over an earlier one: with `middlewares=a,b`, an option both set takes `b`'s value.
- **In a chain**, the middleware's own options win over those of the middlewares it chains.
- **A definition on the workload** wins over one of the same name in static config.

A middleware applies to the routes of the workload that reference it: one workload's `sozune.middlewares.*` labels are not seen by another's routes. Share a middleware between workloads through static config.

## Errors

A route referencing a middleware that is defined nowhere, a chain that refers back to a middleware it is part of, or a middleware option that is no route option emits `W038`; that part is left out and the rest applies. An option's own value is checked as the route's label would be: `ratelimit.average=fast` in a middleware raises the route's rate limit diagnostic.

Static config's middlewares are read at startup: a change to them takes a restart.

## From Traefik

| Traefik | Sōzune |
|---|---|
| `routers.<r>.middlewares=a,b` | `sozune.http.<r>.middlewares=a,b` |
| `middlewares.<name>.<type>.<option>=v` | `sozune.middlewares.<name>.<option>=v`, the option named as the route label is: `headers.customresponseheaders.X-Foo=bar` is `headers.response.X-Foo=bar`. See [Migrating from Traefik](/documentation/getting-started/migrating-from-traefik#middlewares). |
| `middlewares.<name>.chain.middlewares=a,b` | `sozune.middlewares.<name>.chain=a,b` |
| `a@file`, a middleware of the file provider | A middleware of static config's `middlewares:`. |
| `a@docker` from another container | No equivalent: define it in static config. |
