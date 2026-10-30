# Header & query matching

> Since 0.14

Scope a route to requests that carry specific headers or query parameters, on top of the usual host/path matching. Use it to route by API version (`X-Api-Version: 2`), gate a canary on a header, or split traffic on a query flag.

## Labels

```yaml
labels:
  - "sozune.http.<svc>.matchHeaders=<key>:<value>,<key2>:<value2>"
  - "sozune.http.<svc>.matchQuery=<key>:<value>,..."
```

| Label | Description |
|---|---|
| `matchHeaders` | Comma-separated `key:value` conditions on request headers. A request matches only if **every** listed header is present (and equals the value, when given). |
| `matchQuery` | Same, against the request's query-string parameters. |

An entry without a `:` (e.g. `matchHeaders=X-Debug`) matches on **key presence** alone, any value. Only the first `:` splits key from value, so values may themselves contain colons.

### Regular expressions

> Since 0.16

```yaml
labels:
  - "sozune.http.<svc>.matchHeadersRegex.<Header>=<regex>"
  - "sozune.http.<svc>.matchQueryRegex.<param>=<regex>"
```

One label per condition, the header or parameter in the key: a regular expression may hold commas, which `matchHeaders` splits on. The value must match it **whole**, as if it were written between `^` and `$`: `matchHeadersRegex.X-Version=v[0-9]+` takes `v2` and `v12`, not `v2-beta`. The syntax is that of the Rust `regex` crate: no look-around or back-references. These conditions add to those of `matchHeaders` and `matchQuery`, every one of them must hold.

A regular expression that does not compile, or a label naming no header or parameter, drops the route with `E007` (run `sozune explain E007`): served without the condition, it would take requests it does not ask for.

## Example

```yaml
labels:
  - "sozune.http.api-v2.host=api.example.com"
  - "sozune.http.api-v2.matchHeaders=X-Api-Version:2"
```

`api.example.com` is served by this route only when the request carries `X-Api-Version: 2`. A request without that header (or with a different value) goes to the next route of `api.example.com`, or gets `404 Not Found` when there is none.

### Canary on a header

> Since 0.16

```yaml
labels:
  # v1
  - "sozune.http.app.host=app.example.com"
  # v2, on another container
  - "sozune.http.app-canary.host=app.example.com"
  - "sozune.http.app-canary.matchHeaders=X-Canary"
```

A request carrying `X-Canary` (any value) is served by `app-canary`; every other request by `app`. The two routes share their host and path: the header is what picks one.

```yaml
labels:
  - "sozune.http.beta.host=app.example.com"
  - "sozune.http.beta.matchQuery=beta"
```

`app.example.com/?beta` (or `?beta=1`) matches; `app.example.com/` does not.

## Behaviour

- Header names are matched **case-insensitively**; values **exactly**. When a request repeats a header, Sōzu compares its first occurrence (the middleware, for the conditions it checks, any occurrence — see [Limitations](#limitations)).
- Query keys and values are **percent-decoded** before being compared, so `version=%32` matches `version:2`. A `+` stays a literal `+`, as in any URL (only form bodies read it as a space). (since 0.15)
- All conditions are **AND**-combined: every header and every query condition must hold.
- Header conditions are part of routing: Sōzu checks them when it picks the route, and a request that fails them goes on to the next route. (since 0.16)
- Query conditions are part of routing too, up to three per route: a request that fails them goes on to the next route. Among routes on the same host, path, method and headers, the one with more query conditions is tried first. A repeated query parameter matches on any of its occurrences: `?v=2&v=3` meets both `v:2` and `v:3`. (since 0.16)
- A route whose header conditions hold is tried **before every route without header conditions**, whatever their `priority`. Among routes with header conditions, or among routes without, `priority` decides as usual. (since 0.16)

## Limitations

- Header conditions on `Host` or `Cookie`, and query conditions on a route with more than three of them, a condition holding `%` or a regular expression, a `pathRegex`, `stripPrefix`, `addPrefix` or a path rewrite, are checked by a Sōzune middleware once the route is picked: a request that fails them gets `404 Not Found` from that route, without trying another one. The middleware compares every occurrence of a repeated header or parameter: one that holds is enough. Two such routes on the same host and path cannot both be live: give them distinct paths.
- `Host` is better matched with `host`, which routes on it.

## Other surfaces

Besides Docker/Swarm/Podman/Nomad labels, `match_headers` and `match_query` are available via the HTTP provider, the YAML config file, and the REST API (as lists of `{key, value}` objects on the entrypoint; `"regex": true` makes `value` a regular expression, and one that does not compile is refused: the API answers `400`, the HTTP provider drops the entrypoint). On a Kubernetes Ingress, the `sozune.matchHeadersRegex.<Header>` and `sozune.matchQueryRegex.<param>` annotations do the same; one that does not compile leaves the Ingress unserved. (since 0.16)
