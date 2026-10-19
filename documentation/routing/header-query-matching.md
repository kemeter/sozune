# Header & query matching

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

## Example

```yaml
labels:
  - "sozune.http.api-v2.host=api.example.com"
  - "sozune.http.api-v2.matchHeaders=X-Api-Version:2"
```

`api.example.com` is served by this route only when the request carries `X-Api-Version: 2`. A request without that header (or with a different value) goes to the next route of `api.example.com`, or gets `404 Not Found` when there is none.

### Canary on a header

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

- Header names are matched **case-insensitively**; values **exactly**. When a request repeats a header, its first occurrence is the one compared.
- Query keys and values are **percent-decoded** before being compared, so `version=%32` matches `version:2`. A `+` stays a literal `+`, as in any URL (only form bodies read it as a space).
- All conditions are **AND**-combined: every header and every query condition must hold.
- Header conditions are part of routing: Sōzu checks them when it picks the route, and a request that fails them goes on to the next route.
- A route whose header conditions hold is tried **before every route without header conditions**, whatever their `priority`. Among routes with header conditions, or among routes without, `priority` decides as usual.

## Limitations

- Query conditions, and header conditions on `Host` or `Cookie`, are checked by a Sōzune middleware once the route is picked: a request that fails them gets `404 Not Found` from that route, without trying another one. Two routes on the same host and path that differ only by a query parameter (or a cookie) cannot both be live: give them distinct paths.
- `Host` is better matched with `host`, which routes on it.

## Other surfaces

Besides Docker/Swarm/Podman/Nomad labels, `match_headers` and `match_query` are available via the HTTP provider, the YAML config file, and the REST API (as lists of `{key, value}` objects on the entrypoint).
