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

`api.example.com` is served by this route only when the request carries `X-Api-Version: 2`. A request without that header (or with a different value) gets `404 Not Found`.

```yaml
labels:
  - "sozune.http.beta.host=app.example.com"
  - "sozune.http.beta.matchQuery=beta"
```

`app.example.com/?beta` (or `?beta=1`) matches; `app.example.com/` does not.

## Behaviour

- Header names are matched **case-insensitively**; values **exactly**.
- All conditions are **AND**-combined: every header and every query condition must hold.
- Sōzu routes on host/path/method only, so matching is enforced by a Sōzune middleware: the request is routed to the cluster, then rejected with `404 Not Found` if a condition fails — equivalent to the route not matching.

## Limitation

Because the underlying Sōzu frontend keys on host + path + method, **two routes that share the same host and path but differ only by a header or query condition cannot be distinguished** — Sōzu sees a single frontend, and only one cluster is registered for it. Header/query matching can *filter* a route (serve it only when conditions hold) but cannot *select between* two otherwise-identical routes. Give such routes distinct paths if you need both live at once.

## Other surfaces

Besides Docker/Swarm/Podman/Nomad labels, `match_headers` and `match_query` are available via the HTTP provider, the YAML config file, and the REST API (as lists of `{key, value}` objects on the entrypoint).
