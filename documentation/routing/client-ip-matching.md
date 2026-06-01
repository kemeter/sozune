# Client-IP matching

Scope a route to requests coming from specific client IPs or CIDR ranges, on top of the usual host/path matching. Use it to serve an admin route only to your office network, or to pin a route to a known set of upstreams.

`matchClientIP` is a **routing matcher**: when the client IP is not in the list, the request gets `404 Not Found` — the route simply *does not apply*, exactly like [header & query matching](./header-query-matching.md). This is what distinguishes it from the [IP allow-list middleware](../middleware/ip-allow-list.md), which is an *access filter* that returns `403 Forbidden`. Pick the matcher when "this IP shouldn't see this route at all"; pick the middleware when "this IP is forbidden from a route it would otherwise reach".

## Labels

```yaml
labels:
  - "sozune.http.<svc>.matchClientIP=<ip-or-cidr>,<ip-or-cidr>,…"
```

The value is a comma-separated list of:

- IPv4 or IPv6 addresses (auto-promoted to `/32` or `/128`)
- IPv4 or IPv6 CIDR ranges

If the label is absent or empty, the matcher is disabled and the route is not constrained by client IP.

## Example

```yaml
labels:
  - "sozune.http.admin.host=admin.example.com"
  - "sozune.http.admin.matchClientIP=10.0.0.0/8,192.168.1.5,2001:db8::/32"
```

A request from `10.5.7.99` is served. A request from `203.0.113.7` gets a `404 Not Found` — as if the route didn't exist.

## Behaviour

- All conditions are **AND**-combined with any `matchHeaders` / `matchQuery` on the same route: every condition must hold for the route to serve.
- Sōzu routes on host/path/method only, so matching is enforced by a Sōzune middleware: the request is routed to the cluster, then rejected with `404 Not Found` if the client IP is not in the list.
- Entries that don't parse are logged and **dropped**: a typo can only ever narrow the match, never widen it.
- If **every** entry is invalid, the constraint is dropped and the route stays reachable (the route is not silently black-holed). The per-entry warnings remain in the logs.

## Client-IP resolution

The client IP is resolved **identically to the IP allow-list middleware** — `X-Forwarded-For` is only honoured for trusted proxies declared in `proxy.trusted_proxies`, otherwise the direct TCP peer is the client. See [Client-IP resolution](../middleware/ip-allow-list.md#client-ip-resolution) for the full trust model, the IPv6 / dual-stack note, and the resolution-failure behaviour (a request with no resolvable client IP does **not** match).

## Limitation

Like header/query matching, this builds on a Sōzu frontend keyed on host + path + method. **Two routes that share the same host and path but differ only by client IP cannot be distinguished** — Sōzu sees a single frontend. `matchClientIP` can *filter* a route (serve it only for matching clients) but cannot *select between* two otherwise-identical routes. Give such routes distinct paths if you need both live at once.

## REST / YAML surface

Besides Docker/Swarm/Podman/Nomad labels, `match_client_ip` is available via the HTTP provider, the YAML config file, and the REST API (as a list of IP/CIDR strings on the entrypoint):

```jsonc
{
  "name": "admin",
  "protocol": "Http",
  "config": {
    "hostnames": ["admin.example.com"],
    "match_client_ip": ["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"],
    // …
  }
}
```

An empty array (or omitting the field entirely) disables the matcher.
