# IP allow-list

Per-route allow-list of client IPs and CIDR ranges. Requests from a client IP that is not in the list are rejected with `403 Forbidden` **before** they reach auth, rate-limit, or the backend.

## Labels

```yaml
labels:
  - "sozune.http.<svc>.ipAllowList=<ip-or-cidr>,<ip-or-cidr>,…"
```

The value is a comma-separated list of:

- IPv4 or IPv6 addresses (auto-promoted to `/32` or `/128`)
- IPv4 or IPv6 CIDR ranges

If the label is absent or empty, the filter is disabled and every client is served.

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.ipAllowList=10.0.0.0/8,192.168.1.5,2001:db8::/32"
```

A request from `10.5.7.99` is served. A request from `203.0.113.7` gets a `403 Forbidden` with body `sozune: client IP not allowed for host 'api.example.com'.`.

## Behaviour

- The middleware runs **first** in the route's stack — a denied client never reaches request-match, auth, rate-limit, or the backend.
- All `403` rejects are logged at `WARN` level with the denied IP and host.
- A successful allow is logged at `DEBUG`.
- Allow-list entries that don't parse are logged and **dropped silently**: a typo can only narrow access, never widen it.
- If **every** entry of an allow-list is invalid, the middleware is not installed and the route stays reachable. The per-entry warnings remain in the logs so the operator can fix the configuration.

## Client-IP resolution

This is the hard part of any IP allow-list — and the one most implementations get wrong. `X-Forwarded-For` is set by *whoever speaks last to Sōzune*. If that's an attacker on the public internet, the header is attacker-controlled. A naïve "trust the leftmost XFF entry" resolver can be bypassed by anyone with `curl`:

```bash
curl -H "X-Forwarded-For: 10.0.0.1" https://api.example.com/  # pretends to be 10.0.0.1
```

Sōzune solves this by requiring you to declare which reverse-proxies are trusted to set `X-Forwarded-For`. The list lives in `config.yaml` under `proxy.trusted_proxies`:

```yaml
proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
  trusted_proxies:
    - 10.0.0.0/8        # your internal load balancer / k8s ingress
    - 172.16.0.0/12
```

With this setup, the client IP is resolved like this:

1. **`trusted_proxies` is empty** (the default): `X-Forwarded-For` is ignored entirely. The direct TCP peer is the client. Safe to deploy Sōzune publicly without any further configuration.
2. **`trusted_proxies` is set but the TCP peer isn't in it**: `X-Forwarded-For` is still ignored — an untrusted peer can't speak about who is behind it.
3. **`trusted_proxies` is set and the TCP peer is one of them**: walk `X-Forwarded-For` *right to left*, skipping every entry that is itself a trusted proxy. The first non-trusted entry is the client. If every XFF entry is trusted (a long internal chain), fall back to the TCP peer.

This is the standard *rightmost trusted* algorithm — the same model Cloudflare, NGINX with `set_real_ip_from`, and HAProxy use. It is the only safe way to honour `X-Forwarded-For` without letting an attacker forge their identity.

### IPv6 / dual-stack note

An IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) is normalised to its IPv4 form before matching. An allow-list entry of `1.2.3.4` therefore matches a client that arrived on a dual-stack IPv6 socket holding that mapping. A pure IPv6 address like `::1.2.3.4` does **not** match an IPv4 rule — the two address families remain distinct.

### Resolution failure

If neither the TCP peer nor any usable `X-Forwarded-For` entry yields an IP, the request is denied. The middleware fails closed: gating on identity requires identity.

## Combining with other middleware

The allow-list runs before `request-match`, `forward-auth`, and `rate-limit`. A denied client therefore never consumes a rate-limit token, never triggers a forward-auth call, and never reaches the backend. This is the right order for an IP filter: a blocked client must cost as little as possible.

## REST / YAML surface

The same field is also available on the entrypoint payload directly, for the file provider, the HTTP provider, and the REST API:

```jsonc
{
  "name": "api",
  "protocol": "Http",
  "config": {
    "hostnames": ["api.example.com"],
    "ip_allow_list": ["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"],
    // …
  }
}
```

An empty array (or omitting the field entirely) disables the filter.
