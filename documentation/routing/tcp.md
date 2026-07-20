# TCP routing

Sōzune can forward raw TCP traffic to your services. Two pieces:

- **Listeners are declared statically** in `config.yaml`. Each listener binds a port at startup.
- **Backends attach dynamically** through Docker labels and reference a listener by name.

A label that points at an undeclared listener is ignored with a warning. Sōzune does not open ports on the fly from labels alone — by design, to keep startup state predictable.

## Declare listeners

```yaml
proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
  tcp:
    - name: postgres
      listen: 5432
      ip_allow_list: ["94.23.3.96", "172.16.0.0/12"]
    - name: redis
      listen: 6379
```

| Field | Description |
|---|---|
| `name` | Identifier referenced by service labels. Must be unique across `proxy.tcp`. |
| `listen` | Port to bind on `0.0.0.0`. |
| `ip_allow_list` | CIDRs / bare IPs allowed to connect, checked at `accept()`. Empty (default) = allow all. See [Source-IP allow-list](#source-ip-allow-list). |
| `sni_preread_timeout` | Seconds to wait for a complete TLS ClientHello before dropping the connection. Default `5`. Only consulted when the listener carries SNI routes. See [Route by SNI](#route-by-sni-tls-passthrough). |
| `sni_preread_max_bytes` | Cap on the bytes buffered while looking for the ClientHello. Default `16384`. Bounds the hello, not the connection. |

## Attach a backend with Docker labels

```yaml
services:
  db:
    image: postgres:16
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.db.entrypoint=postgres"
      - "sozune.tcp.db.port=5432"
```

| Label | Description |
|---|---|
| `sozune.tcp.<svc>.entrypoint` | Name of a listener declared under `proxy.tcp`. **Required.** Routes are dropped with diagnostic `E005` if missing. |
| `sozune.tcp.<svc>.port` | Backend port on the container. Defaults to `8080` (informational diagnostic emitted). |
| `sozune.tcp.<svc>.priority` | Higher wins when multiple services share the same listener (default `0`). |
| `sozune.tcp.<svc>.sni` | Route TLS connections to this backend by the name in the ClientHello, without terminating TLS. Absent (default) = the listener forwards everything to one backend. See [Route by SNI](#route-by-sni-tls-passthrough). |

The container's IP is resolved through the same network rules as HTTP — see [Docker labels](/documentation/providers/docker) and `sozune.network` to pick a network when the container is on several.

## Source-IP allow-list

A TCP listener can restrict which source IPs may connect, set on the **listener** (not the backend) since it gates the public port:

```yaml
proxy:
  tcp:
    - name: postgres
      listen: 5432
      ip_allow_list: ["94.23.3.96", "172.16.0.0/12"]
```

Sōzune owns the public port and runs a small forwarder in front of the Sōzu worker (which binds a private loopback port). The forwarder checks the connecting peer's IP against the list at `accept()`; a connection from a non-listed source is closed without reaching the backend. Entries are bare IPs (promoted to `/32` or `/128`) or CIDR blocks. An empty or absent `ip_allow_list` allows all sources. Invalid entries are dropped (the list can only narrow, never widen), and an all-invalid list falls back to allow-all rather than black-holing the listener.

This is the direct equivalent of HAProxy's `tcp-request connection reject unless <acl>` and is sufficient for the common case (allow a bastion + internal ranges, reject the rest).

**For a database exposed to the public internet**, you can additionally put a kernel firewall in front — it drops packets *before* the TCP handshake (the forwarder, like HAProxy, filters *after* accept), which also blunts SYN floods:

```sh
nft add rule inet filter input tcp dport 5432 ip saddr { 94.23.3.96, 172.16.0.0/12 } accept
nft add rule inet filter input tcp dport 5432 drop
```

Sōzune neither reads nor manages these rules — they live entirely in your firewall. The allow-list above is enough on its own for most deployments; the firewall is an optional hardening layer.

## Anti-flood (per-source connection rate)

A listener can cap the connection rate per source IP, enforced by the same forwarder:

```yaml
proxy:
  tcp:
    - name: postgres
      listen: 5432
      rate_limit:
        max_conns: 10        # burst absorbed at once
        per_seconds: 3       # sustained refill: max_conns / per_seconds per second
        exempt: ["172.16.0.0/12"]
```

This is a token bucket: a source may open `max_conns` connections back-to-back (the burst), after which it refills at `max_conns / per_seconds` per second. A source over its budget is dropped at `accept()`. Sources matching `exempt` are never limited — use it for internal ranges (e.g. Docker) that open legitimate startup bursts.

It covers the same ground as HAProxy's `stick-table … conn_rate(3s)` + `reject if { src_conn_rate gt N } !exempt`. The token bucket smooths the rate rather than counting a fixed 3-second window, so a brief startup burst is tolerated and a sustained flood is throttled — without the boundary double-burst a fixed window allows. Absent `rate_limit` = no limit.

## Route by SNI (TLS passthrough)

Without an `sni` label, a TCP listener forwards everything it accepts to a single backend. Add one and Sōzune reads the server name from the TLS ClientHello — which travels in the clear, before any key exchange — and picks a backend from it. TLS is never terminated: the client completes its handshake with the backend, using the backend's own certificate.

```yaml
services:
  app-a:
    image: my/app-a
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.appa.entrypoint=tlsgw"
      - "sozune.tcp.appa.port=8443"
      - "sozune.tcp.appa.sni=a.example.com"

  app-b:
    image: my/app-b
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.appb.entrypoint=tlsgw"
      - "sozune.tcp.appb.port=8443"
      - "sozune.tcp.appb.sni=*.b.example.com"
```

Both share one public port; the name decides where each connection lands. Use this when the backend must own its certificates — end-to-end encryption to the service, a tenant terminating its own TLS, or a protocol Sōzune does not speak.

**Accepted patterns.** An exact hostname (`a.example.com`) or a single leading wildcard label (`*.b.example.com`). The wildcard matches exactly one label: `*.b.example.com` matches `api.b.example.com`, but neither `b.example.com` itself nor `x.y.b.example.com`. Anything else — a wildcard elsewhere in the name, a bare `*`, a `/`, an empty label, a non-ASCII character — is refused with diagnostic `W028`, and the route falls back to catch-all. Write internationalised names as punycode A-labels (`xn--caf-dma.example.com`); a Unicode pattern would load and then never match what is on the wire.

**A listener is either SNI-routed or catch-all, never both.** This is a Sōzu constraint, and it differs from what Traefik or HAProxy allow. If some entrypoints on a listener declare an `sni` and others do not, Sōzune logs which ones are the odd ones out and leaves them unapplied — the rest of the listener keeps working. Give them an `sni` of their own, or move them to a separate listener, and the next reload picks them up.

**Unmatched names are dropped.** Once a listener carries SNI routes there is no fallback: a connection whose name matches nothing, or which sends no SNI at all, is closed without reaching any backend. Declare a route for every name you intend to serve.

`sni` is TCP-only. On a `sozune.udp.*` service it emits `W028` and is ignored — datagrams carry no ClientHello.

## Limitations

- **No TLS termination.** Sōzu's TCP path is pure passthrough — TLS bytes flow as-is. For client-side STARTTLS protocols (PostgreSQL, MySQL) this is fine; for terminating TLS, use an HTTPS entrypoint instead. Passthrough can still *route* by name without decrypting — see [Route by SNI](#route-by-sni-tls-passthrough).
- **No half-close.** Sōzu treats a client `FIN` as a full disconnect, so protocols that rely on half-closing one direction to signal end-of-stream may misbehave. Most request/response and long-lived stream protocols are unaffected.
- **The allow-list and rate limit are filtered after `accept()`**, not before the handshake — see the firewall note above for pre-handshake dropping.
- **The rate limit resets on restart.** Token buckets are in-memory per process; a Sōzune restart clears them. Listeners (and their limits) are static config, applied at boot.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.tcp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| `W028` | An `sni=` label is not a routable pattern, or was set on a UDP service. The SNI is dropped and the route falls back to catch-all. Run `sozune explain W028` for the accepted shapes. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.tcp`. The route is dropped. Add the listener to the config or fix the label. |
| Log: `mixes SNI-routed and catch-all entrypoints` | One listener carries both shapes, which Sōzu refuses. The named entrypoints are left unapplied and retried on the next reload. Give them an `sni`, or move them to their own listener. |
