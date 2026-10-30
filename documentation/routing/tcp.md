# TCP routing

> Since 0.12

Sōzune can forward raw TCP traffic to your services. Two pieces:

- **Listeners are declared statically** in `config.yaml`. Each listener binds a port at startup.
- **Backends attach dynamically** through Docker labels and reference a listener by name.

A label that points at an undeclared listener drops the route, with an error in the log. Sōzune does not open ports on the fly from labels alone — by design, to keep startup state predictable.

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
| `name` | Identifier referenced by service labels. Must be unique across `proxy.tcp`. `gateway:tcp:<port>` is reserved for the listeners Kubernetes Gateways open. |
| `listen` | Port to bind on `0.0.0.0`. |
| `ip_allow_list` | CIDRs / bare IPs allowed to connect, checked at `accept()`. Empty (default) = allow all. See [Source-IP allow-list](#source-ip-allow-list). (since 0.14) |
| `rate_limit` | Per-source connection rate cap: `max_conns`, `per_seconds`, `exempt`. Absent (default) = no limit. See [Anti-flood](#anti-flood-per-source-connection-rate). (since 0.14) |
| `idle_timeout` | Seconds a connection may stay silent in both directions before it is closed. Absent keeps Sōzu's defaults (closed after `30`s of silence). See [Idle timeout](#idle-timeout). (since 0.15) |
| `sni_preread_timeout` | Seconds to wait for a complete TLS ClientHello before dropping the connection. Default `5`. Only consulted when the listener carries SNI routes. See [Route by SNI](#route-by-sni-tls-passthrough). (since 0.15) |
| `sni_preread_max_bytes` | Cap on the bytes buffered while looking for the ClientHello. Default `16384`. Bounds the hello, not the connection. (since 0.15) |

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
| `sozune.tcp.<svc>.priority` | Not used on TCP routes: a listener serves one catch-all route, or one route per SNI name. See [One route per listener](#one-route-per-listener). |
| `sozune.tcp.<svc>.sni` | Route TLS connections to this backend by the name in the ClientHello, without terminating TLS. Absent (default) = the listener forwards everything to one backend. See [Route by SNI](#route-by-sni-tls-passthrough). (since 0.15) |

The container's IP is resolved through the same network rules as HTTP — see [Docker labels](/documentation/providers/docker) and `sozune.network` to pick a network when the container is on several.

### One route per listener

Without SNI routes, a listener forwards every connection to a single route. Several containers of the same service are fine — they are its backends — but declare one catch-all service per listener. When several name the same listener, `priority` does not pick between them: the one applied last takes the listener's connections. Give each its own listener, or route them [by SNI](#route-by-sni-tls-passthrough). Of Kubernetes TCPRoutes sharing a port, only the oldest is served, see [Gateway API](/documentation/providers/kubernetes#gateway-api-tcproute). (since 0.16)

## Source-IP allow-list

> Since 0.14

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

> Since 0.14

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

## Idle timeout

> Since 0.15

A TCP connection that carries no byte in either direction is closed after a while. By default that is 30 seconds, which suits request/response protocols and is too short for a database: a query that takes longer to answer, or a pooled connection waiting for its next use, sends nothing for longer than that and gets cut.

```yaml
proxy:
  tcp:
    - name: postgres
      listen: 5432
      idle_timeout: 3600   # seconds
```

`idle_timeout` is the longest silence tolerated. Any byte, from the client or from the backend, starts the count again, so a connection that keeps exchanging data is never closed by it, however long it lives.

Pick a value above the longest silence you expect: the slowest query, or the idle time your connection pool allows before it recycles a connection. TCP keepalive probes do not count — they carry no data, so they do not reset the timer.

The value must be greater than zero. There is no "never" setting; use a large number of seconds instead. Sōzune refuses to start on `idle_timeout: 0` rather than close every connection as it opens.

## Route by SNI (TLS passthrough)

> Since 0.15

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

### Passthrough on the HTTPS port

> Since 0.16

To route by SNI on the HTTPS port itself, next to the routes Sōzune serves over HTTPS there, turn on `proxy.https.passthrough`:

```yaml
proxy:
  https:
    listen_address: 443
    passthrough: true
```

Sōzune then runs a TCP listener named `https-passthrough` behind the HTTPS port, with no port of its own, and reads each ClientHello on 443 first. A connection whose SNI names one of that listener's routes is forwarded to it, undecrypted; one whose SNI a certificate Sōzune holds covers, or with no SNI at all, is served over HTTPS as usual. Any other is closed, rather than answered with Sōzu's default certificate. Point a route at it like at any listener:

```yaml
labels:
  - "sozune.enable=true"
  - "sozune.tcp.vault.entrypoint=https-passthrough"
  - "sozune.tcp.vault.port=8200"
  - "sozune.tcp.vault.sni=vault.example.com"
```

A name served both ways goes to passthrough. Routes on `https-passthrough` need an `sni`: a catch-all one would get nothing. Reading the ClientHello adds a hop in front of the HTTPS listener, the one TLS-ALPN-01 already uses, so the option is off by default. On Kubernetes, a Gateway `TLS` listener on the HTTPS port is served this way (see [Gateway API (TLSRoute)](/documentation/providers/kubernetes#gateway-api-tlsroute)). The name `https-passthrough` is reserved: a `proxy.tcp` entry cannot take it.

## Limitations

- **No TLS termination.** Sōzu's TCP path is pure passthrough — TLS bytes flow as-is. For client-side STARTTLS protocols (PostgreSQL, MySQL) this is fine; for terminating TLS, use an HTTPS entrypoint instead. Passthrough can still *route* by name without decrypting — see [Route by SNI](#route-by-sni-tls-passthrough).
- **Connections follow their backend out.** When a backend leaves the route, its open connections are closed and clients reconnect to the backends that are left — see [When a backend leaves](/documentation/routing/load-balancing#when-a-backend-leaves). (since 0.16)
- **No half-close.** Sōzu treats a client `FIN` as a full disconnect, so protocols that rely on half-closing one direction to signal end-of-stream may misbehave. Most request/response and long-lived stream protocols are unaffected.
- **The allow-list and rate limit are filtered after `accept()`**, not before the handshake — see the firewall note above for pre-handshake dropping.
- **The rate limit resets on restart.** Token buckets are in-memory per process; a Sōzune restart clears them. Listeners (and their limits) are static config, applied at boot: changing one takes a restart.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.tcp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| `W028` | An `sni=` label is not a routable pattern, or was set on a UDP service. The SNI is dropped and the route falls back to catch-all. Run `sozune explain W028` for the accepted shapes. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.tcp`. The route is dropped. Add the listener to the config or fix the label. |
| Log: `mixes SNI-routed and catch-all entrypoints` | One listener carries both shapes, which Sōzu refuses. The named entrypoints are left unapplied and retried on the next reload. Give them an `sni`, or move them to their own listener. |
