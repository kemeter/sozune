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

## Limitations

- **No TLS termination.** Sōzu's TCP path is pure passthrough — TLS bytes flow as-is. For client-side STARTTLS protocols (PostgreSQL, MySQL) this is fine; for terminating TLS, use an HTTPS entrypoint instead.
- **No half-close.** Sōzu treats a client `FIN` as a full disconnect, so protocols that rely on half-closing one direction to signal end-of-stream may misbehave. Most request/response and long-lived stream protocols are unaffected.
- **The allow-list is filtered after `accept()`**, not before the handshake — see the firewall note above for pre-handshake dropping.
- **No connection-rate limit yet.** Per-source anti-flood is not yet wired (Sōzu 2.1.0's native `max_connections_per_ip` is a candidate); only the IP allow-list is enforced today.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.tcp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.tcp`. The route is dropped. Add the listener to the config or fix the label. |
