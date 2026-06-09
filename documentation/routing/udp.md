# UDP routing

Sōzune can load-balance UDP datagrams to your services — DNS, syslog, NTP, or any datagram protocol. Like TCP, it has two pieces:

- **Listeners are declared statically** in `config.yaml`. Each listener binds a UDP port at startup.
- **Backends attach dynamically** through Docker labels and reference a listener by name.

A label that points at an undeclared listener is ignored with a warning. Sōzune does not open ports on the fly from labels alone — by design, to keep startup state predictable.

## Declare listeners

```yaml
proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
  udp:
    - name: dns
      listen: 53
    - name: syslog
      listen: 514
```

| Field | Description |
|---|---|
| `name` | Identifier referenced by service labels. Must be unique across `proxy.udp`. |
| `listen` | UDP port to bind on `0.0.0.0`. |

## Attach a backend with Docker labels

```yaml
services:
  resolver:
    image: coredns/coredns
    labels:
      - "sozune.enable=true"
      - "sozune.udp.dns.entrypoint=dns"
      - "sozune.udp.dns.port=53"
```

| Label | Description |
|---|---|
| `sozune.udp.<svc>.entrypoint` | Name of a listener declared under `proxy.udp`. **Required.** Routes are dropped with diagnostic `E005` if missing. |
| `sozune.udp.<svc>.port` | Backend port on the container. **Required** — datagram protocols have no sensible default, so a missing port drops the route with `E006` rather than binding to a wrong port. |
| `sozune.udp.<svc>.priority` | Higher wins when multiple services share the same listener (default `0`). |

The container's IP is resolved through the same network rules as HTTP — see [Docker labels](/documentation/providers/docker) and `sozune.network` to pick a network when the container is on several.

## Load balancing

UDP traffic is flow-based: datagrams from the same client form a virtual flow keyed by source IP. The flow-affine algorithms keep a flow pinned to one backend:

- **`hrw`** — Highest-Random-Weight (rendezvous) hashing. Stable under backend churn (adding or removing a backend only remaps the flows it owns), recommended for UDP.
- **`maglev`** — Maglev consistent hashing, an O(1) lookup table suited to large backend sets.

`round_robin`, `random`, `power_of_two`, and `least_connections` are also accepted. Set the algorithm on the service like any other entrypoint (`sozune.udp.<svc>.loadBalancer=hrw`).

`hrw` and `maglev` are flow-affine and only meaningful for UDP — Sōzu computes a flow key for datagrams but not for HTTP/TCP. Requesting them on an HTTP or TCP service emits `W022` and falls back to round-robin.

## Limitations

- **Plaintext only.** No DTLS; datagrams flow as-is.
- **No active health checks from Sōzune.** UDP backends are connectionless, so Sōzune's TCP/HTTP health checker does not probe them (a TCP probe would always fail). Sōzu's own UDP health checks are not yet surfaced through Sōzune.
- **In-flight flows reset on hot-reload of the listener.** A listener config change rebinds the socket; existing flow state is not migrated. Scaling a service's backends up or down does **not** rebind the listener — backends are diffed in place (added before removed), so existing flows are preserved.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.udp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| `E006` | A `sozune.udp.<svc>` service has no `port=` label. Datagram protocols have no default port, so the route is dropped. Set the backend port. |
| `W022` | A flow-affine algorithm (`hrw`/`maglev`) was requested on a non-UDP service, or the `loadBalancer` value is unknown. Falls back to round-robin. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.udp`. The route is dropped. Add the listener to the config or fix the label. |
