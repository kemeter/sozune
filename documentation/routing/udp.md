# UDP routing

> Since 0.14

Sōzune can load-balance UDP datagrams to your services — DNS, syslog, NTP, or any datagram protocol. Like TCP, it has two pieces:

- **Listeners are declared statically** in `config.yaml`. Each listener binds a UDP port at startup.
- **Backends attach dynamically** through Docker labels and reference a listener by name.

A label that points at an undeclared listener drops the route, with an error in the log. Sōzune does not open ports on the fly from labels alone — by design, to keep startup state predictable.

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
| `name` | Identifier referenced by service labels. Must be unique across `proxy.udp`. `gateway:udp:<port>` is reserved for the listeners Kubernetes Gateways open. |
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
| `sozune.udp.<svc>.priority` | Not used on UDP routes: a listener serves one route. See below. |

The container's IP is resolved through the same network rules as HTTP — see [Docker labels](/documentation/providers/docker) and `sozune.network` to pick a network when the container is on several.

A listener forwards every datagram to a single route. Several containers of the same service are fine — they are its backends — but declare one service per listener. When several name the same listener, `priority` does not pick between them: the one applied last takes the listener's traffic. Of Kubernetes UDPRoutes sharing a port, only the oldest is served, see [Gateway API](/documentation/providers/kubernetes#gateway-api-udproute). (since 0.16)

## Load balancing

UDP traffic is flow-based: datagrams from the same client form a virtual flow keyed by source IP. The flow-affine algorithms keep a flow pinned to one backend:

- **`hrw`** — Highest-Random-Weight (rendezvous) hashing. Stable under backend churn (adding or removing a backend only remaps the flows it owns), recommended for UDP.
- **`maglev`** — Maglev consistent hashing, an O(1) lookup table suited to large backend sets.

`round_robin`, `random`, `power_of_two`, and `least_connections` are also accepted. Set the algorithm on the service like any other entrypoint (`sozune.udp.<svc>.loadBalancer=hrw`). Every algorithm, `hrw` and `maglev` included, honours the backends' [weights](/documentation/routing/load-balancing#weighted-load-balancing) (since 0.16).

`hrw` and `maglev` are flow-affine and only meaningful for UDP — Sōzu computes a flow key for datagrams but not for HTTP/TCP. Requesting them on an HTTP or TCP service emits `W022` and falls back to round-robin.

## Limitations

- **Plaintext only.** No DTLS; datagrams flow as-is.
- **No active health checks from Sōzune.** UDP backends are connectionless, so Sōzune's TCP/HTTP health checker does not probe them (a TCP probe would always fail). Sōzu's own UDP health checks are not yet surfaced through Sōzune.
- **Listeners are static.** They are read at startup: adding, removing or changing one under `proxy.udp` takes a restart, which drops every flow. Scaling a service's backends up or down does **not** touch the listener — backends are diffed in place (added before removed), so existing flows are preserved.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.udp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| `E006` | A `sozune.udp.<svc>` service has no `port=` label. Datagram protocols have no default port, so the route is dropped. Set the backend port. |
| `W022` | A flow-affine algorithm (`hrw`/`maglev`) was requested on a non-UDP service, or the `loadBalancer` value is unknown. Falls back to round-robin. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.udp`. The route is dropped. Add the listener to the config or fix the label. |
