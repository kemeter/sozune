# TCP routing

Sozune can forward raw TCP traffic to your services. The model mirrors Traefik's:

- **Listeners are declared statically** in `config.yaml`. Each listener binds a port at startup.
- **Backends attach dynamically** through Docker labels and reference a listener by name.

A label that points at an undeclared listener is ignored with a warning. Sozune does not open ports on the fly from labels alone — by design, to keep startup state predictable.

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
    - name: redis
      listen: 6379
```

| Field | Description |
|---|---|
| `name` | Identifier referenced by service labels. Must be unique across `proxy.tcp`. |
| `listen` | Port to bind on `0.0.0.0`. |

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

The container's IP is resolved through the same network rules as HTTP — see [Docker labels](../configuration/docker-labels.md) and `sozune.network` to pick a network when the container is on several.

## Limitations

- **No TLS termination.** Sōzu's TCP path is pure passthrough — TLS bytes flow as-is. For client-side STARTTLS protocols (PostgreSQL, MySQL) this is fine; for terminating TLS, use an HTTPS entrypoint instead.
- **No half-close.** Sōzu treats a client `FIN` as a full disconnect, so protocols that rely on half-closing one direction to signal end-of-stream may misbehave. Most request/response and long-lived stream protocols are unaffected.
- **No IP allowlist or connection-rate limit yet.** Track the [roadmap](https://github.com/kemeter/sozune/blob/main/ROADMAP.md) for `IP allowlist / denylist` and TCP-level rate limiting.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `E005` | A `sozune.tcp.<svc>` service has no `entrypoint=` label. The route is dropped. |
| Log: `references undeclared listener` | The label points at a name not present in `proxy.tcp`. The route is dropped. Add the listener to the config or fix the label. |
