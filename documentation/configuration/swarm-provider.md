# Swarm provider

The Swarm provider discovers entrypoints from Docker Swarm services. Sozune connects to a Swarm **manager**, lists services, and reads `sozune.*` labels declared on the service spec (not on the underlying tasks/containers).

This is the right provider when your stack is deployed with `docker stack deploy` or `docker service create` instead of plain `docker run`.

## Configuration

```yaml
providers:
  swarm:
    enabled: true
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
    network: "sozune-public"
    refresh_interval: 15
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Swarm provider |
| `endpoint` | `/var/run/docker.sock` | Docker socket. Must point to a **Swarm manager** node. |
| `expose_by_default` | `false` | If `true`, every service is a candidate even without `sozune.enable=true` |
| `network` | `""` | Optional overlay network name. When set, Sozune ignores VIPs on other networks. |
| `refresh_interval` | `15` | Periodic poll interval in seconds (safety net behind the event stream) |

## How it works

1. Sozune subscribes to Docker events filtered on `type=service` for near-real-time reactions to `service create`, `service update` and `service rm`.
2. A periodic poll (`refresh_interval`) re-runs the same diff against the Swarm API. This is a safety net for missed events or disconnected streams.
3. On every diff, Sozune replaces the full set of `source: "swarm"` entrypoints in storage and triggers a reload.

Service labels are parsed by the same engine the file, Docker, Podman and HTTP providers use, so `sozune validate` reports the exact diagnostics the runtime applies.

## Example service

```bash
docker service create \
  --name my-api \
  --label sozune.enable=true \
  --label sozune.http.host=api.example.com \
  --label sozune.http.port=8080 \
  --network sozune-public \
  --replicas 3 \
  my-api:latest
```

## Example stack file

Deploy with `docker stack deploy -c stack.yml mystack`:

```yaml
version: "3.9"

networks:
  sozune-public:
    external: true

services:
  api:
    image: my-api:latest
    networks:
      - sozune-public
    deploy:
      replicas: 3
      labels:
        sozune.enable: "true"
        sozune.http.host: "api.example.com"
        sozune.http.port: "8080"
        sozune.network: "sozune-public"
```

> **Important:** put `sozune.*` labels under `deploy.labels`, not `services.api.labels`. Service-level labels live on the running tasks (containers); only `deploy.labels` are stored on the **service** spec, which is what Sozune reads.

## Backend resolution

Swarm exposes two endpoint modes:

- **`vip` (default).** Swarm assigns one virtual IP per attached overlay network and load-balances behind it. Sozune uses that VIP as the single backend, so scaling the service does not churn Sozune's cluster — Swarm balances internally.
- **`dnsrr`.** Swarm relies on DNS round-robin. The Docker API does **not** expose individual task IPs through `bollard 0.20`, so Sozune cannot enumerate per-replica backends in this mode. If a VIP is still attached, Sozune falls back to it and logs a warning. For production multi-replica routing through Sozune, prefer `vip` (the Swarm default).

The `network` config field, when set, restricts which overlay's VIP Sozune considers. This is useful when the same service is attached to several overlays (e.g. a public ingress overlay plus a private backend overlay).

## Coexistence with the Docker provider

On a Swarm node, the local Docker socket exposes both `services` (Swarm) and `containers` (the tasks running locally). If you enable both `providers.docker` and `providers.swarm` against the same socket, you will discover the same workload twice — once at the service level and once at the task level — with potentially conflicting labels.

**Recommendation:** pick one. Use `swarm` when your stack is service-deployed; use `docker` for plain single-host containers.

Each provider tags its entries with a distinct `source` (`swarm` vs `docker`), so a misconfiguration is visible through the API or dashboard, but Sozune does not deduplicate across providers.

## Requirements

- The `endpoint` socket **must** point to a manager node. On a worker, the Docker daemon refuses Swarm API calls and Sozune logs an error per poll.
- Sozune itself must be able to reach the chosen overlay network. The simplest setup is to run Sozune as a Swarm service attached to the same overlay as the discovered services. Otherwise, expose ports with `mode=host`.

## Environment variables

| Field | Env var |
|---|---|
| `providers.swarm.enabled` | `SOZUNE_PROVIDER_SWARM_ENABLED` |
| `providers.swarm.endpoint` | `SOZUNE_PROVIDER_SWARM_ENDPOINT` |
| `providers.swarm.expose_by_default` | `SOZUNE_PROVIDER_SWARM_EXPOSE_BY_DEFAULT` |
| `providers.swarm.network` | `SOZUNE_PROVIDER_SWARM_NETWORK` |
| `providers.swarm.refresh_interval` | `SOZUNE_PROVIDER_SWARM_REFRESH_INTERVAL` |
