# Consul provider

The Consul provider discovers entrypoints from a HashiCorp [Consul](https://www.consul.net/) catalog. Sōzune connects to a Consul agent, lists registered services, reads each instance's health, and turns `sozune.*` service tags into routing configuration.

This is the right provider when your services register in Consul (directly, via Nomad's `provider = "consul"`, or through any other registrator) and you want a Sōzu-powered ingress in front of them.

## Configuration

```yaml
providers:
  consul:
    enabled: true
    endpoint: "http://127.0.0.1:8500"
    token: ""
    datacenter: ""
    poll_interval: 15
    strict_checks: ["passing", "warning"]
    expose_by_default: false
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Consul provider |
| `endpoint` | `http://127.0.0.1:8500` | Consul HTTP API endpoint. Use the agent the Sōzune host is closest to. |
| `token` | `""` | Optional ACL token sent as `X-Consul-Token`. Required when ACLs are enabled. |
| `datacenter` | `""` | Restrict discovery to a single datacenter (`?dc=`). Empty means the agent's default datacenter. |
| `poll_interval` | `15` | Maximum time, in seconds, that a [blocking query](https://developer.hashicorp.com/consul/api-docs/features/blocking) waits before returning. Lower = faster reaction to a stuck wait, higher = fewer round-trips when nothing changes. |
| `strict_checks` | `["passing", "warning"]` | Which Consul health-check states are allowed to receive traffic. With the default, only `critical` (and `maintenance`) instances are excluded. |
| `expose_by_default` | `false` | If `true`, every service is a candidate even without a `sozune.enable=true` tag. |

## How it works

1. Sōzune issues a **blocking query** against `GET /v1/catalog/services?index=N&wait=<poll_interval>s`. Consul holds the connection open until the catalog changes (or `poll_interval` elapses).
2. As soon as Consul responds with a new index, Sōzune fetches each service's instances via `GET /v1/health/service/<name>` — the health endpoint, so it sees the instances **and** their checks in one call.
3. Instances whose aggregate health is not allowed by `strict_checks` are dropped before they ever become a backend.
4. Service tags are parsed by the same engine that handles Docker / Swarm / Kubernetes / Nomad labels, so `sozune validate` and the runtime stay in sync.

Changes (service register/deregister, health flip, scale) propagate within seconds, without polling spam when the cluster is idle.

## Health filtering (`strict_checks`)

Every Consul instance carries one or more checks. Sōzune computes the instance's **effective** status as the worst of its checks (`critical` > `warning` > `passing`; an instance with no checks counts as `passing`), then keeps the instance only if that status is listed in `strict_checks`.

The default `["passing", "warning"]` matches Traefik's `strictChecks`: a `warning` instance still answers requests, so it keeps taking traffic — only `critical` (and Consul `maintenance`) instances are pulled out of rotation. Tighten to `["passing"]` if you want any non-green check to remove an instance.

> Sōzu runs its own backend health checks on top of this. `strict_checks` is the Consul-side gate (it knows about application checks Sōzu can't see); Sōzu's checks are the proxy-side safety net.

## Tags

Service `tags` follow two conventions:

- `key=value` → becomes a label `key` with value `value`.
- bare `key` (no `=`) → becomes a flag label `key` with empty value, useful for boolean toggles like `sozune.enable`.

A service registered directly against Consul:

```json
{
  "Name": "api",
  "Port": 8080,
  "Tags": [
    "sozune.enable=true",
    "sozune.http.web.host=api.example.com"
  ]
}
```

Every annotation listed under [Docker labels](/documentation/providers/docker) — host, path, headers, rate limit, basic auth, redirects, sticky sessions, compression — is supported as-is on Consul services.

## Backend resolution

For each instance, Sōzune uses:

- the service's `Service.Address` as the backend IP, falling back to the node's `Node.Address` when the service registers no address of its own (the common case for host-network services).
- the instance's `Service.Port` as the backend port.

If you declare `sozune.<proto>.<svc>.host` **without** an explicit `sozune.<proto>.<svc>.port`, Sōzune injects the Consul-registered port automatically. Explicit port tags always win.

Consul's built-in `consul` service (the agents themselves) is always skipped.

## Limitations

- **One Consul agent per Sōzune instance.** For multiple datacenters, run one Sōzune per datacenter (or set `datacenter` and run several instances).
- **Catalog only.** Consul Connect / service mesh and the KV store are not used.
- **UDP services** are recognised at the tag level but not yet proxied (same caveat as the Docker provider).

## Environment variables

| Field | Env var |
|---|---|
| `providers.consul.enabled` | `SOZUNE_PROVIDER_CONSUL_ENABLED` |
| `providers.consul.endpoint` | `SOZUNE_PROVIDER_CONSUL_ENDPOINT` |
| `providers.consul.token` | `SOZUNE_PROVIDER_CONSUL_TOKEN` |
| `providers.consul.datacenter` | `SOZUNE_PROVIDER_CONSUL_DATACENTER` |
| `providers.consul.poll_interval` | `SOZUNE_PROVIDER_CONSUL_POLL_INTERVAL` |
| `providers.consul.expose_by_default` | `SOZUNE_PROVIDER_CONSUL_EXPOSE_BY_DEFAULT` |
