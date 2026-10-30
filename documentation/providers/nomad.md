# Nomad provider

> Since 0.12

The Nomad provider discovers entrypoints from a HashiCorp Nomad cluster's [services API](https://developer.hashicorp.com/nomad/api-docs/services). Sōzune connects to a Nomad agent, lists registered services, and reads `sozune.*` tags declared on each service block.

This is the right provider when your workloads run as Nomad jobs and you want a Sōzu-powered ingress for them.

## Configuration

```yaml
providers:
  nomad:
    enabled: true
    endpoint: "http://127.0.0.1:4646"
    token: ""
    namespace: ""
    poll_interval: 15
    expose_by_default: false
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Nomad provider |
| `endpoint` | `http://127.0.0.1:4646` | Nomad HTTP API endpoint. Use the agent the Sōzune host is closest to. |
| `token` | `""` | Optional ACL token sent as `X-Nomad-Token`. Required when ACLs are enabled on the cluster. |
| `namespace` | `""` | Nomad namespace to discover services in, sent as `?namespace=`. Empty sends none, so Nomad answers for its `default` namespace. |
| `poll_interval` | `15` | Maximum time, in seconds, that a [blocking query](https://developer.hashicorp.com/nomad/api-docs#blocking-queries) waits before returning. Lower = faster reaction to a stuck wait, higher = fewer round-trips when nothing changes. |
| `expose_by_default` | `false` | If `true`, every service is a candidate even without a `sozune.enable=true` tag. |

## How it works

1. Sōzune issues a **blocking query** against `GET /v1/services?index=N&wait=<poll_interval>s`. Nomad holds the connection open until the services list changes (or `poll_interval` elapses).
2. As soon as Nomad responds with a new index, Sōzune fetches the affected service instances via `GET /v1/service/<name>` and reconciles its entrypoints.
3. Service tags are parsed by the same engine that handles Docker / Swarm / Kubernetes labels, so `sozune validate` and the runtime stay in sync.

This means changes to service registrations (job deploy, scale, allocation reschedule) propagate to Sōzune within seconds, without polling spam when the cluster is idle. When a blocking query times out with no change, Sōzune issues the next one without re-reading the instances.

## Tags

Service `tags` follow two conventions:

- `key=value` → becomes a label `key` with value `value`.
- bare `key` (no `=`) → becomes a flag label `key` with empty value, useful for boolean toggles like `sozune.enable`.

Drop the `labels:` prefix and put `sozune.*` settings under `tags` in your job spec:

```hcl
job "api" {
  group "web" {
    count = 3

    network {
      port "http" {}
    }

    service {
      name     = "api"
      provider = "nomad"
      port     = "http"

      tags = [
        "sozune.enable=true",
        "sozune.http.web.host=api.example.com",
      ]
    }

    task "server" {
      driver = "docker"
      config {
        image = "my-api:latest"
        ports = ["http"]
      }
    }
  }
}
```

Every annotation listed under [Docker labels](/documentation/providers/docker) — host, path, headers, rate limit, basic auth, redirects, sticky sessions, compression, TCP and UDP routes — is supported as-is on Nomad services.

## Backend resolution

For each service instance, Sōzune uses:

- the instance's `Address` as the backend IP
- the instance's `Port` (the dynamically allocated port from `network { port "<name>" {} }`) as the backend port

If you declare `sozune.<proto>.<svc>.host` **without** an explicit `sozune.<proto>.<svc>.port`, Sōzune injects the Nomad-allocated port automatically. Explicit port tags always win, which is the right behaviour when your service exposes several ports and routes them differently. TCP and UDP services declare no `host`, so they get no injected port: set `sozune.<proto>.<svc>.port` (required on UDP).

## Service provider: `nomad` vs `consul`

Nomad services can register either against Nomad itself (`provider = "nomad"`) or Consul (`provider = "consul"`). Sōzune's Nomad provider only sees the **Nomad-native** registry. To route to Consul-registered services, enable the [Consul provider](/documentation/providers/consul) instead.

## Limitations

- **One Nomad agent per Sōzune instance.** If you have several federated regions, run one Sōzune per region.
- **Nomad-native registry only.** For Consul-registered services, use the [Consul provider](/documentation/providers/consul).
- **One namespace.** Discovery covers the configured `namespace` (or Nomad's `default`); run one Sōzune per namespace to cover several.
- **Registration changes only.** The blocking query wakes when service registrations change, and Sōzune re-reads the instances only then.

## Environment variables

| Field | Env var |
|---|---|
| `providers.nomad.enabled` | `SOZUNE_PROVIDER_NOMAD_ENABLED` |
| `providers.nomad.endpoint` | `SOZUNE_PROVIDER_NOMAD_ENDPOINT` |
| `providers.nomad.token` | `SOZUNE_PROVIDER_NOMAD_TOKEN` |
| `providers.nomad.namespace` | `SOZUNE_PROVIDER_NOMAD_NAMESPACE` |
| `providers.nomad.poll_interval` | `SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL` |
| `providers.nomad.expose_by_default` | `SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT` |
