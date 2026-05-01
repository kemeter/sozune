# Nomad provider

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
| `namespace` | `""` | Restrict discovery to a single Nomad namespace. Empty means cluster-wide. |
| `poll_interval` | `15` | Maximum time, in seconds, that a [blocking query](https://developer.hashicorp.com/nomad/api-docs#blocking-queries) waits before returning. Lower = faster reaction to a stuck wait, higher = fewer round-trips when nothing changes. |
| `expose_by_default` | `false` | If `true`, every service is a candidate even without a `sozune.enable=true` tag. |

## How it works

1. Sōzune issues a **blocking query** against `GET /v1/services?index=N&wait=<poll_interval>s`. Nomad holds the connection open until the services list changes (or `poll_interval` elapses).
2. As soon as Nomad responds with a new index, Sōzune fetches the affected service instances via `GET /v1/service/<name>` and reconciles its entrypoints.
3. Service tags are parsed by the same engine that handles Docker / Swarm / Kubernetes labels, so `sozune validate` and the runtime stay in sync.

This means changes (job deploy, scale, allocation reschedule, healthcheck flip) propagate to Sōzune within seconds, without polling spam when the cluster is idle.

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

Every annotation listed under [Docker labels](/documentation/providers/docker) — host, path, headers, rate limit, basic auth, redirects, sticky sessions, compression — is supported as-is on Nomad services.

## Backend resolution

For each service instance, Sōzune uses:

- the instance's `Address` as the backend IP
- the instance's `Port` (the dynamically allocated port from `network { port "<name>" {} }`) as the backend port

If you declare `sozune.<proto>.<svc>.host` **without** an explicit `sozune.<proto>.<svc>.port`, Sōzune injects the Nomad-allocated port automatically. Explicit port tags always win, which is the right behaviour when your service exposes several ports and routes them differently.

## Service provider: `nomad` vs `consul`

Nomad services can register either against Nomad itself (`provider = "nomad"`) or Consul (`provider = "consul"`). Sōzune's Nomad provider only sees the **Nomad-native** registry. To route to Consul-registered services, run a separate Consul provider (not yet shipped — open an issue if you need it).

## Limitations

- **One Nomad agent per Sōzune instance.** If you have several federated regions, run one Sōzune per region.
- **No Consul integration.** As above.
- **UDP services** are recognised at the tag level but not yet proxied (same caveat as the Docker provider).
- **HCL stack changes** that don't change the services list (e.g. only env-var changes) won't wake up the blocking query — they'll be picked up on the next regular `poll_interval` tick.

## Environment variables

| Field | Env var |
|---|---|
| `providers.nomad.enabled` | `SOZUNE_PROVIDER_NOMAD_ENABLED` |
| `providers.nomad.endpoint` | `SOZUNE_PROVIDER_NOMAD_ENDPOINT` |
| `providers.nomad.token` | `SOZUNE_PROVIDER_NOMAD_TOKEN` |
| `providers.nomad.namespace` | `SOZUNE_PROVIDER_NOMAD_NAMESPACE` |
| `providers.nomad.poll_interval` | `SOZUNE_PROVIDER_NOMAD_POLL_INTERVAL` |
| `providers.nomad.expose_by_default` | `SOZUNE_PROVIDER_NOMAD_EXPOSE_BY_DEFAULT` |
