# Ring provider

The Ring provider discovers entrypoints from a [Ring](https://github.com/kemeter/ring) cluster. Ring is a lightweight orchestrator that runs workloads as containers or microVMs (Firecracker / Cloud Hypervisor). Sōzune reads Ring's deployment list over its HTTP API and turns the `sozune.*` labels declared on each deployment into routing configuration.

Like the Docker / Nomad / Consul providers, Sōzune *observes* Ring — it never registers anything back, so Ring does not need to know Sōzune exists. This is the right provider when your workloads run on Ring and you want a Sōzu-powered ingress in front of them.

## Configuration

```yaml
providers:
  ring:
    enabled: true
    endpoint: "http://127.0.0.1:3030"
    token: ""
    poll_interval: 10
    expose_by_default: false
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Ring provider |
| `endpoint` | `http://127.0.0.1:3030` | Ring HTTP API endpoint. Use the node the Sōzune host is closest to. |
| `token` | `""` | Optional Personal Access Token (scope `deployments:read`) sent as `Authorization: Bearer <token>`. Required when Ring enforces authentication. |
| `poll_interval` | `10` | How often, in seconds, Sōzune polls Ring. Ring has no blocking-query mechanism, so discovery is interval-based. A reload only fires when the Ring-sourced view actually changes, so a short interval is cheap. |
| `expose_by_default` | `false` | If `true`, every running deployment is a candidate even without a `sozune.enable=true` label. |

## How it works

1. Sōzune issues `GET /deployments` against the Ring API every `poll_interval` seconds. A single call returns everything needed: each deployment's `sozune.*` labels, its published `ports`, and its running `instances` (each carrying its routable guest `address`). There is no per-deployment second round-trip.
2. Only deployments with `status = "running"` are considered. Each running instance with a routable address becomes one backend, so a multi-replica deployment fans out to N backends — same host and labels, different IPs (the Nomad / Consul model).
3. Labels are parsed by the same engine that handles Docker / Swarm / Kubernetes / Nomad annotations, so `sozune validate` and the runtime stay in sync.
4. Sōzune diffs the new Ring-sourced view against the previous one and only triggers a reload when something changed (deployment added or removed, scaled, address changed).

## Labels

Set `sozune.*` labels on the Ring deployment (via the deployment manifest or the Ring CLI/API). Sōzune reads them straight from the `labels` map returned by `GET /deployments`:

```yaml
name: api
image: my-api:latest
replicas: 3
labels:
  sozune.enable: "true"
  sozune.http.web.host: "api.example.com"
  sozune.http.web.port: "8080"
```

> **Ports and replicas.** Ring forbids a `ports` block once `replicas > 1` — every replica would race for the same host port. With multiple replicas you therefore declare the backend port with an explicit `sozune.<proto>.<svc>.port` label (as above). With a single replica you may instead declare a `ports` entry, and Sōzune will use its `target` as the backend port automatically (see [Backend resolution](#backend-resolution)). Sōzune always routes to each instance's guest IP directly, never through a host-published port.

Every annotation listed under [Docker labels](/documentation/providers/docker) — host, path, headers, rate limit, basic auth, redirects, sticky sessions, compression — is supported as-is on Ring deployments.

## Backend resolution

For each running instance, Sōzune uses:

- the instance's `address` (the routable guest IP reported by Ring) as the backend IP
- the backend port, resolved in this order:
  1. an explicit `sozune.<proto>.<svc>.port` label, if set (always wins);
  2. otherwise the first `ports` entry's `target` (only possible with a single replica, since Ring forbids `ports` when `replicas > 1`);
  3. otherwise the default (`80` for HTTP), which is why a whoami-style service on port 80 routes with no port label at all.

So a single-replica deployment can rely on its `ports` entry, while a multi-replica deployment must carry an explicit `sozune.<proto>.<svc>.port` label unless its container happens to listen on the default port.

An instance with no routable `address` — typically one that is still starting up, or whose runtime could not be inspected — is skipped. It will become a backend on the next poll once Ring reports its address.

## Limitations

- **One Ring endpoint per Sōzune instance.** Point at the API of the cluster you want to route to.
- **Interval-based discovery.** Ring has no blocking-query / watch mechanism, so reaction time is bounded by `poll_interval` rather than near-instant like the Consul/Nomad providers.
- **UDP services** are recognised at the label level but not yet proxied (same caveat as the Docker provider).

## Environment variables

| Field | Env var |
|---|---|
| `providers.ring.enabled` | `SOZUNE_PROVIDER_RING_ENABLED` |
| `providers.ring.endpoint` | `SOZUNE_PROVIDER_RING_ENDPOINT` |
| `providers.ring.token` | `SOZUNE_PROVIDER_RING_TOKEN` |
| `providers.ring.poll_interval` | `SOZUNE_PROVIDER_RING_POLL_INTERVAL` |
| `providers.ring.expose_by_default` | `SOZUNE_PROVIDER_RING_EXPOSE_BY_DEFAULT` |
