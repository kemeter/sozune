# Kubernetes provider

The Kubernetes provider discovers entrypoints from two sources — `Service` annotations and standard `Ingress` resources — and routes traffic directly to ready pod IPs. Sōzune subscribes to the Kubernetes API for near-real-time updates: scaling a Deployment, rolling a pod, or deleting a Service propagates within seconds without any restart.

This is the right provider when your workloads run on a Kubernetes cluster (kind, k3s, EKS, GKE, AKS, on-prem…) and you want a Sōzu-powered ingress for them.

## Configuration

The minimal block — Sōzune auto-discovers the cluster (in-cluster `ServiceAccount` if it runs in a Pod, otherwise `$KUBECONFIG` / `~/.kube/config`) and watches every namespace it can read.

```yaml
providers:
  kubernetes:
    enabled: true
```

All fields:

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Kubernetes provider. |
| `kubeconfig` | *auto* | Path to a specific kubeconfig file. Omit to auto-discover (in-cluster ServiceAccount, otherwise `$KUBECONFIG` / `~/.kube/config`). |
| `namespace` | *all* | Restrict discovery to a single namespace. Omit to watch the whole cluster. |
| `ingress_class` | `sozune` | Match value for `Ingress.spec.ingressClassName`. Ingresses with a different (or missing) class are ignored. |
| `expose_by_default` | `false` | If `true`, every Service is a candidate even without a `sozune.*` annotation. |

### Restrict to one namespace, point at a specific kubeconfig

```yaml
providers:
  kubernetes:
    enabled: true
    kubeconfig: /home/me/.kube/staging.yaml
    namespace: production
```

## How it works

Sōzune runs three watchers in parallel:

1. **Service watcher.** Every `Service` in scope is inspected. If it carries at least one `sozune.*` annotation (or `expose_by_default` is set), it becomes a candidate. The annotations are parsed by the same engine used for Docker labels, so `sozune validate` and the runtime stay in sync.
2. **EndpointSlice watcher.** Sōzune maintains a per-service cache of ready pod IPs derived from `discovery.k8s.io/v1` `EndpointSlice` objects. Each Service or Ingress entrypoint is populated with **all** ready pod IPs as backends, so Sōzu round-robins directly between pods — bypassing kube-proxy.
3. **Ingress watcher.** Standard `networking.k8s.io/v1` Ingresses with `spec.ingressClassName` matching `ingress_class` are converted into entrypoints, one per `(rule, path)`.

When the EndpointSlice cache is empty (cold-start race, ExternalName Service, or selector-less Service), Sōzune falls back to `Service.spec.clusterIP` so traffic still flows.

## Service annotations

Annotations follow the same schema as [Docker labels](/documentation/providers/docker). Drop the `labels:` prefix and put `sozune.*` settings under `metadata.annotations` instead:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: default
  annotations:
    sozune.enable: "true"
    sozune.http.web.host: "api.example.com"
    sozune.http.web.port: "8080"
    sozune.http.web.tls: "true"
spec:
  selector:
    app: api
  ports:
    - port: 8080
      targetPort: 8080
```

Every annotation listed under [Docker labels](/documentation/providers/docker) — host, path, headers, rate limit, basic auth, redirects, sticky sessions, compression — is supported as-is on Services.

## Ingress resources

Sōzune also consumes standard `networking.k8s.io/v1` `Ingress` objects. This is the right approach when you want to use the same manifests across multiple Ingress controllers, or when you're migrating from Traefik / Nginx Ingress.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
  namespace: default
spec:
  ingressClassName: sozune
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 8080
  tls:
    - hosts:
        - api.example.com
```

- Only Ingresses with `spec.ingressClassName` matching the configured `ingress_class` are picked up. Ingresses without an `ingressClassName` are ignored.
- Each `(rule, path)` pair becomes one entrypoint. The key is `ingress_<namespace>-<name>_r<rule_idx>p<path_idx>`.
- `pathType: Prefix` and `Exact` map directly. `ImplementationSpecific` is treated as `Prefix`.
- `spec.tls[].hosts` enables HTTPS termination and triggers ACME provisioning for those hostnames.
- `spec.defaultBackend` is supported as a catch-all entrypoint with no host filter.
- Backend Services must live in the **same namespace** as the Ingress (Kubernetes spec).
- Ingresses cannot express middleware (auth, rate-limit, headers, compression…). Use Service annotations when you need those.

## Deploying Sōzune in-cluster

Run as a `Deployment` with a `ServiceAccount` bound to a `ClusterRole` that grants read access to Services, EndpointSlices, Ingresses, and Namespaces.

### Minimum RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sozune
rules:
  - apiGroups: [""]
    resources: ["services", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
  # Optional: only needed if you want HTTPRoute support.
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes", "gateways", "gatewayclasses"]
    verbs: ["get", "list", "watch"]
```

`namespaces` is only used for the start-up sanity check; if you want a strictly minimal role, drop it (Sōzune logs a warning instead of an info line).

### Reaching Sōzune from outside

Expose the Sōzune pod with a `Service` of type `LoadBalancer` (cloud) or `NodePort` (kind, on-prem). Sōzune itself listens on the ports declared under `proxy.http.listen_address` and `proxy.https.listen_address`.

## Running outside the cluster

Useful for local development. Sōzune uses the current context from `$KUBECONFIG` or `~/.kube/config` automatically; set `kubeconfig:` only if you need a specific file.

> **Heads up:** pod IPs (`10.244.x.x` on most clusters) are not routable from outside the cluster's CNI. Out-of-cluster Sōzune can therefore *discover* services correctly but cannot actually reach the backends. Use this mode for testing the discovery pipeline; deploy Sōzune in-cluster for real traffic.

## Gateway API (HTTPRoute)

Sōzune watches `gateway.networking.k8s.io/v1` resources alongside Ingress. Three watchers run side by side: `GatewayClass`, `Gateway`, and `HTTPRoute`. They are started automatically when the Kubernetes provider is enabled and the CRDs are installed; no extra configuration is required.

### Prerequisites

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
```

If the CRDs are missing, Sōzune logs `HTTPRoute CRD not installed` once and skips the Gateway watchers — Ingress alone keeps working.

### Opting in: declare a GatewayClass

Sōzune only serves `HTTPRoute`s whose chain of `parentRefs → Gateway → GatewayClass` ends at a `GatewayClass` it owns. Multi-controller clusters depend on this — without it, Sōzune would hijack routes meant for Traefik, Envoy Gateway, NGINX Gateway, and friends.

Declare a `GatewayClass` whose `spec.controllerName` is **`kemeter.io/sozune`**:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: sozune
spec:
  controllerName: kemeter.io/sozune
```

Then a `Gateway` that references it:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: gw
  namespace: default
spec:
  gatewayClassName: sozune
  listeners:
    - name: http
      port: 80
      protocol: HTTP
```

> The listener block is required by the Gateway API schema, but Sōzune currently ignores it: real listening ports stay declared via `proxy.http.listen_address` / `proxy.https.listen_address` in `config.yaml`. Wiring listeners to live ports is a planned post-MVP enhancement.

Finally, the `HTTPRoute` references the `Gateway` via `parentRefs`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
  namespace: default
spec:
  parentRefs:
    - name: gw  # same namespace; add `namespace:` for cross-ns parents
  hostnames:
    - app.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: api-svc
          port: 8080
          weight: 100
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: web-svc
          port: 80
```

Routes whose `parentRefs` point to a `Gateway` Sōzune does not own are silently ignored — you'll see them in `kubectl get httproute` but they will not produce any sōzune entrypoint. Routes with no `parentRefs` at all are also rejected (the Gateway API spec requires every Route to declare its parent).

### What's supported

- Three watchers (`GatewayClass`, `Gateway`, `HTTPRoute`) running cluster-wide and reacting to apply/delete events live.
- Multi-controller scoping via `controllerName: kemeter.io/sozune` (above).
- `spec.hostnames` — matched against the `Host` header of incoming requests.
- `spec.rules[].matches[].path` — `PathPrefix` and `Exact`. `RegularExpression` is silently skipped.
- `spec.rules[].backendRefs[]` — `Service` kind only (the default). Cross-namespace `backendRefs` honour `backendRef.namespace`.
- `backendRef.weight` — propagated to the load balancer.
- Live reconciliation — apply/update/delete of any of the three resources is reflected in routing within seconds, including when the target Service's pods come up after the route was created, or when a `Gateway` appears after the routes that depend on it.

### What's not supported (yet)

- Listener-driven port binding — the `listeners` block on `Gateway` is parsed but ignored; ports are still configured via `proxy.http.listen_address` / `proxy.https.listen_address`.
- `parentRef.sectionName` and `parentRef.port` — the route binds to the whole `Gateway`, not a specific listener.
- `status.parents[].conditions[]` reporting — `kubectl describe httproute` does not yet show "Accepted" / "ResolvedRefs" status from Sōzune.
- HTTPRoute filters (`requestRedirect`, `urlRewrite`, header modifiers, mirror) — use Service annotations or Ingress annotations until these land.
- `GRPCRoute`, `TCPRoute`, `UDPRoute`, `TLSRoute`, `ReferenceGrant`.

### How resolution works

When an `HTTPRoute` is applied, Sōzune resolves each `backendRef` to the ready pod IPs from the matching Service's `EndpointSlice`s. Sōzu requires `IpAddr` backends and refuses cluster-DNS hostnames, so a route that targets a Service with no ready endpoints registers no entrypoint and is retried every 2 seconds until the endpoints appear. Once at least one ready endpoint exists the route becomes live without any user intervention.

## ACME / Let's Encrypt

When a Service is annotated with `sozune.http.<svc>.tls=true`, or an Ingress declares `spec.tls[].hosts`, Sōzune provisions a certificate for the declared hostnames. The HTTP-01 challenge responder runs inside the Sōzune pod, so:

- Sōzune must be reachable on port 80 from the public internet for the challenge to succeed.
- `acme.certs_dir` should point to a `PersistentVolume` so issued certs survive pod restarts.

Refer to [ACME / Let's Encrypt](/documentation/tls/acme) for the full setup.

## Limitations

- **Multi-cluster.** A single Sōzune instance watches a single API server. Run one Sōzune per cluster.
- **EndpointSlice required.** Kubernetes ≥ 1.21 only — the deprecated `Endpoints` API is not consumed.
- **UDP entrypoints** are recognised at the annotation level but not yet proxied (same caveat as the Docker provider).
- **Ingress middleware not supported.** The `Ingress` API has no portable way to express auth, rate-limit, or headers. Use Service annotations when you need middleware.
- **Cross-namespace backends not supported on Ingress.** Backends must live in the same namespace as the Ingress, per the Kubernetes spec. (HTTPRoute does support cross-namespace `backendRefs`.)
- **Gateway API: HTTPRoute only.** `Gateway`, `GatewayClass`, `GRPCRoute`, `TCPRoute`, `ReferenceGrant`, and HTTPRoute filters are not yet implemented. See the Gateway API section above for details.

## Environment variables

| Field | Env var |
|---|---|
| `providers.kubernetes.enabled` | `SOZUNE_PROVIDER_KUBERNETES_ENABLED` |
| `providers.kubernetes.kubeconfig` | `SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG` |
| `providers.kubernetes.namespace` | `SOZUNE_PROVIDER_KUBERNETES_NAMESPACE` |
| `providers.kubernetes.ingress_class` | `SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS` |
| `providers.kubernetes.expose_by_default` | `SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT` |
