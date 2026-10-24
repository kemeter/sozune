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
| `namespace` | *all* | Restrict discovery to a single namespace: Services, Ingresses and the TLS Secrets their certificates come from. Gateway API resources, and the Secrets Gateway listeners name, are watched in every namespace. Omit to watch the whole cluster. |
| `ingress_class` | `sozune` | Match value for `Ingress.spec.ingressClassName`. Ingresses with a different (or missing) class are ignored. |
| `expose_by_default` | `false` | If `true`, every Service is a candidate even without a `sozune.*` annotation. |
| `publish_service` | *none* | The Service, as `namespace/name`, whose load-balancer address the Ingresses Sōzune serves get in `status.loadBalancer`, and the Gateways it owns in `status.addresses` — usually Sōzune's own `LoadBalancer` Service. Followed live (`SOZUNE_PROVIDER_KUBERNETES_PUBLISH_SERVICE`). See [Ingress status](#ingress-status). |
| `publish_addresses` | `[]` | Fixed IPs or hostnames to write there instead, for a Sōzune reached without a `LoadBalancer` Service (host network, an external load balancer). Takes precedence over `publish_service`. |

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
- `spec.tls[].hosts` enables HTTPS termination for those hostnames. With a `secretName`, they are served with the certificate of that `kubernetes.io/tls` Secret in the Ingress's namespace — the one cert-manager writes, for instance — picked up live when it is renewed, and ACME orders nothing for them. Without one, ACME provisions their certificate. A Secret that is missing or unusable (expired, key not matching) leaves those hostnames without a certificate: their handshakes fail, and ACME does not step in. Sōzune needs to read Secrets for this (see [Minimum RBAC](#minimum-rbac)). An ACME wildcard declared in a resolver's `domains` still covers such a hostname: Sōzu then presents whichever of the two certificates expires later.
- `spec.defaultBackend` is supported as a catch-all entrypoint with no host filter.
- Backend Services must live in the **same namespace** as the Ingress (Kubernetes spec).
- Middleware (auth, rate limit, headers, compression…) goes in `sozune.*` annotations on the Ingress: see below.

### Ingress annotations

The `Ingress` API has no field for middleware, so its annotations carry it. They take the keys of a [Service annotation](#service-annotations) without the `http.<service>` part — `sozune.http.<service>.auth.basic` becomes `sozune.auth.basic` — and apply to every route of the Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    sozune.auth.basic: "admin:$2y$05$..."
    sozune.ratelimit.average: "20"
    sozune.headers.response.X-Frame-Options: DENY
    sozune.compress: "true"
spec:
  ingressClassName: sozune
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
```

The route itself comes from the spec: `sozune.host`, `port`, `path`, `prefix`, `pathRegex`, `tls`, `entrypoint`, `sni` and `weight` are ignored with a `W013` warning. An unknown or malformed annotation is reported like a label, under its own name, in `GET /diagnostics`.

### Ingress status

Tools that wait on an Ingress read where it is reachable from its `status.loadBalancer`: external-dns creates its DNS records from it, Argo CD only calls an Ingress healthy once it is set. Sōzune writes it on the Ingresses it serves when `publish_service` or `publish_addresses` is set:

```yaml
providers:
  kubernetes:
    enabled: true
    publish_service: sozune/sozune   # the LoadBalancer Service in front of Sōzune
```

The Gateways Sōzune owns get the same addresses in `status.addresses`, typed `IPAddress` or `Hostname`, which external-dns reads for Gateways too.

With `publish_service`, the Ingresses get the addresses that Service's load balancer was given, updated when they change. With `publish_addresses`, they get those addresses, an IP as `ip` and anything else as `hostname`. An Ingress Sōzune stops serving keeps the status it had. Sōzune needs to update `ingresses/status` for this (see [Minimum RBAC](#minimum-rbac)).

## Deploying Sōzune in-cluster

### With the Helm chart

The chart in [`charts/sozune`](https://github.com/kemeter/sozune/tree/main/charts/sozune) deploys Sōzune with its `ServiceAccount`, RBAC, config and a `LoadBalancer` Service:

```bash
helm install sozune ./charts/sozune --namespace sozune --create-namespace
```

| Value | Default | What it does |
|---|---|---|
| `config` | Kubernetes provider on, HTTP on `8080`, HTTPS on `8443`, API off | Sōzune's `config.yaml`, stored in a Secret since it can hold credentials. The chart sets the provider's `ingress_class` and, with a `LoadBalancer` Service, its `publish_service`; everything else is yours. A change rolls the pods. |
| `ingressClass.create` / `ingressClass.name` | `true` / `sozune` | Creates the `IngressClass` Sōzune serves. `ingressClass.default` makes it the cluster's default. |
| `gatewayClass.create` / `gatewayClass.name` | `false` / `sozune` | Creates the `GatewayClass` (`controllerName: kemeter.io/sozune`). Needs the Gateway API CRDs. |
| `rbac.gatewayAPI` | `true` | Lets Sōzune watch the Gateway API resources and write their status. |
| `rbac.secrets` | `true` | Lets Sōzune read `kubernetes.io/tls` Secrets, for Ingress `secretName` and Gateway HTTPS listeners. |
| `service.extraPorts` | `[]` | More Service ports for TCP and UDP listeners (`proxy.tcp`, `proxy.udp`, `proxy.gateway_ports`): `{name, port, targetPort, protocol}`. |
| `service.type` | `LoadBalancer` | With `LoadBalancer` and `service.publishAddress`, the Ingresses Sōzune serves get the Service's address in their status ([Ingress status](#ingress-status)). |
| `persistence.enabled` | `false` | Keeps the ACME certificates (`/etc/sozune/certs`) on a `PersistentVolumeClaim` instead of an `emptyDir`. Turn it on with ACME. |
| `image.tag` | `edge` | The Sōzune image, from `ghcr.io/kemeter/sozune`. The chart relies on features of the next release: until it is out, it runs `edge`, the current state of `main`, pulled on every start and scheduled on `amd64` nodes (`nodeSelector`), the only architecture it is built for. |
| `replicaCount` | `1` | Pods. Must stay `1` with ACME: each pod keeps its own challenge tokens. With ACME or `persistence.enabled`, an upgrade stops the old pod before starting the new one. |

The pod runs as the image's `nonroot` user with a read-only root filesystem, which is why Sōzune listens on `8080` / `8443` and the Service maps `80` / `443` to them.

The `IngressClass` and `GatewayClass` are cluster-wide: a second release in the same cluster sets its own `ingressClass.name` (and `gatewayClass.name`), or `ingressClass.create=false` to serve the class the first one created.

### By hand

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
  # Optional: only needed with publish_service or publish_addresses, to write
  # the Ingresses' status.loadBalancer.
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses/status"]
    verbs: ["update", "patch"]
  # Optional: only needed if you want Gateway API support. `tlsroutes`,
  # `tcproutes` and `udproutes` are only consulted when their (experimental)
  # CRDs are installed; without the permission Sōzune logs a warning and skips
  # that watcher.
  - apiGroups: ["gateway.networking.k8s.io"]
    resources:
      [
        "httproutes",
        "tlsroutes",
        "tcproutes",
        "udproutes",
        "gateways",
        "gatewayclasses",
        "referencegrants",
      ]
    verbs: ["get", "list", "watch"]
  # Optional: only needed for Gateway API status reporting (kubectl
  # describe will show sōzune's conditions: Accepted/ResolvedRefs on
  # HTTPRoutes, Accepted/Programmed on Gateways and their listeners, Accepted
  # on GatewayClasses).
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes/status", "gateways/status", "gatewayclasses/status"]
    verbs: ["update", "patch"]
  # Optional: only needed for an Ingress `spec.tls[].secretName` and for
  # Gateway HTTPS listeners, which read their certificates from
  # `kubernetes.io/tls` Secrets. Sōzune only watches Secrets of that type;
  # without this rule it logs a warning and serves no such certificate.
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
```

`namespaces` is used for the start-up sanity check and, with the Gateway API, for listeners admitting routes by namespace selector (`allowedRoutes.namespaces.from: Selector`). Without it Sōzune logs a warning, and such listeners admit no route.

### Reaching Sōzune from outside

Expose the Sōzune pod with a `Service` of type `LoadBalancer` (cloud) or `NodePort` (kind, on-prem). Sōzune itself listens on the ports declared under `proxy.http.listen_address` and `proxy.https.listen_address`.

## Running outside the cluster

Useful for local development. Sōzune uses the current context from `$KUBECONFIG` or `~/.kube/config` automatically; set `kubeconfig:` only if you need a specific file.

> **Heads up:** pod IPs (`10.244.x.x` on most clusters) are not routable from outside the cluster's CNI. Out-of-cluster Sōzune can therefore *discover* services correctly but cannot actually reach the backends. Use this mode for testing the discovery pipeline; deploy Sōzune in-cluster for real traffic.

## Gateway API (HTTPRoute)

Sōzune watches `gateway.networking.k8s.io` resources alongside Ingress. Five watchers run side by side: `GatewayClass`, `Gateway`, `ReferenceGrant`, `HTTPRoute`, and `TLSRoute` (see [Gateway API (TLSRoute)](#gateway-api-tlsroute)). They are started automatically when the Kubernetes provider is enabled and the CRDs are installed; no extra configuration is required. The `TLSRoute` watcher exits quietly when its CRD — experimental-channel only — is absent.

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

> The listener block is honoured for route selection and hostname narrowing, but not for the actual listening port: real listening ports stay declared via `proxy.http.listen_address` / `proxy.https.listen_address` in `config.yaml`. A `parentRef` can target a specific listener with `sectionName` (matched against a listener `name`) or `port`, and a listener's `hostname` narrows which of a route's hostnames it serves. Binding traffic on the listener's own `port` (multiple live HTTP ports from one Gateway) is a separate, planned enhancement.

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

### HTTPS listeners

An `HTTPS` listener terminates TLS for the HTTPRoutes attached to it, with the certificates its `tls.certificateRefs` name: `kubernetes.io/tls` Secrets in the Gateway's namespace, or in another one whose `ReferenceGrant` lets Gateways of the Gateway's namespace reference them:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: shared-certificates
  namespace: certificates        # where the Secret lives
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: Gateway
      namespace: default         # the Gateway's namespace
  to:
    - group: ""
      kind: Secret
      name: example-com-tls      # omit to open every Secret of the namespace
```

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
    - name: https
      port: 443
      protocol: HTTPS
      hostname: "*.example.com"
      tls:
        mode: Terminate   # the default
        certificateRefs:
          - name: example-com-tls   # a kubernetes.io/tls Secret
```

- Its routes are served on `proxy.https.listen_address`, as an `HTTP` listener's are on `proxy.http.listen_address`. Sōzu picks the certificate by the SNI of each handshake.
- A hostname the route's `HTTPS` listeners admit and its `HTTP` listeners do too is served over both. One only an `HTTPS` listener admits is served over HTTPS, and its plain HTTP requests are redirected there, to the listener's `port` (none in the URL for `443`).
- A Secret that is renewed, by cert-manager for instance, is picked up live. A certificate no Gateway references any more, because its Secret, listener or Gateway went away, is no longer served.
- ACME never orders a certificate for a Gateway route: its certificate comes from the Secret.
- Sōzune needs to read Secrets for this (see [Minimum RBAC](#minimum-rbac)). It only watches those of type `kubernetes.io/tls`.

A listener whose certificateRefs cannot be used says so in its status (see [Status conditions](#status-conditions)): `ResolvedRefs=False` with `InvalidCertificateRef` for a missing Secret, one of another type or kind, or one whose certificate is expired (checked every minute, so a certificate expiring unrenewed is caught) or does not match its key, and `RefNotPermitted` for a Secret in another namespace that no `ReferenceGrant` opens to the Gateway. The references that resolve are still served. A listener left with no usable certificate serves no route over HTTPS, and redirects none there: its routes come back once a Secret it names is fixed.

Routes whose `parentRefs` point to a `Gateway` Sōzune does not own are silently ignored — you'll see them in `kubectl get httproute` but they will not produce any sōzune entrypoint. Routes with no `parentRefs` at all are also rejected (the Gateway API spec requires every Route to declare its parent).

### What's supported

- Three watchers (`GatewayClass`, `Gateway`, `HTTPRoute`) running cluster-wide and reacting to apply/delete events live.
- Multi-controller scoping via `controllerName: kemeter.io/sozune` (above).
- `spec.hostnames` — matched against the `Host` header of incoming requests, and narrowed by the bound listener's `hostname` (a listener serving `*.example.com` drops a route hostname outside that suffix). A route with none, on a listener with none, serves every host, after the routes naming theirs. A wildcard takes one or more labels, as the spec says: `*.example.com` serves `a.b.example.com` too, unlike a Sōzune label's `*.`.
- `backendRef.port` — the Service port; requests go to the port its pods listen on (its `targetPort`), as its EndpointSlices give it.
- `parentRef.sectionName` / `parentRef.port` — bind the route to a specific `Gateway` listener (by listener `name` or `port`). A ref naming a listener the Gateway doesn't have is refused; an unset `sectionName` and `port` bind to the whole Gateway (any listener), as before.
- Listener `allowedRoutes` — only listeners that admit the route take it (see [below](#which-routes-a-listener-admits-allowedroutes)).
- `spec.rules[].matches[].path` — `PathPrefix` and `Exact`. `RegularExpression` is silently skipped.
- `spec.rules[].matches[].headers[]`, `matches[].queryParams[]`, `matches[].method` — a match can additionally require specific request headers, query parameters, and/or an HTTP method. Within one match these are ANDed with the path (and with each other). Header matches are routing conditions: a request that fails them goes on to the next rule or route, and a rule whose header matches hold is tried before every rule without any, whatever their path. Among rules on the same host and path, one with a method is tried first, then the one with more header matches. A request that fails a query or method condition, or a header match on `Host` or `Cookie` (which Sōzu cannot route on), gets `404`. Header and query matches support `type: Exact` (the default) and presence-only (empty value); `type: RegularExpression` on a header or query match has no faithful representation and the whole route is rejected with `ResolvedRefs=False reason=UnsupportedValue` rather than served too broadly. All nine standard methods are supported.
- Multiple `matches` per rule — Gateway API treats them as OR, so each match becomes its own sōzune entrypoint sharing the rule's backends.
- `spec.rules[].backendRefs[]` — `Service` kind only (the default). Cross-namespace `backendRefs` (`backendRef.namespace` differs from the route's namespace) require a `ReferenceGrant` in the target namespace; without one the backend is dropped (see [Cross-namespace backends](#cross-namespace-backends-referencegrant) below). A backendRef that cannot be used — another kind, another namespace without a grant, a Service that does not exist — is left out of its rule, and a rule left with none, or declaring none, answers `500`, as the spec requires — unless it redirects, which needs no backend; the route's `ResolvedRefs` says why (see [Status conditions](#status-conditions)).
- `backendRef.weight` — the Service's share of the rule's traffic, as the spec defines it: `weight / Σ weights`, however many pods each Service runs (a Service of 3 pods weighted 90 against one of 1 pod weighted 10 is a 90/10 split). An unset weight is `1`; a weight of `0` sends the Service no traffic, and a rule whose backendRefs all weigh `0` forwards nothing (`503`). Each pod carries an integer weight of at most 2³¹−1, so a Service cannot outweigh another by more than 2³¹−1 times the other's pod count: a ratio past that is capped.
- `spec.rules[].filters[]` — `requestRedirect`, `requestHeaderModifier`, `responseHeaderModifier`, `urlRewrite` (see [HTTPRoute filters](#httproute-filters) below). `requestMirror`, `extensionRef` are not supported yet.
- Live reconciliation — apply/update/delete of any of the three resources is reflected in routing within seconds, including when the target Service's pods come up after the route was created, or when a `Gateway` appears after the routes that depend on it.
- Status reporting — Sōzune writes standard conditions back onto the resources it owns, visible via `kubectl describe` / `kubectl get`:
  - `HTTPRoute` — for every `parentRef` Sōzune owns, `status.parents[]` carries `Accepted` and `ResolvedRefs` (`controllerName: kemeter.io/sozune`). Other controllers' entries are preserved untouched.
  - `Gateway` — `status.conditions[]` carries `Accepted` and `Programmed`, both reflecting whether Sōzune owns the Gateway's `GatewayClass`.
  - `GatewayClass` — `status.conditions[]` carries `Accepted` on classes whose `controllerName` is `kemeter.io/sozune`.

### Status conditions

**HTTPRoute** (`status.parents[].conditions[]`):

| Condition | Status | Reason | When |
|---|---|---|---|
| `Accepted` | `True` (`Accepted`) | Route is in scope (parent owned), filters are OK |
| `Accepted` | `False` (`UnsupportedValue`) | Route declares unsupported filters |
| `Accepted` | `False` (`NotAllowedByListeners`) | The `parentRef` names a Gateway Sōzune owns, but none of the listeners it selects is an `HTTP` or `HTTPS` listener that admits the route (see [`allowedRoutes`](#which-routes-a-listener-admits-allowedroutes)) |
| `Accepted` | `False` (`NoMatchingParent`) | The `parentRef`'s `sectionName` / `port` names no listener of a Gateway Sōzune owns |
| `Accepted` | `False` (`NoMatchingListenerHostname`) | No listener the route binds to admits any of its `hostnames` |
| `ResolvedRefs` | `True` (`ResolvedRefs`) | All backendRefs resolved to ready endpoints |
| `ResolvedRefs` | `False` (`InvalidKind`) | A backendRef is not a `Service` |
| `ResolvedRefs` | `False` (`RefNotPermitted`) | A backendRef names a Service of another namespace that no `ReferenceGrant` opens to the route |
| `ResolvedRefs` | `False` (`BackendNotFound`) | A backendRef names a Service that does not exist, or one or more backendRefs has no ready endpoint yet — sōzune retries every 2 s |
| `ResolvedRefs` | `False` (`UnsupportedValue`) | Route was rejected because of unsupported filters |

`ResolvedRefs` is reported for a parent that refuses the route too: it speaks of the route's backendRefs, not of the parent.

Routes whose parent is not sōzune-owned receive **no status entry** from sōzune (per Gateway API spec — implementations only report on parents they own).

**Gateway** (`status.conditions[]`):

| Condition | Status | Reason | When |
|---|---|---|---|
| `Accepted` | `True` (`Accepted`) | Gateway's `gatewayClassName` points at a class sōzune owns |
| `Programmed` | `True` (`Programmed`) | Same instant as acceptance — sōzune does not stage programming |

With `publish_service` or `publish_addresses` set, `status.addresses` carries Sōzune's address (see [Ingress status](#ingress-status)).

**Gateway listeners** (`status.listeners[]`), one entry per listener:

- `supportedKinds` — the route kind the listener carries: `HTTPRoute` for `HTTP` and `HTTPS`, `TLSRoute` for `TLS`, `TCPRoute` for `TCP`, `UDPRoute` for `UDP`; none when its `allowedRoutes.kinds` leaves that kind out.
- `attachedRoutes` — how many routes select the listener through their `parentRefs` (by `sectionName`/`port`, or all of a Gateway's listeners when neither is set) and are admitted by its `allowedRoutes` and its `hostname`, whether or not the routes are accepted.

| Condition | Status | Reason | When |
|---|---|---|---|
| `Accepted`, `Programmed` | `True` (`Accepted`, `Programmed`) | An `HTTP` listener, whatever its port: its routes are served on `proxy.http.listen_address`, which a Service usually maps the listener's port to — the message names that port. An `HTTPS` listener likewise, on `proxy.https.listen_address`, when its certificateRefs resolve. A `TLS`/`TCP` listener on the port of a `proxy.tcp` entry or of `proxy.gateway_ports.tcp`, a `UDP` one on the port of a `proxy.udp` entry or of `proxy.gateway_ports.udp` |
| `Accepted`, `Programmed` | `False` (`PortUnavailable`, `Invalid`) | A `TLS`, `TCP` or `UDP` listener on a port no `proxy.tcp` / `proxy.udp` entry listens on and `proxy.gateway_ports` does not list — the message names the settings to change — or a port of `proxy.gateway_ports` Sōzune could not open, with the reason |
| `ResolvedRefs` | `True` (`ResolvedRefs`) | The listener's `allowedRoutes.kinds` is unset, or only lists the kind it carries, and an `HTTPS` listener's certificateRefs all resolve |
| `ResolvedRefs` | `False` (`InvalidRouteKinds`) | `allowedRoutes.kinds` lists a kind the listener's protocol cannot carry. If it leaves out the one it can, `Programmed` is `False` (`Invalid`) too: no route attaches |
| `ResolvedRefs` | `False` (`InvalidCertificateRef`, `RefNotPermitted`) | An `HTTPS` listener's certificateRef cannot be used (see [HTTPS listeners](#https-listeners)); `Programmed` is `False` (`Invalid`) too |
| `Accepted`, `Programmed` | `False` (`UnsupportedProtocol`, `Invalid`) | An `HTTPS` listener in `Passthrough` mode (that belongs on a `TLS` listener), a `TLS` listener in `Terminate` mode (TLSRoutes need `Passthrough`), or any other protocol |

**GatewayClass** (`status.conditions[]`):

| Condition | Status | Reason | When |
|---|---|---|---|
| `Accepted` | `True` (`Accepted`) | `spec.controllerName` is `kemeter.io/sozune` |

Gateways and GatewayClasses that belong to another controller receive **no status entry** from sōzune.

### Which routes a listener admits (allowedRoutes)

A listener only takes the routes its `allowedRoutes` admits, for every route kind (HTTPRoute, TLSRoute, TCPRoute, UDPRoute). An HTTPRoute only attaches through `HTTP` listeners, a TLSRoute through `TLS` ones, and so on:

| Field | Behaviour |
|---|---|
| `namespaces.from: Same` (the default) | Routes in the Gateway's own namespace only. |
| `namespaces.from: All` | Routes in any namespace. |
| `namespaces.from: Selector` | Routes in the namespaces whose labels match `namespaces.selector` (`matchLabels` and `matchExpressions` with `In`, `NotIn`, `Exists`, `DoesNotExist`), followed live as namespaces are relabelled. A missing selector, or one with another operator, admits no route. Sōzune needs to list and watch namespaces for this (see [Minimum RBAC](#minimum-rbac)). |
| `kinds` | Only the listed route kinds (group `gateway.networking.k8s.io`). Unset or empty, the listener's protocol decides. |

A route in another namespace that names a Gateway therefore needs `from: All` on the listeners it should attach to:

```yaml
listeners:
  - name: http
    protocol: HTTP
    port: 80
    allowedRoutes:
      namespaces:
        from: All
```

A `parentRef` none of whose listeners admits the route is not served; an HTTPRoute reports it with `Accepted=False` (`NotAllowedByListeners`).

### Cross-namespace backends (ReferenceGrant)

An `HTTPRoute` may reference a `Service` in another namespace via `backendRef.namespace`. Per the Gateway API spec, the *target* namespace must opt in with a `ReferenceGrant`: without one, the reference is a potential privilege escalation (any route author could route traffic to any Service cluster-wide), so Sōzune **drops** the backend and logs a `WARN`. Same-namespace references never need a grant.

The grant lives in the namespace that owns the `Service` and names the route's namespace as trusted:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-frontend-routes
  namespace: backend        # the Service's namespace
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: frontend   # the HTTPRoute's namespace
  to:
    - group: ""
      kind: Service
```

With this applied, an `HTTPRoute` in `frontend` may target a `Service` in `backend`. Removing the grant revokes access on the next reconcile (the route falls back to `ResolvedRefs=False` with `RefNotPermitted` once the backend is dropped, and a rule left without backend answers `500`). Grants naming a non-`Service` `to` kind (e.g. `Secret`) do not authorise backendRefs. A `to` entry with a `name` opens that Service only.

### What's not supported (yet)

- Listener-driven port binding — a `parentRef`'s `sectionName`/`port` selects a listener and a listener `hostname` narrows route hostnames (both honoured), but traffic is still served on the ports from `proxy.http.listen_address` / `proxy.https.listen_address`, not on each listener's own `port`. The listener's status names the port its routes are served on. Serving multiple live HTTP ports from one Gateway is a separate, planned enhancement.
- HTTPRoute `filters` `requestMirror` and `extensionRef`. Declaring one of these (or a `requestRedirect` we can't represent, or `requestRedirect` combined with `urlRewrite` on the same rule, see below) causes Sōzune to drop the entire route with a `WARN` log line and surface `Accepted=False reason=UnsupportedValue` in the route status. Routing it as if the filter weren't there would silently rewrite user intent. Use Service or Ingress annotations until support lands. (`requestRedirect`, `requestHeaderModifier`, `responseHeaderModifier`, and `urlRewrite` **are** supported — see [HTTPRoute filters](#httproute-filters).)
- `GRPCRoute`.
- A `backendRef` that is invalid (an unsupported kind, a cross-namespace ref with no `ReferenceGrant`) is left out of the rule, and its share of the traffic goes to the other backends. The spec asks for that share to be answered with `500`.

### HTTPRoute filters

| Filter | Supported | Notes |
|---|---|---|
| `requestRedirect` | Yes | Native frontend redirect; `replacePrefixMatch` is dropped (see below) |
| `requestHeaderModifier` | Yes | `set`, `add` and `remove` map directly (see below) |
| `responseHeaderModifier` | Yes | Same as above, on the response |
| `urlRewrite` | Yes | Transparent path/host rewrite (no redirect); `ReplaceFullPath`, `ReplacePrefixMatch`, `hostname` (see below) |
| `requestMirror` | No | Route dropped with `Accepted=False reason=UnsupportedValue` |
| `extensionRef` | No | Route dropped with `Accepted=False reason=UnsupportedValue` |

A rule may combine a header modifier with **either** a `requestRedirect` **or** a `urlRewrite` (e.g. a `requestRedirect` together with a `requestHeaderModifier`); all are honoured together. `requestRedirect` and `urlRewrite` **conflict** — one redirects the client, the other transparently rewrites the forwarded request, and both target the same frontend rewrite — so a rule carrying both is rejected. A rule carrying any unsupported filter drops the whole route.

#### requestRedirect

Sōzune maps the `requestRedirect` filter onto Sōzu's native frontend redirect — no extra middleware hop. A rule may declare a redirect alongside its `backendRefs`:

```yaml
rules:
  - matches:
      - path:
          type: PathPrefix
          value: /
    filters:
      - type: RequestRedirect
        requestRedirect:
          scheme: https      # http→https is the common case
          hostname: new.example.com   # optional
          port: 8443                  # optional
    backendRefs:
      - name: web-svc
        port: 80
```

| `requestRedirect` field | Mapped to | Notes |
|---|---|---|
| `scheme` (`http` / `https`) | redirect scheme | omitted → preserve the request scheme |
| `statusCode` | redirect policy | `301` (default) → permanent redirect, `302` → temporary redirect |
| `hostname` | `rewrite_host` | rewrites the `Location` authority |
| `port` | `rewrite_port` | rewrites the `Location` port |
| `path.replaceFullPath` | `rewrite_path` | replaces the whole `Location` path with a fixed value |
| `path.replacePrefixMatch` | — | **not supported**: keeping the request's trailing segments needs a path capture Sōzune doesn't set up for redirect rules, so the route is dropped |

A `requestRedirect` declaring only supported fields is honoured; one using `replacePrefixMatch` is treated as unsupported and the whole route is dropped (`Accepted=False reason=UnsupportedValue`).

#### urlRewrite

Unlike `requestRedirect`, the `urlRewrite` filter is **transparent**: the backend receives the rewritten request and the client sees no redirect. It maps onto Sōzu's native frontend `rewrite_path` / `rewrite_host` — no extra middleware hop.

```yaml
rules:
  - matches:
      - path:
          type: PathPrefix
          value: /api
    filters:
      - type: URLRewrite
        urlRewrite:
          hostname: internal.svc          # optional: rewrites the Host header
          path:
            type: ReplacePrefixMatch      # or ReplaceFullPath
            replacePrefixMatch: /v2
    backendRefs:
      - name: api-svc
        port: 80
```

| `urlRewrite` field | Mapped to | Notes |
|---|---|---|
| `hostname` | `rewrite_host` | rewrites the forwarded request's `Host` header to a fixed authority |
| `path.replaceFullPath` | `rewrite_path` | replaces the whole request path with a fixed value, regardless of trailing segments (`/api/users` with `ReplaceFullPath: /new` → `/new`) |
| `path.replacePrefixMatch` | `rewrite_path` | swaps the matched prefix and **keeps** the trailing segments (`/api/users` with prefix `/api`, `ReplacePrefixMatch: /v2` → `/v2/users`; `/api` exactly → `/v2`). Only meaningful with a `PathPrefix` match |

When set, `urlRewrite` takes precedence over the `strip_prefix` / `add_prefix` Service-annotation knobs. `urlRewrite` cannot be combined with `requestRedirect` on the same rule (the route is dropped).

#### requestHeaderModifier / responseHeaderModifier

Header modifiers map onto Sōzu's native frontend header edits — no extra middleware hop. `requestHeaderModifier` edits the request before it reaches the backend; `responseHeaderModifier` edits the response on the way back.

```yaml
rules:
  - filters:
      - type: RequestHeaderModifier
        requestHeaderModifier:
          set:
            - name: X-Env
              value: prod
          remove:
            - X-Debug
      - type: ResponseHeaderModifier
        responseHeaderModifier:
          set:
            - name: X-Powered-By
              value: sozune
    backendRefs:
      - name: web-svc
        port: 80
```

| Field | Mapped to | Notes |
|---|---|---|
| `set` | header set | overwrites the header with the given value |
| `remove` | header delete | maps to an empty-value frontend edit, which deletes the header |
| `add` | header append | adds the value next to the header's existing ones, which the backend reads as `existing,added` |

A `set` or `add` with an empty value cannot be represented — Sōzu reads an empty value as a delete — so it drops the route (`Accepted=False reason=UnsupportedValue`).

### How resolution works

When an `HTTPRoute` is applied, Sōzune resolves each `backendRef` to the ready pod IPs from the matching Service's `EndpointSlice`s. Sōzu requires `IpAddr` backends and refuses cluster-DNS hostnames, so a route that targets a Service with no ready endpoints registers no entrypoint and is retried every 2 seconds until the endpoints appear. Once at least one ready endpoint exists the route becomes live without any user intervention.

## Gateway API (TLSRoute)

`TLSRoute` routes TLS connections to different backends by the server name in the ClientHello, **without decrypting**. The client's handshake completes with the backend, against the backend's own certificate. Use it when the backend must own its certificates: end-to-end encryption to the service, a tenant terminating its own TLS, or a protocol Sōzune does not speak.

`TLSRoute` is `v1alpha2` and ships only in the Gateway API **experimental** channel. Sōzune probes for the CRD at startup and skips the watcher when it is absent, so a cluster with only the standard bundle installed is unaffected.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: tlsgw
spec:
  gatewayClassName: sozune
  listeners:
    - name: passthrough
      protocol: TLS
      port: 8443
      tls:
        mode: Passthrough
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: my-passthrough
spec:
  parentRefs:
    - name: tlsgw
      sectionName: passthrough
  hostnames:
    - app.example.com
  rules:
    - backendRefs:
        - name: my-service
          port: 8443
```

### Which ports a Gateway is served on

A Gateway listener on port `8443` is served in one of two cases:

- **A `proxy.tcp` entry listens on that port.** Sōzune binds it at startup, and the entry's settings (`ip_allow_list`, `rate_limit`, `idle_timeout`, …) apply to the Gateway's routes.
- **`proxy.gateway_ports.tcp` lists the port.** Sōzune opens it once a route is served on the listener, and closes it when no route is left. Nothing else can open a port: the list is how you choose which ones a Gateway may take.

```yaml
proxy:
  tcp:
    - name: tlsgw
      listen: 8443
  # Ports a Gateway may open on its own: single ports or inclusive ranges.
  gateway_ports:
    tcp: [5432, "9000-9099"]
    udp: ["5300-5399"]
```

A declared entry wins when both apply. A port opened from `gateway_ports` has none of the entry settings: declare a `proxy.tcp` entry to filter or rate-limit it.

A `TLSRoute` on a port in neither is tracked but not served: Sōzune logs which port it wanted, and the Gateway's listener status says `PortUnavailable` (see [Status conditions](#status-conditions)). Declare the listener or list the port and the route goes live on the next reload, with no need to re-apply it. If a listed port cannot be bound, because another process holds it, the listener status says `PortUnavailable` with the reason, and Sōzune tries again on the next reload.

### What is supported

| Aspect | Behaviour |
|---|---|
| `tls.mode` | `Passthrough` only. `Terminate` means the Gateway decrypts, which is what [`HTTPS` listeners](#https-listeners) do for HTTPRoutes — such a `TLS` listener is ignored here. |
| `hostnames` | Each becomes one SNI route. Exact names and a single leading `*.` wildcard label, per spec. A route with no hostname serves nothing: there is no name to match a ClientHello against. |
| Listener `hostname` | Intersected with the route's hostnames, exactly as for HTTPRoute. |
| `backendRefs` | Service-typed, resolved to ready pod IPs. Cross-namespace refs need a [`ReferenceGrant`](#cross-namespace-backends-referencegrant). `weight` is the Service's share, divided between its pods; unset is `1`, `0` sends no traffic. |
| `parentRefs` | `sectionName` and `port` select a listener, as for HTTPRoute, among those whose [`allowedRoutes`](#which-routes-a-listener-admits-allowedroutes) admit the route. A route may bind listeners on several ports; each serves only the names its own `hostname` admits. |
| Invalid hostnames | A name Sōzu could not route (a wildcard beyond one leading `*.` label, `/`, an empty label, non-ASCII) is dropped with a warning; the route's other names still serve. |
| Unmatched SNI | Dropped. Once a listener carries SNI routes there is no catch-all — declare a route for every name you serve. See [Route by SNI](/documentation/routing/tcp#route-by-sni-tls-passthrough). |

`TLSRoute` has no matches, filters or paths — the SNI is the whole routing decision — so none of the HTTPRoute filter machinery applies.

## Gateway API (TCPRoute)

`TCPRoute` forwards a whole listener port to its backends — plain TCP, no SNI, no TLS, no matching. It is the raw-TCP counterpart to TLSRoute: where TLSRoute routes by the name in the ClientHello, TCPRoute routes nothing and hands the entire connection to its backend.

`TCPRoute` is `v1alpha2` and ships only in the Gateway API **experimental** channel; the watcher probes for the CRD and skips quietly when it is absent.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: tcpgw
spec:
  gatewayClassName: sozune
  listeners:
    - name: raw
      protocol: TCP
      port: 5432
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: my-db
spec:
  parentRefs:
    - name: tcpgw
      sectionName: raw
  rules:
    - backendRefs:
        - name: postgres
          port: 5432
```

### Which ports a Gateway is served on

Exactly as for TLSRoute: the Gateway's `TCP` listener port must match a `proxy.tcp` entry in `config.yaml`, or be listed in `proxy.gateway_ports.tcp` (see [Which ports a Gateway is served on](#which-ports-a-gateway-is-served-on)). A route on any other port is tracked but not served — the listener status says `PortUnavailable` — and goes live on the next reload once the port is declared or listed.

```yaml
proxy:
  tcp:
    - name: tcpgw
      listen: 5432
```

### What is supported

| Aspect | Behaviour |
|---|---|
| Listener | `protocol: TCP` only. A `TLS` or `HTTP` listener is ignored by TCPRoutes. |
| Routing | None — the whole port goes to the backend. One rule → one entrypoint. No hostnames, matches, or filters (a TCPRoute has none). |
| `backendRefs` | Service-typed, resolved to ready pod IPs. Cross-namespace refs need a [`ReferenceGrant`](#cross-namespace-backends-referencegrant). `weight` is the Service's share, divided between its pods; unset is `1`, `0` sends no traffic. |
| `parentRefs` | `sectionName` and `port` select a listener, among those whose [`allowedRoutes`](#which-routes-a-listener-admits-allowedroutes) admit the route. A route may bind listeners on several ports; each gets its own entrypoint. |

## Gateway API (UDPRoute)

`UDPRoute` is the datagram counterpart to TCPRoute: it forwards a whole UDP listener port to its backends. Same shape, same constraints — the only difference is the listener protocol (`UDP`) and that it resolves against `proxy.udp` listeners rather than `proxy.tcp`.

`UDPRoute` is `v1alpha2`/experimental; the watcher probes for the CRD and skips quietly when it is absent.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: udpgw
spec:
  gatewayClassName: sozune
  listeners:
    - name: dns
      protocol: UDP
      port: 53
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: my-dns
spec:
  parentRefs:
    - name: udpgw
      sectionName: dns
  rules:
    - backendRefs:
        - name: coredns
          port: 53
```

The Gateway's `UDP` listener port must match a `proxy.udp` entry in `config.yaml`, or be listed in `proxy.gateway_ports.udp`, exactly as TCPRoute requires a `proxy.tcp` entry or a port of `proxy.gateway_ports.tcp`:

```yaml
proxy:
  udp:
    - name: dns
      listen: 53
```

Support is the same as TCPRoute — one catch-all entrypoint per rule, Service-typed backends, `ReferenceGrant` for cross-namespace, no hostnames or filters — on a `UDP` listener.

## ACME / Let's Encrypt

When a Service is annotated with `sozune.http.<svc>.tls=true`, or an Ingress declares `spec.tls[].hosts`, Sōzune provisions a certificate for the declared hostnames. The HTTP-01 challenge responder runs inside the Sōzune pod, so:

- Sōzune must be reachable on port 80 from the public internet for the challenge to succeed.
- `acme.certs_dir` should point to a `PersistentVolume` so issued certs survive pod restarts.

Refer to [ACME / Let's Encrypt](/documentation/tls/acme) for the full setup.

## Limitations

- **Multi-cluster.** A single Sōzune instance watches a single API server. Run one Sōzune per cluster.
- **EndpointSlice required.** Kubernetes ≥ 1.21 only — the deprecated `Endpoints` API is not consumed.
- **UDP entrypoints** are recognised at the annotation level but not yet proxied (same caveat as the Docker provider).
- **Cross-namespace backends not supported on Ingress.** Backends must live in the same namespace as the Ingress, per the Kubernetes spec. (HTTPRoute supports cross-namespace `backendRefs` when authorised by a [`ReferenceGrant`](#cross-namespace-backends-referencegrant).)
- **Gateway API: `GRPCRoute` and the `requestMirror` / `extensionRef` HTTPRoute filters are not yet implemented.** `GatewayClass`, `Gateway`, `HTTPRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute` and `ReferenceGrant` are supported, as are the `requestRedirect`, `requestHeaderModifier`, `responseHeaderModifier`, and `urlRewrite` filters. See the Gateway API section above for details.
- **TLSRoute, TCPRoute and UDPRoute serve on a port you allow.** The listener's port must be bound by a `proxy.tcp` / `proxy.udp` entry, or listed in `proxy.gateway_ports` — Sōzune opens no other port from a Gateway. TLSRoute is `Passthrough` only (`tls.mode: Terminate` is out of scope, that is what [`HTTPS` listeners](#https-listeners) are for). See [Gateway API (TLSRoute)](#gateway-api-tlsroute) and [Gateway API (TCPRoute)](#gateway-api-tcproute).

## Environment variables

| Field | Env var |
|---|---|
| `providers.kubernetes.enabled` | `SOZUNE_PROVIDER_KUBERNETES_ENABLED` |
| `providers.kubernetes.kubeconfig` | `SOZUNE_PROVIDER_KUBERNETES_KUBECONFIG` |
| `providers.kubernetes.namespace` | `SOZUNE_PROVIDER_KUBERNETES_NAMESPACE` |
| `providers.kubernetes.ingress_class` | `SOZUNE_PROVIDER_KUBERNETES_INGRESS_CLASS` |
| `providers.kubernetes.expose_by_default` | `SOZUNE_PROVIDER_KUBERNETES_EXPOSE_BY_DEFAULT` |
