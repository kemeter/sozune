# Upgrade

What to change when moving from one Sōzune version to the next. Only the steps that need action are listed here; [`CHANGELOG.md`](CHANGELOG.md) lists every change.

## Upgrade to 0.16

### Configuration file in the Docker image

The image sets `CONFIG_PATH=/etc/sozune/config.yaml`. A file mounted at `/home/nonroot/config.yaml` is no longer read: mount it at `/etc/sozune/config.yaml`, or set `CONFIG_PATH` to its path.

Before:

```yaml
volumes:
  - ./config.yaml:/home/nonroot/config.yaml:ro
```

After:

```yaml
volumes:
  - ./config.yaml:/etc/sozune/config.yaml:ro
```

### Gateway API: `allowedRoutes`

A Gateway listener's `allowedRoutes` is enforced. By default a listener only admits routes from the Gateway's own namespace, so a route in another namespace that names the Gateway is no longer served, and reports `Accepted=False` with `NotAllowedByListeners`. Open the listeners it should attach to with `from: All`, or `from: Selector` with a selector its namespace's labels match. See [Which routes a listener admits](documentation/providers/kubernetes.md#which-routes-a-listener-admits-allowedroutes).

Before, a route in namespace `shop` attached to this Gateway of namespace `infra`:

```yaml
listeners:
  - name: http
    port: 80
    protocol: HTTP
```

After:

```yaml
listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
```

An HTTPRoute now only attaches through `HTTP` and `HTTPS` listeners, and a listener's `allowedRoutes.kinds` keeps out the route kinds it does not list.

### Gateway API: client certificate validation

An `HTTPS` listener on a port where the Gateway asks for client certificates to be checked (`spec.tls.frontend`, a `validation` in mode `AllowValidOnly`, the default) is refused with `UnsupportedValue`, and no route attaches to it. It used to be served without checking them: Sōzu checks client certificates for a whole HTTPS port, not per Gateway. Remove the `validation`, or check client certificates on every HTTPS connection with [`proxy.https.tls.client_auth`](documentation/tls/overview.md#client-certificates-mutual-tls). See [HTTPS listeners](documentation/providers/kubernetes.md#https-listeners).

Refused:

```yaml
spec:
  tls:
    frontend:
      default:
        validation:
          caCertificateRefs:
            - kind: ConfigMap
              name: client-ca
```

Served, every HTTPS client checked against the CA:

```yaml
proxy:
  https:
    tls:
      client_auth:
        mode: required
        ca_files: ["/etc/sozune/client-ca.pem"]
```

### Gateway API: listener isolation

`HTTP` listeners of a Gateway on one port no longer share their routes: a request goes to the listener whose `hostname` matches its host most closely, and only that listener's routes serve it. A route attached to a `*.example.com` listener no longer serves `abc.foo.example.com` when an `abc.foo.example.com` listener of the same Gateway takes that host: it answers `404` there. Attach the route to the more specific listener too if it must keep serving that host.

An HTTPRoute hostname wider than its listener's is narrowed to the listener's: `*.example.com` on a `web.example.com` listener only serves `web.example.com`, where it used to serve every host it matched. Widen the listener's `hostname`, or add a listener for the other hosts.

### Gateway API: `spec.addresses` and `parametersRef`

A Gateway naming in `spec.addresses` an address Sōzune does not publish is not `Programmed` (`AddressNotUsable`); one with an address type other than `IPAddress` and `Hostname`, or with `infrastructure.parametersRef` set, is not `Accepted` (`UnsupportedAddress`, `InvalidParameters`). Both fields used to be ignored, so tools waiting on these conditions may now see such a Gateway as failed. List only addresses of `publish_service` or `publish_addresses` there, and remove `parametersRef`. See [Status conditions](documentation/providers/kubernetes.md#status-conditions).

### Gateway API: HTTPRoute timeouts

A rule's `timeouts.request` and `timeouts.backendRequest` are enforced, where they used to be ignored: past either, the client gets `504`, or a response already started is cut short. Raise or remove those already set on routes whose requests, uploads or responses take longer. `0s` disables either.

### Gateway API: backendRefs that cannot take traffic

An HTTPRoute backendRef that cannot take traffic keeps its share of the rule's requests, by weight, answered `500`: a kind other than `Service`, a Service in another namespace with no `ReferenceGrant` allowing it, a Service that does not exist. One whose Service has no ready pod gets its share answered `503` while the rule has other backendRefs to serve; a rule whose backendRefs are all usable but have no ready pod is not served until one is ready. That share used to go to the other backendRefs. Fix or remove such backendRefs; the route's `ResolvedRefs` condition names the reason (`InvalidKind`, `RefNotPermitted`, `BackendNotFound`). See [Gateway API](documentation/providers/kubernetes.md#gateway-api-httproute).

### Gateway API: backendRef weights

A backendRef's `weight` is the Service's share of the rule's requests, whatever its number of pods, an unset `weight` is `1` instead of `100`, and `weight: 0` sends no traffic. A rule mixing backendRefs with and without a `weight` now splits its requests differently: set every `weight` explicitly.

### Gateway API: TCPRoute and UDPRoute on a shared port

When several TCPRoutes or UDPRoutes bind the same listener port, only the oldest is served, as Gateway API asks; the next takes over when it goes. Their backends used to share the port's connections. Put those backends in one route, or give each route its own listener port. See [Gateway API (TCPRoute)](documentation/providers/kubernetes.md#gateway-api-tcproute).

### `backendTimeout` covers the response body

A `backendTimeout` you set now covers the whole response, its body included: a response still streaming past it is cut short. It used to bound only the wait for the headers. For Server-Sent Events, long downloads and other long-lived responses, set `backendTimeout=0`, or a value above their length. The default 30 seconds still only bound the headers. See [Long polling](documentation/advanced/long-polling.md).

Before:

```yaml
labels:
  - "sozune.http.events.backendTimeout=30000"
```

After:

```yaml
labels:
  - "sozune.http.events.backendTimeout=0"
```

## Upgrade to 0.15

### `backendTimeout` is in milliseconds

`backendTimeout` is read in milliseconds, as the API and the label diagnostics describe it. It used to be applied as seconds: multiply such values by 1000. The default (30 s) and `0` (no timeout) are unchanged.

Before:

```yaml
labels:
  - "sozune.http.api.backendTimeout=30"
```

After:

```yaml
labels:
  - "sozune.http.api.backendTimeout=30000"
```

A `backendTimeout` longer than 30 seconds never took effect: the HTTP and HTTPS listeners cut a request left waiting 30 seconds for its response first. Such routes get diagnostic `W030`. To let them wait longer, raise `proxy.timeouts.backend_idle`, and `client_idle` past 60 seconds. See [Proxy](documentation/configuration/overview.md#proxy).

```yaml
proxy:
  timeouts:
    backend_idle: 120
    client_idle: 120
```

### Path prefixes match whole segments

A path prefix matches on segment boundaries: a route on `/api` serves `/api`, `/api/users` and `/api?page=2`, but no longer `/apidocs`. A route relying on that has to declare the longer prefix, or `/`.

### Hostnames matching every host

A bare `*` hostname, and a regex hostname that does not stay inside a literal domain, are refused: from labels (`E002`), the HTTP provider and the API (`400`). Use an exact name, a `*.` wildcard, or a regex such as `/cdn[0-9]+/.example.com`. See [Regex hostnames](documentation/routing/hostnames.md#regex).

### Custom headers replace the original

A custom header (`headers.<name>`, `headers.response.<name>`, the HTTP provider, the API, Gateway API `set` / `add`) replaces a header of the same name sent by the client or the backend, instead of being sent next to it: a client no longer gets the backend's `Server` next to the one `headers.response.Server` sets.

### WASM security plugins fail open

A WASM plugin whose guest errors now lets the request through to the backend (`fail_open: true`, the default), where it used to answer `502`. Set `fail_open: false` on a security plugin, such as a WAF or a bouncer, that must fail closed:

```yaml
plugins:
  waf:
    path: /plugins/waf.wasm
    fail_open: false
```

See [Execution policy](documentation/middleware/wasm-plugins.md#execution-policy-skip_paths-skip_methods-fail_open).
