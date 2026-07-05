# WASM plugins

Run third-party HTTP middleware compiled to WebAssembly, without building it into Sōzune. Plugins use the [http-wasm](https://http-wasm.io) ABI — the same one Traefik's WASM plugins target — so a guest written for http-wasm runs unchanged here.

A plugin is a `.wasm` module that exports `handle_request` (and optionally `handle_response`). On each request Sōzune hands the guest the method, URI, headers, client address and body; the guest can read and mutate them, short-circuit with its own response, or let the request continue to the backend.

This is how you add behaviour like geo-blocking, custom auth headers, request rewriting, or bot filtering as a sandboxed, swappable module rather than a code change.

## Two steps: declare, then reference

Plugins are **declared once** in the static configuration (where the `.wasm` lives and its settings), then **referenced by name** on the entrypoints that should run them — the same split Traefik uses, and the same pattern as `acme.resolvers`.

### 1. Declare the plugin (static config)

```yaml
# config.yaml
plugins:
  geoblock:
    path: /plugins/geoblock.wasm
    config:
      allow_countries: ["FR", "BE"]
```

| Field | Description |
|---|---|
| `path` | Filesystem path to the http-wasm guest `.wasm`. |
| `config` | Arbitrary settings handed to the guest verbatim (serialized to JSON, read by the guest via the http-wasm `get_config` ABI). Optional. |

A plugin that fails to load (missing file, invalid wasm) is logged and skipped — it does not take down routing.

### 2. Reference it on a service (labels)

```yaml
labels:
  - "sozune.http.<svc>.plugins=<name1>,<name2>"
```

| Label | Description |
|---|---|
| `plugins` | Comma-separated list of plugin names (declared in `config.yaml`) to run as middleware, in order. Unknown names are logged and skipped. |
| `plugins.<name>.<key>` | Per-route config for plugin `<name>`, merged over its global `config`. `<key>` may be dotted to nest. See [Per-route config](#per-route-config). |

## Example

```yaml
# config.yaml
plugins:
  geoblock:
    path: /plugins/geoblock.wasm
    config:
      allow_countries: ["FR", "BE"]
```

```yaml
services:
  app:
    image: my-app
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.plugins=geoblock"
```

For `https://app.example.com/`, Sōzune runs the `geoblock` guest's `handle_request` before forwarding. The guest reads the client IP and headers, checks them against `allow_countries`, and either lets the request continue or short-circuits with a `403`.

## Per-route config

A plugin's `config` in `config.yaml` is its global default. A route can override
or extend that config for itself with `plugins.<name>.<key>=<value>` labels —
the route's config is merged over the global default before the guest reads it.
This lets the same plugin run with different settings per app (an Umami
`websiteId`, a CrowdSec `lapi_key`) without recompiling the guest.

```yaml
services:
  blog:
    image: my-blog
    labels:
      - "sozune.enable=true"
      - "sozune.http.blog.host=blog.example.com"
      - "sozune.http.blog.plugins=umami"
      # route-specific config, merged over the global `umami` config:
      - "sozune.http.blog.plugins.umami.websiteId=abc-123"
      - "sozune.http.blog.plugins.umami.tracking.mode=spa"
```

`<key>` may be dotted to nest into the config object
(`plugins.umami.tracking.mode=spa` → `{"tracking": {"mode": "spa"}}`). Values
that are valid JSON keep their type (`true`, `42`, `["a","b"]`); everything else
is a string. Keys are merged over the global config, so a route only needs to
set what differs. Plugins run on HTTP routes only — `plugins.*` labels on a
TCP/UDP route, or a `plugins.<name>` label with no sub-key, are ignored with a
`W026` diagnostic.

> **Secrets in labels.** Per-route plugin config is set from labels and stored
> on the entrypoint. The API redacts plugin-config *values* (they show as `***`
> in `GET /entrypoints`), but labels themselves are visible to anyone who can
> read the container/orchestrator config. Prefer the operator-controlled global
> `config` in `config.yaml` for shared secrets, and use per-route config for
> non-secret, app-specific settings.

## Ordering

WASM plugins run after the native request-phase middlewares (forward-auth, rate-limit) and before compression, in the order the entrypoint lists them. On the response side they run in reverse (onion model), like every other middleware.

## Limits

Each plugin invocation is bounded by a wall-clock timeout and a maximum linear memory, so a misbehaving guest can't hang or exhaust the proxy. Request/response bodies are buffered up to 1 MiB for the guest; larger bodies are passed through untouched.

## Execution policy (`skip_paths`, `skip_methods`, `fail_open`)

Three operator-set fields on a plugin declaration control *when* it runs and *what happens if it fails*. They live in `config.yaml` (operator-controlled, never overridable per route).

```yaml
plugins:
  umami:
    path: /plugins/umami.wasm
    # Don't run the plugin for these request paths — no body buffering,
    # no guest call, on both the request and the response phase.
    skip_paths:
      - "*.js"
      - "*.css"
      - "*.map"
      - "/assets/*"
    # Don't run it for these methods either.
    skip_methods: ["OPTIONS", "HEAD"]
    # Best-effort: if the guest fails, let the request through (default).
    fail_open: true
```

| Field | Default | Effect |
|-------|---------|--------|
| `skip_paths` | `[]` | Request-path globs the plugin is skipped for. A match means the guest is never invoked and the body is never buffered — the point for keeping an analytics plugin off large static assets (a 1.4 MiB JS bundle otherwise gets buffered up to the 1 MiB limit on every hit for nothing). `*` matches any run of characters including `/`; matching is case-insensitive and ignores the query string. |
| `skip_methods` | `[]` | HTTP methods the plugin is skipped for (case-insensitive), e.g. `OPTIONS`, `HEAD`. |
| `fail_open` | `true` | When the guest errors: `true` logs the failure and lets the request continue to the backend untouched — an observability plugin that can't reach its collector must never turn a page into a `502`. Set `false` for a **security** plugin (a WAF / bouncer) that must fail closed: a guest error then returns `502` and the request never reaches the backend. |

> **Why `skip_paths` and not a content-type filter?** The path is known at request time, so `skip_paths` can prevent the body being buffered at all. A response content-type is only known after the backend replies — too late to avoid the request-phase cost — so it isn't offered.

## Outbound HTTP (`allowed_hosts`)

The http-wasm spec has no way for a guest to make a network call. Sōzune adds
two non-standard extensions for plugins that must reach an external service:

- **`http_fetch`** — blocking: the guest makes a request and waits for the
  response. For decisions in the request path, e.g. a
  [CrowdSec](https://www.crowdsec.net/) bouncer querying its LAPI before
  allowing the request.
- **`http_send`** — fire-and-forget: the guest hands off a request and
  continues immediately; the host enqueues it and a background worker sends it.
  For beacons that must not delay the request, e.g. an analytics feeder. Events
  are dropped if the queue is full (best-effort).

A plugin opts into both by declaring `allowed_hosts`. The guest may build the
request path and query, but the host only performs (or enqueues) the call if the
target host is on the list — this prevents a guest from reaching arbitrary
internal addresses (SSRF). An empty or absent `allowed_hosts` means the plugin
has no network access.

`allowed_hosts` is operator-controlled static config (`config.yaml`) and can
never be set from per-route labels, so a tenant cannot widen a plugin's reach.
On top of the allow-list, a target whose host is an internal IP literal
(loopback, RFC 1918 / unique-local private ranges, or link-local — including the
`169.254.169.254` cloud metadata endpoint) is refused unless the operator's
`allowed_hosts` itself names an internal target. A purely public allow-list can
therefore never reach an internal IP, while an operator running a local service
in dev can still opt in by listing it (e.g. `["127.0.0.1:3000"]`). For an
operator host this checks IP literals only; a hostname in `allowed_hosts` that
resolves to an internal IP is trusted as the operator's choice. Tenant hosts
(see [`outbound_host_keys`](#per-tenant-outbound-hosts-outbound_host_keys)) are
additionally checked after DNS resolution, so they can never reach an internal
address even via a name.

```yaml
plugins:
  crowdsec:
    path: /plugins/sozune_crowdsec.wasm
    allowed_hosts: ["crowdsec:8080"]
    config:
      lapi_host: "crowdsec:8080"
      lapi_key: "<bouncer-api-key>"
```

A list entry may be a bare host (`crowdsec`) or include a port
(`crowdsec:8080`); both forms match.

### Per-tenant outbound hosts (`outbound_host_keys`)

Some plugins call an endpoint that differs per app, configured through per-route
labels rather than the static `config.yaml` — e.g. an analytics feeder that posts
to each app's own Umami instance. Listing every tenant's host in `allowed_hosts`
does not scale. Instead, declare which **config keys** hold an outbound URL:

```yaml
plugins:
  umami:
    path: /plugins/sozune_umami.wasm
    outbound_host_keys: ["umami_host"]   # keys, never hosts
```

```yaml
# labels on a service
- "sozune.http.blog.plugins=umami"
- "sozune.http.blog.plugins.umami.umami_host=https://umami.alpacode.io"
- "sozune.http.blog.plugins.umami.websiteId=abc-123"
```

For each key in `outbound_host_keys`, Sōzune reads the value from that route's
merged config, takes its URL host, and adds it to **that route's** effective
allow-list. So a plugin reaches its tenant-configured endpoint with no
operator-maintained host list, and declaring `outbound_host_keys` alone (empty
`allowed_hosts`) is enough to enable the outbound extension.

These hosts are **tenant-controlled**, so they are locked to the public internet
and can never reach the internal network, whatever a tenant sets:

- A value that is an internal IP literal (loopback, RFC 1918 / unique-local,
  link-local including `169.254.169.254`) is refused and never added.
- A value that is a hostname resolving to an internal IP is refused **at connect
  time**: Sōzune resolves it, rejects it if any resolved address is internal, and
  connects only to the addresses it verified — closing the DNS-rebinding hole (a
  name that flips to an internal IP between check and connect cannot slip
  through). Resolution failure is fail-closed: no address, no call.
- Each route only ever reaches its own configured host (per-route isolation);
  route A cannot reach route B's endpoint.
- Redirects are never followed, so an allowed public host cannot bounce the call
  to an internal one.

The internal-target opt-in described above applies to **operator** `allowed_hosts`
only. A tenant value is never eligible for internal access, and the DNS
rebinding hardening applies only to tenant hosts — an operator host (which the
operator may deliberately point at an internal service) resolves normally.

> A guest using `http_fetch` or `http_send` is no longer portable to a vanilla
> http-wasm host (the extensions are Sōzune-specific).

## Writing a plugin

A guest imports the host functions from the `http_handler` module and exports `handle_request`. You can target the ABI directly or use a guest SDK such as [`http-wasm-guest`](https://crates.io/crates/http-wasm-guest) for Rust. Sōzune's host side is the open-source [`http-wasm-host`](https://github.com/kemeter/http-wasm) crate.

## Getting your plugin listed

Published a plugin? Add it to the [plugins gallery](https://sozune.kemeter.io/plugins) by opening a pull request against [`sozune`](https://github.com/kemeter/sozune) that adds an entry to the plugin manifest (`website/src/data/plugins.json`) with your plugin's name, summary, tags, repository and `.wasm` release URL.
