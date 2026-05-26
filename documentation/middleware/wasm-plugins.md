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

## Ordering

WASM plugins run after the native request-phase middlewares (forward-auth, rate-limit) and before compression, in the order the entrypoint lists them. On the response side they run in reverse (onion model), like every other middleware.

## Limits

Each plugin invocation is bounded by a wall-clock timeout and a maximum linear memory, so a misbehaving guest can't hang or exhaust the proxy. Request/response bodies are buffered up to 1 MiB for the guest; larger bodies are passed through untouched.

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

> A guest using `http_fetch` or `http_send` is no longer portable to a vanilla
> http-wasm host (the extensions are Sōzune-specific).

## Writing a plugin

A guest imports the host functions from the `http_handler` module and exports `handle_request`. You can target the ABI directly or use a guest SDK such as [`http-wasm-guest`](https://crates.io/crates/http-wasm-guest) for Rust. Sōzune's host side is the open-source [`http-wasm-host`](https://github.com/kemeter/http-wasm) crate.
