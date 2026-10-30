# Debugging

> Since 0.12

When the Sōzune middleware cannot serve a request — a route that goes through it (rate limit, forward auth, timeouts, retries…) finds no backend, times out, or is refused by one of its middlewares — it answers with an error status and an empty body, so configured hostnames and backend addresses don't leak to the public. Setting `SOZUNE_DEBUG=true` adds a plain-text body explaining what went wrong, including a did-you-mean suggestion when the request `Host` looks like a typo of a configured host.

A request for a host no route serves never reaches the middleware: Sōzu answers it with its own `404` (see [Error pages](/documentation/middleware/error-pages)), without the header below.

## The `X-Sozune-Diagnostic` header

The header is **always** set on the error responses the middleware produces, regardless of `SOZUNE_DEBUG`. It carries one of the following reasons:

| Value | Status | Meaning |
|---|---|---|
| `no-route-for-host` | `502` | The middleware has no route for the request's `Host` (its table is being updated) |
| `no-healthy-backend` | `503` | A route matched but no backend is currently available |
| `backend-unreachable` | `502` | Connecting to the backend failed (since 0.13) |
| `backend-timeout` | `504` | The backend did not answer within the route's [`backendTimeout`](/documentation/middleware/backend-timeout), or past the whole request's timeout (since 0.13) |
| `invalid-target-uri`, `response-body-read-failed`, `websocket-upgrade-rejected` | `502` | The request could not be forwarded, or the backend refused a WebSocket upgrade (since 0.13) |
| `request-body` | `502` | The client's request body could not be read (since 0.14) |
| `missing-host-header` | `400` | The request carries no usable `Host` header (since 0.13) |
| `rate-limited` | `429` | The route's rate limit was exceeded (since 0.13) |
| `ip-forbidden` | `403` | The client IP is not in the route's IP allow-list (since 0.14) |
| `no-match` | `404` | The request did not meet the route's match conditions (since 0.14) |
| `circuit-open` | `503` | The route's circuit breaker is open (since 0.14) |
| `too-many-in-flight` | `503` | The route's in-flight request limit is reached (since 0.14) |
| `invalid-backends` | `500` | The share of a Gateway API rule's requests that falls to a backendRef which cannot take traffic (since 0.16) |
| `unavailable-backend` | `503` | The share that falls to a backendRef whose Service has no ready pod (since 0.16) |
| `other-listener` | `404` | No route of the Gateway listener that takes this host serves the request (since 0.16) |
| `middleware-routing-corrupted` | `500` | Sōzune's internal state is corrupted; restart it (since 0.13) |

The header is opaque on purpose — it tells operators *why* without exposing topology. Grep for it in CDN/proxy access logs to spot misrouted traffic without turning on debug mode.

## `SOZUNE_DEBUG=true`

When set to `true` (or `1`; any other value leaves it off), sozune adds a plain-text body to these error responses. For `no-route-for-host`:

```
$ SOZUNE_DEBUG=true sozune
$ curl -i -H "Host: exmple.com" http://localhost
HTTP/1.1 502 Bad Gateway
x-sozune-diagnostic: no-route-for-host
content-type: text/plain; charset=utf-8

sozune: no route configured for host 'exmple.com'.

Configured hosts:
  - api.example.com
  - example.com

Did you mean 'example.com'?

Set SOZUNE_DEBUG=false to hide this body in production.
```

For `no-healthy-backend`, the body lists the configured backends instead:

```
sozune: no backend available for host 'example.com'.

Configured backends:
  - 10.0.0.1:8080
  - 10.0.0.2:8080
```

## When to use it

- **Local development** — instantly see why a `Host`/route doesn't match, without tailing logs.
- **Staging** — leave it on so QA gets immediate feedback on misconfigured services.
- **Production** — leave it **off**. The `X-Sozune-Diagnostic` header is enough to diagnose from the operator side, and the server-side log line (`info` level) records the same information without exposing it to clients.

## Configuration validation at boot

`SOZUNE_DEBUG` only affects runtime responses. For diagnostics that surface at config-load time (typos in Docker labels, missing required fields, unknown protocols), use `sozune validate`. Both paths share the same diagnostic codes (`E001` … `W031`, `I001` …), so what `validate` reports cannot drift from what the proxy actually does.

Run `sozune explain <CODE>` for the cause, effect, fix and a copyable example of any code `validate` reports (since 0.13).

## Which route serves a request

> Since 0.15

`sozune route` answers *which route serves this URL, and why not the one I expected* without sending the request: the route Sōzu picks, why each other route on the same host loses (lower priority, other path, refused), what its middlewares decide, and the health of its backends.

```bash
$ SOZUNE_API_PASSWORD=... sozune route https://app.example.com/api/users --user admin
GET https://app.example.com/api/users

✓ proxied by route `api`
  route http_api (docker, priority 10)

candidates
└─ ✗ web · priority 0 · shadowed
      matches too, but `api` has a higher priority (10 > 0)

pipeline
├─ ✓ ip-allow-list
└─ • rate-limit
      depends on the client's recent requests

backends
├─ ✓ 10.0.0.4:8080
└─ ✗ 10.0.0.5:8080
      connection refused
```

It asks the running instance, so the API must be enabled; it is reached at `api.listen_address` from the config, or at `--api <url>`. The user comes from `--user` or `SOZUNE_API_USER`, the password from `SOZUNE_API_PASSWORD` (or `--user name:password`); a `read-only` user is enough.

| Option | |
|---|---|
| `-X, --method` | Request method (default `GET`) |
| `-H, --header 'Name: value'` | Request header, repeatable |
| `--client-ip <ip>` | Client address; IP allow-lists and client-IP matching are not evaluated without it |
| `--client-cert` | The client presents a valid certificate; without it, an `https` URL fails its handshake when [client certificates](../tls/overview.md#client-certificates-mutual-tls) are `required` (since 0.16) |
| `-u, --user <name[:password]>` | API user (or `SOZUNE_API_USER`) |
| `--api <url>` | API base URL, instead of the one derived from `api.listen_address` |
| `--json` | Print the API's JSON answer |

It exits, with or without `--json`, `0` when a route serves the request (proxied, redirected, ACME challenge), `1` when it is not served (no route matches, or sozune answers it with an error such as a `403` or `404`), and `2` when the question could not be answered (API unreachable, credentials refused, invalid URL or header). The same answer is available from the API as `POST /routes/resolve`, see [the endpoint reference](../configuration/api.md#post-routesresolve).

## Checking the environment

> Since 0.13

`sozune doctor` checks the host sozune runs on, before or after it starts:

- the config file parses;
- every port sozune binds is free: HTTP, HTTPS, TCP and UDP listeners, the middleware port, the ACME challenge and TLS-ALPN-01 ports, and the API, dashboard and metrics listeners when enabled. Two listeners configured on the same port are reported as a conflict;
- ACME has a contact email and its `certs_dir` is writable (or can be created);
- each certificate under `proxy.https.tls.certificates` loads, and is not close to expiry (since 0.15);
- each DNS-01 resolver can be built: its env vars are set (in the environment `doctor` runs in) and its fields are valid (since 0.15);
- each enabled provider is reachable: Docker, Podman and Swarm sockets, Nomad, Consul, Ring and HTTP endpoints, the Kubernetes kubeconfig or in-cluster credentials, the `config_file` path.

```bash
sozune doctor            # all checks
sozune doctor --offline  # skip provider checks
```

When sozune is already running, its ports are taken by definition. If the API is enabled, `doctor` detects the running instance through `/health` and skips the bind checks (since 0.15). Without the API it cannot tell sozune from another process, so stop sozune first.

`doctor` exits with `1` when a check fails, `0` otherwise (warnings included).
