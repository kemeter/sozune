# Debugging

When a request can't be routed, sozune returns `502 Bad Gateway`. By default the response body is empty so configured hostnames and backend addresses don't leak to the public. Setting `SOZUNE_DEBUG=true` adds a plain-text body explaining what went wrong, including a did-you-mean suggestion when the request `Host` looks like a typo of a configured host.

## The `X-Sozune-Diagnostic` header

The header is **always** set on routing failures, regardless of `SOZUNE_DEBUG`. It carries one of the following reasons:

| Value | Meaning |
|---|---|
| `no-route-for-host` | No entrypoint matches the request's `Host` header |
| `no-healthy-backend` | A route matched but no backend is currently available |

The header is opaque on purpose — it tells operators *why* without exposing topology. Grep for it in CDN/proxy access logs to spot misrouted traffic without turning on debug mode.

## `SOZUNE_DEBUG=true`

When set to `true` (or `1`), sozune adds a plain-text body to the failure response:

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

`SOZUNE_DEBUG` only affects runtime responses. For diagnostics that surface at config-load time (typos in Docker labels, missing required fields, unknown protocols), use `sozune validate`. Both paths share the same diagnostic codes (`E001` … `W013`, `I001` …), so what `validate` reports cannot drift from what the proxy actually does.
