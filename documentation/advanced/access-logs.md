# Access logs

Sōzune logs every request that flows through its internal middleware proxy (compress, rate limit, backend timeout) via the standard `tracing` infrastructure. There is no separate access log file — logs go to stdout.

## What is and isn't logged

The Sōzune access log is emitted by the middleware proxy. A request reaches that proxy only if its entrypoint uses one of the middleware features that still run in Axum: `compress`, `ratelimit.*`, `backendTimeout`. Entrypoints that use only natively-handled features (basic auth, custom headers, strip prefix, redirects) bypass the middleware proxy entirely and **do not produce a Sōzune access log line**. Sōzu itself still logs at the listener level, but in its own format.

## Format

Each logged request emits one line at `info` level:

```
<source-ip> <method> <host> <path> <status> <duration>ms
```

Example:

```
2026-04-27T17:45:07.300344Z  INFO sozune::middleware::proxy: 192.0.2.10 GET api.example.com /v1/users 200 12ms
```

## Fields

| Field | Source |
|---|---|
| `source-ip` | First entry of `X-Forwarded-For`, or the literal `-` if absent |
| `method` | HTTP method |
| `host` | `Host` header from the incoming request |
| `path` | Request path (before any `stripPrefix` rewrite) |
| `status` | Response status code returned to the client |
| `duration` | Total time to serve the request, milliseconds |

## What's logged additionally

- Rate-limited requests log a separate `WARN` line: `Rate limited request from <ip> to <host>`.
- Backend timeouts and connection failures log `ERROR` lines with the target URI.
- WebSocket upgrades log `DEBUG` lines (only visible at debug level).

## Configuring log output

Sōzune respects the `RUST_LOG` environment variable.

```bash
# Default — info for sozune, warn for noisy deps
sozune

# Verbose
RUST_LOG=sozune=debug sozune

# Quiet — only warnings and errors
RUST_LOG=sozune=warn sozune

# Per-module override
RUST_LOG=sozune::middleware=debug,sozune=info sozune
```

The default filter is:

```
sozune=info, bollard=warn, hyper=warn, rustls=warn
```

## Limitations

- **No format customisation.** The access log line layout is hardcoded; no JSON, no Apache combined, no LTSV.
- **No log file rotation.** Stdout only. If you need persistence, capture stdout in your container orchestrator (Docker, systemd, k8s) and apply rotation there.
- **No sampling.** Every request is logged; high-traffic services produce one log line per request.
