# Access logs

Sōzune logs every request that flows through its internal middleware proxy (compress, rate limit, backend timeout) via the standard `tracing` infrastructure, on a dedicated `access` target. Output is plain text by default or structured JSON (`log.format: json`). There is no separate access log file — logs go to stdout.

## What is and isn't logged

The Sōzune access log is emitted by the middleware proxy. A request reaches that proxy only if its entrypoint uses one of the middleware features that still run in Axum: `compress`, `ratelimit.*`, `backendTimeout`. Entrypoints that use only natively-handled features (basic auth, custom headers, strip prefix, redirects) bypass the middleware proxy entirely and **do not produce a Sōzune access log line**. Sōzu itself still logs at the listener level, but in its own format.

## Format

Each logged request emits one `info`-level event on the dedicated `access` target, carrying **structured fields** (`client_ip`, `method`, `host`, `path`, `status`, `duration_ms`, `phase`). How those fields are rendered depends on `log.format` (see below).

### Text (default)

```
<client_ip> <method> <host> <path> <status> <duration_ms>ms (<phase>)
```

Example:

```
2026-04-27T17:45:07.300344Z  INFO access: 192.0.2.10 GET api.example.com /v1/users 200 12ms (backend)
```

### JSON

With `log.format: json`, the same event is emitted as one JSON object per line, with every field as a top-level key — no regex parsing needed downstream:

```json
{"timestamp":"2026-04-27T17:45:07.300344Z","level":"INFO","target":"access","client_ip":"192.0.2.10","method":"GET","host":"api.example.com","path":"/v1/users","status":200,"duration_ms":12,"phase":"backend","message":"192.0.2.10 GET api.example.com /v1/users 200 12ms (backend)"}
```

## Fields

| Field | Source |
|---|---|
| `client_ip` | First entry of `X-Forwarded-For`, or the literal `-` if absent |
| `method` | HTTP method |
| `host` | `Host` header from the incoming request |
| `path` | Request path (before any `stripPrefix` rewrite) |
| `status` | Response status code returned to the client |
| `duration_ms` | Total time to serve the request, milliseconds |
| `phase` | `backend` for a normally-proxied response, or `middleware` when a middleware short-circuited it (auth deny, rate limit, …) |

## What's logged additionally

- Rate-limited requests log a separate `WARN` line: `Rate limited request from <ip> to <host>`.
- Backend timeouts and connection failures log `ERROR` lines with the target URI.
- WebSocket upgrades log `DEBUG` lines (only visible at debug level).

## Choosing text or JSON

The formatter is global (it applies to every log line, not just the access log) and is selected with `log.format` in `config.yaml`:

```yaml
log:
  format: json   # or `text` (the default)
```

Or via environment variable, which takes precedence over the file:

```bash
SOZUNE_LOG_FORMAT=json sozune
```

Unknown values are ignored and the default (`text`) stands.

## Configuring log verbosity

Sōzune respects the `RUST_LOG` environment variable. To capture **only** the access log, filter on its target:

```bash
# Access log only, nothing else
RUST_LOG=access=info,sozune=warn sozune
```

More generally:

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

- **Two layouts only.** `text` or `json` — no Apache combined, no LTSV, no per-field custom templates. The field set is fixed.
- **No log file rotation.** Stdout only. If you need persistence, capture stdout in your container orchestrator (Docker, systemd, k8s) and apply rotation there.
- **No sampling.** Every request is logged; high-traffic services produce one log line per request.
