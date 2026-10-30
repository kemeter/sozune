# Access logs

> Since 0.9

Sōzune logs every request that flows through its internal middleware proxy via the standard `tracing` infrastructure, on a dedicated `access` target (since 0.14). Output is plain text by default or structured JSON (`log.format: json`, since 0.14). There is no separate access log file — logs go to stdout.

## What is and isn't logged

The Sōzune access log is emitted by the middleware proxy. A request reaches that proxy only if its entrypoint uses one of the middleware features that run in Axum: compression, rate limit, in-flight limit, backend timeout, forward auth, IP allow-list, client-IP or query matching, retry, circuit breaker, request mirroring, CORS, WASM plugins, among others. Entrypoints that use only natively-handled features (basic auth, custom headers, strip prefix, most redirects) bypass the middleware proxy entirely and **do not produce a Sōzune access log line**. Sōzu itself still logs at the listener level, but in its own format.

## Format

Each logged request emits one `info`-level event on the dedicated `access` target, carrying **structured fields** (`client_ip`, `method`, `host`, `path`, `status`, `duration_ms`, `phase`, `trace_id`). How those fields are rendered depends on `log.format` (see below).

### Text (default)

```
<client_ip> <method> <host> <path> <status> <duration_ms>ms (<phase>) trace=<trace_id>
```

Example:

```
2026-04-27T17:45:07.300344Z  INFO access: 192.0.2.10 GET api.example.com /v1/users 200 12ms (backend) trace=-
```

### JSON

> Since 0.14

With `log.format: json`, the same event is emitted as one JSON object per line, with every field as a top-level key — no regex parsing needed downstream:

```json
{"timestamp":"2026-04-27T17:45:07.300344Z","level":"INFO","target":"access","client_ip":"192.0.2.10","method":"GET","host":"api.example.com","path":"/v1/users","status":200,"duration_ms":12,"phase":"backend","trace_id":"-","message":"192.0.2.10 GET api.example.com /v1/users 200 12ms (backend) trace=-"}
```

## Fields

| Field | Source |
|---|---|
| `client_ip` | First entry of `X-Forwarded-For`, or the literal `-` if absent |
| `method` | HTTP method |
| `host` | `Host` header from the incoming request |
| `path` | Request path as the middleware receives it, after Sōzu's path rewrites (`stripPrefix`, `addPrefix`) |
| `status` | Response status code returned to the client |
| `duration_ms` | Total time to serve the request, milliseconds |
| `phase` | `backend` for a normally-proxied response, or `middleware` when a middleware short-circuited it (forward-auth deny, rate limit, …) (since 0.14) |
| `trace_id` | OpenTelemetry trace id of the request, or `-` when [tracing](/documentation/advanced/observability#distributed-tracing-opentelemetry) is off (since 0.14) |

## What's logged additionally

- Rate-limited requests log a separate `WARN` line: `Rate limited request from <ip> to <host>`.
- Backend timeouts and connection failures log `ERROR` lines with the target URI.
- WebSocket upgrades log `DEBUG` lines (only visible at debug level).

## Choosing text or JSON

> Since 0.14

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

Sōzune reads the `RUST_LOG` environment variable, then applies its own filter on top:

```
sozune=info, bollard=warn, hyper=warn, hyper_util=warn, rustls=warn, sozu_lib=warn,
sozu_command_lib=warn, mio=warn, h2=warn, kube=warn, tower=warn
```

Every other target, `access` included, logs only errors unless `RUST_LOG` names it. **The access log is therefore off by default**; turn it on by enabling its target:

```bash
RUST_LOG=access=info sozune
```

Because the filter above is applied after `RUST_LOG`, a `RUST_LOG` directive on one of those exact targets (`sozune=debug`, `hyper=info`) has no effect. Target a module below them instead:

```bash
# Verbose middleware logs
RUST_LOG=sozune::middleware=debug sozune

# Access log plus verbose provider logs
RUST_LOG=access=info,sozune::provider=debug sozune
```

## Limitations

- **Two layouts only.** `text` or `json` — no Apache combined, no LTSV, no per-field custom templates. The field set is fixed.
- **No log file rotation.** Stdout only. If you need persistence, capture stdout in your container orchestrator (Docker, systemd, k8s) and apply rotation there.
- **No sampling.** Every request is logged; high-traffic services produce one log line per request.
