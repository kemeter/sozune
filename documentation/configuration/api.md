# REST API

Sōzune exposes a REST API to manage entrypoints on the fly, without restarting.

## Configuration

`config.yaml`:

```yaml
api:
  enabled: true
  listen_address: "127.0.0.1:3035"
  users:
    - name: admin
      hash: "b630f5d579dfef28c45ddf5e3c7a65f09ebca4d5b064a70c4203578c8667fdeb"
      role: admin
    - name: dashboard
      hash: "7d4cab0d7c8a5e9eef83b7d306b4cb6dad27b3aaf7df9e0db18f78f9efb1ee43"
      role: read-only
  cors_origins:
    - "https://dashboard.example.com"
```

The API refuses to start when `users` is empty. There is no anonymous mode.

## Authentication

The API uses HTTP Basic. Each user has a `name`, a `hash` (hex of `sha256(password)`), and a `role`.

Generate a hash with:

```bash
echo -n "your-password" | sha256sum
```

Then call the API with the password — sozune hashes it on receive and compares in constant time:

```bash
curl -u admin:your-password http://localhost:3035/entrypoints
```

The hash format matches what sozune accepts in route-level basic auth (`sozune.http.<svc>.auth.basic`), so the same generation step works on both sides.

## Roles

| Role | GET | POST / PUT / DELETE |
|---|---|---|
| `admin` (default) | yes | yes |
| `read-only` | yes | 403 |

`role` can be omitted; it defaults to `admin`.

## Securing the API on a network

> **HTTP Basic over plaintext HTTP sends the password in the clear on every request.** It is only safe when the connection is encrypted.

Sōzune's API listens in HTTP. If you bind it to anything other than `127.0.0.1`, put it behind TLS yourself. Two common patterns:

- **Behind sozune itself** — declare an entrypoint that points at `127.0.0.1:3035` with `tls: true` and an ACME-issued certificate, and only the TLS-fronted hostname is reachable from outside.
- **Behind another reverse proxy** that already terminates TLS (nginx, Caddy, an ingress controller).

The default `listen_address: "127.0.0.1:3035"` keeps the API local-only — fine for CLI use from the same host, never expose it on `0.0.0.0` without TLS in front.

## Endpoints

### `GET /health`

Service status. No auth.

```bash
curl http://localhost:3035/health
# 200 OK
```

### `GET /entrypoints`

Lists every entrypoint (Docker + API). Available to both roles.

### `POST /entrypoints`

Creates an entrypoint through the API. Admin only.

```bash
curl -X POST http://localhost:3035/entrypoints \
  -u admin:your-password \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-api",
    "backends": ["10.0.0.5:8080"],
    "protocol": "Http",
    "config": {
      "hostnames": ["api.example.com"],
      "port": 8080,
      "tls": true,
      "https_redirect": true
    }
  }'
```

The `config` object accepts the same fields as the [HTTP provider](/documentation/providers/http) schema. Optional fields default to `null` / `false` when omitted.

### `GET /entrypoints/:id`

Fetches a single entrypoint.

### `PUT /entrypoints/:id`

Updates an entrypoint (only those created through the API, not Docker). Admin only.

### `DELETE /entrypoints/:id`

Deletes an entrypoint. Admin only.

## Note

Entrypoints discovered from Docker are **read-only** through the API. To change them, edit the container labels.
