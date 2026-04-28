# REST API

Sozune exposes a REST API to manage entrypoints on the fly, without restarting.

## Configuration

`config.yaml`:

```yaml
api:
  enabled: true
  listen_address: "127.0.0.1:3035"
  token: "your-secret-token"
  cors_origins:
    - "https://dashboard.example.com"
```

## Authentication

When a `token` is configured, every route (except `/health`) requires a matching bearer token:

```bash
curl -H "Authorization: Bearer your-secret-token" \
     http://localhost:3035/entrypoints
```

**If `token` is not set, the API runs without any authentication.** Every route is publicly reachable on `listen_address`. Always either bind the API to `127.0.0.1` (default) or set a token before exposing it.

## Endpoints

### `GET /health`

Service status. No auth.

```bash
curl http://localhost:3035/health
# 200 OK
```

### `GET /entrypoints`

Lists every entrypoint (Docker + API).

### `POST /entrypoints`

Creates an entrypoint through the API.

```bash
curl -X POST http://localhost:3035/entrypoints \
  -H "Authorization: Bearer your-secret-token" \
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

The `config` object accepts the same fields as the [HTTP provider](/documentation/configuration/http-provider) schema. Optional fields default to `null` / `false` when omitted.

### `GET /entrypoints/:id`

Fetches a single entrypoint.

### `PUT /entrypoints/:id`

Updates an entrypoint (only those created through the API, not Docker).

### `DELETE /entrypoints/:id`

Deletes an entrypoint.

## Note

Entrypoints discovered from Docker are **read-only** through the API. To change them, edit the container labels.
