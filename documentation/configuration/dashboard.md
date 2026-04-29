# Dashboard

Sozune ships with a built-in web dashboard to inspect entrypoints, check health, and manage settings without hitting the REST API by hand.

## Configuration

Disabled by default. Enable it in `config.yaml`:

```yaml
dashboard:
  enabled: true
  listen_address: "127.0.0.1:3038"
```

Restart sozune to pick up the change.

## Authentication

The dashboard talks to the [REST API](/documentation/configuration/api) and uses the same credentials. Configure at least one user under `api.users` and log in from the dashboard's `/login` page.

## Exposing the dashboard

The dashboard listens on `127.0.0.1:3038` by default — local-only, like the API. Two patterns to expose it externally:

- **Behind sozune itself** — declare an entrypoint pointing at `127.0.0.1:3038` with `tls: true`. Example with Docker labels on the sozune container:

  ```yaml
  labels:
    - "sozune.enable=true"
    - "sozune.http.dashboard.host=dashboard.example.com"
    - "sozune.http.dashboard.port=3038"
    - "sozune.http.dashboard.tls=true"
  ```

- **Behind another reverse proxy** that already terminates TLS.

If you need it reachable on a LAN without going through a proxy, switch `listen_address` to `0.0.0.0:3038` — but never expose it on a public interface without TLS.

## CORS

The dashboard runs on its own origin (e.g. `http://dashboard.example.com`) and calls the API on another (`http://localhost:3035`). The API allows any origin by default; restrict with `api.cors_origins` if you need to.
