# Dashboard

> Since 0.11

Sōzune ships with a built-in web dashboard to inspect entrypoints, check health, and manage settings without hitting the REST API by hand.

## Configuration

Disabled by default. Enable it in `config.yaml`:

```yaml
dashboard:
  enabled: true
  listen_address: "127.0.0.1:3038"
```

Restart sozune to pick up the change.

## Pages

- **Overview** — a landing page summarising entrypoints, backends, and diagnostics at a glance, so you can spot the health of the whole proxy in one screen. (since 0.14)
- **Entrypoints** — the full route list with drill-down filters (by host, provider, diagnostic) to go from the summary straight to a single route, and a page per route with its settings, backends and diagnostics.
- **Providers** — every provider Sōzune knows about, whether it is configured and enabled, and how many entrypoints it serves, backed by `GET /providers`. (since 0.14)
- **Diagnostics** — every active warning/error, filterable, each linking back to the entrypoint that raised it. (since 0.13)
- **Route tester** — enter a URL (with a method, headers, a client IP and a client certificate if they matter) to see which route serves it and why the others do not: routes shadowed by a higher priority, rejected by their path, or refused by Sōzu, the middlewares the request goes through, and the health of the backends. Nothing is sent to a backend. Each entrypoint's page has a *Test a request* button that opens it pre-filled with a URL the route serves. Backed by `POST /routes/resolve`, the same answer as [`sozune route`](../advanced/debugging.md#which-route-serves-a-request). (since 0.15)
- **Certificates** — the TLS certificates Sōzune serves, with their names, expiry and source, backed by `GET /certificates`.
- **Health** — the answer of the API's `GET /health`.
- **Config** — a read-only view of the effective running configuration, backed by the `GET /config` endpoint, with secrets masked. Use it to confirm what Sōzune actually loaded (environment overrides, provider merges) without exposing credentials. (since 0.15)
- **Settings** — the address of the API the dashboard talks to.

## Authentication

The dashboard talks to the [REST API](/documentation/configuration/api) and uses the same credentials. Configure at least one user under `api.users` and log in from the dashboard's `/login` page.

The dashboard runs in the browser and calls the API itself, at `http://127.0.0.1:3035` unless another address is set on its **Settings** page: the API must be reachable from the browser, not only from the dashboard's host.

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

## Preview

![Sōzune dashboard](/documentation/assets/dashboard-entrypoints.png)
