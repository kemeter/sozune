# Observability

Sōzune exposes a Prometheus-compatible `/metrics` endpoint so any Prometheus scraper (or Grafana, VictoriaMetrics, Mimir, etc.) can ingest its state. A reference Grafana stack ships with the repo.

## The `/metrics` endpoint

- Path: `/metrics` on the API listener (default `:3035`)
- Method: `GET`
- Auth: **none** (Prometheus scrapers don't authenticate by default; protect the listener with TLS / network ACLs at the perimeter)
- Re-computed on every scrape from authoritative state — no background aggregator, no stale cache

### Output formats

The same endpoint serves two formats, picked by the request's `Accept` header:

| `Accept` value | Response | Use case |
|---|---|---|
| missing, `*/*`, `text/plain`, … | Prometheus text exposition `version=0.0.4` | Prometheus scrapers, `curl`, anything that reads the standard format |
| `application/json` | Structured JSON (same values, same names) | The Sōzune dashboard or any client that prefers to skip text parsing |

JSON example:

```json
{
  "static": {
    "entrypoints": 14,
    "entrypoints_by_protocol": {"http": 12, "tcp": 2},
    "entrypoints_tls": 8,
    "backends": 52,
    "backends_unhealthy": 1,
    "diagnostics": {"error": 0, "warn": 3, "info": 0},
    "acme_enabled": true
  },
  "proxy": {
    "last_poll_seconds": 1748547231,
    "metrics": {
      "connections": 14,
      "http_requests": 1042
    }
  }
}
```

Numeric values in both formats are produced from the same in-memory snapshot, so they can never drift.

## Static gauges

| Metric | Type | Description |
|---|---|---|
| `sozune_entrypoints` | gauge | Number of entrypoints currently loaded |
| `sozune_entrypoints_by_protocol{protocol="http\|tcp\|udp"}` | gauge | Entrypoints per protocol |
| `sozune_entrypoints_tls` | gauge | Entrypoints with TLS enabled |
| `sozune_backends` | gauge | Total backends across all entrypoints |
| `sozune_backends_unhealthy` | gauge | Backends currently marked down by the health checker |
| `sozune_diagnostics{severity="error\|warn\|info"}` | gauge | Active diagnostics by severity |
| `sozune_acme_enabled` | gauge | `1` if the ACME module is enabled, `0` otherwise |

## Sōzu worker bridge

The Sōzu workers maintain their own counters and gauges (connections, HTTP requests, errors, bytes in/out, …). Sōzune polls them every **5 seconds** through the Sōzu command-channel and exposes the result alongside the static gauges.

| Metric | Type | Description |
|---|---|---|
| `sozune_proxy_last_poll_seconds` | gauge | Unix timestamp of the last successful worker poll. `0` if no poll has succeeded yet |
| `sozune_proxy_metric{key="..."}` | untyped | Worker counter or gauge as reported by Sōzu. Keys come straight from Sōzu (`connections`, `http.requests`, `http.errors_4xx`, `bytes_in`, …) |

The `{key="..."}` label is intentional: Sōzu emits a dynamic set of counters that is not known at compile time. The naming is preserved verbatim with `.` and `-` replaced by `_` so it is a valid Prometheus label value.

Cardinality is bounded — Sōzune asks Sōzu for proxy-wide metrics only (`no_clusters: true`), so the number of keys does not grow with the number of clusters.

To get a rate from a counter, use `rate()`:

```promql
rate(sozune_proxy_metric{key="http_requests"}[1m])
```

## Polling trade-off

Sōzune polls workers every 5 s; Prometheus typically scrapes every 5–15 s. Worst case the value you see in Grafana is ~10 s old. That's acceptable for the gauges and counters we expose; if you need lower latency, raise the poll frequency in code or run a sidecar that scrapes the Sōzu command-channel directly.

If `time() - sozune_proxy_last_poll_seconds` grows past ~30 s, the worker is no longer responding. Check Sōzune logs for `metrics: failed to write QueryMetrics`.

## Reference Grafana stack

The repo ships a turnkey Docker Compose stack: Prometheus + Grafana with the dashboard auto-provisioned.

```bash
docker compose -f compose.metrics.yaml up -d
```

Then open:

- Sōzune (assuming it's running on the host): `http://127.0.0.1:3035/metrics`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000` — login `admin` / `admin`, dashboard "Sozune Overview" auto-loaded

The dashboard JSON, Prometheus scrape config, and Grafana provisioning files live under `tests/observability/`. Copy them into your own stack to ingest Sōzune in production.

## What it does not do

- **No tracing.** Sōzune does not emit OpenTelemetry spans today. A scrape-only metrics interface is intentional — if you need traces, an OTel collector can scrape `/metrics` and re-emit as OTLP.
- **No per-route latency histograms.** Sōzu's `Histogram` and `Percentiles` metric types are skipped on export because their bucket bounds are not part of the protocol contract. Only `Gauge`, `Count`, and `Time` values are bridged.
- **No metric labels for hostnames, paths, or clusters.** Adding them would explode cardinality on large parks. Use Sōzu's per-cluster query directly if you need that granularity.
