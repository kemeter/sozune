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
    },
    "middleware_request_duration_seconds": {
      "buckets": [["0.005", 812], ["0.01", 970], ["0.025", 1020]],
      "sum": 7.42,
      "count": 1042
    },
    "middleware_requests_by_status": {
      "1xx": 0, "2xx": 1001, "3xx": 12, "4xx": 25, "5xx": 4, "other": 0
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

## Middleware request-latency histogram

Sōzune times every request that flows through its **middleware layer** (wall-clock, from the moment the handler receives it to the moment the response is ready) and aggregates the durations into a Prometheus **histogram**. Unlike the worker bridge below, this value is not polled — it is updated live on the request path.

| Metric | Type | Description |
|---|---|---|
| `sozune_middleware_request_duration_seconds` | histogram | Latency of requests served through the Sōzune middleware layer, in seconds. Cumulative `_bucket{le="…"}` series plus `_sum` and `_count` |

The bucket bounds (seconds) are: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0`, plus the mandatory `+Inf`.

Because it's a real histogram, you get percentiles for free with `histogram_quantile`:

```promql
# p95 middleware request latency over the last 5 minutes
histogram_quantile(0.95, rate(sozune_middleware_request_duration_seconds_bucket[5m]))

# average middleware request latency
rate(sozune_middleware_request_duration_seconds_sum[5m]) / rate(sozune_middleware_request_duration_seconds_count[5m])
```

### Scope — read this before relying on it

This histogram **only** covers requests that traverse the Sōzune middleware layer: routes that declare auth, forward-auth, rate-limit, header/query/client-IP matching, compression, a backend timeout, an IP allow-list, or a WASM plugin. Those routes are pointed at the in-process Axum handler, which is where the timing happens.

Routes with **no** middleware are served **directly by the Sōzu workers** and never reach this timer — they are *not* counted here. For their latency, use the Sōzu worker `Time` metrics surfaced through the bridge below.

So: think of this as *"how slow is my middleware path"*, not *"how slow is every request"*. On a deployment where every route uses at least one middleware, the two coincide.

**What is counted** (among middleware routes): every request, including those that end in a proxy-level error (no healthy backend, backend timeout, backend unreachable) — their latency is real and worth watching. **Not counted:** WebSocket upgrades (the tunnel lives for the whole connection, so its duration is not a request latency and would skew the distribution) and requests rejected before routing (missing/unknown Host).

The histogram is global — there are no `method`, `status`, or `host` labels, keeping cardinality flat regardless of traffic shape.

## Error rate

Alongside the latency histogram, Sōzune counts middleware-layer responses by **HTTP status class**, so you can track error rates without parsing logs.

| Metric | Type | Description |
|---|---|---|
| `sozune_middleware_requests_total{class="…"}` | counter | Responses served through the middleware layer, one series per class: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `other` |

Proxy-level failures (no healthy backend, backend timeout, backend unreachable) count under their real status — typically `5xx` — so they show up in the error rate.

```promql
# 5xx error ratio over the last 5 minutes
sum(rate(sozune_middleware_requests_total{class="5xx"}[5m]))
  / sum(rate(sozune_middleware_requests_total[5m]))

# 4xx + 5xx request rate
sum(rate(sozune_middleware_requests_total{class=~"4xx|5xx"}[5m]))
```

Same scope as the histogram above: only requests through the middleware layer are counted.

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

The stack also ships **Grafana Tempo** (a traces backend) wired as a datasource, so the same `docker compose -f compose.metrics.yaml up -d` gives you both metrics and traces. Tempo listens for OTLP/gRPC on `:4317` — point Sōzune's `tracing.endpoint` there.

The dashboard JSON, Prometheus scrape config, Tempo config, and Grafana provisioning files live under `tests/observability/`. Copy them into your own stack to ingest Sōzune in production.

## Distributed tracing (OpenTelemetry)

Beyond metrics, Sōzune can emit a **trace span per proxied request** and export it over **OTLP/gRPC** to a collector (Jaeger, Grafana Tempo, Zipkin via OTel, …). Disabled by default — no spans, no exporter, zero overhead.

### Enable it

```yaml
tracing:
  enabled: true
  endpoint: "http://127.0.0.1:4317"   # OTLP/gRPC collector
  service_name: "sozune"               # service.name on every span
  sampler: "parent_based_always_on"    # see below
```

Every field has an environment override: `SOZUNE_TRACING_ENABLED`, `SOZUNE_TRACING_ENDPOINT`, `SOZUNE_TRACING_SERVICE_NAME`, `SOZUNE_TRACING_SAMPLER` (env wins over YAML).

### What you get

- **One span per request** named `proxy.request`, with attributes `http.request.method`, `server.address`, `url.path`, and `http.response.status_code`.
- **W3C context propagation, both ways.** An incoming `traceparent` header is honoured as the span's parent (so Sōzune continues an upstream trace); an outgoing `traceparent` is injected toward the backend (so the backend joins the same trace).
- **Trace correlation in logs.** Each access-log line carries the `trace_id` (a `trace=` field in text, a `"trace_id"` key in JSON), so you can jump from a log line to its trace. It is `-` when tracing is off.

### Sampling

The `sampler` controls which traces are recorded:

| Value | Behaviour |
|---|---|
| `parent_based_always_on` (default) | Follow the upstream sampling decision; if there is none, sample. The right default for a proxy — if the caller is tracing, so are we. |
| `parent_based_always_off` | Follow the upstream decision; otherwise drop. |
| `always_on` / `always_off` | Force the decision regardless of parent. |
| `ratio:<0..1>` | Parent-based ratio sampling, e.g. `ratio:0.1` records ~10% of root traces. |

### Scope

Like the latency histogram and access log, only requests that traverse the Sōzune **middleware layer** produce a span — middleware-less routes are served directly by Sōzu and are not traced here.

### Try it with the demo stack

`compose.metrics.yaml` includes Tempo. With it up, set `tracing.enabled: true` and `tracing.endpoint: http://127.0.0.1:4317`, send a request through Sōzune, then open Grafana → Explore → Tempo and search recent traces.

## What it does not do

- **No span for middleware-less routes.** Requests served directly by the Sōzu workers (no auth/rate-limit/etc.) never reach the Axum handler that opens the span, so they are not traced. Same boundary as the access log and the latency histogram.
- **No _per-route_ latency histograms.** Sōzune exposes one **global** histogram for the middleware path (`sozune_middleware_request_duration_seconds`, see above), but does not break it down per route, host, or method — that would explode cardinality. It also does not cover middleware-less routes (served directly by Sōzu). Sōzu's own `Histogram` and `Percentiles` worker metrics are still skipped on the bridge because their bucket bounds are not part of the protocol contract; only `Gauge`, `Count`, and `Time` worker values are forwarded.
- **No metric labels for hostnames, paths, or clusters.** Adding them would explode cardinality on large parks. Use Sōzu's per-cluster query directly if you need that granularity.
