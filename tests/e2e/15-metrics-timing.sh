#!/usr/bin/env bash
# Middleware request-latency histogram on /metrics.
#
# Sōzune times every request that flows through its middleware layer and
# exposes a Prometheus histogram `sozune_middleware_request_duration_seconds`
# (cumulative _bucket / _sum / _count) on the unauthenticated /metrics endpoint
# of the API listener.
#
# IMPORTANT: only middleware routes are counted. Routes with no middleware are
# served directly by the Sōzu workers and never reach this timer. So this suite
# drives traffic through `svc-ipallow` (which has an ipAllowList middleware and
# allows 127.0.0.1 → 200), NOT a plain route like svc-a.
#
# Sourced by run-all.sh.

METRICS_URL="http://127.0.0.1:$API_PORT/metrics"
HIST="sozune_middleware_request_duration_seconds"

# Helper: value of a single metric line by exact name.
metric_value() {
    local name="$1"
    # `|| true`: under `set -euo pipefail`, a missing metric makes `grep` exit
    # non-zero (and `head` closing the pipe early can SIGPIPE `awk`), which would
    # otherwise abort the whole runner mid-suite via the command substitution.
    { curl -s --max-time 2 "$METRICS_URL" 2>/dev/null \
        | grep -E "^${name} " | awk '{print $2}' | head -1; } || true
}

log "[15] Timing metrics: histogram series are present"

body=$(curl -s --max-time 2 "$METRICS_URL" 2>/dev/null || echo "")
if grep -q "# TYPE ${HIST} histogram" <<<"$body" \
    && grep -q "${HIST}_bucket{le=\"+Inf\"}" <<<"$body" \
    && grep -q "${HIST}_count " <<<"$body" \
    && grep -q "${HIST}_sum " <<<"$body"; then
    pass "histogram exposes _bucket/_sum/_count series"
else
    fail "histogram series missing from /metrics"
fi

log "[15] Timing metrics: a middleware request increments the histogram count"

before=$(metric_value "${HIST}_count")
before=${before:-0}

# Drive requests through a route WITH middleware (ipAllowList allows loopback).
for _ in 1 2 3; do
    curl -s -o /dev/null --max-time 2 -H "Host: $HOST_IPALLOW" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true
done

# The histogram is updated on the request path; poll briefly for the increment.
after=""
for _ in $(seq 1 10); do
    after=$(metric_value "${HIST}_count")
    after=${after:-0}
    if (( after > before )); then
        break
    fi
    sleep 0.2
done

if (( after > before )); then
    pass "middleware request count grew from $before to $after"
else
    fail "middleware request count did not grow (before=$before after=$after)"
fi

log "[15] Timing metrics: +Inf bucket equals the total count"

inf=$({ curl -s --max-time 2 "$METRICS_URL" 2>/dev/null \
    | grep -E "${HIST}_bucket\{le=\"\+Inf\"\}" \
    | awk '{print $2}' | head -1; } || true)
inf=${inf:-0}
count=$(metric_value "${HIST}_count")
count=${count:-0}
if [[ "$inf" == "$count" ]]; then
    pass "+Inf bucket ($inf) equals _count ($count)"
else
    fail "+Inf bucket ($inf) does not equal _count ($count)"
fi

log "[15] Timing metrics: JSON view carries the histogram"

json_count=$({ curl -s --max-time 2 -H "Accept: application/json" "$METRICS_URL" 2>/dev/null \
    | grep -oE '"middleware_request_duration_seconds":\{[^}]*"count":[0-9]+' \
    | grep -oE '"count":[0-9]+' | grep -oE '[0-9]+' | head -1; } || true)
if [[ -n "$json_count" ]]; then
    pass "JSON /metrics exposes proxy.middleware_request_duration_seconds.count ($json_count)"
else
    fail "JSON /metrics did not expose middleware_request_duration_seconds"
fi
