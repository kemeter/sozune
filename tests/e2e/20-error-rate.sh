#!/usr/bin/env bash
# Error-rate tracking: per-status-class counters on /metrics.
#
# Sōzune counts middleware-layer responses by HTTP status class and exposes
# `sozune_middleware_requests_total{class="…"}`. A request that a middleware
# short-circuits with 404 (here: the client-IP matcher denying loopback on
# `svc-clientip-deny`) is counted under the `4xx` class. We drive a few of
# those and assert the counter grows.
#
# Sourced by run-all.sh.

METRICS_URL="http://127.0.0.1:$API_PORT/metrics"
SERIES='sozune_middleware_requests_total{class="4xx"}'

# Value of the 4xx counter (0 if the line is absent).
count_4xx() {
    # `|| true`: a missing series makes `grep` exit non-zero under
    # `set -euo pipefail`, which would abort the runner via the substitution.
    { curl -s --max-time 2 "$METRICS_URL" 2>/dev/null \
        | grep -F "$SERIES" | awk '{print $2}' | head -1; } || true
}

log "[20] Error rate: status-class counters are exposed"

body=$(curl -s --max-time 2 "$METRICS_URL" 2>/dev/null || echo "")
if grep -q "# TYPE sozune_middleware_requests_total counter" <<<"$body" \
    && grep -qF 'sozune_middleware_requests_total{class="5xx"}' <<<"$body" \
    && grep -qF 'sozune_middleware_requests_total{class="2xx"}' <<<"$body"; then
    pass "per-status-class counters are present"
else
    fail "sozune_middleware_requests_total series missing from /metrics"
fi

log "[20] Error rate: a middleware 4xx increments the 4xx class"

before=$(count_4xx); before=${before:-0}

# `svc-clientip-deny` 404s loopback via the client-IP matcher (a middleware
# short-circuit), so each request bumps the 4xx class.
for _ in 1 2 3; do
    curl -s -o /dev/null --max-time 2 -H "Host: $HOST_CLIENTIP_DENY" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true
done

after=""
for _ in $(seq 1 10); do
    after=$(count_4xx); after=${after:-0}
    if (( after > before )); then
        break
    fi
    sleep 0.2
done

if (( after > before )); then
    pass "4xx counter grew from $before to $after after middleware 404s"
else
    fail "4xx counter did not grow (before=$before after=$after)"
fi

log "[20] Error rate: JSON view carries the per-status map"

json=$(curl -s --max-time 2 -H "Accept: application/json" "$METRICS_URL" 2>/dev/null \
    | grep -oE '"middleware_requests_by_status":\{[^}]*\}' | head -1 || true)
if [[ "$json" == *'"4xx"'* ]]; then
    pass "JSON /metrics exposes proxy.middleware_requests_by_status"
else
    fail "JSON /metrics did not expose middleware_requests_by_status"
fi
