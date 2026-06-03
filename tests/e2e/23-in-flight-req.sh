#!/usr/bin/env bash
# InFlightReq middleware
#
# The `svc-inflight` route caps concurrent in-flight requests per client IP at
# 2 (`sozune.http.svcinflight.inFlightReq=2`). The backend is traefik/whoami,
# which holds a response open for the duration of `?wait=<dur>` — so two slow
# requests pin both slots while a third arrives and must be rejected with 503.
#
# After the slow requests drain, a fresh request must succeed again, proving the
# slot is released on every request's completion (the RAII guard on RequestCtx),
# not leaked.
#
# Sourced by run-all.sh.

URL="http://127.0.0.1:$HTTP_PORT"

log "[23] InFlightReq: pinning both slots with two slow requests"

# Two slow requests run in the background, each holding a slot for ~5s. The
# route carries a generous backendTimeout so Sōzune does not cut them short and
# free the slots before the over-limit probe lands.
curl -s -o /dev/null --max-time 8 -H "Host: $HOST_INFLIGHT" "$URL/?wait=5s" &
slow1=$!
curl -s -o /dev/null --max-time 8 -H "Host: $HOST_INFLIGHT" "$URL/?wait=5s" &
slow2=$!

# Give the two slow requests a moment to be accepted and occupy their slots
# before we probe with the third.
sleep 1

log "[23] InFlightReq: third concurrent request is rejected with 503 + diagnostic header"

# Capture status and headers in a SINGLE request: a second probe could land on a
# slot that just freed, so status and header must come from the same response.
headers=$(curl -s -o /dev/null -D - -w "HTTPSTATUS:%{http_code}" --max-time 2 \
    -H "Host: $HOST_INFLIGHT" \
    "$URL/" 2>/dev/null | tr -d '\r' || echo "HTTPSTATUS:000")
over_status="${headers##*HTTPSTATUS:}"
diag_header=$(printf '%s\n' "$headers" | grep -i "^x-sozune-diagnostic:" || true)

if [[ "$over_status" == "503" ]]; then
    pass "third concurrent request over the limit is rejected (503)"
else
    fail "third concurrent request returned $over_status, expected 503"
fi

if [[ "$diag_header" == *"too-many-in-flight"* ]]; then
    pass "503 response carries X-Sozune-Diagnostic: too-many-in-flight"
else
    fail "503 response did not include X-Sozune-Diagnostic: too-many-in-flight (got: $diag_header)"
fi

# Let the two slow requests finish and release their slots.
wait "$slow1" "$slow2" 2>/dev/null || true

log "[23] InFlightReq: slots released after the slow requests drain -> 200"

# A short poll: the slots free up the instant the slow requests complete, but
# allow a beat for the guards to drop and the count to fall back to zero.
released_status="000"
for _ in 1 2 3 4 5; do
    released_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "Host: $HOST_INFLIGHT" \
        "$URL/" 2>/dev/null || echo "000")
    [[ "$released_status" == "200" ]] && break
    sleep 0.5
done
if [[ "$released_status" == "200" ]]; then
    pass "request succeeds again once slots are released (200)"
else
    fail "request after drain returned $released_status, expected 200 (slot may be leaked)"
fi
