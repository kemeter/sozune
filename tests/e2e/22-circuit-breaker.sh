#!/usr/bin/env bash
# Circuit breaker (`circuitBreaker.*`).
#
# `svc-cb` is registered with a circuit breaker (threshold 0.5, minRequests 10,
# cooldown 5s) in front of a healthy whoami. The deterministic contract here:
# with the breaker closed (backend healthy), requests pass through normally.
# The open/half-open state machine and the trip-on-failure logic are covered
# exhaustively by the unit tests in `src/middleware/circuit_breaker.rs`;
# deterministically driving a failing backend through the active health checker
# in e2e is out of scope.
#
# Sourced by run-all.sh.

log "[22] Circuit breaker: closed breaker passes traffic (200)"

ok=1
for _ in $(seq 1 5); do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "Host: $HOST_CB" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
    [[ "$status" != "200" ]] && { ok=0; break; }
done
if [[ "$ok" == "1" ]]; then
    pass "circuit-breaker route serves 200 while the backend is healthy"
else
    fail "circuit-breaker route returned $status, expected 200"
fi
