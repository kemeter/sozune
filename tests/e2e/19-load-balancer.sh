#!/usr/bin/env bash
# Load-balancing algorithm selection (`loadBalancer` label).
#
# `svc-lb` is registered with `loadBalancer=least_connections`. The observable,
# deterministic contract here is that Sōzu *accepts* the algorithm and the
# route is served — an unsupported/garbled algorithm would fail cluster
# registration and the route would not answer 200. (The fallback-on-invalid
# behaviour is covered by unit tests.)
#
# Sourced by run-all.sh.

log "[19] Load balancer: route with least_connections is served"

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_LB" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "least_connections route is served (Sōzu accepted the algorithm)"
else
    fail "least_connections route returned $status, expected 200"
fi
