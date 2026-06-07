#!/usr/bin/env bash
# Ring service discovery: labels drive routing, each running instance is
# reached directly through its guest address. Sourced by run-ring.sh.

log "[01] Whoami service is reachable through Sozune"
if wait_for_status "$HOST_WHOAMI" "200"; then
    pass "$HOST_WHOAMI returns 200"
else
    fail "$HOST_WHOAMI not reachable"
    return 0
fi

log "[01] Round-robin hits all 3 instances"
# Each replica runs with its own guest address; Sozune carries a port per
# backend (synthesized from the deployment's published port), so the three
# instances show up as distinct routing targets.
distinct=$(wait_for_distinct_backends "$HOST_WHOAMI" 3 30 || true)
if [[ "$distinct" -ge 3 ]]; then
    pass "round-robin hits $distinct distinct instances"
else
    fail "expected >=3 distinct instances after 30s, got $distinct"
fi

log "[01] Sozu-Id header is present (proves Sōzu, not host network, served the request)"
sozu_id=$(curl -s -H "Host: $HOST_WHOAMI" --max-time 3 -D - \
            "http://localhost:$HTTP_PORT/" | awk -F': ' 'tolower($1)=="sozu-id"{print $2}' | tr -d '\r')
if [[ -n "$sozu_id" ]]; then
    pass "Sozu-Id header present (id=${sozu_id:0:12}...)"
else
    fail "Sozu-Id header missing — request did not go through Sōzu"
fi
