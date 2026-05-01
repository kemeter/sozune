#!/usr/bin/env bash
# Nomad service discovery: tags drive routing, allocations are reached
# directly through their dynamic ports.

log "[01] Whoami service is reachable through Sozune"
if wait_for_status "$HOST_WHOAMI" "200"; then
    pass "$HOST_WHOAMI returns 200"
else
    fail "$HOST_WHOAMI not reachable"
    return 0
fi

log "[01] Round-robin hits all 3 allocations"
# Each allocation in Nomad `-dev` runs on 127.0.0.1 with its own dynamic port.
# Now that Sozune carries a port per backend, the three allocations each show
# up as distinct routing targets even on a single host.
distinct=$(wait_for_distinct_backends "$HOST_WHOAMI" 3 30 || true)
if [[ "$distinct" -ge 3 ]]; then
    pass "round-robin hits $distinct distinct allocations"
else
    fail "expected >=3 distinct allocations after 30s, got $distinct"
fi

log "[01] Sozune-Id header is present (proves Sōzu, not host network, served the request)"
sozu_id=$(curl -s -H "Host: $HOST_WHOAMI" --max-time 3 -D - \
            "http://localhost:$HTTP_PORT/" | awk -F': ' 'tolower($1)=="sozu-id"{print $2}' | tr -d '\r')
if [[ -n "$sozu_id" ]]; then
    pass "Sozu-Id header present (id=${sozu_id:0:12}...)"
else
    fail "Sozu-Id header missing — request did not go through Sōzu"
fi
