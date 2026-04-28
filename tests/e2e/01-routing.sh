#!/usr/bin/env bash
# Routing: stale route cleanup, mixed hostnames (exact + wildcard), regex hostnames.
# Sourced by run-all.sh.

log "[01] Routing: stale route cleanup"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca reachable after startup"
else
    fail "svca NOT reachable after startup (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable after startup"
else
    fail "svcb NOT reachable after startup (timeout)"
fi

log "Stopping svcb..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" stop svcb

log "Waiting for route cleanup..."
got_status=$(wait_for_not_200 "http://127.0.0.1:$HTTP_PORT/" "$HOST_B")
if [[ "$got_status" != "200" ]]; then
    pass "svcb route cleaned up after stop (got $got_status)"
else
    fail "svcb route NOT cleaned up after stop (still returning 200)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca still reachable after stopping svcb"
else
    fail "svca NOT reachable after stopping svcb"
fi

log "Restarting svcb..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" start svcb
sleep "$ROUTE_DELAY"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable again after restart"
else
    fail "svcb NOT reachable after restart (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca still reachable after svcb restart"
else
    fail "svca NOT reachable after svcb restart"
fi

log "[01] Routing: mixed hostnames (exact + wildcard)"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_MIXED_SUFFIX" "200" || true

mixed_apex=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MIXED_SUFFIX" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$mixed_apex" == "200" ]]; then
    pass "mixed hostnames: apex $HOST_MIXED_SUFFIX reachable"
else
    fail "mixed hostnames: apex returned $mixed_apex instead of 200"
fi

mixed_sub=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: sub.$HOST_MIXED_SUFFIX" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$mixed_sub" == "200" ]]; then
    pass "mixed hostnames: sub.$HOST_MIXED_SUFFIX reachable via wildcard"
else
    fail "mixed hostnames: sub returned $mixed_sub instead of 200"
fi

log "[01] Routing: regex hostname matching"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "cdn1.$HOST_HOSTREGEX_SUFFIX" "200" || true

hostregex_ok=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: cdn42.$HOST_HOSTREGEX_SUFFIX" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$hostregex_ok" == "200" ]]; then
    pass "regex hostname: cdn42.$HOST_HOSTREGEX_SUFFIX matches /cdn[0-9]+/"
else
    fail "regex hostname: cdn42.$HOST_HOSTREGEX_SUFFIX returned $hostregex_ok instead of 200"
fi

hostregex_ko=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: cdnabc.$HOST_HOSTREGEX_SUFFIX" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$hostregex_ko" != "200" ]]; then
    pass "regex hostname: cdnabc.$HOST_HOSTREGEX_SUFFIX does not match /cdn[0-9]+/"
else
    fail "regex hostname: cdnabc should not match but returned 200"
fi
