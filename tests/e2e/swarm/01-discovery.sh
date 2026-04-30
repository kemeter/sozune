#!/usr/bin/env bash
# Swarm provider: VIP discovery, scale via service update, removal cleanup,
# source tagging via REST API.
# Sourced by run-swarm.sh.

log "[01] Swarm: discovery via VIP"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca reachable through Sozune (Swarm VIP)"
else
    fail "svca NOT reachable (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable through Sozune (Swarm VIP)"
else
    fail "svcb NOT reachable (timeout)"
fi

log "[01] Swarm: source tag via REST API"

api_response=$(curl -sf --max-time 5 \
    -H "Authorization: Basic $API_BASIC_AUTH" \
    "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null || echo "")

if [[ -z "$api_response" ]]; then
    fail "API call /entrypoints failed"
else
    swarm_count=$(echo "$api_response" | grep -o '"source":"swarm"' | wc -l)
    if [[ "$swarm_count" -ge 2 ]]; then
        pass "API reports >=2 entrypoints with source=swarm (got $swarm_count)"
    else
        fail "API reports only $swarm_count entrypoints with source=swarm (expected >=2)"
        echo "$api_response" | head -c 500
    fi
fi

log "[01] Swarm: scale service via update"

docker service scale "${STACK_NAME}_svcb=4" >/dev/null
sleep "$ROUTE_DELAY"

# Scale change keeps the same VIP, so traffic should remain on the same backend
# entry. We just verify the route still works after scaling — i.e. the event
# stream did not corrupt storage.
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb still reachable after scaling to 4 replicas"
else
    fail "svcb NOT reachable after scale to 4"
fi

log "[01] Swarm: service removal cleans up route"

docker service rm "${STACK_NAME}_svca" >/dev/null
sleep "$ROUTE_DELAY"

got_status=$(wait_for_not_200 "http://127.0.0.1:$HTTP_PORT/" "$HOST_A")
if [[ "$got_status" != "200" ]]; then
    pass "svca route cleaned up after service rm (got $got_status)"
else
    fail "svca route NOT cleaned up after service rm (still returning 200)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb still reachable after svca removal"
else
    fail "svcb impacted by svca removal — possible cross-service cleanup bug"
fi
