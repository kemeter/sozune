#!/usr/bin/env bash
# An exact path must match with a query string. Sōzu compares the path rule
# against the path *with* its query, so an exact `/login` used to refuse
# `/login?next=/`. Exact paths have no label: the route is created through the
# API, pointing at a whoami container.
# Sourced by run-all.sh.

log "[31] Exact path: a request with a query still matches"

HOST_EXACT="exact.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"
EXACT_API_URL="http://127.0.0.1:$API_PORT"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_exact() {
    docker rm -f sozune-exact >/dev/null 2>&1 || true
}
cleanup_exact

docker run -d --name sozune-exact --hostname exact-login --network "$NETWORK" \
    traefik/whoami >/dev/null
EXACT_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" sozune-exact)

exact_id=$(curl -s --max-time 2 -X POST \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "{\"name\":\"exact-login\",\"backends\":[{\"address\":\"$EXACT_IP\",\"port\":80,\"weight\":100}],\"protocol\":\"Http\",\"config\":{\"hostnames\":[\"$HOST_EXACT\"],\"path\":{\"rule_type\":\"Exact\",\"value\":\"/login\"},\"tls\":false,\"strip_prefix\":false,\"https_redirect\":false,\"priority\":0,\"auth\":null,\"headers\":[]}}" \
    "$EXACT_API_URL/entrypoints" 2>/dev/null | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')

if wait_for_status "http://127.0.0.1:$HTTP_PORT/login" "$HOST_EXACT" "200"; then
    pass "exact path /login is served"
else
    fail "exact path /login was never served"
fi

query_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_EXACT" "http://127.0.0.1:$HTTP_PORT/login?next=/" 2>/dev/null || echo "000")
if [[ "$query_status" == "200" ]]; then
    pass "exact path /login also serves /login?next=/"
else
    fail "exact path /login answered $query_status for /login?next=/ (expected 200)"
fi

below_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_EXACT" "http://127.0.0.1:$HTTP_PORT/login/x" 2>/dev/null || echo "000")
if [[ "$below_status" != "200" ]]; then
    pass "exact path /login does not serve /login/x"
else
    fail "exact path /login served /login/x"
fi

if [[ -n "$exact_id" ]]; then
    curl -s -o /dev/null --max-time 2 -X DELETE \
        -H "Authorization: Basic $API_BASIC_AUTH" "$EXACT_API_URL/entrypoints/$exact_id" || true
fi
cleanup_exact
