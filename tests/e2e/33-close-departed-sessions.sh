#!/usr/bin/env bash
# A WebSocket open on a backend that leaves its route is closed, so the client
# reconnects to a backend that is still there. The backend keeps running: only
# the route moves to another one, through the API.
# Sourced by run-all.sh.

log "[33] Departed backend: its WebSocket sessions are closed"

HOST_DEPART="depart.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"
DEPART_API_URL="http://127.0.0.1:$API_PORT"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_depart() {
    docker rm -f sozune-depart-a sozune-depart-b >/dev/null 2>&1 || true
}
cleanup_depart

docker run -d --name sozune-depart-a --network "$NETWORK" jmalloc/echo-server >/dev/null
docker run -d --name sozune-depart-b --network "$NETWORK" jmalloc/echo-server >/dev/null
DEPART_A=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" sozune-depart-a)
DEPART_B=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" sozune-depart-b)

# $1: backend address; $2: the route's header edits, as JSON; $3: its
# backend timeout, which sends it through the middleware.
depart_entrypoint() {
    printf '{"name":"depart","backends":[{"address":"%s","port":8080,"weight":100}],"protocol":"Http","config":{"hostnames":["%s"],"path":null,"tls":false,"strip_prefix":false,"https_redirect":false,"priority":0,"auth":null,"headers":%s,"backend_timeout":%s}}' \
        "$1" "$HOST_DEPART" "${2:-[]}" "${3:-null}"
}

# Opens a WebSocket on the route and starts watching it: `cat` ends when
# Sōzune closes the connection, or after 30s, and writes its exit status to
# $ws_status. A plain `nc` would not do: it keeps running after the server
# closes while its input is open.
open_websocket() {
    ws_out=$(mktemp)
    ws_status=$(mktemp)
    exec 3<>"/dev/tcp/127.0.0.1/$HTTP_PORT"
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$HOST_DEPART" >&3
    (timeout 30 cat <&3 >"$ws_out"; echo $? >"$ws_status") &
    ws_pid=$!
    exec 3<&-
    sleep 2
}

# Waits up to 10s for the watched WebSocket to be closed by Sōzune.
websocket_closed() {
    for _ in $(seq 1 20); do
        if [[ "$(cat "$ws_status")" == "0" ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

close_websocket() {
    kill "$ws_pid" 2>/dev/null || true
    wait "$ws_pid" 2>/dev/null || true
    rm -f "$ws_out" "$ws_status"
}

depart_id=$(curl -s --max-time 2 -X POST \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_A")" \
    "$DEPART_API_URL/entrypoints" 2>/dev/null | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_DEPART" "200" || true

open_websocket
if grep -qi "101 Switching Protocols" "$ws_out"; then
    pass "a WebSocket is open on the first backend"
else
    fail "the WebSocket upgrade failed: $(head -1 "$ws_out")"
fi

# Move the route to backend B; A keeps running. Only the backends change, so
# the route is updated in place.
curl -s -o /dev/null --max-time 5 -X PUT \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_B")" \
    "$DEPART_API_URL/entrypoints/$depart_id" 2>/dev/null || true

if websocket_closed; then
    pass "the WebSocket closes once its backend leaves the route"
else
    fail "the WebSocket stayed open on a backend that left the route"
fi
close_websocket

log "[33] Departed backend: closed after a changed route is back"

# Back to A with a header edit as well: the route is reinstalled, and the
# session on B closes only once it is, so a client reconnecting at once is
# served.
open_websocket
curl -s -o /dev/null --max-time 5 -X PUT \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_A" '[{"name":"X-Depart","value":"1","direction":"request"}]')" \
    "$DEPART_API_URL/entrypoints/$depart_id" 2>/dev/null || true

if websocket_closed; then
    pass "the WebSocket closes when a changed route drops its backend"
    reconnect_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "Host: $HOST_DEPART" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
    if [[ "$reconnect_status" == "200" ]]; then
        pass "a client reconnecting at once reaches the route"
    else
        fail "a client reconnecting at once got $reconnect_status, expected 200"
    fi
else
    fail "the WebSocket stayed open after a changed route dropped its backend"
fi
close_websocket

log "[33] Departed backend: middleware tunnels are closed too"

# A backend timeout sends the route through the middleware, whose WebSocket
# tunnel to A must close when the route moves to B.
curl -s -o /dev/null --max-time 5 -X PUT \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_A" '[]' 30000)" \
    "$DEPART_API_URL/entrypoints/$depart_id" 2>/dev/null || true
sleep 2

open_websocket
if grep -qi "101 Switching Protocols" "$ws_out"; then
    pass "a WebSocket is open through the middleware"
else
    fail "the WebSocket upgrade through the middleware failed: $(head -1 "$ws_out")"
fi
curl -s -o /dev/null --max-time 5 -X PUT \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_B" '[]' 30000)" \
    "$DEPART_API_URL/entrypoints/$depart_id" 2>/dev/null || true

if websocket_closed; then
    pass "the middleware's tunnel closes once its backend leaves the route"
else
    fail "the middleware's tunnel stayed open on a backend that left the route"
fi
close_websocket

# A change that keeps the backend leaves the tunnel open.
open_websocket
curl -s -o /dev/null --max-time 5 -X PUT \
    -H "Authorization: Basic $API_BASIC_AUTH" -H "Content-Type: application/json" \
    -d "$(depart_entrypoint "$DEPART_B" '[]' 31000)" \
    "$DEPART_API_URL/entrypoints/$depart_id" 2>/dev/null || true
if websocket_closed; then
    fail "the middleware's tunnel closed although its backend stayed"
else
    pass "the middleware's tunnel stays open while its backend stays"
fi
close_websocket

if [[ -n "$depart_id" ]]; then
    curl -s -o /dev/null --max-time 2 -X DELETE \
        -H "Authorization: Basic $API_BASIC_AUTH" "$DEPART_API_URL/entrypoints/$depart_id" || true
fi
cleanup_depart
