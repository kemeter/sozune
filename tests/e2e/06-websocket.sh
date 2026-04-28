#!/usr/bin/env bash
# WebSocket: HTTP/1.1 upgrade flows through Sozune to the backend.
# Sourced by run-all.sh.

log "[06] WebSocket: HTTP/1.1 upgrade"

# Wait for the backend to be reachable (jmalloc/echo-server returns 200 on plain HTTP)
wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_WS" "200" || true

# Send a raw HTTP/1.1 upgrade request and check for "101 Switching Protocols".
# We use a fixed Sec-WebSocket-Key — the test only verifies that Sozune relays the
# upgrade to the backend and forwards the 101 response, not that we can speak the
# WebSocket protocol after the upgrade.
ws_response=$(printf 'GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$HOST_WS" \
    | timeout 3 nc 127.0.0.1 "$HTTP_PORT" 2>/dev/null | head -20 || true)

if echo "$ws_response" | grep -qi "101 Switching Protocols"; then
    pass "WebSocket upgrade: backend returned 101 through Sozune"
else
    fail "WebSocket upgrade: no 101 in response. Got:"
    echo "$ws_response" | head -5
fi

# Sanity: the response should also include the Upgrade and Connection headers
if echo "$ws_response" | grep -qi "^Upgrade: websocket"; then
    pass "WebSocket upgrade: Upgrade: websocket header forwarded"
else
    fail "WebSocket upgrade: missing Upgrade header in response"
fi
