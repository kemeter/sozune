#!/usr/bin/env bash
# TCP entrypoints: declared listener forwards to a backend resolved via Docker labels.
# Sourced by run-all.sh.

log "[07] TCP: listener accepts connections"

if wait_for_tcp_open "127.0.0.1" "$TCP_ECHO_PORT"; then
    pass "TCP listener on $TCP_ECHO_PORT is open"
else
    fail "TCP listener on $TCP_ECHO_PORT did not open"
fi

log "[07] TCP: bidirectional forwarding"

response=$(tcp_send "127.0.0.1" "$TCP_ECHO_PORT" "ping-sozune")
if [[ "$response" == *"ping-sozune"* ]]; then
    pass "echo backend reachable through TCP entrypoint"
else
    fail "echo backend did not reply (got: '$response')"
fi

log "[07] TCP: second listener also forwards"

if wait_for_tcp_open "127.0.0.1" "$TCP_RR_PORT"; then
    pass "TCP listener on $TCP_RR_PORT is open"
else
    fail "TCP listener on $TCP_RR_PORT did not open"
fi

response=$(tcp_send "127.0.0.1" "$TCP_RR_PORT" "")
if [[ "$response" == *"backend-a"* || "$response" == *"backend-b"* ]]; then
    pass "second listener forwards to its declared backend"
else
    fail "second listener did not forward (got: '$response')"
fi
