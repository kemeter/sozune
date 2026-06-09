#!/usr/bin/env bash
# TCP pre-accept IP allow-list: the forwarder gates the peer IP at accept().
# The e2e client connects from 127.0.0.1, so:
#   - tcpallow (allow 127.0.0.1/32) → connection forwarded, echo returns
#   - tcpdeny  (allow 10.0.0.0/8)   → loopback peer dropped, no echo
# Sourced by run-all.sh.

log "[25] TCP allow-list: an allowed peer is forwarded"

if wait_for_tcp_open "127.0.0.1" "$TCP_ALLOW_PORT"; then
    pass "allow-listed TCP listener on $TCP_ALLOW_PORT is open"
else
    fail "allow-listed TCP listener on $TCP_ALLOW_PORT did not open"
fi

allow_reply=$(tcp_send "127.0.0.1" "$TCP_ALLOW_PORT" "allowed-peer")
if [[ "$allow_reply" == *"allowed-peer"* ]]; then
    pass "loopback peer in the allow-list reaches the backend"
else
    fail "allowed peer did not get an echo (got: '$allow_reply')"
fi

log "[25] TCP allow-list: a peer outside the list is dropped"

# The deny listener allows only 10.0.0.0/8, so our loopback connection is
# accepted then closed without forwarding — no echo comes back.
deny_reply=$(tcp_send "127.0.0.1" "$TCP_DENY_PORT" "denied-peer")
if [[ "$deny_reply" != *"denied-peer"* ]]; then
    pass "loopback peer outside the allow-list gets no backend echo"
else
    fail "denied peer unexpectedly received an echo (got: '$deny_reply')"
fi
