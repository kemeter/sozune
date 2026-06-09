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

log "[25] TCP anti-flood: a connection flood gets throttled"

# Listener tcpflood allows a burst of 2 (per_seconds 60 → effectively no refill
# during the test). The first connection echoes; a rapid flood beyond the burst
# must produce at least one dropped (empty) reply. We assert the robust
# invariants — first connection works, and the flood is not fully served —
# rather than pinning exactly which connection is the first to be dropped
# (socat's per-connection fork timing makes that brittle).
if wait_for_tcp_open "127.0.0.1" "$TCP_FLOOD_PORT"; then
    pass "rate-limited TCP listener on $TCP_FLOOD_PORT is open"
else
    fail "rate-limited TCP listener on $TCP_FLOOD_PORT did not open"
fi

first=$(tcp_send "127.0.0.1" "$TCP_FLOOD_PORT" "flood-first")
if [[ "$first" == *"flood-first"* ]]; then
    pass "first connection within the burst is forwarded"
else
    fail "first burst connection did not echo (got: '$first')"
fi

# Hammer past the burst; count how many of several rapid connections are dropped.
dropped=0
for n in 1 2 3 4 5 6; do
    reply=$(tcp_send "127.0.0.1" "$TCP_FLOOD_PORT" "flood-$n")
    [[ "$reply" != *"flood-$n"* ]] && dropped=$((dropped + 1))
done
if (( dropped > 0 )); then
    pass "flood beyond the burst is rate-limited ($dropped/6 connections dropped)"
else
    fail "no connection was throttled despite exceeding the burst"
fi
