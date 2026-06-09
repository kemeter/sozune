#!/usr/bin/env bash
# UDP load balancing: a declared UDP listener forwards datagrams to a backend
# resolved via Docker labels (sozune.udp.<name>.{entrypoint,port}).
# Sourced by run-all.sh.

log "[24] UDP: listener forwards datagrams to its backend"

# The UDP listener has no HTTP readiness probe, so retry the echo a few times
# while the reload installs the frontend + backend.
udp_reply=""
i=0
while [[ $i -lt $MAX_RETRIES ]]; do
    udp_reply=$(udp_send "127.0.0.1" "$UDP_ECHO_PORT" "ping-udp-sozune")
    if [[ "$udp_reply" == *"ping-udp-sozune"* ]]; then
        break
    fi
    sleep 0.5
    i=$((i + 1))
done

if [[ "$udp_reply" == *"ping-udp-sozune"* ]]; then
    pass "datagram echoed back through UDP entrypoint"
else
    fail "UDP backend did not echo through Sozune (got: '$udp_reply')"
fi
