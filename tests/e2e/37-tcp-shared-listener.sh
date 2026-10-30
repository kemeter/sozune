#!/usr/bin/env bash
# A TCP listener without SNI routing takes one route. Two routes declared on
# it: the higher priority serves, the other waits. Removing the waiting one
# leaves the listener alone; removing the serving one hands it to the other.
# Sourced by run-all.sh.

log "[37] TCP shared listener: the highest priority route serves"

NETWORK="${COMPOSE_PROJECT}_default"

# No `trap ... EXIT` here: this file is sourced, so it would replace the
# cleanup trap run-all.sh relies on.
cleanup_shared_containers() {
    docker rm -f sozune-shared-low sozune-shared-high >/dev/null 2>&1 || true
}
cleanup_shared_containers

start_shared_backend() {
    local name="$1" priority="$2"
    docker run -d --name "sozune-shared-$name" \
        --network "$NETWORK" \
        -l sozune.enable=true \
        -l "sozune.tcp.shared$name.entrypoint=tcpshared" \
        -l "sozune.tcp.shared$name.port=9000" \
        -l "sozune.tcp.shared$name.priority=$priority" \
        -l "sozune.network=$NETWORK" \
        alpine/socat "TCP-LISTEN:9000,fork,reuseaddr" "SYSTEM:'echo shared-$name'" >/dev/null
}

# Polls until the listener answers `expected`, or gives up after ~15s.
shared_wait_for() {
    local expected="$1" i=0
    while [[ $i -lt 30 ]]; do
        if [[ "$(tcp_send "127.0.0.1" "$TCP_SHARED_PORT" "")" == *"$expected"* ]]; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

start_shared_backend low 1
start_shared_backend high 10

if shared_wait_for shared-high; then
    pass "the priority 10 route serves the listener"
else
    fail "the listener did not reach the priority 10 route (got: '$(tcp_send "127.0.0.1" "$TCP_SHARED_PORT" "")')"
fi

log "[37] TCP shared listener: removing the waiting route leaves it alone"

docker rm -f sozune-shared-low >/dev/null
sleep "$ROUTE_DELAY"
if shared_wait_for shared-high; then
    pass "the listener still serves the priority 10 route"
else
    fail "the listener lost its route when the waiting one went (got: '$(tcp_send "127.0.0.1" "$TCP_SHARED_PORT" "")')"
fi

log "[37] TCP shared listener: the waiting route takes over"

start_shared_backend low 1
sleep "$ROUTE_DELAY"
docker rm -f sozune-shared-high >/dev/null
if shared_wait_for shared-low; then
    pass "the priority 1 route took the listener over"
else
    fail "the listener did not move to the priority 1 route (got: '$(tcp_send "127.0.0.1" "$TCP_SHARED_PORT" "")')"
fi

cleanup_shared_containers
