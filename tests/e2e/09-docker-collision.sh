#!/usr/bin/env bash
# Docker provider: two unrelated containers that happen to share the same
# `sozune.<protocol>.<service-name>` segment must produce two distinct
# entrypoints (not be merged silently into one).
# Sourced by run-all.sh.

log "[09] Docker collision: same service-name, different hostnames"

HOST_COLL_A="collide-a.func-test.localhost"
HOST_COLL_B="collide-b.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

cleanup_collision_containers() {
    docker rm -f sozune-collide-a sozune-collide-b >/dev/null 2>&1 || true
}
trap cleanup_collision_containers EXIT

# Start two containers, both using the `collide` service-name segment but
# exposing distinct hostnames. Without the dedup-by-routing-surface fix the
# second container's hostname would be silently dropped.
docker run -d --rm --name sozune-collide-a \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.collide.host=$HOST_COLL_A" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

docker run -d --rm --name sozune-collide-b \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.collide.host=$HOST_COLL_B" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_COLL_A" "200"; then
    pass "first collision container (host A) reachable"
else
    fail "first collision container (host A) NOT reachable"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_COLL_B" "200"; then
    pass "second collision container (host B) reachable — not merged silently"
else
    fail "second collision container (host B) NOT reachable — likely merged into the first cluster"
fi

cleanup_collision_containers
trap - EXIT
