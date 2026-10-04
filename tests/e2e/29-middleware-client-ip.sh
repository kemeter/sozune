#!/usr/bin/env bash
# The middleware must judge a request by the client's address, not by Sōzu's.
# Sōzu is what connects to the middleware server, always from loopback, so a
# client on loopback cannot tell the two apart: these checks send the request
# from a container, reaching Sōzu through the network gateway with the
# container's own address on the test network.
# Sourced by run-all.sh.

log "[29] Middleware client IP: IP-based rules see the real client"

HOST_CIP_SELF="cip-self.func-test.localhost"
HOST_CIP_LOOP="cip-loop.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"
CIP_GATEWAY=$(docker network inspect "$NETWORK" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
CIP_SUBNET=$(docker network inspect "$NETWORK" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_cip_containers() {
    docker rm -f sozune-cip-self sozune-cip-loop >/dev/null 2>&1 || true
}
cleanup_cip_containers

# Allows only the test network: where requests from a container come from.
docker run -d --name sozune-cip-self \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.cipself.host=$HOST_CIP_SELF" \
    -l "sozune.http.cipself.ipAllowList=$CIP_SUBNET" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

# Allows only loopback: where Sōzu connects to the middleware from.
docker run -d --name sozune-cip-loop \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.ciploop.host=$HOST_CIP_LOOP" \
    -l "sozune.http.ciploop.ipAllowList=127.0.0.1" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

# Status of a request sent from a container on the test network.
cip_status_from_container() {
    docker run --rm --network "$NETWORK" curlimages/curl:latest \
        -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H "Host: $1" "http://$CIP_GATEWAY:$HTTP_PORT/" 2>/dev/null || echo "000"
}

# Both routes are up once the host (on loopback) gets its expected answers.
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_CIP_LOOP" "200" \
    && wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_CIP_SELF" "403"; then
    pass "client IP routes installed"
else
    fail "client IP routes never reached their expected answers from the host"
fi

status=$(cip_status_from_container "$HOST_CIP_SELF")
if [[ "$status" == "200" ]]; then
    pass "a client from $CIP_SUBNET is allowed by an allow-list naming that network"
else
    fail "a client from $CIP_SUBNET got $status from an allow-list naming that network (expected 200) — the middleware does not see the client's address"
fi

status=$(cip_status_from_container "$HOST_CIP_LOOP")
if [[ "$status" == "403" ]]; then
    pass "a client from $CIP_SUBNET is refused by an allow-list naming only 127.0.0.1"
else
    fail "a client from $CIP_SUBNET got $status from an allow-list naming only 127.0.0.1 (expected 403) — it was taken for Sōzu's loopback address"
fi

cleanup_cip_containers
