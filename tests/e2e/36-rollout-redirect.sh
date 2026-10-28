#!/usr/bin/env bash
# A rolling update that turns a service into a redirect: the old container
# keeps serving while it runs, and the redirect takes over once it stops. The
# route used to go with the old container, the redirect with it.
# Sourced by run-all.sh.

log "[36] Rollout to a redirect: served, then redirected"

HOST_ROLLOUT="rollout.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_rollout() {
    docker rm -f sozune-rollout-old sozune-rollout-new >/dev/null 2>&1 || true
}
cleanup_rollout

docker run -d --name sozune-rollout-old --network "$NETWORK" \
    --label "sozune.enable=true" \
    --label "sozune.http.rollout.host=$HOST_ROLLOUT" \
    --label "sozune.http.rollout.port=80" \
    --label "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_ROLLOUT" "200"; then
    pass "the old container serves the route"
else
    fail "the old container never served the route"
fi

docker run -d --name sozune-rollout-new --network "$NETWORK" \
    --label "sozune.enable=true" \
    --label "sozune.http.rollout.host=$HOST_ROLLOUT" \
    --label "sozune.http.rollout.redirect=permanent" \
    --label "sozune.http.rollout.redirectHost=www.example.com" \
    --label "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null
sleep 2

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_ROLLOUT" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "the route still forwards while the old container runs"
else
    fail "the route answered $status while the old container runs, expected 200"
fi

docker rm -f sozune-rollout-old >/dev/null 2>&1 || true

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_ROLLOUT" "301"; then
    pass "the route redirects once the old container is gone"
else
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "Host: $HOST_ROLLOUT" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
    fail "the route answered $status once the old container was gone, expected 301"
fi

cleanup_rollout
