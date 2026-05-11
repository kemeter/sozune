#!/usr/bin/env bash
# Docker provider: routing must be gated on the container's HEALTHCHECK status.
#
# Contract verified:
#   - Container WITHOUT a healthcheck → routed as soon as it's running.
#   - Container WITH a healthcheck → not routed while `starting`/`unhealthy`,
#     routed once `healthy`.
#
# Sourced by run-all.sh.

log "[11] Docker HEALTHCHECK gating"

HOST_NOHC="nohc.func-test.localhost"
HOST_HC="hc.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

cleanup_healthcheck_containers() {
    docker rm -f sozune-nohc sozune-hc-slow >/dev/null 2>&1 || true
}
trap cleanup_healthcheck_containers EXIT

# -- Case 1: container without HEALTHCHECK is routed immediately --
docker run -d --rm --name sozune-nohc \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.nohc.host=$HOST_NOHC" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_NOHC" "200"; then
    pass "no-healthcheck container is routed as soon as running"
else
    fail "no-healthcheck container should be routed but is not"
fi

# -- Case 2: container with a slow HEALTHCHECK is gated until it becomes healthy
# We give the healthcheck a long start period so the container stays `starting`
# for several seconds — long enough to assert that routing is refused during
# that window. We use nginx:alpine because it ships wget out of the box; the
# healthcheck targets nginx's own welcome page on :80.
docker run -d --rm --name sozune-hc-slow \
    --network "$NETWORK" \
    --health-cmd='wget -q -O- http://localhost:80/ >/dev/null 2>&1 || exit 1' \
    --health-interval=1s \
    --health-timeout=2s \
    --health-retries=2 \
    --health-start-period=4s \
    -l sozune.enable=true \
    -l "sozune.http.hc.host=$HOST_HC" \
    -l "sozune.http.hc.port=80" \
    -l "sozune.network=$NETWORK" \
    nginx:alpine >/dev/null

# Give Docker a moment to register the container and Sōzune to receive the
# `start` event. The container should be in `starting` and NOT routed: nginx
# may already be serving on :80, but the first health probe hasn't run yet.
sleep 1

STATUS_DURING_STARTING="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST_HC" "http://127.0.0.1:$HTTP_PORT/" || true)"
if [[ "$STATUS_DURING_STARTING" != "200" ]]; then
    pass "gated container is NOT routed while HEALTHCHECK is starting (status=$STATUS_DURING_STARTING)"
else
    fail "gated container should NOT be routed during starting, but got 200"
fi

# Now wait for the container to become healthy and confirm routing is enabled.
# wait_for_status polls up to MAX_RETRIES×0.5s (=10s); the healthcheck runs
# its first probe at T+1s (interval=1s) and flips to healthy then.
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_HC" "200"; then
    pass "gated container IS routed once HEALTHCHECK reports healthy"
else
    fail "gated container should be routed after becoming healthy, but never reached 200"
fi

# -- Case 3: a previously routed container that goes unhealthy is removed --
# Kill nginx inside the container so the healthcheck flips to unhealthy.
# With interval=1s and retries=2, the transition takes ~3s.
docker exec sozune-hc-slow nginx -s stop >/dev/null 2>&1 || true

# Wait for any non-200 response (Sōzune drops the backend → 404 from the
# proxy, or 502 if a stale cluster lingers briefly). wait_for_status polls
# every 500ms for up to 10s — more than enough for retries × interval.
i=0
STATUS_AFTER_UNHEALTHY=200
while [[ $i -lt 20 ]]; do
    STATUS_AFTER_UNHEALTHY="$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: $HOST_HC" "http://127.0.0.1:$HTTP_PORT/" || echo "000")"
    [[ "$STATUS_AFTER_UNHEALTHY" != "200" ]] && break
    sleep 0.5
    i=$((i + 1))
done
if [[ "$STATUS_AFTER_UNHEALTHY" != "200" ]]; then
    pass "previously routed container is dropped once HEALTHCHECK reports unhealthy (status=$STATUS_AFTER_UNHEALTHY)"
else
    fail "container should be removed from the pool after going unhealthy, but still returns 200"
fi

cleanup_healthcheck_containers
trap - EXIT
