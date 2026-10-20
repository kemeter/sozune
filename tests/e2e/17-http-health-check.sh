#!/usr/bin/env bash
# Sōzune HTTP health check (`healthCheck.path` / `healthCheck.status`).
#
# Distinct from 11-docker-healthcheck.sh (which gates on Docker's own
# HEALTHCHECK). Here Sōzune itself issues `GET <path>` to the backend and
# judges health on the status code.
#
# `traefik/whoami` answers 200 on `/`, and on `/health` until a POST sets
# another status. So:
#   - healthCheck.path=/ with no status  → 200 accepted → routed.
#   - two backends on /health, one set to 503 → it leaves the rotation, and
#     comes back once set to 200 again.
#   - healthCheck.path=/ with status=503 on a route's only backend → marked
#     down, but kept: a route never loses every backend to its health check.
#
# Sourced by run-all.sh.

log "[17] Sōzune HTTP health check"

HOST_HCOK="hcok.func-test.localhost"
HOST_HCBAD="hcbad.func-test.localhost"
HOST_HCPAIR="hcpair.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

cleanup_http_hc_containers() {
    docker rm -f sozune-hcok sozune-hcbad sozune-hcpair-a sozune-hcpair-b >/dev/null 2>&1 || true
}
# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_http_hc_containers

# -- Case 1: HTTP health check passes (whoami answers 200 on /) → routed --
docker run -d --rm --name sozune-hcok \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.hcok.host=$HOST_HCOK" \
    -l "sozune.http.hcok.healthCheck.path=/" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_HCOK" "200"; then
    pass "backend passing its HTTP health check is routed (200)"
else
    fail "healthy HTTP-checked backend should be routed but is not"
fi

# -- Case 2: a backend failing its health check leaves the rotation --
# Two whoami containers serve one route. Their `/health` answers 200 until a
# POST sets another status, which makes one unhealthy on demand.
docker run -d --rm --name sozune-hcpair-a --hostname hcpair-a \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.hcpair.host=$HOST_HCPAIR" \
    -l "sozune.http.hcpair.healthCheck.path=/health" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null
docker run -d --rm --name sozune-hcpair-b --hostname hcpair-b \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.hcpair.host=$HOST_HCPAIR" \
    -l "sozune.http.hcpair.healthCheck.path=/health" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null
HCPAIR_B=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" sozune-hcpair-b)

# The hostnames serving 6 requests in a row, one per line.
hcpair_served_by() {
    for _ in 1 2 3 4 5 6; do
        curl -s --max-time 2 -H "Host: $HOST_HCPAIR" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null \
            | awk '/^Hostname:/ {print $2}'
    done
}

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_HCPAIR" "200" || true
# Both serve first, so a later run of a alone means b left.
names=$(hcpair_served_by)
if grep -q '^hcpair-b$' <<<"$names"; then
    pass "both backends of the pair serve while healthy"
else
    fail "backend b never served while healthy: $(tr '\n' ' ' <<<"$names")"
fi
curl -s -o /dev/null --max-time 2 -X POST -d 503 "http://$HCPAIR_B/health" || true
b_health=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$HCPAIR_B/health" 2>/dev/null || echo "000")
if [[ "$b_health" == "503" ]]; then
    pass "backend b's health endpoint now answers 503"
else
    fail "backend b's health endpoint answers $b_health, expected 503"
fi

# Probes run every 10s: wait for b to leave the rotation.
only_a=false
for _ in $(seq 1 30); do
    names=$(hcpair_served_by)
    if [[ -n "$names" ]] && ! grep -qv '^hcpair-a$' <<<"$names"; then
        only_a=true
        break
    fi
    sleep 1
done
if [[ "$only_a" == "true" ]]; then
    pass "a backend failing its health check leaves the rotation"
else
    fail "a backend failing its health check still takes requests"
fi

curl -s -o /dev/null --max-time 2 -X POST -d 200 "http://$HCPAIR_B/health" || true
back=false
for _ in $(seq 1 30); do
    # Captured first: under `pipefail`, `grep -q` quitting early would fail
    # the pipeline even on a match.
    names=$(hcpair_served_by)
    if grep -q '^hcpair-b$' <<<"$names"; then
        back=true
        break
    fi
    sleep 1
done
if [[ "$back" == "true" ]]; then
    pass "a backend passing its health check again comes back"
else
    fail "a recovered backend did not come back into rotation"
fi

# -- Case 3: a route's only backend stays when it fails (expects 503, whoami
# returns 200), and the API says why --
docker run -d --rm --name sozune-hcbad \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.hcbad.host=$HOST_HCBAD" \
    -l "sozune.http.hcbad.healthCheck.path=/" \
    -l "sozune.http.hcbad.healthCheck.status=503" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_HCBAD" "200" || true
# `/entrypoints` is admin-only. The `grep` may not match (exit 1); under
# `set -e`/`pipefail` that would abort the suite, so guard it with `|| true`.
kept=""
for _ in $(seq 1 30); do
    kept=$(curl -s --max-time 2 \
        -H "Authorization: Basic $API_BASIC_AUTH" \
        "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null \
        | grep -o '{[^{}]*"kind":"bad_status"[^{}]*}' | grep '"in_rotation":true' | head -1 || true)
    [[ -n "$kept" ]] && break
    sleep 1
done
if [[ -n "$kept" ]]; then
    pass "the API reports bad_status and keeps a route's only backend in rotation"
else
    fail "the API did not report a kept bad_status backend"
fi
bad_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
    -H "Host: $HOST_HCBAD" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$bad_status" == "200" ]]; then
    pass "a route whose every backend is unhealthy still serves"
else
    fail "a route whose every backend is unhealthy answered $bad_status"
fi

cleanup_http_hc_containers
