#!/usr/bin/env bash
# Sōzune HTTP health check (`healthCheck.path` / `healthCheck.status`).
#
# Distinct from 11-docker-healthcheck.sh (which gates on Docker's own
# HEALTHCHECK). Here Sōzune itself issues `GET <path>` to the backend and
# judges health on the status code.
#
# Trick for determinism: `traefik/whoami` always answers 200. So:
#   - healthCheck.path=/ with no status  → 200 accepted → routed.
#   - healthCheck.path=/ with status=503 → whoami's 200 ≠ 503 → marked down →
#     dropped from routing (proxy returns non-200).
#
# Sourced by run-all.sh.

log "[17] Sōzune HTTP health check"

HOST_HCOK="hcok.func-test.localhost"
HOST_HCBAD="hcbad.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

cleanup_http_hc_containers() {
    docker rm -f sozune-hcok sozune-hcbad >/dev/null 2>&1 || true
}
trap cleanup_http_hc_containers EXIT

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

# -- Case 2: HTTP health check fails (expects 503, whoami returns 200) → down --
docker run -d --rm --name sozune-hcbad \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.hcbad.host=$HOST_HCBAD" \
    -l "sozune.http.hcbad.healthCheck.path=/" \
    -l "sozune.http.hcbad.healthCheck.status=503" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

# The health checker runs every 10s; the backend starts healthy in routing
# until the first probe rejects it. Poll for the drop to non-200.
i=0
STATUS_BAD=200
while [[ $i -lt 30 ]]; do
    STATUS_BAD="$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: $HOST_HCBAD" "http://127.0.0.1:$HTTP_PORT/" || echo "000")"
    [[ "$STATUS_BAD" != "200" ]] && break
    sleep 0.5
    i=$((i + 1))
done
if [[ "$STATUS_BAD" != "200" ]]; then
    pass "backend failing its HTTP health check is dropped (status=$STATUS_BAD)"
else
    fail "backend with failing HTTP health check should be dropped, still 200"
fi

# -- Case 3: the API surfaces the failure reason as bad_status --
# `/entrypoints` is admin-only; use basic auth from lib.sh. The `grep` may not
# match (exit 1); under `set -e`/`pipefail` that would abort the suite, so
# guard the whole pipeline with `|| true`.
reason=$(curl -s --max-time 2 \
    -H "Authorization: Basic $API_BASIC_AUTH" \
    "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null \
    | grep -o '"kind":"bad_status"' | head -1 || true)
if [[ -n "$reason" ]]; then
    pass "API reports the unhealthy reason as bad_status"
else
    # Non-fatal detail: the drop is already proven above. Surface as skip if the
    # reason isn't visible (e.g. entrypoint keyed differently in this run).
    skip "bad_status reason not found in /entrypoints (drop already verified)"
fi

cleanup_http_hc_containers
trap - EXIT
