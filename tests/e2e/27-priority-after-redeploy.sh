#!/usr/bin/env bash
# Route priority must survive a redeploy. Sōzu matches its frontends in the
# order they were added, first match wins, so priority only holds if a
# higher-priority route is always installed before the ones it overrides.
#
# Two routes share a host: `web` on `/` (priority 0) and `api` on `/api`
# (priority 10). Stopping the api container removes its route (no backend
# left); starting it again adds it back. It must still win over `/` for
# `/api/...`. Stop and start are separate steps on purpose: a restart fast
# enough to land in one reload never removes the route at all.
# Sourced by run-all.sh.

log "[27] Priority: a redeployed route keeps precedence over a catch-all"

HOST_PRIO="prio.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

# No `trap ... EXIT` here: this file is sourced, so it would replace the
# cleanup trap run-all.sh relies on. Clearing up front instead removes what an
# aborted run left behind.
cleanup_prio_containers() {
    docker rm -f sozune-prio-web sozune-prio-api >/dev/null 2>&1 || true
}
cleanup_prio_containers

docker run -d --name sozune-prio-web --hostname prio-web \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.prioweb.host=$HOST_PRIO" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

docker run -d --name sozune-prio-api --hostname prio-api \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.prioapi.host=$HOST_PRIO" \
    -l "sozune.http.prioapi.path=/api" \
    -l "sozune.http.prioapi.priority=10" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

# Which backend answers a path: whoami echoes its container hostname.
prio_backend_for() {
    curl -s --max-time 2 -H "Host: $HOST_PRIO" "http://127.0.0.1:$HTTP_PORT$1" 2>/dev/null \
        | sed -n 's/^Hostname: //p' | tr -d '\r'
}

# Polls until `path` is served by `expected`, or gives up after ~15s.
prio_wait_for_backend() {
    local path="$1" expected="$2" i=0
    while [[ $i -lt 30 ]]; do
        if [[ "$(prio_backend_for "$path")" == "$expected" ]]; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

if prio_wait_for_backend "/" "prio-web" && prio_wait_for_backend "/api/users" "prio-api"; then
    pass "before redeploy: /api/users goes to api, / goes to web"
else
    fail "before redeploy: expected /api/users → prio-api and / → prio-web, got $(prio_backend_for "/api/users") and $(prio_backend_for "/")"
fi

docker stop sozune-prio-api >/dev/null

# With api gone, `/` catches /api/users. Seeing it proves the removal reached
# the workers before the route comes back.
if prio_wait_for_backend "/api/users" "prio-web"; then
    pass "api stopped: /api/users falls back to web"
else
    fail "api stopped: /api/users goes to $(prio_backend_for "/api/users") instead of prio-web"
fi

docker start sozune-prio-api >/dev/null

if prio_wait_for_backend "/api/users" "prio-api"; then
    pass "api started again: /api/users goes back to api (priority 10 over /)"
else
    fail "api started again: /api/users still goes to $(prio_backend_for "/api/users") instead of prio-api — the re-added route lost its precedence"
fi

cleanup_prio_containers
