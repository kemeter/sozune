#!/usr/bin/env bash
# `POST /routes/resolve` must name the route that actually serves a request.
# For each request below, the route the resolver announces is compared with
# the backend that answers it (whoami echoes its container hostname).
# Sourced by run-all.sh.

log "[30] Route resolver: the announced route is the one that answers"

HOST_FID="fid.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"
FID_API_URL="http://127.0.0.1:$API_PORT"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_fid_containers() {
    docker rm -f sozune-fid-web sozune-fid-app sozune-fid-admin >/dev/null 2>&1 || true
}
cleanup_fid_containers

# web on `/`, admin on `/admin` (priority 5), app on `/app` (priority 10).
# Not `/api`: whoami answers that path itself, without its hostname line.
fid_start() {
    local name="$1"
    shift
    docker run -d --name "sozune-fid-$name" --hostname "fid-$name" \
        --network "$NETWORK" \
        -l sozune.enable=true \
        -l "sozune.http.fid$name.host=$HOST_FID" \
        -l "sozune.network=$NETWORK" \
        "$@" \
        traefik/whoami >/dev/null
}
fid_start web
fid_start admin -l "sozune.http.fidadmin.path=/admin" -l "sozune.http.fidadmin.priority=5"
fid_start app -l "sozune.http.fidapp.path=/app" -l "sozune.http.fidapp.priority=10"

# The whoami hostname that answers a path.
fid_backend_for() {
    curl -s --max-time 2 -H "Host: $HOST_FID" "http://127.0.0.1:$HTTP_PORT$1" 2>/dev/null \
        | sed -n 's/^Hostname: //p' | tr -d '\r'
}

# The route the resolver announces for a path, as the matching whoami
# hostname (`http_fidapp` → `fid-app`).
fid_resolved_for() {
    curl -s --max-time 2 -X POST \
        -H "Authorization: Basic $API_BASIC_AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"http://$HOST_FID$1\"}" \
        "$FID_API_URL/routes/resolve" 2>/dev/null \
        | sed -n 's/.*"route":{"id":"http_fid\([a-z]*\)".*/fid-\1/p'
}

# Wait until all three routes answer, and until the resolver sees them: it
# reads what the last reload installed, published once the reload ends.
i=0
until [[ "$(fid_backend_for /)" == "fid-web" && "$(fid_backend_for /app)" == "fid-app" \
        && "$(fid_backend_for /admin)" == "fid-admin" \
        && "$(fid_resolved_for /)" == "fid-web" && "$(fid_resolved_for /app)" == "fid-app" \
        && "$(fid_resolved_for /admin)" == "fid-admin" ]]; do
    i=$((i + 1))
    if [[ $i -ge 40 ]]; then
        break
    fi
    sleep 0.5
done

for path in / /app /app/users /admin /admin/settings /shop "/app?x=1" /apple; do
    actual=$(fid_backend_for "$path")
    announced=$(fid_resolved_for "$path")
    if [[ -n "$actual" && "$announced" == "$actual" ]]; then
        pass "resolver names $actual for $path, which is what answers"
    else
        fail "resolver names '${announced:-nothing}' for $path, but '${actual:-nothing}' answers"
    fi
done

# `sozune route` asks the same endpoint and exits 0 when a route serves the
# request, 1 when none does.
# run-all.sh runs under `set -e`: the exit status is captured, not tripped on.
cli_exit=0
cli_out=$("$SOZUNE_BIN" route "http://$HOST_FID/app/users" \
    --api "$FID_API_URL" --user "$API_USER:$API_PASSWORD" 2>&1) || cli_exit=$?
if [[ $cli_exit -eq 0 && "$cli_out" == *"route http_fidapp ("* ]]; then
    pass "sozune route names the route that serves /app/users"
else
    fail "sozune route exited $cli_exit for /app/users: $cli_out"
fi

cli_exit=0
cli_out=$("$SOZUNE_BIN" route "http://fdi.func-test.localhost/" \
    --api "$FID_API_URL" --user "$API_USER:$API_PASSWORD" 2>&1) || cli_exit=$?
if [[ $cli_exit -eq 1 && "$cli_out" == *"did you mean \`$HOST_FID\`"* ]]; then
    pass "sozune route exits 1 for an unknown host and suggests the closest one"
else
    fail "sozune route exited $cli_exit for an unknown host: $cli_out"
fi

# The exit status does not depend on the output format: a script reading
# --json gets the same answer from it.
cli_exit=0
"$SOZUNE_BIN" route "http://fdi.func-test.localhost/" --json \
    --api "$FID_API_URL" --user "$API_USER:$API_PASSWORD" >/dev/null 2>&1 || cli_exit=$?
if [[ $cli_exit -eq 1 ]]; then
    pass "sozune route --json also exits 1 for an unknown host"
else
    fail "sozune route --json exited $cli_exit for an unknown host (expected 1)"
fi

cleanup_fid_containers
