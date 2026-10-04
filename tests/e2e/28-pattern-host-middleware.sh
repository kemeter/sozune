#!/usr/bin/env bash
# A wildcard or regex hostname must still reach its backend when the route
# goes through the middleware server. Sōzu matches the pattern and forwards
# the request with its real Host; the middleware then has to find the route
# for that host, which is not the pattern it was declared with.
# `compress=true` is enough to send a route through the middleware.
# Sourced by run-all.sh.

log "[28] Pattern hostnames: routes through the middleware keep working"

PATTERN_SUFFIX="pattern.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on. Clearing up front removes an aborted run's
# leftovers instead.
cleanup_pattern_containers() {
    docker rm -f sozune-pattern-wild sozune-pattern-regex >/dev/null 2>&1 || true
}
cleanup_pattern_containers

docker run -d --name sozune-pattern-wild --hostname pattern-wild \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.patternwild.host=*.wild.$PATTERN_SUFFIX" \
    -l "sozune.http.patternwild.compress=true" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

docker run -d --name sozune-pattern-regex --hostname pattern-regex \
    --network "$NETWORK" \
    -l sozune.enable=true \
    -l "sozune.http.patternregex.host=/node[0-9]+/.regex.$PATTERN_SUFFIX" \
    -l "sozune.http.patternregex.compress=true" \
    -l "sozune.network=$NETWORK" \
    traefik/whoami >/dev/null

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "app.wild.$PATTERN_SUFFIX" "200"; then
    pass "wildcard host through the middleware reaches its backend"
else
    fail "wildcard host through the middleware: app.wild.$PATTERN_SUFFIX returned $(curl -s -o /dev/null -w '%{http_code}' --max-time 2 -H "Host: app.wild.$PATTERN_SUFFIX" "http://127.0.0.1:$HTTP_PORT/") instead of 200"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "node7.regex.$PATTERN_SUFFIX" "200"; then
    pass "regex host through the middleware reaches its backend"
else
    fail "regex host through the middleware: node7.regex.$PATTERN_SUFFIX returned $(curl -s -o /dev/null -w '%{http_code}' --max-time 2 -H "Host: node7.regex.$PATTERN_SUFFIX" "http://127.0.0.1:$HTTP_PORT/") instead of 200"
fi

cleanup_pattern_containers
