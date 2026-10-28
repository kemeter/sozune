#!/usr/bin/env bash
# Mirroring: svc-mirror-shadow declares `mirrorOf=mirrored`. Each request
# svc-mirrored serves is copied to it, its answer ignored, and it logs the
# request line it got.
# Sourced by run-all.sh.

log "[35] Mirror: a route's requests are copied to its mirror"

marker="mirror-check-$RANDOM$RANDOM"
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    -H "Host: $HOST_MIRROR" "http://127.0.0.1:$HTTP_PORT/$marker" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "the mirrored route answers with its own backend (200)"
else
    fail "the mirrored route returned $status, expected 200"
fi

copied=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    if docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs svc-mirror-shadow 2>/dev/null \
        | grep -q "GET /$marker"; then
        copied="yes"
        break
    fi
    sleep 1
done
if [[ "$copied" == "yes" ]]; then
    pass "the mirror got a copy of the request"
else
    fail "the mirror never got GET /$marker"
fi
