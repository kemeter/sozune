#!/usr/bin/env bash
# serviceWeight: svc-sw-stable runs 2 replicas and svc-sw-canary 1, both
# serving the sw route with serviceWeight=1. Each service takes half of the
# requests, whatever its replica count: the canary half, not a third.
# Sourced by run-all.sh.

log "[49] serviceWeight: a service's weight is shared by its replicas"

# The three replicas join the route as they start: wait for all of them.
backends=""
for _ in $(seq 1 30); do
    backends=$(curl -s --max-time 2 -H "Authorization: Basic $API_BASIC_AUTH" \
        "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null | python3 -c '
import json, sys
host = sys.argv[1]
data = json.load(sys.stdin)
routes = data if isinstance(data, list) else data.get("member", data.get("entrypoints", []))
for route in routes:
    if host in route.get("config", {}).get("hostnames", []):
        print(len(route.get("backends", [])))
' "$HOST_SERVICE_WEIGHT" 2>/dev/null || true)
    [[ "$backends" == "3" ]] && break
    sleep 1
done

canary=0
total=40
for _ in $(seq 1 "$total"); do
    name=$(curl -s --max-time 2 -H "Host: $HOST_SERVICE_WEIGHT" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | sed -n 's/^Name: //p' || true)
    [[ "$name" == "canary" ]] && canary=$((canary + 1))
done
# Round-robin by weight: exactly half; a third would be about 13.
if [[ "$backends" == "3" && $canary -ge 17 && $canary -le 23 ]]; then
    pass "the one-replica service takes half the requests ($canary of $total)"
else
    fail "the canary took $canary of $total requests with $backends backends, expected about half"
fi
