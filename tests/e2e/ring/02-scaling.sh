#!/usr/bin/env bash
# Ring scaling: re-apply the deployment with a new replica count and verify
# Sozune picks up the instance changes on its next poll. Sourced by run-ring.sh.

SCALED_MANIFEST="$RING_DATA_DIR/whoami-scaled.yaml"

apply_replicas() {
    local count="$1"
    sed "s/replicas: 3/replicas: $count/" "$RING_DIR/whoami.ring.yaml" > "$SCALED_MANIFEST"
    "$RING_BIN" apply --file "$SCALED_MANIFEST" >/dev/null
}

log "[02] Scale to 5 — backend list grows"
apply_replicas 5
if ! wait_for_ring_instances 5; then
    fail "Ring did not converge to 5 addressable instances in time"
    return 0
fi

distinct=$(wait_for_distinct_backends "$HOST_WHOAMI" 5 30 || true)
if [[ "$distinct" -ge 5 ]]; then
    pass "after scale to 5, $distinct distinct instances served traffic"
else
    fail "expected >=5 backends after scale-up, got $distinct"
fi

log "[02] Scale to 1 — backend list shrinks"
apply_replicas 1
if ! wait_for_ring_instances 1; then
    fail "Ring did not converge to 1 addressable instance in time"
    return 0
fi
# Sozune polls every few seconds; give the watcher a moment to drop the
# removed instances and reload Sōzu.
sleep "$ROUTE_DELAY"

distinct=$(count_distinct_hostnames "$HOST_WHOAMI" 12)
if [[ "$distinct" -le 1 ]]; then
    pass "after scale to 1, only $distinct distinct backend(s) served traffic"
else
    fail "expected <=1 backend after scale-down, got $distinct (stale instances?)"
fi
