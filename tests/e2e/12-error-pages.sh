#!/usr/bin/env bash
# Custom HTTP error pages: listener-level body served on unknown hostname (404),
# and cluster-level label parses + routes through without breaking the entrypoint.
# Sourced by run-all.sh.

log "[12] Error pages: listener-level 404 body"

response=$(curl -s --max-time 2 -H "Host: $HOST_UNKNOWN_404" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_UNKNOWN_404" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")

if [[ "$status" == "404" ]]; then
    pass "listener-level 404 returns expected status"
else
    fail "listener-level 404 returned $status, expected 404"
fi

if [[ "$response" == *"sozune custom 404"* ]]; then
    pass "listener-level 404 served the custom body"
else
    fail "listener-level 404 body did not contain the configured template (got: $response)"
fi

log "[12] Error pages: cluster-level label keeps the route healthy"

# The svc-errorpages container declares `sozune.http.svcerrorpages.errorPages.503=...`.
# We can't easily induce a 503 here (whoami is healthy), so we just assert the
# route itself parses cleanly and serves 200 — proves the label didn't get
# rejected by the catalog and didn't break entrypoint registration.
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_ERRORPAGES" "200"; then
    pass "cluster-level errorPages label did not break route registration"
else
    fail "cluster-level errorPages label broke route registration"
fi
