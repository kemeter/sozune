#!/usr/bin/env bash
# Retry middleware (`retry.attempts`).
#
# `svc-retry` is registered with `retry.attempts=3`. The deterministic contract
# verified here is that enabling retries does not break a normal request: the
# route still serves 200, and the request body is replayable (a POST with a
# body succeeds through the retry-buffering path). The retry-on-failure path is
# exercised by code review + unit tests; reproducing a flaky backend
# deterministically in e2e is out of scope.
#
# Sourced by run-all.sh.

log "[21] Retry: a route with retry.attempts serves normally (200)"

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_RETRY" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "retry-enabled route serves 200"
else
    fail "retry-enabled route returned $status, expected 200"
fi

log "[21] Retry: a POST body is replayable through the retry buffer (200)"

# The retry path buffers the body so it can be replayed; a POST with a body
# must still reach the backend on the first (successful) attempt.
post=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -X POST --data "hello-retry" \
    -H "Host: $HOST_RETRY" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$post" == "200" ]]; then
    pass "POST with body through retry buffer serves 200"
else
    fail "POST through retry route returned $post, expected 200"
fi
