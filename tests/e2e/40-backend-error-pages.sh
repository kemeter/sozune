#!/usr/bin/env bash
# Backend error pages: svc-backend-errors is a whoami, whose `GET /health`
# answers the status last posted to `/health`. Its route `backenderrors`
# replaces 500-599 and 404 with an inline page, and `backenderrorsurl`
# replaces 503 with the page fetched from svc-error-pages-server, a whoami
# that echoes the request line it got.
# Sourced by run-all.sh.

log "[40] Backend error pages: an inline page replaces the backend's error"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/health" "$HOST_BACKEND_ERRORS" "200"; then
    pass "a backend answer that is not an error passes through (200)"
else
    fail "the backenderrors route never answered 200"
fi

# Both routes share the backend: from now on its /health answers 503.
curl -s -o /dev/null --max-time 3 -X POST -d 503 \
    -H "Host: $HOST_BACKEND_ERRORS" "http://127.0.0.1:$HTTP_PORT/health" 2>/dev/null || true

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    -H "Host: $HOST_BACKEND_ERRORS" "http://127.0.0.1:$HTTP_PORT/health" 2>/dev/null || echo "000")
body=$(curl -s --max-time 3 \
    -H "Host: $HOST_BACKEND_ERRORS" "http://127.0.0.1:$HTTP_PORT/health" 2>/dev/null || true)
if [[ "$status" == "503" ]]; then
    pass "the replaced error keeps the backend's status (503)"
else
    fail "the replaced error returned $status, expected 503"
fi
if [[ "$body" == *"sozune backend error page"* ]]; then
    pass "the route's page replaced the backend's body"
else
    fail "the backend's body was not replaced (got: $body)"
fi

log "[40] Backend error pages: the page is fetched from errors.url"

for _ in $(seq 1 "$MAX_RETRIES"); do
    body=$(curl -s --max-time 3 \
        -H "Host: $HOST_BACKEND_ERRORS_URL" "http://127.0.0.1:$HTTP_PORT/health?x=1" 2>/dev/null || true)
    [[ "$body" == *"GET /503"* ]] && break
    sleep 1
done
if [[ "$body" == *"GET /503?from=%2Fhealth%3Fx%3D1 "* ]]; then
    pass "the page was fetched for the status and the request's URL"
else
    fail "the page was not fetched from errors.url (got: $body)"
fi

# Back to healthy, for any later suite.
curl -s -o /dev/null --max-time 3 -X POST -d 200 \
    -H "Host: $HOST_BACKEND_ERRORS" "http://127.0.0.1:$HTTP_PORT/health" 2>/dev/null || true
