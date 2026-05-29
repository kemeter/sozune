#!/usr/bin/env bash
# Header & query matching: the svc-match route requires header X-Env:prod AND
# query version=2. A request meeting both conditions is served (200); missing
# either is rejected with 404.
# Sourced by run-all.sh.

log "[14] Header/query matching: both conditions met is served"

ok_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MATCH" -H "X-Env: prod" \
    "http://127.0.0.1:$HTTP_PORT/?version=2" 2>/dev/null || echo "000")
if [[ "$ok_status" == "200" ]]; then
    pass "request with matching header + query is served (200)"
else
    fail "matching request returned $ok_status, expected 200"
fi

log "[14] Header/query matching: missing header is rejected"

no_header=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MATCH" \
    "http://127.0.0.1:$HTTP_PORT/?version=2" 2>/dev/null || echo "000")
if [[ "$no_header" == "404" ]]; then
    pass "request missing X-Env header is rejected (404)"
else
    fail "request missing header returned $no_header, expected 404"
fi

log "[14] Header/query matching: missing query is rejected"

no_query=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MATCH" -H "X-Env: prod" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$no_query" == "404" ]]; then
    pass "request missing version query is rejected (404)"
else
    fail "request missing query returned $no_query, expected 404"
fi

log "[14] Header/query matching: wrong header value is rejected"

wrong_value=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MATCH" -H "X-Env: staging" \
    "http://127.0.0.1:$HTTP_PORT/?version=2" 2>/dev/null || echo "000")
if [[ "$wrong_value" == "404" ]]; then
    pass "request with wrong header value is rejected (404)"
else
    fail "request with wrong header value returned $wrong_value, expected 404"
fi
