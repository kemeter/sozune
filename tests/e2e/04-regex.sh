#!/usr/bin/env bash
# Regex path matching + future feature placeholders.
# Sourced by run-all.sh.

log "[04] Regex path matching"

wait_for_status "http://127.0.0.1:$HTTP_PORT/users/123" "$HOST_REGEX" "200" || true

regex_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_REGEX" \
    "http://127.0.0.1:$HTTP_PORT/users/456" 2>/dev/null || echo "000")
if [[ "$regex_status" == "200" ]]; then
    pass "regex path matching: /users/456 matches /users/[0-9]+"
else
    fail "regex path matching: /users/456 returned $regex_status instead of 200"
fi

regex_fail_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_REGEX" \
    "http://127.0.0.1:$HTTP_PORT/users/abc" 2>/dev/null || echo "000")
if [[ "$regex_fail_status" != "200" ]]; then
    pass "regex path matching: /users/abc does not match /users/[0-9]+"
else
    fail "regex path matching: /users/abc should not match but returned 200"
fi

skip "method-based routing: POST /api returns different backend than GET /api"
skip "response caching: second request returns cached response"
