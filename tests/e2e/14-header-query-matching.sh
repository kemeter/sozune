#!/usr/bin/env bash
# Header & query matching: the svc-match route requires header X-Env:prod AND
# query version=2. A request meeting both conditions is served (200); missing
# either is rejected with 404. Two routes on the canary host differ only by
# the X-Canary header, which picks one.
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

log "[14] Header/query matching: an encoded query value still matches"

# `version=%32` is `version=2` percent-encoded: the condition compares the
# decoded value.
encoded_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_MATCH" -H "X-Env: prod" \
    "http://127.0.0.1:$HTTP_PORT/?version=%32" 2>/dev/null || echo "000")
if [[ "$encoded_status" == "200" ]]; then
    pass "request with a percent-encoded matching query is served (200)"
else
    fail "request with version=%32 returned $encoded_status, expected 200"
fi

log "[14] Header matching: a header picks between two routes on one host"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_CANARY" "200" || true

canary_name=$(curl -s --max-time 2 -H "Host: $HOST_CANARY" -H "X-Canary: 1" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | awk '/^Name:/ {print $2}')
stable_name=$(curl -s --max-time 2 -H "Host: $HOST_CANARY" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | awk '/^Name:/ {print $2}')
if [[ "$canary_name" == "canary" ]]; then
    pass "a request with X-Canary is served by the canary route"
else
    fail "a request with X-Canary was served by '$canary_name', expected canary"
fi
if [[ "$stable_name" == "stable" ]]; then
    pass "a request without X-Canary falls through to the stable route"
else
    fail "a request without X-Canary was served by '$stable_name', expected stable"
fi

log "[14] Header/query matching: a header regex picks its route, matching whole"

regex_name() {
    curl -s --max-time 2 -H "Host: $HOST_MATCH_REGEX" -H "X-Version: $1" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | awk -F': ' '/^Name:/{print $2; exit}'
}
matched=$(regex_name v12)
partial=$(regex_name v12-beta)
if [[ "$matched" == "regexversion" && "$partial" == "regexstable" ]]; then
    pass "X-Version v12 takes the regex route, v12-beta the other one"
else
    fail "header regex routing: v12 -> '$matched', v12-beta -> '$partial'"
fi

log "[14] Header/query matching: a query regex must match the whole value"

page_ok=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_QUERY_REGEX" "http://127.0.0.1:$HTTP_PORT/?page=12" 2>/dev/null || echo "000")
page_bad=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_QUERY_REGEX" "http://127.0.0.1:$HTTP_PORT/?page=12a" 2>/dev/null || echo "000")
if [[ "$page_ok" == "200" && "$page_bad" == "404" ]]; then
    pass "page=12 is served, page=12a is not"
else
    fail "query regex: page=12 -> $page_ok, page=12a -> $page_bad (expected 200, 404)"
fi
