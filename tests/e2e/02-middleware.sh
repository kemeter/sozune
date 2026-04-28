#!/usr/bin/env bash
# Middleware: basic auth, header injection, strip prefix, HTTPS redirect,
# rate limiting, gzip compression, backend timeout.
# Sourced by run-all.sh.

log "[02] Middleware: basic auth"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_AUTH" "401"; then
    pass "basic auth returns 401 without credentials"
else
    fail "basic auth did NOT return 401 without credentials"
fi

wrong_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_AUTH" -u "admin:wrong" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$wrong_status" == "401" ]]; then
    pass "basic auth returns 401 with wrong credentials"
else
    fail "basic auth returned $wrong_status instead of 401 with wrong credentials"
fi

correct_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_AUTH" -u "admin:secret" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$correct_status" == "200" ]]; then
    pass "basic auth returns 200 with correct credentials"
else
    fail "basic auth returned $correct_status instead of 200 with correct credentials"
fi

log "[02] Middleware: custom headers injection"

header_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_HEADERS" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if echo "$header_body" | grep -qi "X-Custom-Test: hello-sozune"; then
    pass "custom header X-Custom-Test injected and visible in backend"
else
    fail "custom header X-Custom-Test NOT found in backend response"
fi

log "[02] Middleware: response-side header injection"

response_headers=$(curl -s -D - -o /dev/null --max-time 2 \
    -H "Host: $HOST_HEADERS_RESPONSE" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if echo "$response_headers" | grep -qi "^X-Powered-By: sozune"; then
    pass "response header X-Powered-By added to client response"
else
    fail "response header X-Powered-By NOT found in client response"
fi

both_body=$(curl -s -D /tmp/sozune-both-headers --max-time 2 \
    -H "Host: $HOST_HEADERS_BOTH" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if grep -qi "^X-Trace: tracevalue" /tmp/sozune-both-headers 2>/dev/null; then
    pass "both-direction header X-Trace visible in client response"
else
    fail "both-direction header X-Trace NOT found in client response"
fi
if printf '%s\n' "$both_body" | grep -qi "^X-Trace: tracevalue"; then
    pass "both-direction header X-Trace also forwarded to backend"
else
    fail "both-direction header X-Trace NOT forwarded to backend"
fi
rm -f /tmp/sozune-both-headers

log "[02] Middleware: header delete"

delete_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_HEADERS_DELETE" \
    -H "User-Agent: should-be-deleted/1.0" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if echo "$delete_body" | grep -qi "User-Agent: should-be-deleted"; then
    fail "header delete: User-Agent leaked through to backend"
else
    pass "header delete: User-Agent removed before reaching backend"
fi

log "[02] Middleware: strip prefix"

strip_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_STRIP" \
    "http://127.0.0.1:$HTTP_PORT/api/info" 2>/dev/null || echo "")
if echo "$strip_body" | grep -q "GET /info"; then
    pass "strip prefix: /api/info -> backend received /info"
else
    fail "strip prefix: backend did not receive /info, got: $(echo "$strip_body" | grep -i 'GET ' | head -1)"
fi

strip_root_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_STRIP" \
    "http://127.0.0.1:$HTTP_PORT/api" 2>/dev/null || echo "")
if echo "$strip_root_body" | grep -q "GET /"; then
    pass "strip prefix: /api -> backend received /"
else
    fail "strip prefix: backend did not receive /, got: $(echo "$strip_root_body" | grep -i 'GET ' | head -1)"
fi

log "[02] Middleware: HTTPS redirect"

redirect_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_REDIRECT" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$redirect_status" == "301" ]]; then
    pass "HTTPS redirect returns 301"
else
    fail "HTTPS redirect returned $redirect_status instead of 301"
fi

log "[02] Middleware: rate limiting"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_RATELIMIT" "200" || true

for i in $(seq 1 3); do
    curl -s -o /dev/null --max-time 2 -H "Host: $HOST_RATELIMIT" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true
done

rl_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_RATELIMIT" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$rl_status" == "429" ]]; then
    pass "rate limiting returns 429 after burst exceeded"
else
    fail "rate limiting returned $rl_status instead of 429"
fi

log "[02] Middleware: gzip compression"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_COMPRESS" "200" || true

compress_encoding=$(curl -s -D - -o /dev/null --max-time 2 \
    -H "Host: $HOST_COMPRESS" \
    -H "Accept-Encoding: gzip" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | grep -i "content-encoding" || echo "")
if echo "$compress_encoding" | grep -qi "gzip"; then
    pass "gzip compression: response has Content-Encoding: gzip"
else
    fail "gzip compression: no Content-Encoding: gzip header found"
fi

no_compress_encoding=$(curl -s -D - -o /dev/null --max-time 2 \
    -H "Host: $HOST_COMPRESS" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | grep -i "content-encoding" || echo "")
if echo "$no_compress_encoding" | grep -qi "gzip"; then
    fail "gzip compression: response compressed without Accept-Encoding"
else
    pass "gzip compression: no compression without Accept-Encoding"
fi

log "[02] Middleware: backend timeout"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_TIMEOUT" "200" || true

timeout_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Host: $HOST_TIMEOUT" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$timeout_status" == "200" ]]; then
    pass "backend timeout: normal request succeeds within timeout"
else
    fail "backend timeout: normal request returned $timeout_status instead of 200"
fi
