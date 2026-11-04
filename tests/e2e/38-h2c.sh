#!/usr/bin/env bash
# Cleartext HTTP/2 with prior knowledge on the HTTP port (proxy.http.h2c),
# HTTP/1.1 still served next to it. Sourced by run-all.sh.

log "[38] h2c prior knowledge on the HTTP port"

if ! curl --version 2>/dev/null | grep -qi "HTTP2"; then
    skip "h2c: local curl built without HTTP/2 support"
    return 0
fi

h2c_result=$(curl -s -o /dev/null -w '%{http_version} %{http_code}' --http2-prior-knowledge \
    --max-time 5 -H "Host: $HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)
if [[ "$h2c_result" == "2 200" ]]; then
    pass "a prior-knowledge HTTP/2 client is served over HTTP/2"
else
    fail "prior-knowledge HTTP/2: got '$h2c_result' (expected '2 200')"
fi

h1_result=$(curl -s -o /dev/null -w '%{http_version} %{http_code}' --http1.1 \
    --max-time 5 -H "Host: $HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)
if [[ "$h1_result" == "1.1 200" ]]; then
    pass "HTTP/1.1 is still served on the same port"
else
    fail "HTTP/1.1 next to h2c: got '$h1_result' (expected '1.1 200')"
fi

h2c_body=$(curl -s --http2-prior-knowledge --max-time 5 -H "Host: $HOST_A" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)
if grep -qi '^X-Forwarded-Proto: http$' <<<"$(tr -d '\r' <<<"$h2c_body")"; then
    pass "an h2c request reaches the backend as plain http"
else
    fail "h2c request: X-Forwarded-Proto is not http ($(grep -i forwarded-proto <<<"$h2c_body"))"
fi
