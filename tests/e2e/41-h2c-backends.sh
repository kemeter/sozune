#!/usr/bin/env bash
# Backends that speak h2c (scheme=h2c): svc-h2c is an nginx that answers
# the protocol it got, and whose /health is only healthy over HTTP/2.
# svc-grpc is a gRPC server, called by grpcurl over h2c (proxy.http.h2c).
# Sourced by run-all.sh.

log "[41] h2c backends: scheme=h2c reaches the backend over HTTP/2"

body=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    body=$(curl -s --http1.1 --max-time 3 -H "Host: $HOST_H2C" \
        "http://127.0.0.1:$HTTP_PORT/hello" 2>/dev/null || true)
    [[ "$body" == HTTP/* ]] && break
    sleep 0.5
done
if [[ "$body" == "HTTP/2.0 /hello" ]]; then
    pass "an HTTP/1.1 request reaches an h2c backend over HTTP/2"
else
    fail "the h2c backend got '$body', expected 'HTTP/2.0 /hello'"
fi

body=$(curl -s --http1.1 --max-time 3 -H "Host: $HOST_H2C_MW" \
    "http://127.0.0.1:$HTTP_PORT/mw" 2>/dev/null || true)
if [[ "$body" == "HTTP/2.0 /mw" ]]; then
    pass "through the middleware, the backend is reached over HTTP/2 too"
else
    fail "through the middleware, the h2c backend got '$body', expected 'HTTP/2.0 /mw'"
fi

log "[41] h2c backends: the health check is sent over h2c"

# How many backends the API reports unhealthy on the route serving $1.
unhealthy_count() {
    curl -s --max-time 2 -H "Authorization: Basic $API_BASIC_AUTH" \
        "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null \
        | python3 -c '
import json, sys
host = sys.argv[1]
data = json.load(sys.stdin)
routes = data if isinstance(data, list) else data.get("member", data.get("entrypoints", []))
for route in routes:
    if host in route.get("config", {}).get("hostnames", []):
        print(len(route.get("unhealthy_backends", [])))
        break
' "$1" 2>/dev/null || true
}

# Probes run every second. The control route checks the same nginx over
# HTTP/1.1, which its /health refuses: once it is reported unhealthy, the
# h2c route has been probed too.
control=""
for _ in $(seq 1 30); do
    control=$(unhealthy_count "$HOST_H2C_CHECK_HTTP1")
    [[ "$control" == "1" ]] && break
    sleep 1
done
if [[ "$control" == "1" ]]; then
    pass "the same check over HTTP/1.1 reports the backend unhealthy (control)"
else
    fail "the HTTP/1.1-checked route reports '$control' unhealthy backends, expected 1"
fi
checked=$(unhealthy_count "$HOST_H2C_CHECK")
if [[ "$checked" == "0" ]]; then
    pass "a check sent over h2c finds the h2c backend healthy"
else
    fail "the h2c-checked route reports '$checked' unhealthy backends, expected 0"
fi

log "[41] h2c backends: a gRPC call goes through"

reply=$(docker run --rm --network host fullstorydev/grpcurl:v1.9.3 -plaintext \
    -authority "$HOST_GRPC" -d '{"greeting":"sozune"}' \
    "127.0.0.1:$HTTP_PORT" hello.HelloService/SayHello 2>&1 || true)
if [[ "$reply" == *'"reply": "hello sozune"'* ]]; then
    pass "a gRPC call reaches the gRPC server and gets its reply"
else
    fail "the gRPC call failed: $reply"
fi
