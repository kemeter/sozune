#!/usr/bin/env bash
# gRPC-Web (grpcWeb): a browser's call, sent here by curl over HTTP/1.1, is
# translated into gRPC for svc-grpc (grpcbin) and its answer back, the
# call's status as the answer's last message. grpcweb allows pages of
# https://app.example; grpcwebdown points at a port nothing listens on.
# Sourced by run-all.sh.

log "[46] gRPC-Web: a browser's call is translated to gRPC and back"

# HelloRequest{greeting: "web"} as a gRPC message: no compression, length
# 5, then field 1 (0x0a), length 3, "web".
call() { printf '\x00\x00\x00\x00\x05\x0a\x03web'; }

reply=$(call | curl -s --http1.1 --max-time 5 -H "Host: $HOST_GRPC_WEB" \
    -H "Content-Type: application/grpc-web+proto" -H "X-Grpc-Web: 1" \
    --data-binary @- "http://127.0.0.1:$HTTP_PORT/hello.HelloService/SayHello" \
    2>/dev/null | tr -d '\0' || true)
if [[ "$reply" == *"hello web"* && "$reply" == *"grpc-status:0"* ]]; then
    pass "a gRPC-Web call gets the reply, its status as the last message"
else
    fail "the gRPC-Web call got: $(printf '%q' "$reply")"
fi

# The same call in the -text variant: base64 both ways. The answer is
# base64 runs, each padded: they are decoded one by one.
text=$(call | base64 -w0)
answer=$(curl -s --http1.1 --max-time 5 -H "Host: $HOST_GRPC_WEB" \
    -H "Content-Type: application/grpc-web-text" -H "X-Grpc-Web: 1" \
    --data "$text" "http://127.0.0.1:$HTTP_PORT/hello.HelloService/SayHello" \
    2>/dev/null || true)
decoded=$(python3 -c '
import base64, re, sys
runs = re.findall(r"[A-Za-z0-9+/]*={0,2}", sys.argv[1])
sys.stdout.write(b"".join(base64.b64decode(r) for r in runs if r).decode("latin-1"))
' "$answer" 2>/dev/null | tr -d '\0' || true)
if [[ "$decoded" == *"hello web"* && "$decoded" == *"grpc-status:0"* ]]; then
    pass "a gRPC-Web text call is decoded, and its answer encoded"
else
    fail "the gRPC-Web text call got: $answer"
fi

# A page of an allowed origin asks before calling: the preflight lets it
# send the gRPC-Web headers.
preflight=$(curl -s -i --http1.1 --max-time 3 -X OPTIONS -H "Host: $HOST_GRPC_WEB" \
    -H "Origin: https://app.example" -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type,x-grpc-web" \
    "http://127.0.0.1:$HTTP_PORT/hello.HelloService/SayHello" 2>/dev/null | tr -d '\r' || true)
if grep -qi '^access-control-allow-origin: https://app.example' <<<"$preflight" \
    && grep -qi '^access-control-allow-headers:.*x-grpc-web' <<<"$preflight"; then
    pass "the preflight of an allowed origin lets it send a gRPC-Web call"
else
    fail "the gRPC-Web preflight got: $preflight"
fi

# The middleware's own answer comes in gRPC-Web form.
headers=$(call | curl -s -D - -o /dev/null --http1.1 --max-time 5 \
    -H "Host: $HOST_GRPC_WEB_DOWN" -H "Content-Type: application/grpc-web+proto" \
    --data-binary @- "http://127.0.0.1:$HTTP_PORT/hello.HelloService/SayHello" \
    2>/dev/null | tr -d '\r' || true)
if grep -q '^HTTP/1.1 200' <<<"$headers" && grep -qi '^grpc-status: 14' <<<"$headers" \
    && grep -qi '^content-type: application/grpc-web+proto' <<<"$headers"; then
    pass "a gRPC-Web call no backend answers is UNAVAILABLE, in gRPC-Web form"
else
    fail "the gRPC-Web call to an unreachable backend got: $headers"
fi
