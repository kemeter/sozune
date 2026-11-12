#!/usr/bin/env bash
# A gRPC stream through a route that retries (retry.attempts=2): the
# middleware streams the call instead of reading it whole first, so the
# server answers each message while the client still streams. svc-grpc
# (grpcbin) answers each BidiHello message at once. Sourced by run-all.sh.

log "[43] gRPC streaming: a route that retries streams the call"

# The client sends one message, then keeps its stream open for 6 seconds.
# Each reply line is stamped with the milliseconds since the call began.
start=$(date +%s%N)
replies=$( (echo '{"greeting":"stream"}'; sleep 6) \
    | docker run --rm -i --network host fullstorydev/grpcurl:v1.9.3 -plaintext \
        -authority "$HOST_GRPC_RETRY" -d @ \
        "127.0.0.1:$HTTP_PORT" hello.HelloService/BidiHello 2>&1 \
    | while IFS= read -r line; do
        echo "$(( ($(date +%s%N) - start) / 1000000 )) $line"
    done || true)
first=$(echo "$replies" | grep '"reply": "hello stream"' | head -1 | cut -d' ' -f1)
if [[ -n "$first" && "$first" -lt 4000 ]]; then
    pass "the server answers a message while the client still streams (${first}ms)"
else
    fail "the reply came after the client ended its stream, or not at all: $replies"
fi
