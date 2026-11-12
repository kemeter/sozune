#!/usr/bin/env bash
# gRPC calls through a WASM plugin (svc-grpc's grpcwasm route runs the
# headerguest plugin): the plugin sees the call's headers, not its body,
# and the call's messages and trailers (its grpc-status) go through
# untouched. Sourced by run-all.sh.

if [[ ! -f "$WASM_PLUGIN_FILE" ]]; then
    skip "gRPC through a WASM plugin: the e2e guest was not built"
    return 0
fi

log "[44] gRPC through a WASM plugin: the call keeps its trailers"

reply=$(docker run --rm --network host fullstorydev/grpcurl:v1.9.3 -plaintext -v \
    -authority "$HOST_GRPC_WASM" -d '{"greeting":"wasm"}' \
    "127.0.0.1:$HTTP_PORT" hello.HelloService/SayHello 2>&1 || true)
if [[ "$reply" == *'"reply": "hello wasm"'* && "$reply" != *"ERROR"* ]]; then
    pass "a gRPC call through a plugin succeeds, its grpc-status kept"
else
    fail "the gRPC call through the plugin failed: $reply"
fi
if [[ "$reply" == *"x-wasm-plugin: ran"* ]]; then
    pass "the plugin still runs on the gRPC call"
else
    fail "the plugin did not run on the gRPC call: $reply"
fi

# One message, then the client keeps its stream open for 6 seconds: the
# reply comes while it streams, the plugin holding none of it.
start=$(date +%s%N)
replies=$( (echo '{"greeting":"wasm stream"}'; sleep 6) \
    | docker run --rm -i --network host fullstorydev/grpcurl:v1.9.3 -plaintext \
        -authority "$HOST_GRPC_WASM" -d @ \
        "127.0.0.1:$HTTP_PORT" hello.HelloService/BidiHello 2>&1 \
    | while IFS= read -r line; do
        echo "$(( ($(date +%s%N) - start) / 1000000 )) $line"
    done || true)
first=$(echo "$replies" | grep '"reply": "hello wasm stream"' | head -1 | cut -d' ' -f1)
if [[ -n "$first" && "$first" -lt 4000 ]]; then
    pass "a gRPC stream goes through the plugin as it comes (${first}ms)"
else
    fail "the stream through the plugin was held, or failed: $replies"
fi
