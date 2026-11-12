#!/usr/bin/env bash
# The middleware's own answers to a gRPC call come in gRPC form: a status
# and a message the client reads, not an HTTP error. svc-grpc's grpcdown
# route points at a port nothing listens on; grpclimited allows two
# requests at once, one a second after. grpcurl asks the server's
# reflection service before each call: those are requests too, and the
# error may come on them. Sourced by run-all.sh.

log "[45] gRPC errors: the middleware answers a call in gRPC form"

reply=$(docker run --rm --network host fullstorydev/grpcurl:v1.9.3 -plaintext \
    -authority "$HOST_GRPC_DOWN" -d '{"greeting":"down"}' \
    "127.0.0.1:$HTTP_PORT" hello.HelloService/SayHello 2>&1 || true)
if [[ "$reply" =~ (Code:|code\ =)\ Unavailable && "$reply" == *"sozune: backend-unreachable"* ]]; then
    pass "a call no backend answers is UNAVAILABLE, with the reason"
else
    fail "the call to an unreachable backend got: $reply"
fi

# Five calls in a row: past the first requests, the limit answers.
replies=$(docker run --rm --network host --entrypoint sh fullstorydev/grpcurl:v1.9.3-alpine -c "
    for i in 1 2 3 4 5; do
        grpcurl -plaintext -authority $HOST_GRPC_LIMITED -d '{\"greeting\":\"limited\"}' \
            127.0.0.1:$HTTP_PORT hello.HelloService/SayHello 2>&1
    done" 2>&1 || true)
if [[ "$replies" =~ (Code:|code\ =)\ ResourceExhausted && "$replies" == *"sozune: rate-limited"* ]]; then
    pass "a call past the rate limit is RESOURCE_EXHAUSTED"
else
    fail "the calls past the rate limit got: $replies"
fi
