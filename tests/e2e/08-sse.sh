#!/usr/bin/env bash
# Server-Sent Events: a long-lived stream propagates events from backend to
# client through Sozune chunk-by-chunk, not buffered until the connection
# closes. Uses a Mercure hub (anonymous publish allowed) as the SSE source.
# Sourced by run-all.sh.

log "[08] SSE: subscriber endpoint reachable"

# Mercure responds with the keepalive comment ":\n" almost immediately on
# subscribe. We give it a generous 5s and assert the connection completes
# (curl exit 28 is the expected timeout, exit 0 means EOF — both fine).
sse_probe=$(curl -s -N --max-time 3 -H "Host: $HOST_SSE" \
    "http://127.0.0.1:$HTTP_PORT/.well-known/mercure?topic=probe" 2>&1 | head -c 64 || true)

if [[ "$sse_probe" == *":"* ]]; then
    pass "SSE keepalive received from Mercure through Sozune"
else
    fail "no SSE keepalive received (got: '$sse_probe')"
    return 0
fi

log "[08] SSE: published event reaches subscriber in real time"

# Subscribe in background, capture wall-clock timestamps for every line.
sub_out="$(mktemp)"
trap "rm -f $sub_out" RETURN

(
    curl -s -N --max-time 8 -H "Host: $HOST_SSE" \
        "http://127.0.0.1:$HTTP_PORT/.well-known/mercure?topic=e2e-sse-test" 2>/dev/null \
    | while IFS= read -r line; do
        printf '%s.%03d %s\n' "$(date +%s)" "$((10#$(date +%N) / 1000000))" "$line"
    done
) > "$sub_out" &
sub_pid=$!

# Give the subscriber time to connect (first keepalive sets up the stream).
sleep 1.5

publish_ts=$(($(date +%s) * 1000 + 10#$(date +%N) / 1000000))

# Mercure's `anonymous` directive only allows anonymous SUBSCRIBE; publish
# always requires a publisher JWT. This token is signed with the same
# `MERCURE_PUBLISHER_JWT_KEY` configured on the svc-sse container in
# run-all.sh and grants publish on every topic.
SSE_PUBLISHER_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXJjdXJlIjp7InB1Ymxpc2giOlsiKiJdfX0.a8cjcSRUAcHdnGNMKifA4BK5epRXxQI0UBp2XpNrBdw"

publish_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    -H "Host: $HOST_SSE" \
    -H "Authorization: Bearer $SSE_PUBLISHER_JWT" \
    -d "topic=e2e-sse-test&data=hello-from-sozune-e2e" \
    "http://127.0.0.1:$HTTP_PORT/.well-known/mercure")

if [[ "$publish_status" != "200" ]]; then
    fail "publish failed (HTTP $publish_status)"
    kill "$sub_pid" 2>/dev/null || true
    wait "$sub_pid" 2>/dev/null || true
    return 0
fi

# Wait long enough for the event to flow back, then stop the subscriber.
sleep 2
kill "$sub_pid" 2>/dev/null || true
wait "$sub_pid" 2>/dev/null || true

if grep -q "data: hello-from-sozune-e2e" "$sub_out"; then
    pass "published event delivered to subscriber through Sozune"
else
    fail "subscriber never received the event. Stream contents:"
    cat "$sub_out"
    return 0
fi

# Find the timestamp of the data line and assert it arrived within 1s of
# publish — proves Sozune doesn't buffer the chunk until connection close.
data_line=$(grep "data: hello-from-sozune-e2e" "$sub_out" | head -1)
data_ts_str=$(echo "$data_line" | awk '{print $1}')
# Convert "1777672623.131" → 1777672623131 (ms)
data_ts=$(echo "$data_ts_str" | awk -F. '{printf "%d", $1 * 1000 + $2}')
delta_ms=$((data_ts - publish_ts))

if [[ "$delta_ms" -lt 1000 ]]; then
    pass "event streamed in real time (${delta_ms} ms after publish)"
else
    fail "event delivery was buffered: ${delta_ms} ms after publish (expected < 1000)"
fi
