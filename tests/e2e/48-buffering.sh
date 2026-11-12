#!/usr/bin/env bash
# Buffering: svc-buffer's bufferreq route reads request bodies whole, up to
# 1000 bytes; bufferresp reads answers whole, up to 50 bytes, which whoami's
# pass. Sourced by run-all.sh.

log "[48] Buffering: bodies past the route's limit are refused"

# The status a POST of $2 bytes to the route serving $1 gets, with the
# curl arguments that follow.
post_status() {
    local host=$1 size=$2
    shift 2
    head -c "$size" /dev/zero | tr '\0' 'a' | curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 -H "Host: $host" "$@" --data-binary @- \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true
}

small=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    small=$(post_status "$HOST_BUFFER_REQ" 1000)
    [[ "$small" == "200" ]] && break
    sleep 0.5
done
if [[ "$small" == "200" ]]; then
    pass "a request body within the limit reaches the backend"
else
    fail "a 1000-byte body got $small, expected 200"
fi

large=$(post_status "$HOST_BUFFER_REQ" 1001)
chunked=$(post_status "$HOST_BUFFER_REQ" 5000 -H "Transfer-Encoding: chunked")
if [[ "$large" == "413" && "$chunked" == "413" ]]; then
    pass "a request body past the limit is answered 413, with a length or chunked"
else
    fail "bodies past the limit got $large (with a length) and $chunked (chunked), expected 413"
fi

answer=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "Host: $HOST_BUFFER_RESP" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)
if [[ "$answer" == "500" ]]; then
    pass "an answer past the limit is replaced by a 500"
else
    fail "whoami's answer past 50 bytes got $answer, expected 500"
fi
