#!/usr/bin/env bash
# WASM plugin middleware: a http-wasm guest that adds a response header on
# every request and short-circuits with 403 when `x-wasm-block: yes` is set.
# Sourced by run-all.sh.

log "[12] WASM plugin: http-wasm guest middleware"

# The guest only builds when the wasm32-unknown-unknown target is available.
# Without it, the plugin is never declared and the suite is skipped.
if [[ ! -f "${WASM_PLUGIN_FILE:-}" ]]; then
    skip "WASM plugin guest not built (wasm32-unknown-unknown target missing)"
    return 0 2>/dev/null || true
fi

# 1. The guest adds `x-wasm-plugin: ran` to the response.
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_WASM" "200"; then
    headers=$(curl -s -D - -o /dev/null --max-time 2 \
        -H "Host: $HOST_WASM" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
    if echo "$headers" | grep -qi "x-wasm-plugin: ran"; then
        pass "wasm plugin added response header x-wasm-plugin: ran"
    else
        fail "wasm plugin response header x-wasm-plugin NOT found"
    fi
else
    fail "wasm plugin route did not return 200"
fi

# 2. The guest short-circuits with 403 when x-wasm-block: yes is present.
block_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_WASM" -H "x-wasm-block: yes" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$block_status" == "403" ]]; then
    pass "wasm plugin short-circuited with 403 on x-wasm-block"
else
    fail "wasm plugin returned $block_status instead of 403 on x-wasm-block"
fi

# 3. The short-circuit body comes from the guest, not the backend.
block_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_WASM" -H "x-wasm-block: yes" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if echo "$block_body" | grep -qi "blocked by wasm plugin"; then
    pass "wasm plugin returned its own response body on block"
else
    fail "wasm plugin block body not found (got: $block_body)"
fi

# 4. A request body larger than the 1 MiB buffer limit must reach the backend
#    UNTRUNCATED. The guest can't see it (it's not buffered), but the backend
#    must receive the full payload — not a silently emptied body. whoami echoes
#    the request headers it received, so the first `Content-Length:` line in its
#    output is what the backend actually saw.
big_file=$(mktemp)
# 2 MiB — comfortably over MAX_BUFFERED_BODY (1 MiB).
head -c 2097152 /dev/zero | tr '\0' 'x' > "$big_file"
big_len=$(wc -c < "$big_file" | tr -d ' ')
resp_file=$(mktemp)
curl -s --max-time 10 -X POST --data-binary "@$big_file" \
    -H "Host: $HOST_WASM" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null > "$resp_file" || true
rm -f "$big_file"
# whoami emits the received headers first; take the FIRST Content-Length line
# (the header it saw) and read only its numeric value. Each step is guarded so a
# non-match can't abort the suite under `set -e`.
seen_len=$(grep -i -m1 '^Content-Length:' "$resp_file" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "")
if [[ "$seen_len" == "$big_len" ]]; then
    pass "oversize request body ($big_len bytes) forwarded untouched to backend"
else
    fail "oversize request body truncated: backend saw Content-Length='$seen_len', expected '$big_len'"
fi
# The response side is symmetric: whoami echoes the full 2 MiB body back, which
# is over the buffer limit, so the response must also reach the client
# untruncated (the on_response oversize path).
resp_size=$(wc -c < "$resp_file" 2>/dev/null | tr -d ' ' || echo "0")
resp_size=${resp_size:-0}
rm -f "$resp_file"
if [[ "$resp_size" -gt 1048576 ]]; then
    pass "oversize response body streamed back to client untruncated ($resp_size bytes)"
else
    fail "oversize response body truncated: client received only $resp_size bytes"
fi
