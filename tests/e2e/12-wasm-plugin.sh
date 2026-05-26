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
