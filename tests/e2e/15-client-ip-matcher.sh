#!/usr/bin/env bash
# Client-IP route matcher (`matchClientIP`)
#
# Unlike the `ipAllowList` *middleware* (which returns 403 Forbidden), the
# `matchClientIP` *routing matcher* returns 404 Not Found when the client IP
# is not in the list — the route simply "does not apply", same semantics as
# matchHeaders / matchQuery.
#
# The `svc-clientip` route matches `127.0.0.1,::1`. Sōzune runs with
# `trusted_proxies` empty (the default), so `X-Forwarded-For` is *ignored
# entirely* — the TCP peer (127.0.0.1 from curl) is the client → 200.
#
# The `svc-clientip-deny` route matches only `10.0.0.0/8`, which excludes the
# loopback peer → every request from the host gets 404, regardless of
# `X-Forwarded-For`.
#
# Sourced by run-all.sh.

# `HOST_CLIENTIP_DENY` is intentionally absent from the warm-up list (its
# matcher excludes 127.0.0.1, so the warm-up would loop on a 404). Poll for the
# steady-state 404 here before asserting.
log "[15] Client-IP matcher: waiting for the deny route to install its matcher"
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_CLIENTIP_DENY" 404; then
    pass "deny route installed its client-IP matcher"
else
    fail "deny route never reached 404 — client-IP matcher may not be installed"
fi

log "[15] Client-IP matcher: TCP peer is in the match list -> 200"

allowed_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_CLIENTIP" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$allowed_status" == "200" ]]; then
    pass "client at 127.0.0.1 (in 127.0.0.1 entry) matches the route (200)"
else
    fail "client at 127.0.0.1 returned $allowed_status, expected 200"
fi

log "[15] Client-IP matcher: X-Forwarded-For spoof is ignored without trusted_proxies"

# Forge an out-of-list XFF: without trusted_proxies the resolver must keep the
# loopback TCP peer (in the list) → still 200. If the resolver naively trusted
# XFF, this would flip to 404.
spoof_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_CLIENTIP" -H "X-Forwarded-For: 203.0.113.7" \
    -H "Connection: close" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$spoof_status" == "200" ]]; then
    pass "X-Forwarded-For is ignored (spoof did not divert the matcher)"
else
    fail "spoofed X-Forwarded-For returned $spoof_status; the matcher may be trusting XFF unconditionally"
fi

log "[15] Client-IP matcher: client outside the match list is rejected with 404"

# svc-clientip-deny matches only 10.0.0.0/8; the curl peer 127.0.0.1 is not in
# it → the route does not apply → 404 (not 403 — this is routing, not an
# access filter).
denied_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_CLIENTIP_DENY" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$denied_status" == "404" ]]; then
    pass "client at 127.0.0.1 (not in 10.0.0.0/8) does not match (404)"
else
    fail "client outside the match list returned $denied_status, expected 404"
fi

log "[15] Client-IP matcher: 404 response carries the X-Sozune-Diagnostic header"

diag_header=$(curl -s -I --max-time 2 \
    -H "Host: $HOST_CLIENTIP_DENY" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | tr -d '\r' | grep -i "^x-sozune-diagnostic:" || true)
if [[ "$diag_header" == *"no-match"* ]]; then
    pass "404 response carries X-Sozune-Diagnostic: no-match"
else
    fail "404 response did not include X-Sozune-Diagnostic: no-match (got: $diag_header)"
fi
