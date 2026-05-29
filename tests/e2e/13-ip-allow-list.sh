#!/usr/bin/env bash
# IP allow-list middleware
#
# The `svc-ipallow` route whitelists `127.0.0.1` and `10.0.0.0/8`. Sōzune is
# running with `trusted_proxies` empty (the default), so `X-Forwarded-For` is
# *ignored entirely* — the TCP peer (127.0.0.1 from curl) is the client.
#
# The second service `svc-ipallow-deny` whitelists `203.0.113.0/24`, which
# *does not* include 127.0.0.1 → every request from the host gets 403,
# regardless of what we put in `X-Forwarded-For`.
#
# Sourced by run-all.sh.

# Wait until the deny route is actually rejecting. `HOST_IPALLOW_DENY` is not
# in the warm-up list (its allow-list specifically excludes 127.0.0.1, so the
# warm-up would loop on a 403) — we poll for the 403 here instead so the
# assertions below see the steady state, not a half-installed middleware.
log "[13] IP allow-list: waiting for the deny route to install its middleware"
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_IPALLOW_DENY" 403; then
    pass "deny route installed its allow-list middleware"
else
    fail "deny route never reached 403 — allow-list middleware may not be installed"
fi

log "[13] IP allow-list: TCP peer is in the allow-list -> 200"

allowed_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_IPALLOW" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$allowed_status" == "200" ]]; then
    pass "client at 127.0.0.1 (in 127.0.0.1 entry) is allowed (200)"
else
    fail "client at 127.0.0.1 returned $allowed_status, expected 200"
fi

log "[13] IP allow-list: X-Forwarded-For spoof attempt is ignored without trusted_proxies"

# Without `trusted_proxies`, X-Forwarded-For is dropped. The middleware sees
# 127.0.0.1 (the TCP peer), which is in the allow-list → 200. If the resolver
# were the naive "leftmost XFF" one, this would surface as either:
#   - 200 because XFF says 10.0.0.5 (still in CIDR, hard to distinguish)
#   - the test would need to spoof an *out-of-list* IP to detect the bug
# So we forge an out-of-list address and assert we *still* get 200, which
# proves the spoof did not steer the resolver.
spoof_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_IPALLOW" -H "X-Forwarded-For: 203.0.113.7" \
    -H "Connection: close" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$spoof_status" == "200" ]]; then
    pass "X-Forwarded-For is ignored (spoof did not divert the resolver)"
else
    fail "spoofed X-Forwarded-For returned $spoof_status; the resolver may be trusting XFF unconditionally"
fi

log "[13] IP allow-list: client outside the allow-list is rejected with 403"

# This service whitelists only 203.0.113.0/24; the curl peer 127.0.0.1 is not
# in it.
denied_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_IPALLOW_DENY" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$denied_status" == "403" ]]; then
    pass "client at 127.0.0.1 (not in 203.0.113.0/24) is rejected (403)"
else
    fail "client outside the allow-list returned $denied_status, expected 403"
fi

log "[13] IP allow-list: 403 response carries the X-Sozune-Diagnostic header"

# Sōzune puts the failure reason in a header rather than the body so operators
# can grep for it without leaking topology to the public client.
diag_header=$(curl -s -I --max-time 2 \
    -H "Host: $HOST_IPALLOW_DENY" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | tr -d '\r' | grep -i "^x-sozune-diagnostic:" || true)
if [[ "$diag_header" == *"ip-forbidden"* ]]; then
    pass "403 response carries X-Sozune-Diagnostic: ip-forbidden"
else
    fail "403 response did not include X-Sozune-Diagnostic: ip-forbidden (got: $diag_header)"
fi
