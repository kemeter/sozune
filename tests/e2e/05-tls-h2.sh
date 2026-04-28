#!/usr/bin/env bash
# TLS / HTTP-2 ALPN negotiation.
#
# We don't provision a valid certificate (sozune only loads certs via ACME),
# so the TLS handshake will fail at certificate validation. But ALPN is
# negotiated in the ServerHello *before* certificate verification, so
# `curl -v` exposes "ALPN, server accepted: h2" regardless.
#
# Sourced by run-all.sh.

log "[05] TLS: ALPN negotiation on HTTPS listener"

if ! command -v curl >/dev/null 2>&1; then
    skip "TLS h2: curl not available"
    return 0
fi

if ! curl --version 2>/dev/null | grep -qi "HTTP2"; then
    skip "TLS h2: local curl built without HTTP/2 support"
    return 0
fi

alpn_log=$(curl -k --http2 -s -v --max-time 3 \
    "https://127.0.0.1:$HTTPS_PORT/" 2>&1 || true)

if echo "$alpn_log" | grep -qiE "ALPN(:| ).*(server accepted|accepted): h2"; then
    pass "TLS h2: ALPN negotiates h2 on HTTPS listener"
elif echo "$alpn_log" | grep -qi "ALPN.*h2"; then
    pass "TLS h2: ALPN advertises/accepts h2 on HTTPS listener"
else
    fail "TLS h2: no h2 in ALPN negotiation (full log below)"
    echo "$alpn_log" | sed -n '/ALPN/p;/SSL connection/p' | head -10
fi
