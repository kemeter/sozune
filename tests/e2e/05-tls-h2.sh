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

# --- Listener TLS version floor (proxy.https.tls.min_version: "1.3") -------
# Version negotiation happens before certificate validation, so a 1.2-only
# client is rejected at the handshake even though we serve no valid cert. This
# proves the min_version floor is applied to the listener.
log "[05] TLS: min_version 1.3 rejects a TLS 1.2 client"

v12=$(curl -k -s -v --tlsv1.2 --tls-max 1.2 --max-time 3 \
    "https://127.0.0.1:$HTTPS_PORT/" 2>&1 || true)
# A rejected 1.2 client fails at the handshake: either a protocol-version alert
# or the listener closing the connection (unexpected eof / TLS connect error).
# What must NOT appear is a certificate-stage error, which would mean the
# version was accepted and negotiation got past it.
if echo "$v12" | grep -qiE "alert protocol version|no protocols available|version too low|unexpected eof|tls connect error|handshake fail|tlsv1 alert" \
    && ! echo "$v12" | grep -qi "certificate"; then
    pass "TLS 1.2 client is rejected by the 1.3-only listener"
else
    fail "TLS 1.2 client was not rejected (min_version not applied?)"
    echo "$v12" | sed -n '/SSL/p;/alert/p;/TLS/p' | head -8
fi

# A 1.3 client gets past version negotiation (it then fails on the cert, which
# is expected — we only care that the version floor let it through).
log "[05] TLS: min_version 1.3 admits a TLS 1.3 client"

v13=$(curl -k -s -v --tlsv1.3 --max-time 3 \
    "https://127.0.0.1:$HTTPS_PORT/" 2>&1 || true)
if echo "$v13" | grep -qiE "alert protocol version|no protocols available|version too low"; then
    fail "TLS 1.3 client was wrongly rejected on version"
    echo "$v13" | sed -n '/SSL/p;/alert/p' | head -8
else
    pass "TLS 1.3 client passes version negotiation"
fi
