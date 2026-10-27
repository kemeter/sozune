#!/usr/bin/env bash
# TLS passthrough on the HTTPS port: run-all.sh turns on
# `proxy.https.passthrough`, and a TCP route on `https-passthrough` names
# https.sni.test. A ClientHello naming it reaches that backend undecrypted on
# $HTTPS_PORT; the HTTPS routes there are still served over HTTPS.
# Sourced by run-all.sh.

log "[34] HTTPS passthrough: a TCP route on the HTTPS port"

if ! command -v openssl >/dev/null 2>&1; then
    skip "HTTPS passthrough: openssl not available"
    return 0
fi

reply=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    reply=$(tls_sni_probe "127.0.0.1" "$HTTPS_PORT" "https.sni.test")
    [[ "$reply" == *"sni-backend-https"* ]] && break
    sleep 1
done
if [[ "$reply" == *"sni-backend-https"* ]]; then
    pass "https.sni.test reaches its backend through the HTTPS port"
else
    fail "https.sni.test did not reach its backend on the HTTPS port (got: '$reply')"
fi

subject=$(timeout 5 openssl s_client -connect "127.0.0.1:$HTTPS_PORT" \
    -servername "https.sni.test" -verify_quiet </dev/null 2>/dev/null |
    grep -m1 "subject=" || true)
if [[ "$subject" == *"https.sni.test"* ]]; then
    pass "the backend presents its own certificate"
else
    fail "unexpected certificate subject through passthrough (got: '$subject')"
fi

tls_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    --cacert "$TLS_CERT_DIR/fullchain.pem" \
    --resolve "$HOST_TLS:$HTTPS_PORT:127.0.0.1" \
    "https://$HOST_TLS:$HTTPS_PORT/" 2>/dev/null || echo "000")
if [[ "$tls_status" == "200" ]]; then
    pass "$HOST_TLS is still served over HTTPS on the same port"
else
    fail "expected 200 over HTTPS for $HOST_TLS next to passthrough, got $tls_status"
fi
