#!/usr/bin/env bash
# A certificate from proxy.https.tls.certificates is served by SNI: run-all.sh
# generates a self-signed `*.func-test.localhost` and the `tls=true` route on
# $HOST_TLS references nothing, yet its handshake validates against that
# certificate.
# Sourced by run-all.sh.

log "[32] TLS: a certificate from proxy.https.tls.certificates is served by SNI"

tls_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    --cacert "$TLS_CERT_DIR/fullchain.pem" \
    --resolve "$HOST_TLS:$HTTPS_PORT:127.0.0.1" \
    "https://$HOST_TLS:$HTTPS_PORT/" 2>/dev/null || echo "000")
if [[ "$tls_status" == "200" ]]; then
    pass "wildcard certificate validates for $HOST_TLS"
else
    fail "expected 200 over verified TLS for $HOST_TLS, got $tls_status"
fi
