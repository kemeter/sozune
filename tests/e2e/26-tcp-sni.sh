#!/usr/bin/env bash
# TCP routing by SNI, in TLS passthrough.
#
# Two backends share one listener port and terminate TLS themselves with their
# own self-signed certs. Sōzune reads the name from the ClientHello and picks
# between them without ever decrypting — so the handshake the client completes
# is with the backend, not the proxy.
#
# Sourced by run-all.sh.

log "[26] TCP SNI: routing two backends on one port"

if ! command -v openssl >/dev/null 2>&1; then
    skip "TCP SNI: openssl not available"
    return 0
fi

if ! wait_for_tcp_open "127.0.0.1" "$TCP_SNI_PORT"; then
    fail "SNI listener on $TCP_SNI_PORT never opened"
    return 0
fi
pass "SNI listener on $TCP_SNI_PORT is open"

# The backends build a cert and install packages on first boot, which takes
# longer than the socat-only services. Give the TLS path time to come up.
sni_ready=0
for _ in $(seq 1 "$MAX_RETRIES"); do
    if [[ "$(tls_sni_probe "127.0.0.1" "$TCP_SNI_PORT" "alpha.sni.test")" == *"sni-backend-alpha"* ]]; then
        sni_ready=1
        break
    fi
    sleep 1
done

if [[ $sni_ready -ne 1 ]]; then
    fail "alpha.sni.test never reached its backend through the SNI listener"
    return 0
fi
pass "alpha.sni.test routes to its own backend"

log "[26] TCP SNI: a different name on the same port reaches a different backend"

beta=$(tls_sni_probe "127.0.0.1" "$TCP_SNI_PORT" "beta.sni.test")
if [[ "$beta" == *"sni-backend-beta"* ]]; then
    pass "beta.sni.test routes to its own backend on the same port"
else
    fail "beta.sni.test did not reach its backend (got: '$beta')"
fi

log "[26] TCP SNI: an unmatched name is refused, not misrouted"

# Sōzu has no catch-all once a listener carries SNI routes, so an unknown name
# is dropped. The failure that matters is not "refused" but "answered by the
# wrong backend", which would mean the SNI was ignored.
unknown=$(tls_sni_probe "127.0.0.1" "$TCP_SNI_PORT" "nope.sni.test")
if [[ "$unknown" == *"sni-backend-"* ]]; then
    fail "unmatched SNI was routed to a backend (got: '$unknown')"
else
    pass "unmatched SNI reaches no backend"
fi

log "[26] TCP SNI: passthrough leaves TLS termination to the backend"

# The cert must be the backend's own. If Sōzune were terminating, the subject
# would be whatever the proxy serves instead.
subject=$(timeout 5 openssl s_client -connect "127.0.0.1:$TCP_SNI_PORT" \
    -servername "alpha.sni.test" -verify_quiet </dev/null 2>/dev/null |
    grep -m1 "subject=" || true)

if [[ "$subject" == *"alpha.sni.test"* ]]; then
    pass "client negotiates TLS with the backend's own certificate"
else
    fail "unexpected certificate subject through passthrough (got: '$subject')"
fi
