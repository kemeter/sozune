#!/usr/bin/env bash
# Gateway API: TLSRoute in passthrough mode.
#
# A Gateway declares a TLS listener with `mode: Passthrough` on a port that a
# `proxy.tcp` listener already binds. The TLSRoute names an SNI; Sōzune reads
# it from the ClientHello and forwards the encrypted bytes to the backend,
# which owns the certificate.
#
# Sourced by run-k8s.sh after 02-gateway.sh.

set +e

TLS_HOST="passthrough.k8s-test.localhost"

log "[03] TLSRoute: CRD is installed"

if ! kubectl get crd tlsroutes.gateway.networking.k8s.io >/dev/null 2>&1; then
    skip "TLSRoute: CRD not installed"
    return 0
fi
pass "TLSRoute CRD present"

if ! command -v openssl >/dev/null 2>&1; then
    skip "TLSRoute: openssl not available"
    return 0
fi

log "[03] TLSRoute: backend pod becomes ready"

# The backend installs packages and builds a cert on boot, so it lags the
# other workloads.
if ! kubectl wait --for=condition=ready pod -l app=svc-tls \
    -n sozune-test --timeout=120s >/dev/null 2>&1; then
    fail "TLS backend pod never became ready"
    kubectl logs -l app=svc-tls -n sozune-test --tail=20 2>/dev/null
    return 0
fi
pass "TLS backend pod is ready"

log "[03] TLSRoute: SNI reaches the backend through passthrough"

banner=""
for _ in $(seq 1 30); do
    banner=$(timeout 5 openssl s_client -connect "127.0.0.1:$TLS_PASSTHROUGH_PORT" \
        -servername "$TLS_HOST" -quiet -verify_quiet </dev/null 2>/dev/null || true)
    [[ "$banner" == *"k8s-tls-passthrough-ok"* ]] && break
    sleep 2
done

if [[ "$banner" == *"k8s-tls-passthrough-ok"* ]]; then
    pass "TLSRoute forwards $TLS_HOST to its backend"
else
    fail "TLSRoute did not reach the backend (got: '$banner')"
    kubectl get tlsroute -n sozune-test -o wide 2>/dev/null
fi

log "[03] TLSRoute: the backend owns the certificate (no termination)"

# If Sōzune were terminating, the subject would be whatever it serves instead.
subject=$(timeout 5 openssl s_client -connect "127.0.0.1:$TLS_PASSTHROUGH_PORT" \
    -servername "$TLS_HOST" -verify_quiet </dev/null 2>/dev/null |
    grep -m1 "subject=" || true)

if [[ "$subject" == *"$TLS_HOST"* ]]; then
    pass "client negotiates TLS with the backend's own certificate"
else
    fail "unexpected certificate subject through passthrough (got: '$subject')"
fi

log "[03] TLSRoute: an unmatched SNI is refused, not misrouted"

# Once a listener carries SNI routes Sōzu has no catch-all, so an unknown name
# reaches nothing. Being answered by the wrong backend is the real failure.
unknown=$(timeout 5 openssl s_client -connect "127.0.0.1:$TLS_PASSTHROUGH_PORT" \
    -servername "nope.k8s-test.localhost" -quiet -verify_quiet </dev/null 2>/dev/null || true)

if [[ "$unknown" == *"k8s-tls-passthrough-ok"* ]]; then
    fail "unmatched SNI was routed to the backend (got: '$unknown')"
else
    pass "unmatched SNI reaches no backend"
fi
