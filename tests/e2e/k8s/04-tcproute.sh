#!/usr/bin/env bash
# Gateway API: TCPRoute.
#
# A Gateway declares a plain TCP listener on a port a `proxy.tcp` listener
# already binds. The TCPRoute forwards the whole port to its backend — no SNI,
# no TLS, the raw-TCP catch-all.
#
# Sourced by run-k8s.sh after 03-tlsroute.sh.

set +e

log "[04] TCPRoute: CRD is installed"

if ! kubectl get crd tcproutes.gateway.networking.k8s.io >/dev/null 2>&1; then
    skip "TCPRoute: CRD not installed"
    return 0
fi
pass "TCPRoute CRD present"

log "[04] TCPRoute: backend pod becomes ready"

if ! kubectl wait --for=condition=ready pod -l app=svc-tcp \
    -n sozune-test --timeout=120s >/dev/null 2>&1; then
    fail "TCP backend pod never became ready"
    kubectl logs -l app=svc-tcp -n sozune-test --tail=20 2>/dev/null
    return 0
fi
pass "TCP backend pod is ready"

log "[04] TCPRoute: the whole port is forwarded to the backend"

reply=""
for _ in $(seq 1 30); do
    reply=$(printf '' | timeout 4 nc -w 2 127.0.0.1 "$TCP_RAW_PORT" 2>/dev/null || true)
    [[ "$reply" == *"k8s-tcproute-ok"* ]] && break
    sleep 2
done

if [[ "$reply" == *"k8s-tcproute-ok"* ]]; then
    pass "TCPRoute forwards the port to its backend"
else
    fail "TCPRoute did not reach the backend (got: '$reply')"
    kubectl get tcproute -n sozune-test -o wide 2>/dev/null
fi
