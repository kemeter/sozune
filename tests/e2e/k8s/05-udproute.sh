#!/usr/bin/env bash
# Gateway API: UDPRoute.
#
# A Gateway declares a plain UDP listener on a port a `proxy.udp` listener
# already binds. The UDPRoute forwards the whole datagram port to its backend.
#
# Sourced by run-k8s.sh after 04-tcproute.sh.

set +e

log "[05] UDPRoute: CRD is installed"

if ! kubectl get crd udproutes.gateway.networking.k8s.io >/dev/null 2>&1; then
    skip "UDPRoute: CRD not installed"
    return 0
fi
pass "UDPRoute CRD present"

log "[05] UDPRoute: backend pod becomes ready"

if ! kubectl wait --for=condition=ready pod -l app=svc-udp \
    -n sozune-test --timeout=120s >/dev/null 2>&1; then
    fail "UDP backend pod never became ready"
    kubectl logs -l app=svc-udp -n sozune-test --tail=20 2>/dev/null
    return 0
fi
pass "UDP backend pod is ready"

log "[05] UDPRoute: the datagram port is forwarded to the backend"

reply=""
for _ in $(seq 1 30); do
    reply=$(printf 'ping' | timeout 4 nc -u -w 2 127.0.0.1 "$UDP_RAW_PORT" 2>/dev/null || true)
    [[ "$reply" == *"k8s-udproute-ok"* ]] && break
    sleep 2
done

if [[ "$reply" == *"k8s-udproute-ok"* ]]; then
    pass "UDPRoute forwards the datagram port to its backend"
else
    fail "UDPRoute did not reach the backend (got: '$reply')"
    kubectl get udproute -n sozune-test -o wide 2>/dev/null
fi
