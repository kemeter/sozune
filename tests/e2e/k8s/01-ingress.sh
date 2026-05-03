#!/usr/bin/env bash
# Ingress: sozune routes traffic to pod IP backends discovered via the
# Kubernetes provider (Ingress + Service + EndpointSlice watch).
# Sourced by run-k8s.sh.

# Relax errexit/pipefail for the test body — failures should produce `fail`
# lines, not abort the whole orchestrator.
set +e

log "[01] Ingress: route to svca via host header"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca reachable through Sozune Ingress"
else
    fail "svca NOT reachable through Sozune Ingress (timeout)"
fi

log "[01] Ingress: route to svcb via host header"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable through Sozune Ingress"
else
    fail "svcb NOT reachable through Sozune Ingress (timeout)"
fi

log "[01] Ingress: backend identifies itself correctly (no cross-routing)"

a_body=$(curl -s --max-time 2 -H "Host: $HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
b_body=$(curl -s --max-time 2 -H "Host: $HOST_B" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
a_hostname=$(printf '%s\n' "$a_body" | awk -F': ' '/^Hostname:/{print $2; exit}')
b_hostname=$(printf '%s\n' "$b_body" | awk -F': ' '/^Hostname:/{print $2; exit}')

if [[ -n "$a_hostname" ]] && [[ -n "$b_hostname" ]] && [[ "$a_hostname" != "$b_hostname" ]]; then
    pass "svca and svcb routed to different pods ($a_hostname vs $b_hostname)"
else
    fail "svca and svcb appear to share a backend (a='$a_hostname' b='$b_hostname')"
fi

log "[01] Ingress: unknown host returns 404"

unknown_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: nope.k8s-test.localhost" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
unknown_status=${unknown_status:-000}
if [[ "$unknown_status" == "404" ]]; then
    pass "unknown host returns 404"
else
    fail "unknown host returned $unknown_status instead of 404"
fi

# Restore strict mode for the orchestrator.
set -e
