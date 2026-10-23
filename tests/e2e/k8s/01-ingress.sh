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

log "[01] Ingress: status.loadBalancer carries the published address"

published=""
for _ in $(seq 1 30); do
    published=$(kubectl get ingress svca-ingress -n sozune-test -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
    [[ "$published" == "192.0.2.10" ]] && break
    sleep 1
done
if [[ "$published" == "192.0.2.10" ]]; then
    pass "Ingress status.loadBalancer carries publish_addresses"
else
    fail "Ingress status.loadBalancer was not written (got '$published')"
fi

log "[01] Ingress: sozune.* annotations add middleware to its routes"

kubectl annotate ingress svca-ingress -n sozune-test --overwrite \
    sozune.headers.response.X-Sozune-Ingress=annotated >/dev/null 2>&1

header=""
for _ in $(seq 1 30); do
    header=$(curl -s -o /dev/null -D - --max-time 2 -H "Host: $HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="x-sozune-ingress"{print $2}')
    [[ "$header" == "annotated" ]] && break
    sleep 1
done
if [[ "$header" == "annotated" ]]; then
    pass "An Ingress annotation sets a response header on its route"
else
    fail "The Ingress annotation did not reach the route (got '$header')"
fi

kubectl annotate ingress svca-ingress -n sozune-test sozune.headers.response.X-Sozune-Ingress- >/dev/null 2>&1
