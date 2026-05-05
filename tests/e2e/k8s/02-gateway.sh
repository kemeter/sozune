#!/usr/bin/env bash
# Gateway API: sozune routes traffic according to HTTPRoute resources.
# Sourced by run-k8s.sh after 01-ingress.sh — assumes the cluster is up,
# CRDs are installed, and the gateway manifests are applied.

set +e

GW_HOST_A="gw-svca.k8s-test.localhost"
GW_HOST_B="gw-svcb.k8s-test.localhost"
GW_HOST_SPLIT="gw-split.k8s-test.localhost"

log "[02] Gateway: route to svca via HTTPRoute"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$GW_HOST_A" "200"; then
    pass "svca reachable through HTTPRoute"
else
    fail "svca NOT reachable through HTTPRoute (timeout)"
fi

log "[02] Gateway: route to svcb via HTTPRoute"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$GW_HOST_B" "200"; then
    pass "svcb reachable through HTTPRoute"
else
    fail "svcb NOT reachable through HTTPRoute (timeout)"
fi

log "[02] Gateway: each HTTPRoute lands on its own backend"

a_body=$(curl -s --max-time 2 -H "Host: $GW_HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
b_body=$(curl -s --max-time 2 -H "Host: $GW_HOST_B" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
a_hostname=$(printf '%s\n' "$a_body" | awk -F': ' '/^Hostname:/{print $2; exit}')
b_hostname=$(printf '%s\n' "$b_body" | awk -F': ' '/^Hostname:/{print $2; exit}')

if [[ -n "$a_hostname" ]] && [[ -n "$b_hostname" ]] && [[ "$a_hostname" != "$b_hostname" ]]; then
    pass "svca and svcb HTTPRoutes routed to different pods ($a_hostname vs $b_hostname)"
else
    fail "svca and svcb HTTPRoutes appear to share a backend (a='$a_hostname' b='$b_hostname')"
fi

log "[02] Gateway: path-based routing within a single HTTPRoute"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/a" "$GW_HOST_SPLIT" "200"; then
    split_a_body=$(curl -s --max-time 2 -H "Host: $GW_HOST_SPLIT" "http://127.0.0.1:$HTTP_PORT/a" 2>/dev/null)
    split_a_hostname=$(printf '%s\n' "$split_a_body" | awk -F': ' '/^Hostname:/{print $2; exit}')
    if [[ "$split_a_hostname" == "$a_hostname" ]]; then
        pass "/a routed to svca pod"
    else
        fail "/a expected svca pod ($a_hostname), got '$split_a_hostname'"
    fi
else
    fail "/a NOT reachable on split host (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/b" "$GW_HOST_SPLIT" "200"; then
    split_b_body=$(curl -s --max-time 2 -H "Host: $GW_HOST_SPLIT" "http://127.0.0.1:$HTTP_PORT/b" 2>/dev/null)
    split_b_hostname=$(printf '%s\n' "$split_b_body" | awk -F': ' '/^Hostname:/{print $2; exit}')
    if [[ "$split_b_hostname" == "$b_hostname" ]]; then
        pass "/b routed to svcb pod"
    else
        fail "/b expected svcb pod ($b_hostname), got '$split_b_hostname'"
    fi
else
    fail "/b NOT reachable on split host (timeout)"
fi

log "[02] Gateway: unknown host returns 404"

unknown_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: gw-nope.k8s-test.localhost" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
unknown_status=${unknown_status:-000}
if [[ "$unknown_status" == "404" ]]; then
    pass "unknown gateway host returns 404"
else
    fail "unknown gateway host returned $unknown_status instead of 404"
fi

log "[02] Gateway: deleting an HTTPRoute removes its routes"

kubectl delete httproute svca-gw -n sozune-test >/dev/null 2>&1
sleep 4
deleted_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $GW_HOST_A" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
deleted_status=${deleted_status:-000}
if [[ "$deleted_status" == "404" ]]; then
    pass "deleted HTTPRoute no longer routes (got 404)"
else
    fail "deleted HTTPRoute still serving (got $deleted_status, expected 404)"
fi

set -e
