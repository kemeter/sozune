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

# ----------------------------------------------------------------------
# Scope: a route attached to a Gateway sōzune does NOT own must be
# silently ignored. Without this guarantee, deploying sōzune in a
# multi-controller cluster (e.g. alongside Traefik) would steal the
# other controller's traffic.
# ----------------------------------------------------------------------
log "[02] Gateway: route attached to a foreign GatewayClass is ignored"

kubectl apply -n sozune-test -f - >/dev/null 2>&1 <<'YAML'
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: foreign
spec:
  controllerName: example.com/other-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: foreign-gw
  namespace: sozune-test
spec:
  gatewayClassName: foreign
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: foreign-route
  namespace: sozune-test
spec:
  parentRefs:
    - name: foreign-gw
  hostnames:
    - gw-foreign.k8s-test.localhost
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: svcb
          port: 80
YAML
sleep 4
foreign_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: gw-foreign.k8s-test.localhost" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
foreign_status=${foreign_status:-000}
if [[ "$foreign_status" == "404" ]]; then
    pass "route attached to a foreign Gateway is not served (got 404)"
else
    fail "foreign-controller route was served (got $foreign_status, expected 404)"
fi

# Status: sōzune must not have written into the foreign route's status
# (Gateway API conformance — only the owning controller reports).
foreign_status_owners=$(kubectl get httproute foreign-route -n sozune-test \
    -o jsonpath='{.status.parents[*].controllerName}' 2>/dev/null || true)
if [[ "$foreign_status_owners" != *"kemeter.io/sozune"* ]]; then
    pass "sōzune did not write status on a route it doesn't own"
else
    fail "sōzune wrote status on a foreign-controller route (controllers='$foreign_status_owners')"
fi

# ----------------------------------------------------------------------
# Filters: any HTTPRoute filter (urlRewrite, requestRedirect, etc.)
# causes the entire route to be dropped, AND the rejection is reflected
# in status with reason=UnsupportedValue. Routing as if the filter
# wasn't there would silently rewrite user intent.
# ----------------------------------------------------------------------
log "[02] Gateway: route declaring an HTTPRoute filter is dropped with status"

kubectl apply -n sozune-test -f - >/dev/null 2>&1 <<'YAML'
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: filtered-route
  namespace: sozune-test
spec:
  parentRefs:
    - name: gw
  hostnames:
    - gw-filtered.k8s-test.localhost
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      filters:
        - type: URLRewrite
          urlRewrite:
            path:
              type: ReplacePrefixMatch
              replacePrefixMatch: /rewritten
      backendRefs:
        - name: svcb
          port: 80
YAML
sleep 4
filtered_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: gw-filtered.k8s-test.localhost" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
filtered_status=${filtered_status:-000}
if [[ "$filtered_status" == "404" ]]; then
    pass "route with urlRewrite filter is not served (got 404)"
else
    fail "filtered route was served (got $filtered_status, expected 404)"
fi

# The status must show our Accepted=False / reason=UnsupportedValue.
# kubectl jsonpath supports the ?(@.field=='value') filter syntax — no
# external `jq` dependency required.
filtered_reason=$(kubectl get httproute filtered-route -n sozune-test \
    -o jsonpath="{.status.parents[?(@.controllerName=='kemeter.io/sozune')].conditions[?(@.type=='Accepted')].reason}" 2>/dev/null)
if [[ "$filtered_reason" == "UnsupportedValue" ]]; then
    pass "filtered route has Accepted=False reason=UnsupportedValue in status"
else
    fail "filtered route status missing or wrong (reason='$filtered_reason')"
fi

# ----------------------------------------------------------------------
# Status reporting on a happy-path route: Accepted=True / ResolvedRefs=True.
# ----------------------------------------------------------------------
log "[02] Gateway: happy-path route has Accepted=True / ResolvedRefs=True in status"

happy_accepted=$(kubectl get httproute svcb-gw -n sozune-test \
    -o jsonpath="{.status.parents[?(@.controllerName=='kemeter.io/sozune')].conditions[?(@.type=='Accepted')].status}" 2>/dev/null)
happy_resolved=$(kubectl get httproute svcb-gw -n sozune-test \
    -o jsonpath="{.status.parents[?(@.controllerName=='kemeter.io/sozune')].conditions[?(@.type=='ResolvedRefs')].status}" 2>/dev/null)
if [[ "$happy_accepted" == "True" ]] && [[ "$happy_resolved" == "True" ]]; then
    pass "happy-path route status: Accepted=True, ResolvedRefs=True"
else
    fail "happy-path status wrong (Accepted='$happy_accepted', ResolvedRefs='$happy_resolved')"
fi

# ----------------------------------------------------------------------
# `kubectl describe httproute` must render the status block readably:
# both conditions must appear by name, with their resolved status and the
# sōzune controller name. The jsonpath checks above verify the data; this
# checks the human-facing rendering that an admin would see.
# ----------------------------------------------------------------------
log "[02] Gateway: kubectl describe surfaces Accepted + ResolvedRefs conditions"

describe_output=$(kubectl describe httproute svcb-gw -n sozune-test 2>/dev/null || true)
missing=()
echo "$describe_output" | grep -q "Controller Name:[[:space:]]*kemeter.io/sozune" || missing+=("controller-name")
echo "$describe_output" | grep -q "Type:[[:space:]]*Accepted" || missing+=("Accepted-type")
echo "$describe_output" | grep -q "Type:[[:space:]]*ResolvedRefs" || missing+=("ResolvedRefs-type")
# Both conditions are True on the happy path, so "Status:  True" appears at
# least twice in the rendered status block.
true_count=$(echo "$describe_output" | grep -cE "^[[:space:]]*Status:[[:space:]]+True[[:space:]]*$")
[[ "$true_count" -ge 2 ]] || missing+=("two-True-statuses (got=$true_count)")

if [[ ${#missing[@]} -eq 0 ]]; then
    pass "kubectl describe httproute renders both conditions with controller name"
else
    fail "kubectl describe output missing fields: ${missing[*]}"
fi

# Cleanup of the dynamically-applied resources to leave the cluster
# tidy if the suite is re-run.
kubectl delete httproute filtered-route foreign-route -n sozune-test >/dev/null 2>&1 || true
kubectl delete gateway foreign-gw -n sozune-test >/dev/null 2>&1 || true
kubectl delete gatewayclass foreign >/dev/null 2>&1 || true

set -e
