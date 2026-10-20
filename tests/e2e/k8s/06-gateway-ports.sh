#!/usr/bin/env bash
# Gateway API: ports opened from `proxy.gateway_ports`.
#
# A Gateway declares a TCP and a UDP listener on ports no `proxy.tcp` /
# `proxy.udp` entry binds, but that `proxy.gateway_ports` lists. Sōzune opens
# them once a route attaches, and closes the TCP one when its route is gone.
#
# Sourced by run-k8s.sh after 05-udproute.sh, whose backends it reuses.

set +e

log "[06] Gateway ports: route CRDs are installed"

if ! kubectl get crd tcproutes.gateway.networking.k8s.io >/dev/null 2>&1 \
    || ! kubectl get crd udproutes.gateway.networking.k8s.io >/dev/null 2>&1; then
    skip "Gateway ports: TCPRoute / UDPRoute CRD not installed"
    return 0
fi
pass "TCPRoute and UDPRoute CRDs present"

# A kind cluster reused from before these ports were mapped cannot reach them
# from the host: recreate it to run this suite.
mapped=$(docker port "$CLUSTER_NAME-control-plane" 2>/dev/null || true)
if [[ "$mapped" != *"$GATEWAY_TCP_PORT/tcp"* || "$mapped" != *"$GATEWAY_UDP_PORT/udp"* ]]; then
    skip "Gateway ports: kind cluster lacks the $GATEWAY_TCP_PORT/$GATEWAY_UDP_PORT mappings, recreate it"
    return 0
fi

kubectl apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: portsgw
  namespace: sozune-test
spec:
  gatewayClassName: sozune
  listeners:
    - name: tcp
      protocol: TCP
      port: $GATEWAY_TCP_PORT
    - name: udp
      protocol: UDP
      port: $GATEWAY_UDP_PORT
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: ports-tcp
  namespace: sozune-test
spec:
  parentRefs:
    - name: portsgw
      sectionName: tcp
  rules:
    - backendRefs:
        - name: svc-tcp
          port: 9000
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: ports-udp
  namespace: sozune-test
spec:
  parentRefs:
    - name: portsgw
      sectionName: udp
  rules:
    - backendRefs:
        - name: svc-udp
          port: 9001
EOF

log "[06] Gateway ports: the listeners are programmed"

programmed=""
for _ in $(seq 1 30); do
    programmed=$(kubectl get gateway portsgw -n sozune-test \
        -o jsonpath='{.status.listeners[*].conditions[?(@.type=="Programmed")].status}' 2>/dev/null || true)
    [[ "$programmed" == "True True" ]] && break
    sleep 2
done

if [[ "$programmed" == "True True" ]]; then
    pass "Listeners on ports of gateway_ports are Programmed"
else
    fail "Listeners on ports of gateway_ports are not Programmed (got: '$programmed')"
fi

log "[06] Gateway ports: the TCP port is opened and forwarded"

reply=""
for _ in $(seq 1 30); do
    reply=$(printf '' | timeout 4 nc -w 2 127.0.0.1 "$GATEWAY_TCP_PORT" 2>/dev/null || true)
    [[ "$reply" == *"k8s-tcproute-ok"* ]] && break
    sleep 2
done

if [[ "$reply" == *"k8s-tcproute-ok"* ]]; then
    pass "A Gateway opens a TCP port of gateway_ports"
else
    fail "The TCP port of gateway_ports was not served (got: '$reply')"
fi

log "[06] Gateway ports: the UDP port is opened and forwarded"

reply=""
for _ in $(seq 1 30); do
    reply=$(printf 'ping' | timeout 4 nc -u -w 2 127.0.0.1 "$GATEWAY_UDP_PORT" 2>/dev/null || true)
    [[ "$reply" == *"k8s-udproute-ok"* ]] && break
    sleep 2
done

if [[ "$reply" == *"k8s-udproute-ok"* ]]; then
    pass "A Gateway opens a UDP port of gateway_ports"
else
    fail "The UDP port of gateway_ports was not served (got: '$reply')"
fi

log "[06] Gateway ports: the TCP port closes with its last route"

kubectl delete tcproute ports-tcp -n sozune-test >/dev/null 2>&1

closed=""
for _ in $(seq 1 30); do
    if kubectl logs -n sozune-test pod/sozune 2>/dev/null \
        | grep -q "Closed Gateway listener \`gateway:tcp:$GATEWAY_TCP_PORT\`"; then
        closed=1
        break
    fi
    sleep 2
done

reply=$(printf '' | timeout 4 nc -w 2 127.0.0.1 "$GATEWAY_TCP_PORT" 2>/dev/null || true)
if [[ -n "$closed" && "$reply" != *"k8s-tcproute-ok"* ]]; then
    pass "The TCP port is closed once no route is served on it"
else
    fail "The TCP port stayed open after its route was deleted (closed log: '${closed:-no}', got: '$reply')"
fi

kubectl delete udproute ports-udp -n sozune-test >/dev/null 2>&1
kubectl delete gateway portsgw -n sozune-test >/dev/null 2>&1
