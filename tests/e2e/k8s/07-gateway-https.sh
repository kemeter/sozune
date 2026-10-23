#!/usr/bin/env bash
# Gateway API: HTTPS listeners.
#
# A Gateway declares an HTTPS listener whose certificateRefs name a TLS
# Secret. Its HTTPRoute is served over HTTPS with that certificate, on
# Sōzune's HTTPS port, and its plain HTTP requests are redirected there. A
# missing Secret is reported on the listener.
#
# Sourced by run-k8s.sh after 06-gateway-ports.sh.

set +e

GW_HTTPS_HOST="gw-https.k8s-test.localhost"

log "[07] Gateway HTTPS: a TLS Secret and an HTTPS listener"

tls_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=$GW_HTTPS_HOST" -addext "subjectAltName=DNS:$GW_HTTPS_HOST" \
    -keyout "$tls_dir/tls.key" -out "$tls_dir/tls.crt" >/dev/null 2>&1
kubectl create secret tls gw-https-tls -n sozune-test \
    --cert="$tls_dir/tls.crt" --key="$tls_dir/tls.key" >/dev/null 2>&1
rm -rf "$tls_dir"

kubectl apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: httpsgw
  namespace: sozune-test
spec:
  gatewayClassName: sozune
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        certificateRefs:
          - name: gw-https-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: https-route
  namespace: sozune-test
spec:
  parentRefs:
    - name: httpsgw
  hostnames:
    - $GW_HTTPS_HOST
  rules:
    - backendRefs:
        - name: svca
          port: 80
EOF

listener_condition() {
    kubectl get gateway httpsgw -n sozune-test \
        -o jsonpath="{.status.listeners[?(@.name==\"https\")].conditions[?(@.type==\"$1\")].$2}" 2>/dev/null || true
}

resolved=""
for _ in $(seq 1 30); do
    resolved=$(listener_condition ResolvedRefs status)
    [[ "$resolved" == "True" && "$(listener_condition Programmed status)" == "True" ]] && break
    sleep 2
done
if [[ "$resolved" == "True" && "$(listener_condition Programmed status)" == "True" ]]; then
    pass "The HTTPS listener resolves its certificate and is Programmed"
else
    fail "The HTTPS listener is not ready (ResolvedRefs: '$resolved', Programmed: '$(listener_condition Programmed status)')"
fi

log "[07] Gateway HTTPS: the route is served over HTTPS with the Secret's certificate"

code=""
for _ in $(seq 1 30); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
        --resolve "$GW_HTTPS_HOST:$HTTPS_PORT:127.0.0.1" "https://$GW_HTTPS_HOST:$HTTPS_PORT/" 2>/dev/null)
    [[ "$code" == "200" ]] && break
    sleep 2
done
if [[ "$code" == "200" ]]; then
    pass "The route answers over HTTPS"
else
    fail "The route did not answer over HTTPS (got: '$code')"
fi

subject=$(printf '' | openssl s_client -connect "127.0.0.1:$HTTPS_PORT" \
    -servername "$GW_HTTPS_HOST" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
if [[ "$subject" == *"$GW_HTTPS_HOST"* ]]; then
    pass "The handshake presents the Secret's certificate"
else
    fail "The handshake did not present the Secret's certificate (got: '$subject')"
fi

log "[07] Gateway HTTPS: plain HTTP is redirected to HTTPS"

location=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 3 \
    -H "Host: $GW_HTTPS_HOST" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)
if [[ "$location" == https://* ]]; then
    pass "Plain HTTP is redirected to HTTPS"
else
    fail "Plain HTTP was not redirected to HTTPS (Location: '$location')"
fi

log "[07] Gateway HTTPS: a missing Secret is reported on the listener"

kubectl delete secret gw-https-tls -n sozune-test >/dev/null 2>&1

reason=""
for _ in $(seq 1 30); do
    reason=$(listener_condition ResolvedRefs reason)
    [[ "$reason" == "InvalidCertificateRef" ]] && break
    sleep 2
done
if [[ "$reason" == "InvalidCertificateRef" ]]; then
    pass "A missing Secret is reported InvalidCertificateRef"
else
    fail "A missing Secret was not reported (ResolvedRefs reason: '$reason')"
fi

code=""
for _ in $(seq 1 15); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
        --resolve "$GW_HTTPS_HOST:$HTTPS_PORT:127.0.0.1" "https://$GW_HTTPS_HOST:$HTTPS_PORT/" 2>/dev/null)
    [[ "$code" != "200" ]] && break
    sleep 2
done
if [[ "$code" != "200" ]]; then
    pass "Without its certificate, the route is no longer served over HTTPS"
else
    fail "The route is still served over HTTPS without its certificate"
fi

kubectl delete httproute https-route -n sozune-test >/dev/null 2>&1
kubectl delete gateway httpsgw -n sozune-test >/dev/null 2>&1
