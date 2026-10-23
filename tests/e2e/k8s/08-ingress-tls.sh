#!/usr/bin/env bash
# Ingress: spec.tls[].secretName.
#
# An Ingress names a TLS Secret for its hostname. Sōzune serves it over HTTPS
# with that Secret's certificate.
#
# Sourced by run-k8s.sh after 07-gateway-https.sh.

set +e

INGRESS_TLS_HOST="ingress-tls.k8s-test.localhost"

log "[08] Ingress TLS: a TLS Secret named by an Ingress"

tls_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=$INGRESS_TLS_HOST" -addext "subjectAltName=DNS:$INGRESS_TLS_HOST" \
    -keyout "$tls_dir/tls.key" -out "$tls_dir/tls.crt" >/dev/null 2>&1
kubectl create secret tls ingress-tls -n sozune-test \
    --cert="$tls_dir/tls.crt" --key="$tls_dir/tls.key" >/dev/null 2>&1
rm -rf "$tls_dir"

kubectl apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-tls
  namespace: sozune-test
spec:
  ingressClassName: sozune
  tls:
    - hosts:
        - $INGRESS_TLS_HOST
      secretName: ingress-tls
  rules:
    - host: $INGRESS_TLS_HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: svca
                port:
                  number: 80
EOF

code=""
for _ in $(seq 1 30); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
        --resolve "$INGRESS_TLS_HOST:$HTTPS_PORT:127.0.0.1" "https://$INGRESS_TLS_HOST:$HTTPS_PORT/" 2>/dev/null)
    [[ "$code" == "200" ]] && break
    sleep 2
done
if [[ "$code" == "200" ]]; then
    pass "The Ingress answers over HTTPS"
else
    fail "The Ingress did not answer over HTTPS (got: '$code')"
fi

subject=$(printf '' | openssl s_client -connect "127.0.0.1:$HTTPS_PORT" \
    -servername "$INGRESS_TLS_HOST" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
if [[ "$subject" == *"$INGRESS_TLS_HOST"* ]]; then
    pass "The handshake presents the Secret's certificate"
else
    fail "The handshake did not present the Secret's certificate (got: '$subject')"
fi

kubectl delete ingress ingress-tls -n sozune-test >/dev/null 2>&1
kubectl delete secret ingress-tls -n sozune-test >/dev/null 2>&1
