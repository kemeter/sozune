#!/usr/bin/env bash
# Gateway API: GRPCRoute.
#
# A gRPC echo server (the Gateway API conformance one) behind a GRPCRoute on
# the HTTP listener, called in cleartext with prior knowledge (proxy.http.h2c)
# through grpcurl: a local binary, or its container image.
#
# Sourced by run-k8s.sh after 09-helm.sh.

set +e

log "[10] GRPCRoute: CRD is installed"

if ! kubectl get crd grpcroutes.gateway.networking.k8s.io >/dev/null 2>&1; then
    skip "GRPCRoute: CRD not installed"
    return 0
fi
pass "GRPCRoute CRD present"

GRPC_PROTO_DIR="$K8S_DIR/grpc"
GRPCURL_IMAGE="fullstorydev/grpcurl:v1.9.1"
if command -v grpcurl >/dev/null 2>&1; then
    grpc_call() {
        grpcurl -plaintext -max-time 5 -import-path "$GRPC_PROTO_DIR" -proto grpcecho.proto "$@"
    }
elif docker image inspect "$GRPCURL_IMAGE" >/dev/null 2>&1 \
    || docker pull -q "$GRPCURL_IMAGE" >/dev/null 2>&1; then
    grpc_call() {
        docker run --rm --network host -v "$GRPC_PROTO_DIR:/protos:ro" "$GRPCURL_IMAGE" \
            -plaintext -max-time 5 -import-path /protos -proto grpcecho.proto "$@"
    }
else
    skip "GRPCRoute: neither grpcurl nor its image ($GRPCURL_IMAGE) is available"
    return 0
fi

GRPC_HOST="grpc.k8s-test.localhost"

# The reason of sōzune's Accepted condition on a GRPCRoute, once it is `want`
# or after 20 s.
grpc_accepted_reason() {
    local route=$1 want=$2 got=""
    for _ in $(seq 1 10); do
        got=$(kubectl get grpcroute "$route" -n sozune-test \
            -o jsonpath="{.status.parents[?(@.controllerName=='kemeter.io/sozune')].conditions[?(@.type=='Accepted')].reason}" 2>/dev/null)
        [[ "$got" == "$want" ]] && break
        sleep 2
    done
    echo "$got"
}
GRPC_SERVICE="gateway_api_conformance.echo_basic.grpcecho.GrpcEcho"

kubectl apply -n sozune-test -f - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grpc-echo
  namespace: sozune-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grpc-echo
  template:
    metadata:
      labels:
        app: grpc-echo
    spec:
      containers:
        - name: grpc-echo
          image: gcr.io/k8s-staging-gateway-api/echo-basic:v20240412-v1.0.0-394-g40c666fd
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: GRPC_ECHO_SERVER
              value: "1"
---
apiVersion: v1
kind: Service
metadata:
  name: grpc-echo
  namespace: sozune-test
spec:
  selector:
    app: grpc-echo
  ports:
    - port: 8080
      targetPort: 3000
      appProtocol: kubernetes.io/h2c
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: grpc-echo
  namespace: sozune-test
spec:
  parentRefs:
    - name: gw
  hostnames:
    - grpc.k8s-test.localhost
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: grpc-echo
          port: 8080
    - matches:
        - headers:
            - name: version
              value: two
      backendRefs:
        - name: grpc-echo
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: grpc-mirrored
  namespace: sozune-test
spec:
  parentRefs:
    - name: gw
  hostnames:
    - grpc-mirror.k8s-test.localhost
  rules:
    - filters:
        - type: RequestMirror
          requestMirror:
            backendRef:
              name: grpc-echo
              port: 8080
      backendRefs:
        - name: grpc-echo
          port: 8080
YAML

log "[10] GRPCRoute: gRPC backend pod becomes ready"

if ! kubectl wait --for=condition=ready pod -l app=grpc-echo \
    -n sozune-test --timeout=180s >/dev/null 2>&1; then
    fail "gRPC echo pod never became ready"
    kubectl describe pod -l app=grpc-echo -n sozune-test 2>/dev/null | tail -20
    return 0
fi
pass "gRPC echo pod is ready"

log "[10] GRPCRoute: a matched method reaches the backend over h2c"

reply=""
for _ in $(seq 1 20); do
    reply=$(grpc_call -authority "$GRPC_HOST" -d '{}' "127.0.0.1:$HTTP_PORT" \
        "$GRPC_SERVICE/Echo" 2>&1)
    [[ "$reply" == *"grpc-echo"* ]] && break
    sleep 2
done
if [[ "$reply" == *"grpc-echo"* ]]; then
    pass "GRPCRoute serves $GRPC_SERVICE/Echo from the echo pod"
else
    fail "GRPCRoute Echo call failed: $(head -c 300 <<<"$reply")"
fi

log "[10] GRPCRoute: an unmatched method is UNIMPLEMENTED"

reply=$(grpc_call -authority "$GRPC_HOST" -d '{}' "127.0.0.1:$HTTP_PORT" \
    "$GRPC_SERVICE/EchoTwo" 2>&1)
if [[ "$reply" == *"Unimplemented"* ]]; then
    pass "EchoTwo, which no rule matches, gets Unimplemented"
else
    fail "EchoTwo was not refused with Unimplemented: $(head -c 300 <<<"$reply")"
fi

log "[10] GRPCRoute: a header match routes any method"

reply=$(grpc_call -authority "$GRPC_HOST" -H "version: two" -d '{}' \
    "127.0.0.1:$HTTP_PORT" "$GRPC_SERVICE/EchoTwo" 2>&1)
if [[ "$reply" == *"grpc-echo"* ]]; then
    pass "EchoTwo with version: two reaches the echo pod"
else
    fail "header-matched EchoTwo failed: $(head -c 300 <<<"$reply")"
fi

log "[10] GRPCRoute: status"

reason=$(grpc_accepted_reason grpc-echo Accepted)
if [[ "$reason" == "Accepted" ]]; then
    pass "GRPCRoute has Accepted=True"
else
    fail "GRPCRoute status wrong (reason='$reason', expected Accepted)"
fi

attached=$(kubectl get gateway gw -n sozune-test \
    -o jsonpath='{.status.listeners[0].supportedKinds[*].kind}' 2>/dev/null)
if [[ "$attached" == *"GRPCRoute"* ]]; then
    pass "the HTTP listener lists GRPCRoute among its supported kinds"
else
    fail "the HTTP listener does not list GRPCRoute (supportedKinds: '$attached')"
fi

log "[10] GRPCRoute: a request mirror, which the middleware would serve, is refused"

reason=$(grpc_accepted_reason grpc-mirrored UnsupportedValue)
if [[ "$reason" == "UnsupportedValue" ]]; then
    pass "a mirrored GRPCRoute is refused with UnsupportedValue"
else
    fail "mirrored GRPCRoute status wrong (reason='$reason', expected UnsupportedValue)"
fi

kubectl delete grpcroute grpc-echo grpc-mirrored -n sozune-test >/dev/null 2>&1
kubectl delete deployment grpc-echo -n sozune-test >/dev/null 2>&1
kubectl delete service grpc-echo -n sozune-test >/dev/null 2>&1
