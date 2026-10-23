#!/usr/bin/env bash
# Helm chart: charts/sozune installs a working Sōzune.
#
# Installs the chart in its own namespace with the image under test, and
# checks it serves an Ingress of the test namespace. Runs last: the release
# watches the same Ingresses as the Sōzune pod of the other suites.
#
# Sourced by run-k8s.sh after 08-ingress-tls.sh.

set +e

log "[09] Helm: the chart installs"

if ! command -v helm >/dev/null 2>&1; then
    skip "Helm: helm is not installed"
    return 0
fi

image_ref="${SOZUNE_IMAGE_REF:-kemeter/sozune:latest}"
image_repo="${image_ref%:*}"
image_tag="${image_ref##*:}"

if helm upgrade --install sozune-chart "$K8S_DIR/../../../charts/sozune" \
    --namespace sozune-helm --create-namespace \
    --set image.repository="$image_repo" \
    --set image.tag="$image_tag" \
    --set image.pullPolicy=IfNotPresent \
    --set service.type=ClusterIP \
    --set ingressClass.create=false \
    --set rbac.gatewayAPI=false \
    --set config.providers.kubernetes.namespace=sozune-test \
    --wait --timeout 120s >/dev/null 2>&1; then
    pass "The chart installs and its pod becomes ready"
else
    fail "The chart did not install"
    kubectl get pods -n sozune-helm 2>/dev/null
    kubectl logs -n sozune-helm deploy/sozune-chart --tail=30 2>/dev/null
    helm uninstall sozune-chart --namespace sozune-helm >/dev/null 2>&1
    kubectl delete namespace sozune-helm --wait=false >/dev/null 2>&1
    return 0
fi

log "[09] Helm: the release serves the test Ingresses"

kubectl port-forward -n sozune-helm svc/sozune-chart 18190:80 >/dev/null 2>&1 &
forward_pid=$!

code=""
for _ in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        -H "Host: $HOST_A" "http://127.0.0.1:18190/" 2>/dev/null)
    [[ "$code" == "200" ]] && break
    sleep 2
done
kill "$forward_pid" 2>/dev/null
wait "$forward_pid" 2>/dev/null

if [[ "$code" == "200" ]]; then
    pass "The chart's Sōzune routes an Ingress"
else
    fail "The chart's Sōzune did not route the Ingress (got: '$code')"
    kubectl logs -n sozune-helm deploy/sozune-chart --tail=30 2>/dev/null
fi

helm uninstall sozune-chart --namespace sozune-helm >/dev/null 2>&1
kubectl delete namespace sozune-helm --wait=false >/dev/null 2>&1
