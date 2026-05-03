#!/usr/bin/env bash
#
# Functional test orchestrator for the Sozune Kubernetes Ingress provider.
# Spins up a kind cluster, applies workload manifests and the Sozune
# Pod (hostNetwork) so it can reach the cluster pod CIDR directly.
#
# Requirements: docker, kind, kubectl, curl

set -euo pipefail

K8S_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$K8S_DIR/lib-k8s.sh"

cleanup() {
    log "Cleaning up..."
    teardown_cluster_if_ours
    rm -f "$KUBECONFIG_FILE"
}
trap cleanup EXIT

require_kind

# Use a published image so we don't have to build + load on every run.
# To test a local build instead, replace SOZUNE_IMAGE_REF and uncomment
# the `kind load docker-image` line.
SOZUNE_IMAGE_REF="${SOZUNE_IMAGE_REF:-kemeter/sozune:latest}"

# -- Cluster --
ensure_cluster

log "Waiting for cluster nodes to be Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s >/dev/null

log "Pre-loading sozune image into kind..."
# `kind load` is idempotent and fast when the image is already present in
# the node's containerd. It's required because the cluster has no internet
# access for non-kind images by default on some setups.
kind load docker-image "$SOZUNE_IMAGE_REF" --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

# -- Workload manifests (must come before the sozune Pod so the namespace
# and ingresses already exist when sozune starts watching).
log "Applying workload manifests..."
kubectl apply -f "$MANIFESTS_FILE"

log "Applying sozune deployment..."
# Sed-substitute the image ref in case the user overrode it.
sed "s|image: kemeter/sozune:latest|image: $SOZUNE_IMAGE_REF|" "$K8S_DIR/sozune-deploy.yaml" \
    | kubectl apply -f -

log "Waiting for backend pods to be ready (image pull may take a minute)..."
kubectl wait --for=condition=Ready pod -l app=svca -n sozune-test --timeout=180s
kubectl wait --for=condition=Ready pod -l app=svcb -n sozune-test --timeout=180s

log "Waiting for sozune pod to be ready..."
kubectl wait --for=condition=Ready pod -l app=sozune -n sozune-test --timeout=120s

log "Waiting for routes to propagate..."
sleep "$ROUTE_DELAY"

# -- Run suites --
for suite in "$K8S_DIR"/[0-9][0-9]-*.sh; do
    echo ""
    source "$suite"
done

# -- Summary --
echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"
echo "=============================="

if [[ $FAILED -gt 0 ]]; then
    log "sozune logs (last 120 lines):"
    kubectl logs -n sozune-test pod/sozune --tail=120 2>&1 || true
    log "kubectl get all -n sozune-test:"
    kubectl get pods,svc,ingress,endpoints,endpointslices -n sozune-test 2>&1 || true
    exit 1
fi
