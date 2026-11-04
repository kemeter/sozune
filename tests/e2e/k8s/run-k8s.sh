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

# -- Gateway API CRDs (standard channel — must exist before sozune starts so
# the route watchers' CRD probes succeed on first try). v1.2.0 is vendored
# under tests/e2e/k8s/ so the default run needs no internet from the kind
# node; GATEWAY_API_VERSION picks another release, fetched from GitHub.
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.2.0}"
if [[ "$GATEWAY_API_VERSION" == "v1.2.0" ]]; then
    log "Installing Gateway API CRDs (standard v1.2.0)..."
    kubectl apply -f "$K8S_DIR/gateway-api-crds-v1.2.0.yaml" >/dev/null

    # TLSRoute is v1alpha2 and lives in the experimental channel, so it is not
    # in the bundle above. Vendored on its own — see the file header.
    log "Installing TLSRoute CRD (experimental v1.2.0)..."
    kubectl apply -f "$K8S_DIR/tlsroute-crd-v1.2.0.yaml" >/dev/null

    log "Installing TCPRoute CRD (experimental v1.2.0)..."
    kubectl apply -f "$K8S_DIR/tcproute-crd-v1.2.0.yaml" >/dev/null

    log "Installing UDPRoute CRD (experimental v1.2.0)..."
    kubectl apply -f "$K8S_DIR/udproute-crd-v1.2.0.yaml" >/dev/null
else
    crd_cache="${XDG_CACHE_HOME:-$HOME/.cache}/sozune-e2e/gateway-api-$GATEWAY_API_VERSION"
    mkdir -p "$crd_cache"
    for bundle in standard experimental; do
        if [[ ! -s "$crd_cache/$bundle-install.yaml" ]]; then
            curl -fsSL -o "$crd_cache/$bundle-install.yaml" \
                "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/$bundle-install.yaml"
        fi
    done
    log "Installing Gateway API CRDs (standard $GATEWAY_API_VERSION)..."
    kubectl apply --server-side -f "$crd_cache/standard-install.yaml" >/dev/null

    # TCPRoute and UDPRoute joined the standard channel in v1.6. Before, take
    # only their CRDs from the experimental bundle, so every other kind stays
    # at its standard version.
    if ! grep -q "name: tcproutes.gateway.networking.k8s.io" "$crd_cache/standard-install.yaml"; then
        log "Installing TCPRoute and UDPRoute CRDs (experimental $GATEWAY_API_VERSION)..."
        awk -v RS='\n---\n' -v ORS='\n---\n' \
            '/name: (tcproutes|udproutes)\.gateway\.networking\.k8s\.io/' \
            "$crd_cache/experimental-install.yaml" | kubectl apply --server-side -f - >/dev/null
    fi
fi

# The version the manifests use for each L4 route kind: `v1` where its CRD
# serves it (the standard channel, since v1.5 for TLSRoute and v1.6 for
# TCPRoute and UDPRoute), `v1alpha2` before.
served_route_version() {
    if kubectl get crd "$1.gateway.networking.k8s.io" \
        -o jsonpath='{.spec.versions[?(@.served==true)].name}' 2>/dev/null | tr ' ' '\n' | grep -qx v1; then
        echo v1
    else
        echo v1alpha2
    fi
}
TLSROUTE_API_VERSION=$(served_route_version tlsroutes)
TCPROUTE_API_VERSION=$(served_route_version tcproutes)
UDPROUTE_API_VERSION=$(served_route_version udproutes)
export TLSROUTE_API_VERSION TCPROUTE_API_VERSION UDPROUTE_API_VERSION
log "L4 route manifests use TLSRoute $TLSROUTE_API_VERSION, TCPRoute $TCPROUTE_API_VERSION, UDPRoute $UDPROUTE_API_VERSION"

# -- Workload manifests (must come before the sozune Pod so the namespace
# and ingresses already exist when sozune starts watching).
log "Applying workload manifests..."
kubectl apply -f "$MANIFESTS_FILE"

log "Applying Gateway API workloads..."
sed -e "/^apiVersion: gateway.networking.k8s.io\/v1alpha2$/{N;s|v1alpha2\(\nkind: TLSRoute\)|$TLSROUTE_API_VERSION\1|;s|v1alpha2\(\nkind: TCPRoute\)|$TCPROUTE_API_VERSION\1|;s|v1alpha2\(\nkind: UDPRoute\)|$UDPROUTE_API_VERSION\1|}" \
    "$K8S_DIR/gateway-manifests.yaml" | kubectl apply -f -

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
