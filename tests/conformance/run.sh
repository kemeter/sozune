#!/usr/bin/env bash
#
# Runs the upstream Gateway API conformance suite against Sōzune on kind.
# Local only, like the other e2e suites.
#
# Requirements: docker, kind, kubectl, git.
#
#   SOZUNE_IMAGE_REF   image to test (default kemeter/sozune:latest), loaded
#                      into kind
#   CONFORMANCE_ARGS   extra flags for the suite, e.g.
#                      "--supported-features=HTTPRouteMethodMatching"
#   KEEP_CLUSTER=1     leave the cluster up afterwards
#   SOZUNE_LOG         Sōzune's RUST_LOG (default sozune=info)
#
# Writes the suite's report to tests/conformance/report.yaml.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="sozune-conformance"
GATEWAY_API_VERSION="v1.2.0"
SOZUNE_IMAGE_REF="${SOZUNE_IMAGE_REF:-kemeter/sozune:latest}"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/sozune-conformance"
KUBECONFIG_FILE="$(mktemp)"
export KUBECONFIG="$KUBECONFIG_FILE"

log() { echo -e "\033[1;33m[CONFORMANCE]\033[0m $*"; }

cleanup() {
    if [[ "${KEEP_CLUSTER:-}" != "1" ]]; then
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
    rm -f "$KUBECONFIG_FILE"
}
trap cleanup EXIT

if ! kind get clusters 2>/dev/null | grep -q "^$CLUSTER_NAME$"; then
    log "Creating kind cluster $CLUSTER_NAME..."
    kind create cluster --name "$CLUSTER_NAME" >/dev/null
fi
kind get kubeconfig --name "$CLUSTER_NAME" > "$KUBECONFIG_FILE"
kubectl wait --for=condition=Ready nodes --all --timeout=120s >/dev/null

log "Installing Gateway API CRDs ($GATEWAY_API_VERSION, standard)..."
kubectl apply -f "$DIR/../e2e/k8s/gateway-api-crds-$GATEWAY_API_VERSION.yaml" >/dev/null

log "Deploying Sōzune ($SOZUNE_IMAGE_REF)..."
kind load docker-image "$SOZUNE_IMAGE_REF" --name "$CLUSTER_NAME" >/dev/null
node_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$CLUSTER_NAME-control-plane")
kubectl delete pod sozune -n sozune-conformance --ignore-not-found >/dev/null
sed -e "s|__IMAGE__|$SOZUNE_IMAGE_REF|" -e "s|__NODE_IP__|$node_ip|" \
    -e "s|__LOG__|${SOZUNE_LOG:-sozune=info}|" "$DIR/sozune.yaml" \
    | kubectl apply -f - >/dev/null
kubectl wait --for=condition=Ready pod/sozune -n sozune-conformance --timeout=120s >/dev/null

log "Fetching the conformance suite ($GATEWAY_API_VERSION)..."
suite="$CACHE_DIR/gateway-api-$GATEWAY_API_VERSION"
if [[ ! -d "$suite" ]]; then
    mkdir -p "$CACHE_DIR"
    git clone --quiet --depth 1 --branch "$GATEWAY_API_VERSION" \
        https://github.com/kubernetes-sigs/gateway-api.git "$suite"
fi

log "Running the suite (Sōzune at $node_ip)..."
status=0
# shellcheck disable=SC2086
docker run --rm --network host \
    -v "$suite:/src" -v "$KUBECONFIG_FILE:/kubeconfig:ro" -v "$DIR:/out" \
    -v sozune-conformance-gomod:/go/pkg/mod \
    -e KUBECONFIG=/kubeconfig -w /src golang:1.23 \
    go test ./conformance -run TestConformance -timeout 60m -args \
        --gateway-class=sozune \
        --conformance-profiles=GATEWAY-HTTP \
        --organization=kemeter --project=sozune \
        --url=https://github.com/kemeter/sozune --version=dev \
        --report-output=/out/report.yaml \
        ${CONFORMANCE_ARGS:-} || status=$?

if [[ $status -ne 0 ]]; then
    log "Sōzune logs (last 80 lines):"
    kubectl logs -n sozune-conformance pod/sozune --tail=80 || true
fi
exit "$status"
