#!/usr/bin/env bash
# Shared helpers for the Kubernetes Ingress e2e suite.
# Sourced by run-k8s.sh; not meant to be run standalone.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLUSTER_NAME="sozune-k8s-test"
KUBECONFIG_FILE="$K8S_DIR/kubeconfig.k8s.yaml"
MANIFESTS_FILE="$K8S_DIR/manifests.yaml"
KIND_CLUSTER_CONFIG="$K8S_DIR/kind-cluster.yaml"

HTTP_PORT=18180
HTTPS_PORT=18443
API_PORT=18181
MIDDLEWARE_PORT=13180

HOST_A="svca.k8s-test.localhost"
HOST_B="svcb.k8s-test.localhost"

STARTUP_DELAY=4
ROUTE_DELAY=10
MAX_RETRIES=60

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
CLUSTER_CREATED_BY_US=0

log()  { echo -e "${YELLOW}[K8S]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED + 1)); }

require_kind() {
    if ! command -v kind >/dev/null 2>&1; then
        echo "Kind not found. Install: https://kind.sigs.k8s.io/docs/user/quick-start/"
        exit 1
    fi
    if ! command -v kubectl >/dev/null 2>&1; then
        echo "kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi
}

ensure_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^$CLUSTER_NAME$"; then
        log "Reusing existing kind cluster '$CLUSTER_NAME'"
    else
        log "Creating kind cluster '$CLUSTER_NAME'..."
        # The cluster config maps Sozune's HTTP/HTTPS/API ports from the
        # node container back to the developer's host so curl can hit them.
        kind create cluster \
            --name "$CLUSTER_NAME" \
            --config "$KIND_CLUSTER_CONFIG" \
            --kubeconfig "$KUBECONFIG_FILE" >/dev/null
        CLUSTER_CREATED_BY_US=1
    fi
    kind get kubeconfig --name "$CLUSTER_NAME" > "$KUBECONFIG_FILE"
    export KUBECONFIG="$KUBECONFIG_FILE"
}

teardown_cluster_if_ours() {
    if [[ "$CLUSTER_CREATED_BY_US" -eq 1 ]]; then
        log "Deleting kind cluster '$CLUSTER_NAME'..."
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
}

wait_for_pod_ready() {
    local label="$1"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        if kubectl get pods -l "$label" -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null | grep -q "true"; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_for_status() {
    local url="$1" host="$2" expected="$3"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "Host: $host" "$url" 2>/dev/null || echo "000")
        if [[ "$status" == "$expected" ]]; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}
