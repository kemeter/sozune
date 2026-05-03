#!/usr/bin/env bash
#
# Functional test orchestrator for the Sozune Kubernetes Ingress provider.
# Spins up a kind cluster, applies manifests (Deployments + Services +
# Ingresses), starts Sozune locally pointing at the cluster's kubeconfig,
# then runs all suite scripts in order.
#
# Requirements: docker, kind, kubectl, curl, cargo

set -euo pipefail

K8S_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$K8S_DIR/lib-k8s.sh"

cleanup() {
    log "Cleaning up..."
    docker rm -f "$SOZUNE_CONTAINER" >/dev/null 2>&1 || true
    teardown_cluster_if_ours
    rm -f "$CONFIG_FILE" "$KUBECONFIG_FILE" "$KUBECONFIG_INTERNAL"
}
trap cleanup EXIT

require_kind

# -- Build sozune --
log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    echo "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# -- Cluster + manifests --
ensure_cluster

log "Waiting for cluster nodes to be Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s >/dev/null

log "Applying manifests..."
kubectl apply -f "$MANIFESTS_FILE"

log "Waiting for pods to be ready (image pull may take a minute on first run)..."
if ! kubectl wait --for=condition=Ready pod -l app=svca -n sozune-test --timeout=180s; then
    fail "svca pod did not become ready"
    kubectl describe pods -l app=svca -n sozune-test | tail -30 || true
    exit 1
fi
if ! kubectl wait --for=condition=Ready pod -l app=svcb -n sozune-test --timeout=180s; then
    fail "svcb pod did not become ready"
    kubectl describe pods -l app=svcb -n sozune-test | tail -30 || true
    exit 1
fi

# -- Internal kubeconfig --
# kind writes a kubeconfig that points at 127.0.0.1:<random>; that only
# works from the host. Sozune runs in a container on the kind network, so
# we need a kubeconfig whose server URL points at the control-plane
# container by name (resolvable on the kind network).
log "Generating internal kubeconfig..."
kind get kubeconfig --internal --name "$CLUSTER_NAME" > "$KUBECONFIG_INTERNAL"

# -- Config file --
log "Generating sozune config..."
cat > "$CONFIG_FILE" <<EOF
providers:
  kubernetes:
    enabled: true
    kubeconfig: "/kubeconfig.yaml"
    namespace: "sozune-test"
    ingress_class: "sozune"

api:
  enabled: true
  listen_address: "0.0.0.0:$API_PORT"

proxy:
  http:
    listen_address: $HTTP_PORT
  https:
    listen_address: $HTTPS_PORT

middleware:
  port: $MIDDLEWARE_PORT
EOF

# -- Start sozune as a container on the kind Docker network --
# Pod IPs (10.244.x.x) only route from inside the kind network, so sozune
# must be attached to it. We expose just the HTTP port back to the host
# for the test harness.
log "Starting sozune container on kind network..."
docker run -d --rm \
    --name "$SOZUNE_CONTAINER" \
    --network "$KIND_NETWORK" \
    -p "127.0.0.1:$HTTP_PORT:$HTTP_PORT" \
    -p "127.0.0.1:$API_PORT:$API_PORT" \
    -v "$SOZUNE_BIN:/sozune:ro" \
    -v "$CONFIG_FILE:/config.yaml:ro" \
    -v "$KUBECONFIG_INTERNAL:/kubeconfig.yaml:ro" \
    -e CONFIG_PATH=/config.yaml \
    -e RUST_LOG=sozune=debug \
    "$SOZUNE_IMAGE" \
    /sozune >/dev/null

sleep "$STARTUP_DELAY"

if ! docker ps --format '{{.Names}}' | grep -q "^$SOZUNE_CONTAINER$"; then
    fail "sozune container died on startup"
    docker logs "$SOZUNE_CONTAINER" 2>&1 | tail -50 || true
    exit 1
fi

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
    docker logs "$SOZUNE_CONTAINER" 2>&1 | tail -120 || true
    log "kubectl get all -A:"
    kubectl get pods,svc,ingress,endpoints,endpointslices -n sozune-test 2>&1 || true
    log "Network debug:"
    sozune_ip=$(docker inspect "$SOZUNE_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
    echo "Sozune container IP (on kind network): $sozune_ip"
    echo "Curl from host to mapped port:"
    curl -s -o /dev/null -w "  127.0.0.1:$HTTP_PORT -> %{http_code} (time=%{time_total}s)\n" --max-time 3 \
        -H "Host: $HOST_A" "http://127.0.0.1:$HTTP_PORT/" 2>&1 || true
    if [[ -n "$sozune_ip" ]]; then
        echo "Curl from host directly to container IP on kind network:"
        curl -s -o /dev/null -w "  $sozune_ip:$HTTP_PORT -> %{http_code} (time=%{time_total}s)\n" --max-time 3 \
            -H "Host: $HOST_A" "http://$sozune_ip:$HTTP_PORT/" 2>&1 || true
    fi
    echo "Docker port mappings:"
    docker port "$SOZUNE_CONTAINER" 2>&1 || true
    exit 1
fi
