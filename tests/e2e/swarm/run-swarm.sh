#!/usr/bin/env bash
#
# Functional test orchestrator for the Sozune Swarm provider.
# Inits Swarm, deploys a stack, runs Sozune in a container attached to the
# overlay (so it can reach VIPs), then runs all suite scripts in order.
#
# Requirements: docker (with Swarm capability), curl, cargo

set -euo pipefail

SWARM_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SWARM_DIR/lib-swarm.sh"

cleanup() {
    log "Cleaning up..."
    docker rm -f "$SOZUNE_CONTAINER" >/dev/null 2>&1 || true
    docker stack rm "$STACK_NAME" >/dev/null 2>&1 || true
    # Wait for the stack tasks to release their overlay attachments before we
    # try to remove it.
    local i=0
    while [[ $i -lt 30 ]] && docker network inspect "$OVERLAY_NETWORK" --format '{{len .Containers}}' 2>/dev/null | grep -qv '^0$'; do
        sleep 1
        i=$((i + 1))
    done
    docker network rm "$OVERLAY_NETWORK" >/dev/null 2>&1 || true
    leave_swarm_if_ours
    rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

# -- Build sozune --
log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    echo "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# -- Swarm init + overlay + stack deploy --
ensure_swarm

log "Creating attachable overlay '$OVERLAY_NETWORK'..."
docker network create --driver overlay --attachable --scope swarm \
    "$OVERLAY_NETWORK" >/dev/null

log "Deploying stack '$STACK_NAME'..."
docker stack deploy -c "$COMPOSE_FILE" "$STACK_NAME" >/dev/null

log "Waiting for stack services to be ready..."
if ! wait_for_stack_ready; then
    fail "Stack did not converge in time"
    docker stack services "$STACK_NAME"
    exit 1
fi

# -- Config file (read by sozune inside the container) --
log "Generating sozune config..."
cat > "$CONFIG_FILE" <<EOF
providers:
  swarm:
    enabled: true
    endpoint: "/var/run/docker.sock"
    expose_by_default: false
    network: "$OVERLAY_NETWORK"
    refresh_interval: 5

api:
  enabled: true
  listen_address: "0.0.0.0:$API_PORT"
  users:
    - name: "$API_USER"
      hash: "$API_PASSWORD_HASH"
      role: admin

proxy:
  http:
    listen_address: $HTTP_PORT
  https:
    listen_address: $HTTPS_PORT
  max_buffers: 500
  buffer_size: 16384
  startup_delay_ms: 1000
  cluster_setup_delay_ms: 200

middleware:
  port: $MIDDLEWARE_PORT
EOF

# -- Run sozune as a container attached to the overlay --
# The Docker socket gives it access to the Swarm API. The overlay
# attachment lets it route to service VIPs.
log "Starting sozune container on overlay '$OVERLAY_NETWORK'..."
docker run -d --rm \
    --name "$SOZUNE_CONTAINER" \
    --network "$OVERLAY_NETWORK" \
    -p "127.0.0.1:$HTTP_PORT:$HTTP_PORT" \
    -p "127.0.0.1:$API_PORT:$API_PORT" \
    -v "/var/run/docker.sock:/var/run/docker.sock:ro" \
    -v "$SOZUNE_BIN:/sozune:ro" \
    -v "$CONFIG_FILE:/config.yaml:ro" \
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
for suite in "$SWARM_DIR"/[0-9][0-9]-*.sh; do
    echo ""
    source "$suite"
done

# -- Summary --
echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"
echo "=============================="

if [[ $FAILED -gt 0 ]]; then
    log "sozune logs (last 80 lines):"
    docker logs "$SOZUNE_CONTAINER" 2>&1 | tail -80 || true
    exit 1
fi
