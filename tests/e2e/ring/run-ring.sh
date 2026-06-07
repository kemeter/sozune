#!/usr/bin/env bash
#
# Functional test orchestrator for the Sozune Ring provider.
# Boots a Ring server (Docker runtime), deploys a whoami deployment carrying
# sozune.* labels, starts Sozune locally pointed at the Ring API, then runs
# all suite scripts in order.
#
# Ring is not a standard tool, so this suite is opt-in: it is NOT wired into
# tests/e2e/run-all.sh and skips cleanly when the `ring` binary is absent.
# Point RING_BIN at a built Ring binary to run it:
#   RING_BIN=/path/to/ring bash tests/e2e/ring/run-ring.sh
#
# Requirements: ring, docker, jq, curl, cargo

set -euo pipefail

RING_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$RING_DIR/lib-ring.sh"

RING_BIN="${RING_BIN:-ring}"
KEEP_SERVER="${KEEP_SERVER:-0}"

# Ring server bootstrap: isolated config dir + database, Docker runtime on.
export RING_CONFIG_DIR="$RING_DATA_DIR"
export RING_DATABASE_PATH="$RING_DATA_DIR/ring.db"
export RING_SECRET_KEY="${RING_SECRET_KEY:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
RING_PORT="${RING_PORT:-3030}"

cleanup() {
    log "Cleaning up..."
    if [[ -n "${SOZUNE_PID:-}" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    if [[ -f "$RING_PID_FILE" ]]; then
        local server_pid
        server_pid=$(cat "$RING_PID_FILE")
        if kill -0 "$server_pid" 2>/dev/null; then
            kill "$server_pid" 2>/dev/null || true
            wait "$server_pid" 2>/dev/null || true
        fi
        rm -f "$RING_PID_FILE"
    fi
    # Remove any container Ring created for this run (labelled ring_deployment).
    if command -v docker >/dev/null 2>&1; then
        docker ps -aq --filter "label=ring_deployment" 2>/dev/null \
            | xargs -r docker rm -f >/dev/null 2>&1 || true
    fi
    rm -f "$CONFIG_FILE"
    if [[ "$KEEP_SERVER" != "1" ]]; then
        rm -rf "$RING_DATA_DIR"
    else
        log "Keeping Ring data dir at $RING_DATA_DIR"
    fi
}
trap cleanup EXIT

# -- Pre-flight: skip (don't fail) when Ring is unavailable --
if ! command -v "$RING_BIN" >/dev/null 2>&1; then
    skip "Ring binary not found (set RING_BIN to a built ring); skipping Ring e2e suite"
    echo "=============================="
    echo -e "  ${YELLOW}Skipped: 1${NC}"
    echo "=============================="
    exit 0
fi
for tool in docker jq curl cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "Missing required tool: $tool"
        exit 1
    fi
done

# -- Build sozune --
log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    fail "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# -- Ring server config --
cat > "$RING_DATA_DIR/config.toml" <<EOF
[contexts.default]
current = true
host = "127.0.0.1"

api.scheme = "http"
api.port = ${RING_PORT}

user.salt = "sozune-e2e-salt"

[server.scheduler]
interval = 1

[server.runtime.docker]
enabled = true
EOF

# -- Boot Ring server --
log "Starting Ring server on port $RING_PORT (config: $RING_DATA_DIR)..."
"$RING_BIN" server start >"$RING_LOG" 2>&1 &
echo $! > "$RING_PID_FILE"

if ! wait_for_ring; then
    fail "Ring server did not become ready in time"
    tail -40 "$RING_LOG" || true
    exit 1
fi
log "Ring server ready at $RING_ADDR"

# -- Deploy whoami --
log "Logging in to Ring (admin)..."
"$RING_BIN" login --username admin --password changeme >/dev/null

# Mint a read-only PAT for Sozune (and for this runner's API probes). The
# clear token is printed on stdout by `ring token create`.
log "Creating a deployments:read token for Sozune..."
RING_TOKEN="$("$RING_BIN" token create sozune-e2e --scope deployments:read 2>/dev/null)"
if [[ -z "$RING_TOKEN" ]]; then
    fail "Could not mint a Ring token"
    exit 1
fi

log "Deploying '$DEPLOYMENT_NAME' (3 replicas of traefik/whoami)..."
"$RING_BIN" apply --file "$RING_DIR/whoami.ring.yaml" >/dev/null

if ! wait_for_ring_instances 3; then
    fail "Deployment '$DEPLOYMENT_NAME' did not report 3 addressable instances in time"
    ring_api "/deployments" | jq '.' || true
    exit 1
fi
log "Deployment '$DEPLOYMENT_NAME' has 3 addressable instances"

# -- Sozune config --
cat > "$CONFIG_FILE" <<EOF
providers:
  ring:
    enabled: true
    endpoint: "$RING_ADDR"
    token: "$RING_TOKEN"
    poll_interval: 3

api:
  enabled: false

proxy:
  http:
    listen_address: $HTTP_PORT
  https:
    listen_address: $HTTPS_PORT
  startup_delay_ms: 500
  cluster_setup_delay_ms: 200

middleware:
  port: $MIDDLEWARE_PORT
EOF

log "Starting sozune (HTTP on :$HTTP_PORT)..."
CONFIG_PATH="$CONFIG_FILE" RUST_LOG=sozune=info "$SOZUNE_BIN" \
    >"$SOZUNE_LOG" 2>&1 &
SOZUNE_PID=$!
sleep "$STARTUP_DELAY"

if ! kill -0 "$SOZUNE_PID" 2>/dev/null; then
    fail "sozune process died on startup"
    tail -40 "$SOZUNE_LOG" || true
    exit 1
fi

log "Waiting for routes to propagate..."
sleep "$ROUTE_DELAY"

# -- Run suites --
for suite in "$RING_DIR"/[0-9][0-9]-*.sh; do
    echo ""
    source "$suite"
done

# -- Summary --
echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"
echo "=============================="

if [[ $FAILED -gt 0 ]]; then
    log "sozune logs (last 60 lines):"
    tail -60 "$SOZUNE_LOG" || true
    exit 1
fi
