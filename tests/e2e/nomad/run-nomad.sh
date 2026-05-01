#!/usr/bin/env bash
#
# Functional test orchestrator for the Sozune Nomad provider.
# Boots a Nomad agent in `-dev` mode (Docker driver), deploys a whoami job
# with sozune.* tags, runs Sozune locally pointed at the Nomad API, then
# runs all suite scripts in order.
#
# Requirements: nomad, docker, jq, curl, cargo

set -euo pipefail

NOMAD_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$NOMAD_DIR/lib-nomad.sh"

KEEP_AGENT="${KEEP_AGENT:-0}"

cleanup() {
    log "Cleaning up..."
    if [[ -n "${SOZUNE_PID:-}" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    nomad job stop -purge "$JOB_NAME" >/dev/null 2>&1 || true
    if [[ -f "$NOMAD_PID_FILE" ]]; then
        local agent_pid
        agent_pid=$(cat "$NOMAD_PID_FILE")
        if kill -0 "$agent_pid" 2>/dev/null; then
            kill "$agent_pid" 2>/dev/null || true
            wait "$agent_pid" 2>/dev/null || true
        fi
        rm -f "$NOMAD_PID_FILE"
    fi
    rm -f "$CONFIG_FILE"
    if [[ "$KEEP_AGENT" != "1" ]]; then
        rm -rf "$NOMAD_DATA_DIR"
    else
        log "Keeping Nomad data dir at $NOMAD_DATA_DIR"
    fi
}
trap cleanup EXIT

# -- Pre-flight --
for tool in nomad docker jq curl cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "Missing required tool: $tool"
        exit 1
    fi
done

# -- Build --
log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    fail "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# -- Boot Nomad agent in dev mode --
log "Starting Nomad agent in dev mode (data: $NOMAD_DATA_DIR)..."
nomad agent -dev -bind=127.0.0.1 -log-level=WARN \
    -data-dir="$NOMAD_DATA_DIR/data" \
    >"$NOMAD_LOG" 2>&1 &
echo $! > "$NOMAD_PID_FILE"

if ! wait_for_nomad; then
    fail "Nomad agent did not become ready in time"
    tail -40 "$NOMAD_LOG" || true
    exit 1
fi
log "Nomad agent ready at $NOMAD_ADDR"

# -- Deploy job --
log "Deploying job '$JOB_NAME' (3 instances of traefik/whoami)..."
nomad job run -detach "$NOMAD_DIR/whoami.nomad.hcl" >/dev/null

if ! wait_for_service_instances 3; then
    fail "Service '$SERVICE_NAME' did not register 3 instances in time"
    nomad job status "$JOB_NAME" || true
    exit 1
fi
log "Service '$SERVICE_NAME' has 3 healthy instances"

# -- Sozune config --
cat > "$CONFIG_FILE" <<EOF
providers:
  nomad:
    enabled: true
    endpoint: "$NOMAD_ADDR"
    poll_interval: 5

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
for suite in "$NOMAD_DIR"/[0-9][0-9]-*.sh; do
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
