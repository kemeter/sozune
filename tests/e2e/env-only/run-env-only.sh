#!/usr/bin/env bash
#
# E2e: prove that sozune starts and routes correctly with NO config.yaml,
# driven entirely by SOZUNE_* environment variables.
#
# Regression guard for the bug where AppConfig::default() bypassed the
# serde-based env var deserializers, leaving Docker discovery and ACME off
# even when SOZUNE_PROVIDER_DOCKER_ENABLED=true was set.

set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$E2E_DIR/lib.sh"

ENV_HTTP_PORT=18180
ENV_HTTPS_PORT=18543
ENV_COMPOSE_PROJECT="sozune-env-only"
ENV_HOST="env.func-test.localhost"
ENV_COMPOSE_FILE="$PROJECT_DIR/compose.env-only.yaml"

cleanup() {
    log "Cleaning up..."
    if [[ -n "${SOZUNE_PID:-}" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    docker compose -p "$ENV_COMPOSE_PROJECT" -f "$ENV_COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    rm -f "$ENV_COMPOSE_FILE"
}
trap cleanup EXIT

log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
[[ -x "$SOZUNE_BIN" ]] || { echo "Build failed"; exit 1; }

log "Generating backend compose..."
cat > "$ENV_COMPOSE_FILE" <<EOF
services:
  envwhoami:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.envwhoami.host=$ENV_HOST"
      - "sozune.network=${ENV_COMPOSE_PROJECT}_default"
EOF

log "Starting backend container..."
docker compose -p "$ENV_COMPOSE_PROJECT" -f "$ENV_COMPOSE_FILE" up -d --wait

log "Starting sozune with env-only config (no config.yaml on disk)..."
# CONFIG_PATH points at a path that does NOT exist, forcing the
# AppConfig::default() branch in main.rs.
TMP_CFG="$(mktemp -u /tmp/sozune-no-such-config-XXXXXX.yaml)"
SOZUNE_PROVIDER_DOCKER_ENABLED=true \
SOZUNE_PROVIDER_DOCKER_EXPOSE_BY_DEFAULT=false \
SOZUNE_HTTP_PORT=$ENV_HTTP_PORT \
SOZUNE_HTTPS_PORT=$ENV_HTTPS_PORT \
SOZUNE_API_ENABLED=false \
SOZUNE_DASHBOARD_ENABLED=false \
CONFIG_PATH="$TMP_CFG" \
RUST_LOG=sozune=info \
"$SOZUNE_BIN" &
SOZUNE_PID=$!
sleep "$STARTUP_DELAY"

if ! kill -0 "$SOZUNE_PID" 2>/dev/null; then
    fail "sozune process died on startup with env-only config"
    exit 1
fi

log "TEST: sozune binds on SOZUNE_HTTP_PORT=$ENV_HTTP_PORT"
if (echo > "/dev/tcp/127.0.0.1/$ENV_HTTP_PORT") 2>/dev/null; then
    pass "HTTP listener up on custom port from env"
else
    fail "sozune is NOT listening on $ENV_HTTP_PORT — env var was ignored"
    exit 1
fi

log "TEST: Docker provider discovered the labeled backend"
status=$(wait_for_not_404 "http://127.0.0.1:$ENV_HTTP_PORT/" "$ENV_HOST")
if [[ "$status" == "200" ]]; then
    pass "route to $ENV_HOST returns 200 — Docker provider enabled via env var"
else
    fail "route to $ENV_HOST returned $status (expected 200) — Docker provider not active"
    exit 1
fi

echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}"
echo "=============================="

[[ $FAILED -eq 0 ]]
