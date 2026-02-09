#!/usr/bin/env bash
#
# Functional test suite for sozune proxy.
#
# Tests:
#   - Stale route cleanup (start/stop containers, verify 200/503)
#   - Basic auth middleware (401 without/wrong creds, 200 with correct creds)
#   - Custom headers injection (verify backend receives injected header)
#   - Strip prefix middleware (verify path rewriting before backend)
#   - HTTPS redirect (verify 301 on HTTP port)
#
# Requirements: docker, curl, cargo
#

set -euo pipefail

# -- Configuration --
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_PROJECT="sozune-functest"
COMPOSE_FILE="$PROJECT_DIR/compose.func-test.yaml"
CONFIG_FILE="$PROJECT_DIR/config.func-test.yaml"
HTTP_PORT=18080
HTTPS_PORT=18443
STARTUP_DELAY=3       # seconds to wait for sozune to start
ROUTE_DELAY=4         # seconds to wait for routes to propagate
MAX_RETRIES=20        # max curl retries (x0.5s = 10s)

HOST_A="svca.func-test.localhost"
HOST_B="svcb.func-test.localhost"
HOST_AUTH="auth.func-test.localhost"
HOST_HEADERS="headers.func-test.localhost"
HOST_STRIP="strip.func-test.localhost"
HOST_REDIRECT="redirect.func-test.localhost"
MIDDLEWARE_PORT=13037

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SOZUNE_PID=""
PASSED=0
FAILED=0

# -- Helpers --
log()  { echo -e "${YELLOW}[TEST]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }

cleanup() {
    log "Cleaning up..."
    if [[ -n "$SOZUNE_PID" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    rm -f "$COMPOSE_FILE" "$CONFIG_FILE"
}
trap cleanup EXIT

# Wait for an HTTP endpoint to respond with a given status code.
# Returns 0 on match, 1 on timeout.
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

# Wait for the route to stop returning 200 (any non-200 is success).
wait_for_not_200() {
    local url="$1" host="$2"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "Host: $host" "$url" 2>/dev/null || echo "000")
        if [[ "$status" != "200" ]]; then
            echo "$status"
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "200"
    return 1
}

# -- Step 0: Build --
log "Building sozune..."
cargo build --quiet 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    echo "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# -- Step 1: Generate config files --
log "Generating test config files..."

cat > "$CONFIG_FILE" <<EOF
providers:
  docker:
    enabled: true
    expose_by_default: false
  config_file:
    enabled: false

api:
  enabled: false

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

cat > "$COMPOSE_FILE" <<EOF
services:
  svca:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svca.host=$HOST_A"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svcb:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcb.host=$HOST_B"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-auth:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcauth.host=$HOST_AUTH"
      - "sozune.http.svcauth.auth.basic=admin:secret"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-headers:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcheaders.host=$HOST_HEADERS"
      - "sozune.http.svcheaders.headers.X-Custom-Test=hello-sozune"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-strip:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcstrip.host=$HOST_STRIP"
      - "sozune.http.svcstrip.path=/api"
      - "sozune.http.svcstrip.stripPrefix=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-redirect:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcredirect.host=$HOST_REDIRECT"
      - "sozune.http.svcredirect.httpsRedirect=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"
EOF

# -- Step 2: Start containers --
log "Starting test containers..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d --wait

# -- Step 3: Start sozune --
log "Starting sozune (HTTP on :$HTTP_PORT)..."
CONFIG_PATH="$CONFIG_FILE" RUST_LOG=sozune=debug "$SOZUNE_BIN" &
SOZUNE_PID=$!
sleep "$STARTUP_DELAY"

if ! kill -0 "$SOZUNE_PID" 2>/dev/null; then
    fail "sozune process died on startup"
    exit 1
fi

# -- Step 4: Wait for both routes to be ready --
log "Waiting for routes to propagate..."
sleep "$ROUTE_DELAY"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca reachable after startup"
else
    fail "svca NOT reachable after startup (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable after startup"
else
    fail "svcb NOT reachable after startup (timeout)"
fi

# -- Step 5: Stop svcb, verify route cleanup --
log "Stopping svcb..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" stop svcb

log "Waiting for route cleanup..."
got_status=$(wait_for_not_200 "http://127.0.0.1:$HTTP_PORT/" "$HOST_B")
if [[ "$got_status" != "200" ]]; then
    pass "svcb route cleaned up after stop (got $got_status)"
else
    fail "svcb route NOT cleaned up after stop (still returning 200)"
fi

# svca should be unaffected
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca still reachable after stopping svcb"
else
    fail "svca NOT reachable after stopping svcb"
fi

# -- Step 6: Restart svcb, verify route re-creation --
log "Restarting svcb..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" start svcb

log "Waiting for route re-creation..."
sleep "$ROUTE_DELAY"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_B" "200"; then
    pass "svcb reachable again after restart"
else
    fail "svcb NOT reachable after restart (timeout)"
fi

if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_A" "200"; then
    pass "svca still reachable after svcb restart"
else
    fail "svca NOT reachable after svcb restart"
fi

# ==============================================================
# Middleware & feature tests
# ==============================================================

# -- Basic Auth --
log "Testing basic auth..."

# Without credentials -> 401
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_AUTH" "401"; then
    pass "basic auth returns 401 without credentials"
else
    fail "basic auth did NOT return 401 without credentials"
fi

# With wrong credentials -> 401
wrong_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_AUTH" -u "admin:wrong" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$wrong_status" == "401" ]]; then
    pass "basic auth returns 401 with wrong credentials"
else
    fail "basic auth returned $wrong_status instead of 401 with wrong credentials"
fi

# With correct credentials -> 200
correct_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_AUTH" -u "admin:secret" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$correct_status" == "200" ]]; then
    pass "basic auth returns 200 with correct credentials"
else
    fail "basic auth returned $correct_status instead of 200 with correct credentials"
fi

# -- Custom Headers --
log "Testing custom headers injection..."

# whoami echoes received headers in its response body
header_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_HEADERS" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "")
if echo "$header_body" | grep -qi "X-Custom-Test: hello-sozune"; then
    pass "custom header X-Custom-Test injected and visible in backend"
else
    fail "custom header X-Custom-Test NOT found in backend response"
fi

# -- Strip Prefix --
log "Testing strip prefix..."

# Request /api/info -> backend should see /info (whoami shows the request URI)
strip_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_STRIP" \
    "http://127.0.0.1:$HTTP_PORT/api/info" 2>/dev/null || echo "")
if echo "$strip_body" | grep -q "GET /info"; then
    pass "strip prefix: /api/info -> backend received /info"
else
    fail "strip prefix: backend did not receive /info, got: $(echo "$strip_body" | grep -i 'GET ' | head -1)"
fi

# Request /api -> backend should see /
strip_root_body=$(curl -s --max-time 2 \
    -H "Host: $HOST_STRIP" \
    "http://127.0.0.1:$HTTP_PORT/api" 2>/dev/null || echo "")
if echo "$strip_root_body" | grep -q "GET /"; then
    pass "strip prefix: /api -> backend received /"
else
    fail "strip prefix: backend did not receive /, got: $(echo "$strip_root_body" | grep -i 'GET ' | head -1)"
fi

# -- HTTPS Redirect --
log "Testing HTTPS redirect..."

# Request on HTTP port should get 301 redirect
redirect_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_REDIRECT" \
    "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$redirect_status" == "301" ]]; then
    pass "HTTPS redirect returns 301"
else
    fail "HTTPS redirect returned $redirect_status instead of 301"
fi

# -- Summary --
echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}"
echo "=============================="

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
