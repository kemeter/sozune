#!/usr/bin/env bash
# Shared helpers for sozune e2e suites.
# Sourced by run-all.sh; not meant to be run standalone.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_PROJECT="sozune-functest"
COMPOSE_FILE="$PROJECT_DIR/compose.func-test.yaml"
CONFIG_FILE="$PROJECT_DIR/config.func-test.yaml"

HTTP_PORT=18080
HTTPS_PORT=18443
API_PORT=18888
MIDDLEWARE_PORT=13037
TCP_ECHO_PORT=15555
TCP_RR_PORT=15556
API_USER="admin"
API_PASSWORD="test-secret-token"
API_PASSWORD_HASH=$(printf '%s' "$API_PASSWORD" | sha256sum | cut -d' ' -f1)
API_BASIC_AUTH=$(printf '%s:%s' "$API_USER" "$API_PASSWORD" | base64 -w0)

STARTUP_DELAY=3
ROUTE_DELAY=4
MAX_RETRIES=20

HOST_A="svca.func-test.localhost"
HOST_B="svcb.func-test.localhost"
HOST_AUTH="auth.func-test.localhost"
HOST_HEADERS="headers.func-test.localhost"
HOST_HEADERS_RESPONSE="headers-response.func-test.localhost"
HOST_HEADERS_BOTH="headers-both.func-test.localhost"
HOST_HEADERS_DELETE="headers-delete.func-test.localhost"
HOST_STRIP="strip.func-test.localhost"
HOST_REDIRECT="redirect.func-test.localhost"
HOST_RATELIMIT="ratelimit.func-test.localhost"
HOST_COMPRESS="compress.func-test.localhost"
HOST_TIMEOUT="timeout.func-test.localhost"
HOST_REGEX="regex.func-test.localhost"
HOST_MIXED_SUFFIX="mixed-test.localhost"
HOST_HOSTREGEX_SUFFIX="hostregex-test.localhost"
HOST_TLS="tls.func-test.localhost"
HOST_WS="ws.func-test.localhost"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
SOZUNE_PID=""

log()  { echo -e "${YELLOW}[TEST]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED + 1)); }

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

tcp_send() {
    local host="$1" port="$2" payload="$3"
    # `nc -w 2` waits 2s of idle on the socket before closing — gives the
    # backend time to respond. We avoid socat's shut-down half-close because
    # Sōzu's TCP path closes the full connection on FIN, racing the response.
    printf '%s' "$payload" | timeout 5 nc -w 2 "$host" "$port" 2>/dev/null || true
}

wait_for_tcp_open() {
    local host="$1" port="$2"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        if timeout 1 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

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
