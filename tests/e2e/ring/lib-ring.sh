#!/usr/bin/env bash
# Shared helpers for the Ring e2e suite. Sourced by run-ring.sh.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RING_ADDR="${RING_ADDR:-http://127.0.0.1:3030}"
# PAT (scope deployments:read) minted by the runner; helpers that hit the
# auth-gated /deployments endpoint send it as a Bearer token.
RING_TOKEN="${RING_TOKEN:-}"
RING_DATA_DIR="${RING_DATA_DIR:-$(mktemp -d -t sozune-ring-XXXXXX)}"
RING_LOG="$RING_DATA_DIR/server.log"
RING_PID_FILE="$RING_DATA_DIR/server.pid"

DEPLOYMENT_NAME="sozune-e2e-whoami"

HTTP_PORT=18180
HTTPS_PORT=18443
MIDDLEWARE_PORT=13139

CONFIG_FILE="$(mktemp -t sozune-ring-config.XXXXXX.yaml)"
SOZUNE_LOG="$RING_DATA_DIR/sozune.log"
SOZUNE_PID=""

HOST_WHOAMI="whoami.ring-test.localhost"

STARTUP_DELAY=2
ROUTE_DELAY=4

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

log()  { echo -e "${YELLOW}[RING]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED + 1)); }

probe_http() {
    local host="$1"
    local path="${2:-/}"
    curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: $host" \
        --max-time 3 \
        "http://localhost:$HTTP_PORT$path" || echo "000"
}

probe_body() {
    local host="$1"
    local path="${2:-/}"
    curl -s -H "Host: $host" --max-time 3 "http://localhost:$HTTP_PORT$path"
}

wait_for_status() {
    local host="$1"
    local expected="$2"
    local path="${3:-/}"
    for _ in $(seq 1 30); do
        if [[ "$(probe_http "$host" "$path")" == "$expected" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

count_distinct_hostnames() {
    local host="$1"
    local n="${2:-12}"
    local seen
    seen=$(for _ in $(seq 1 "$n"); do
        probe_body "$host" / | awk '/^Hostname:/ {print $2}'
    done | sort -u | wc -l)
    echo "$seen"
}

# Ready when the Ring API answers on /healthz (no auth required, unlike
# /deployments which is gated behind a token).
wait_for_ring() {
    for _ in $(seq 1 30); do
        if curl -sf "$RING_ADDR/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# curl against the auth-gated Ring API, sending the Bearer token when set.
ring_api() {
    local path="$1"
    if [[ -n "$RING_TOKEN" ]]; then
        curl -sf -H "Authorization: Bearer $RING_TOKEN" "$RING_ADDR$path"
    else
        curl -sf "$RING_ADDR$path"
    fi
}

# Wait until the named deployment reports `expected` running instances, each
# carrying a routable address (the shape Sozune's provider consumes).
wait_for_ring_instances() {
    local expected="$1"
    for _ in $(seq 1 60); do
        local got
        got=$(ring_api "/deployments" 2>/dev/null \
              | jq --arg n "$DEPLOYMENT_NAME" \
                   '[.[] | select(.name == $n and .status == "running")
                          | .instances[] | select(.address != null)] | length' \
                   2>/dev/null || echo 0)
        if [[ "$got" == "$expected" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Wait until Sozune routes to at least `expected` distinct backends, or fail
# after `timeout` seconds — gives the poll-based watcher time to catch up.
wait_for_distinct_backends() {
    local host="$1"
    local expected="$2"
    local timeout="${3:-30}"
    local distinct=0
    for _ in $(seq 1 "$timeout"); do
        distinct=$(count_distinct_hostnames "$host" 12)
        if [[ "$distinct" -ge "$expected" ]]; then
            echo "$distinct"
            return 0
        fi
        sleep 1
    done
    echo "$distinct"
    return 1
}
