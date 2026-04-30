#!/usr/bin/env bash
# Shared helpers for the Swarm e2e suite.
# Sourced by run-swarm.sh; not meant to be run standalone.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SWARM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STACK_NAME="sozune-swarm-test"
OVERLAY_NETWORK="sozune-swarm-test"
COMPOSE_FILE="$SWARM_DIR/compose.swarm.yaml"
SOZUNE_CONTAINER="sozune-swarm-runner"
# Pick an image whose glibc is >= the one used to build the host binary.
# ubuntu:rolling tracks the latest Ubuntu and matches typical dev hosts.
SOZUNE_IMAGE="ubuntu:rolling"

CONFIG_FILE="$SWARM_DIR/config.swarm.yaml"

HTTP_PORT=18090
HTTPS_PORT=18493
API_PORT=18898
MIDDLEWARE_PORT=13047

API_USER="admin"
API_PASSWORD="swarm-test-secret"
API_PASSWORD_HASH=$(printf '%s' "$API_PASSWORD" | sha256sum | cut -d' ' -f1)
API_BASIC_AUTH=$(printf '%s:%s' "$API_USER" "$API_PASSWORD" | base64 -w0)

HOST_A="svca.swarm-test.localhost"
HOST_B="svcb.swarm-test.localhost"

STARTUP_DELAY=4
ROUTE_DELAY=8
MAX_RETRIES=40

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
SWARM_INITIALIZED_BY_US=0

log()  { echo -e "${YELLOW}[SWARM]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED + 1)); }

is_swarm_active() {
    local state
    state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo "inactive")
    [[ "$state" == "active" ]]
}

ensure_swarm() {
    if is_swarm_active; then
        log "Swarm already active on this daemon, reusing it"
        SWARM_INITIALIZED_BY_US=0
    else
        log "Initializing Swarm (single-node)..."
        docker swarm init --advertise-addr 127.0.0.1 >/dev/null
        SWARM_INITIALIZED_BY_US=1
    fi
}

leave_swarm_if_ours() {
    if [[ "$SWARM_INITIALIZED_BY_US" == "1" ]]; then
        log "Leaving the Swarm we created..."
        docker swarm leave --force >/dev/null 2>&1 || true
    fi
}

# Wait for every replica of every service in the stack to reach Running state.
wait_for_stack_ready() {
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        local pending
        pending=$(docker stack services "$STACK_NAME" --format '{{.Replicas}}' 2>/dev/null \
                  | awk -F'/' '$1 != $2 { print }' | wc -l)
        if [[ "$pending" == "0" ]]; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# Wait for an HTTP route through the sozune container to reach `expected` status.
wait_for_status() {
    local url="$1" host="$2" expected="$3"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
                  -H "Host: $host" "$url" 2>/dev/null || echo "000")
        if [[ "$status" == "$expected" ]]; then
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
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
                  -H "Host: $host" "$url" 2>/dev/null || echo "000")
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
