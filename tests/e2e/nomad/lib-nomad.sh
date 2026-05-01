#!/usr/bin/env bash
# Shared helpers for the Nomad e2e suite. Sourced by run-nomad.sh.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NOMAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NOMAD_ADDR="${NOMAD_ADDR:-http://127.0.0.1:4646}"
NOMAD_DATA_DIR="${NOMAD_DATA_DIR:-$(mktemp -d -t sozune-nomad-XXXXXX)}"
NOMAD_LOG="$NOMAD_DATA_DIR/agent.log"
NOMAD_PID_FILE="$NOMAD_DATA_DIR/agent.pid"

JOB_NAME="sozune-e2e-whoami"
SERVICE_NAME="whoami"

HTTP_PORT=18180
HTTPS_PORT=18443
API_PORT=18389
MIDDLEWARE_PORT=13139

CONFIG_FILE="$(mktemp -t sozune-nomad-config.XXXXXX.yaml)"
SOZUNE_LOG="$NOMAD_DATA_DIR/sozune.log"
SOZUNE_PID=""

HOST_WHOAMI="whoami.nomad-test.localhost"

STARTUP_DELAY=2
ROUTE_DELAY=4

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

log()  { echo -e "${YELLOW}[NOMAD]${NC} $*"; }
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

wait_for_nomad() {
    for _ in $(seq 1 30); do
        if curl -sf "$NOMAD_ADDR/v1/status/leader" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_service_instances() {
    local expected="$1"
    for _ in $(seq 1 60); do
        local got
        got=$(curl -sf "$NOMAD_ADDR/v1/service/$SERVICE_NAME" 2>/dev/null \
              | jq 'length' 2>/dev/null || echo 0)
        if [[ "$got" == "$expected" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Wait until Sozune routes to at least `expected` distinct backends, or fail
# after `timeout` seconds. Useful right after a scale event when the routing
# table needs a moment to propagate.
wait_for_distinct_backends() {
    local host="$1"
    local expected="$2"
    local timeout="${3:-30}"
    for _ in $(seq 1 "$timeout"); do
        local distinct
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

# Block until the most recent deployment for $JOB_NAME reaches a stable state
# ("successful" or "complete"). Required before issuing scale operations —
# Nomad rejects them with 400 while a deployment is still in flight.
wait_for_deployment_done() {
    for _ in $(seq 1 60); do
        local status
        status=$(nomad job status "$JOB_NAME" 2>/dev/null \
                 | awk '/Latest Deployment/{flag=1; next} flag && /Status/{print $3; exit}')
        case "$status" in
            successful|complete) return 0 ;;
            failed|cancelled)    return 1 ;;
        esac
        sleep 1
    done
    return 1
}
