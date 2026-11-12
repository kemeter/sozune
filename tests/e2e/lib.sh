#!/usr/bin/env bash
# Shared helpers for sozune e2e suites.
# Sourced by run-all.sh; not meant to be run standalone.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_PROJECT="sozune-functest"
COMPOSE_FILE="$PROJECT_DIR/compose.func-test.yaml"
CONFIG_FILE="$PROJECT_DIR/config.func-test.yaml"

HTTP_PORT="${E2E_HTTP_PORT:-18080}"
HTTPS_PORT="${E2E_HTTPS_PORT:-18443}"
API_PORT="${E2E_API_PORT:-18888}"
MIDDLEWARE_PORT=13037
TCP_ECHO_PORT=15555
TCP_RR_PORT=15556
UDP_ECHO_PORT=15557
TCP_ALLOW_PORT=15558
TCP_DENY_PORT=15559
TCP_FLOOD_PORT=15560
TCP_SNI_PORT=15561
TCP_SHARED_PORT=15562
# Host side of the pages server the backend error pages are fetched from.
ERROR_PAGES_HOST_PORT=15563
# Host side of Authelia's port mapping, where sozune reaches the verify
# endpoint. Overridable when something else on the host already holds 9091.
AUTHELIA_HOST_PORT="${AUTHELIA_HOST_PORT:-9091}"
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
HOST_ADD_PREFIX="add-prefix.func-test.localhost"
HOST_REDIRECT="redirect.func-test.localhost"
HOST_RATELIMIT="ratelimit.func-test.localhost"
HOST_INFLIGHT="inflight.func-test.localhost"
HOST_COMPRESS="compress.func-test.localhost"
HOST_CLOSE="close.func-test.localhost"
HOST_TIMEOUT="timeout.func-test.localhost"
HOST_REGEX="regex.func-test.localhost"
HOST_MIXED_SUFFIX="mixed-test.localhost"
HOST_HOSTREGEX_SUFFIX="hostregex-test.localhost"
HOST_TLS="tls.func-test.localhost"
HOST_WS="ws.func-test.localhost"
HOST_SSE="sse.func-test.localhost"
HOST_SSE_GZ="sse-gz.func-test.localhost"
HOST_FAUTH="fauth.func-test.localhost"
HOST_WASM="wasm.func-test.localhost"
HOST_AUTHELIA="authelia.func-test.localhost"
HOST_UNKNOWN_404="nope.func-test.localhost"
HOST_ERRORPAGES="errorpages.func-test.localhost"
HOST_BACKEND_ERRORS="backenderrors.func-test.localhost"
HOST_BACKEND_ERRORS_URL="backenderrors-url.func-test.localhost"
HOST_H2C="h2c.func-test.localhost"
HOST_H2C_MW="h2c-mw.func-test.localhost"
HOST_H2C_CHECK="h2c-check.func-test.localhost"
HOST_H2C_CHECK_HTTP1="h2c-check-http1.func-test.localhost"
HOST_GRPC="grpc.func-test.localhost"
HOST_GRPC_HC="grpc-hc.func-test.localhost"
HOST_GRPC_HC_NONE="grpc-hc-none.func-test.localhost"
HOST_GRPC_RETRY="grpc-retry.func-test.localhost"
HOST_GRPC_WASM="grpc-wasm.func-test.localhost"
HOST_GRPC_DOWN="grpc-down.func-test.localhost"
HOST_GRPC_LIMITED="grpc-limited.func-test.localhost"
HOST_GRPC_WEB="grpc-web.func-test.localhost"
HOST_GRPC_WEB_DOWN="grpc-web-down.func-test.localhost"
HOST_CORS="cors.func-test.localhost"
HOST_CORS_TRAEFIK="cors-traefik.func-test.localhost"
HOST_BUFFER_REQ="buffer-req.func-test.localhost"
HOST_BUFFER_RESP="buffer-resp.func-test.localhost"
HOST_SERVICE_WEIGHT="service-weight.func-test.localhost"
HOST_MATCH="match.func-test.localhost"
HOST_CANARY="canary.func-test.localhost"
HOST_MATCH_REGEX="matchregex.func-test.localhost"
HOST_QUERY_REGEX="queryregex.func-test.localhost"
HOST_MIRROR="mirror.func-test.localhost"
HOST_IPALLOW="ipallow.func-test.localhost"
HOST_IPALLOW_DENY="ipallow-deny.func-test.localhost"
HOST_CLIENTIP="clientip.func-test.localhost"
HOST_CLIENTIP_DENY="clientip-deny.func-test.localhost"
HOST_LB="lb.func-test.localhost"
HOST_WEIGHT="weight.func-test.localhost"
HOST_WEIGHT_MW="weightmw.func-test.localhost"
HOST_BACKUP="backup.func-test.localhost"
HOST_FAILOVER="failover.func-test.localhost"
HOST_FAILOVER_MW="failovermw.func-test.localhost"
HOST_RETRY="retry.func-test.localhost"
HOST_CB="cb.func-test.localhost"

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

# Open a TLS connection announcing `servername` and capture what the backend
# sends back. Used for SNI passthrough: Sōzune never terminates TLS here, so the
# handshake is with the backend and its self-signed cert — hence no verification.
# Prints the backend's plaintext banner, or nothing if the connection was
# refused (which is itself the expected outcome for an unmatched SNI).
tls_sni_probe() {
    local host="$1" port="$2" servername="$3"
    # `-quiet` keeps the handshake chatter on stderr, so stdout carries only
    # what the backend wrote. The self-signed warning is expected and ignored.
    timeout 5 openssl s_client -connect "$host:$port" -servername "$servername" \
        -quiet -verify_quiet </dev/null 2>/dev/null || true
}

# The certificate subject the server at host:port presents for servername,
# tried until it names `expected` or the attempts run out: the backend may
# still be starting.
tls_subject_until() {
    local host="$1" port="$2" servername="$3" expected="$4" subject=""
    for _ in $(seq 1 30); do
        subject=$(timeout 5 openssl s_client -connect "$host:$port" \
            -servername "$servername" -verify_quiet </dev/null 2>/dev/null |
            grep -m1 "subject=" || true)
        [[ "$subject" == *"$expected"* ]] && break
        sleep 1
    done
    printf '%s' "$subject"
}

# Send a UDP datagram and capture the reply. `nc -u -w 2` waits up to 2s for the
# backend's echo to come back through Sōzune's UDP flow before closing.
udp_send() {
    local host="$1" port="$2" payload="$3"
    printf '%s' "$payload" | timeout 5 nc -u -w 2 "$host" "$port" 2>/dev/null || true
}

wait_for_not_404() {
    local url="$1" host="$2"
    local i=0
    while [[ $i -lt $MAX_RETRIES ]]; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "Host: $host" "$url" 2>/dev/null || echo "000")
        if [[ "$status" != "404" ]]; then
            echo "$status"
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "404"
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
