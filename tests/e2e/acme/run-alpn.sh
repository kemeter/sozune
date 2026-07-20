#!/usr/bin/env bash
#
# TLS-ALPN-01 e2e harness. Same setup as run-acme.sh, but Sōzune uses a
# tls-alpn-01 resolver: declaring it flips the HTTPS listener into the
# ALPN-aware gate on 443, and Pebble validates the challenge over the TLS
# handshake (ALPN acme-tls/1) instead of an HTTP request. Proves the gate
# routes acme-tls/1 to the responder AND keeps normal HTTPS working.
#
# Hermetic: no public ACME. Not run by run-all.sh; invoke directly.
#
# Requirements: docker (compose v2), openssl, curl

set -euo pipefail

ACME_DIR="$(cd "$(dirname "$0")" && pwd)"
export SOZUNE_CONFIG="config.alpn.yaml"
COMPOSE="docker compose -p sozune-alpn -f $ACME_DIR/compose.acme.yaml"

PASSED=0
FAILED=0
pass() { echo -e "\033[0;32m[PASS]\033[0m $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "\033[0;31m[FAIL]\033[0m $*"; FAILED=$((FAILED + 1)); }
log()  { echo -e "\033[1;33m[ALPN]\033[0m $*"; }

cleanup() {
    log "Cleaning up..."
    $COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true
    rm -f "$ACME_DIR/pebble-ca.pem"
}
trap cleanup EXIT

$COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true
rm -rf "$ACME_DIR/pebble-ca.pem"
: > "$ACME_DIR/pebble-ca.pem"

# --- Pebble's minica root (signs the directory endpoint) ------------------
log "Extracting Pebble's minica root..."
cid=$(docker create ghcr.io/letsencrypt/pebble:latest 2>/dev/null)
if ! docker cp "$cid:/test/certs/pebble.minica.pem" "$ACME_DIR/pebble-ca.pem" 2>/dev/null; then
    docker rm "$cid" >/dev/null 2>&1 || true
    fail "could not extract minica root from the Pebble image"
    exit 1
fi
docker rm "$cid" >/dev/null 2>&1 || true
pass "minica root extracted"

log "Starting Pebble + backend..."
$COMPOSE up -d pebble backend >/dev/null 2>&1
for _ in $(seq 1 30); do
    if docker run --rm --network sozune-alpn_default curlimages/curl:latest \
        -sk --max-time 3 https://pebble:14000/dir 2>/dev/null | grep -q newOrder; then
        break
    fi
    sleep 1
done

log "Building and starting Sōzune (TLS-ALPN-01 gate on 443)..."
$COMPOSE up -d --build sozune >/dev/null 2>&1

# --- Wait for the certificate ---------------------------------------------
# Pebble validates by connecting to acme.test:443 with ALPN acme-tls/1; the
# gate must route that to the responder, which presents cheti's challenge cert.
log "Waiting for Sōzune to provision the certificate via TLS-ALPN-01..."
issued=0
for _ in $(seq 1 60); do
    certs=$(curl -s -u admin:admin --max-time 3 \
        http://127.0.0.1:18081/certificates 2>/dev/null || true)
    if [[ "$certs" == *"acme.test"* ]]; then
        issued=1
        break
    fi
    sleep 2
done

if [[ $issued -eq 1 ]]; then
    pass "certificate for acme.test provisioned through TLS-ALPN-01"
else
    fail "no certificate for acme.test after 120s"
    echo "--- last API response ---"; echo "$certs"
    echo "--- sozune logs (tail) ---"
    $COMPOSE logs --tail=50 sozune 2>/dev/null || true
fi

# --- Normal HTTPS still works through the gate ----------------------------
# The whole point of the gate: acme-tls/1 goes to the responder, but ordinary
# HTTPS (no acme-tls/1 in ALPN) must still reach the HTTPS worker and serve the
# real, Pebble-issued certificate.
if [[ $issued -eq 1 ]]; then
    log "Checking normal HTTPS still serves the issued cert through the gate..."
    served=$(timeout 5 openssl s_client -connect 127.0.0.1:18443 \
        -servername acme.test -alpn h2,http/1.1 </dev/null 2>/dev/null |
        openssl x509 -noout -issuer 2>/dev/null || true)
    if [[ "$served" == *"Pebble"* || "$served" == *"minica"* ]]; then
        pass "normal HTTPS reaches the worker and serves the issued cert"
    else
        fail "normal HTTPS did not serve the expected cert (got: '$served')"
    fi

    # And a real HTTP request over that TLS reaches the backend.
    log "Checking a request flows end-to-end through the gate..."
    body=$(curl -sk --max-time 5 --resolve acme.test:18443:127.0.0.1 \
        https://acme.test:18443/ 2>/dev/null || true)
    if [[ -n "$body" ]]; then
        pass "an HTTPS request reaches the backend through the gate"
    else
        fail "no response body from an HTTPS request through the gate"
    fi
fi

echo ""
echo "=============================="
echo -e "  \033[0;32mPassed: $PASSED\033[0m  \033[0;31mFailed: $FAILED\033[0m"
echo "=============================="
[[ $FAILED -eq 0 ]]
