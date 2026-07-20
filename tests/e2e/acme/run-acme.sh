#!/usr/bin/env bash
#
# ACME e2e harness. Boots Pebble (Let's Encrypt's test CA), a backend, and
# Sōzune in one Docker network, then asserts Sōzune completes a real HTTP-01
# challenge and serves the Pebble-issued certificate.
#
# Hermetic: no public ACME, no host port 80. Not run by run-all.sh (needs
# Docker + a network pull); invoke directly.
#
# Requirements: docker (compose v2), openssl, curl

set -euo pipefail

ACME_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -p sozune-acme -f $ACME_DIR/compose.acme.yaml"

PASSED=0
FAILED=0
pass() { echo -e "\033[0;32m[PASS]\033[0m $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "\033[0;31m[FAIL]\033[0m $*"; FAILED=$((FAILED + 1)); }
log()  { echo -e "\033[1;33m[ACME]\033[0m $*"; }

cleanup() {
    log "Cleaning up..."
    $COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true
    rm -f "$ACME_DIR/pebble-ca.pem"
}
trap cleanup EXIT

# The CA file is a bind mount. If it doesn't exist when any `up` runs, Docker
# creates a *directory* in its place, which then breaks every later run. Touch
# it up front so the mount is always a file, and start from a clean slate.
$COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true
rm -rf "$ACME_DIR/pebble-ca.pem"
: > "$ACME_DIR/pebble-ca.pem"

# --- Pebble's test CA -----------------------------------------------------
# Sōzune must trust the root that signs Pebble's *ACME directory* endpoint,
# which is minica (`CN=localhost` issued by `minica root ca`) — NOT the ACME
# issuance root served at /roots/0, a different chain entirely. minica mints a
# fresh root per image build, so extract it from the image rather than
# committing a stale copy.
log "Extracting Pebble's minica root..."
cid=$(docker create ghcr.io/letsencrypt/pebble:latest 2>/dev/null)
if ! docker cp "$cid:/test/certs/pebble.minica.pem" "$ACME_DIR/pebble-ca.pem" 2>/dev/null; then
    docker rm "$cid" >/dev/null 2>&1 || true
    fail "could not extract minica root from the Pebble image"
    exit 1
fi
docker rm "$cid" >/dev/null 2>&1 || true
pass "minica root extracted"

# --- Pebble, then gate Sōzune on it ---------------------------------------
# Sōzune runs its ACME check seconds after boot and only retries every 12h, so
# it must not start before Pebble's directory answers.
log "Starting Pebble + backend..."
$COMPOSE up -d pebble backend >/dev/null 2>&1

# The directory itself must answer before Sōzune's ACME manager fires.
for _ in $(seq 1 30); do
    if docker run --rm --network sozune-acme_default curlimages/curl:latest \
        -sk --max-time 3 https://pebble:14000/dir 2>/dev/null | grep -q newOrder; then
        break
    fi
    sleep 1
done

# --- Now Sōzune, with the CA in place -------------------------------------
log "Building and starting Sōzune..."
$COMPOSE up -d --build sozune >/dev/null 2>&1

# --- Wait for the certificate ---------------------------------------------
# Provisioning races container startup; poll the API until the cert for
# acme.test appears, or give up.
log "Waiting for Sōzune to provision the certificate via Pebble..."
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
    pass "certificate for acme.test provisioned through HTTP-01"
else
    fail "no certificate for acme.test after 120s"
    echo "--- last API response ---"; echo "$certs"
    echo "--- sozune logs (tail) ---"
    $COMPOSE logs --tail=40 sozune 2>/dev/null || true
fi

# --- The cert is actually served on 443, and it's Pebble's ----------------
if [[ $issued -eq 1 ]]; then
    log "Checking the served certificate..."
    served=$(timeout 5 openssl s_client -connect 127.0.0.1:18443 \
        -servername acme.test </dev/null 2>/dev/null |
        openssl x509 -noout -issuer 2>/dev/null || true)
    if [[ "$served" == *"Pebble"* || "$served" == *"minica"* ]]; then
        pass "acme.test serves the Pebble-issued certificate on 443"
    else
        fail "unexpected issuer on the served cert (got: '$served')"
    fi
fi

echo ""
echo "=============================="
echo -e "  \033[0;32mPassed: $PASSED\033[0m  \033[0;31mFailed: $FAILED\033[0m"
echo "=============================="
[[ $FAILED -eq 0 ]]
