#!/usr/bin/env bash
#
# Functional test orchestrator for sozune.
# Builds the binary, spins up backend containers via docker compose,
# starts sozune, then runs all suite scripts in order.
#
# Requirements: docker, curl, cargo

set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$E2E_DIR/lib.sh"

AUTHELIA_CONFIG_DIR="$(mktemp -d -t sozune-authelia-XXXXXX)"
export AUTHELIA_CONFIG_DIR

cleanup() {
    log "Cleaning up..."
    if [[ -n "${SOZUNE_PID:-}" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    rm -f "$COMPOSE_FILE" "$CONFIG_FILE"
    # Authelia runs as root inside the container, so cleanup needs the same.
    if [[ -d "$AUTHELIA_CONFIG_DIR" ]]; then
        docker run --rm -v "$AUTHELIA_CONFIG_DIR:/c" alpine:latest \
            sh -c 'rm -rf /c/* /c/.[!.]* 2>/dev/null || true' >/dev/null 2>&1 || true
        rmdir "$AUTHELIA_CONFIG_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# -- Build --
log "Building sozune..."
cargo build --quiet --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1
SOZUNE_BIN="$PROJECT_DIR/target/debug/sozune"
if [[ ! -x "$SOZUNE_BIN" ]]; then
    echo "Build failed: $SOZUNE_BIN not found"
    exit 1
fi

# Build the e2e WASM plugin guest (skipped gracefully if the wasm target or
# rustup is unavailable; the wasm suite then reports the dependency as missing).
WASM_GUEST_DIR="$E2E_DIR/plugins/header-guest"
WASM_PLUGIN_FILE="$WASM_GUEST_DIR/target/wasm32-unknown-unknown/release/header_guest.wasm"
export WASM_PLUGIN_FILE
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    log "Building e2e WASM plugin guest..."
    cargo build --quiet --release --target wasm32-unknown-unknown \
        --manifest-path "$WASM_GUEST_DIR/Cargo.toml" 2>&1 || true
fi

# -- Config files --
log "Generating test config files..."

cat > "$CONFIG_FILE" <<EOF
providers:
  docker:
    enabled: true
    expose_by_default: false
  config_file:
    enabled: false

api:
  enabled: true
  listen_address: "127.0.0.1:$API_PORT"
  users:
    - name: "$API_USER"
      hash: "$API_PASSWORD_HASH"
      role: admin

proxy:
  http:
    listen_address: $HTTP_PORT
    error_pages:
      "404": "<html><body><h1>sozune custom 404</h1></body></html>"
  https:
    listen_address: $HTTPS_PORT
  tcp:
    - name: tcpecho
      listen: $TCP_ECHO_PORT
    - name: tcprr
      listen: $TCP_RR_PORT
  max_buffers: 500
  buffer_size: 16384
  startup_delay_ms: 1000
  cluster_setup_delay_ms: 200

middleware:
  port: $MIDDLEWARE_PORT
EOF

# Declare the WASM plugin only if its guest was built, so the rest of the suite
# still runs on systems without the wasm target.
if [[ -f "$WASM_PLUGIN_FILE" ]]; then
    cat >> "$CONFIG_FILE" <<EOF

plugins:
  headerguest:
    path: $WASM_PLUGIN_FILE
EOF
fi

# -- Authelia config (mounted as a volume so $-prefixed argon2 hashes survive
#    docker-compose interpolation) --
cat > "$AUTHELIA_CONFIG_DIR/configuration.yml" <<EOF
server:
  address: "tcp://0.0.0.0:9091/"
log:
  level: warn
identity_validation:
  reset_password:
    jwt_secret: a_very_long_jwt_secret_at_least_64_characters_long_blah_blah_blah_blah
authentication_backend:
  file:
    path: /config/users.yml
access_control:
  default_policy: deny
  rules:
    - domain: $HOST_FAUTH
      policy: one_factor
session:
  cookies:
    - domain: func-test.localhost
      authelia_url: https://$HOST_AUTHELIA
      default_redirection_url: https://$HOST_FAUTH
  secret: a_very_long_session_secret_at_least_64_characters_long_blah_blah_blah_blah
  expiration: 1h
  inactivity: 5m
storage:
  encryption_key: another_very_long_encryption_key_at_least_64_characters_long_blah_blah
  local:
    path: /config/db.sqlite3
notifier:
  filesystem:
    filename: /config/notifications.txt
EOF

# argon2id hash of "alicepass". Generated once with:
#   docker run --rm authelia/authelia:latest \
#     authelia crypto hash generate argon2 --password 'alicepass'
cat > "$AUTHELIA_CONFIG_DIR/users.yml" <<'USERS_EOF'
users:
  alice:
    disabled: false
    displayname: "Alice"
    password: "$argon2id$v=19$m=65536,t=3,p=4$1Jn+sBXzxE3Rm+uYmtWTVg$mvYLvk5lHWYCBKRh5eXjQ2QSOM5EoImMtzKD7U4ixmc"
    email: alice@func-test.localhost
    groups:
      - admins
USERS_EOF

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
      - "sozune.http.svcauth.auth.basic=admin:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-headers:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcheaders.host=$HOST_HEADERS"
      - "sozune.http.svcheaders.headers.X-Custom-Test=hello-sozune"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-wasm:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcwasm.host=$HOST_WASM"
      - "sozune.http.svcwasm.plugins=headerguest"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-headers-response:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcheadresp.host=$HOST_HEADERS_RESPONSE"
      - "sozune.http.svcheadresp.headers.response.X-Powered-By=sozune"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-headers-both:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcheadboth.host=$HOST_HEADERS_BOTH"
      - "sozune.http.svcheadboth.headers.both.X-Trace=tracevalue"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-headers-delete:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcheaddel.host=$HOST_HEADERS_DELETE"
      - "sozune.http.svcheaddel.headers.User-Agent="
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-strip:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcstrip.host=$HOST_STRIP"
      - "sozune.http.svcstrip.path=/api"
      - "sozune.http.svcstrip.stripPrefix=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-add-prefix:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcaddprefix.host=$HOST_ADD_PREFIX"
      - "sozune.http.svcaddprefix.addPrefix=/foo"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-redirect:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcredirect.host=$HOST_REDIRECT"
      - "sozune.http.svcredirect.httpsRedirect=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-ratelimit:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcratelimit.host=$HOST_RATELIMIT"
      - "sozune.http.svcratelimit.ratelimit.average=5"
      - "sozune.http.svcratelimit.ratelimit.burst=3"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-compress:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svccompress.host=$HOST_COMPRESS"
      - "sozune.http.svccompress.compress=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-timeout:
    image: kennethreitz/httpbin
    labels:
      - "sozune.enable=true"
      - "sozune.http.svctimeout.host=$HOST_TIMEOUT"
      - "sozune.http.svctimeout.backendTimeout=2"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-regex:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcregex.host=$HOST_REGEX"
      - "sozune.http.svcregex.pathRegex=/users/[0-9]+"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-mixed:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcmixed.host=$HOST_MIXED_SUFFIX,*.$HOST_MIXED_SUFFIX"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-hostregex:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svchostregex.host=/cdn[0-9]+/.$HOST_HOSTREGEX_SUFFIX"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-ws:
    image: jmalloc/echo-server
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcws.host=$HOST_WS"
      - "sozune.http.svcws.port=8080"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-sse:
    image: dunglas/mercure:v0.16
    environment:
      SERVER_NAME: ":80"
      MERCURE_PUBLISHER_JWT_KEY: "!ChangeThisMercureHubJWTSecretKey!"
      MERCURE_SUBSCRIBER_JWT_KEY: "!ChangeThisMercureHubJWTSecretKey!"
      MERCURE_EXTRA_DIRECTIVES: |
        cors_origins *
        anonymous
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcsse.host=$HOST_SSE"
      - "sozune.http.svcsse.port=80"
      - "sozune.http.svcsse.backendTimeout=0"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  authelia:
    image: authelia/authelia:latest
    # Map 9091 onto the host so sozune (running on the host, not inside the
    # compose network) can reach Authelia's verify endpoint directly.
    ports:
      - "127.0.0.1:9091:9091"
    volumes:
      - "$AUTHELIA_CONFIG_DIR:/config"
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcauthelia.host=$HOST_AUTHELIA"
      - "sozune.http.svcauthelia.port=9091"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-errorpages:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcerrorpages.host=$HOST_ERRORPAGES"
      - "sozune.http.svcerrorpages.errorPages.503=<html>cluster maintenance</html>"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-match:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcmatch.host=$HOST_MATCH"
      - "sozune.http.svcmatch.matchHeaders=X-Env:prod"
      - "sozune.http.svcmatch.matchQuery=version:2"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-ipallow:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcipallow.host=$HOST_IPALLOW"
      - "sozune.http.svcipallow.ipAllowList=127.0.0.1,10.0.0.0/8"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-ipallow-deny:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcipallowdeny.host=$HOST_IPALLOW_DENY"
      - "sozune.http.svcipallowdeny.ipAllowList=203.0.113.0/24"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-clientip:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcclientip.host=$HOST_CLIENTIP"
      - "sozune.http.svcclientip.matchClientIP=127.0.0.1,::1"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-clientip-deny:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcclientipdeny.host=$HOST_CLIENTIP_DENY"
      - "sozune.http.svcclientipdeny.matchClientIP=10.0.0.0/8"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-lb:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svclb.host=$HOST_LB"
      - "sozune.http.svclb.loadBalancer=least_connections"
  svc-retry:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcretry.host=$HOST_RETRY"
      - "sozune.http.svcretry.retry.attempts=3"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-fauth:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.svcfauth.host=$HOST_FAUTH"
      - "sozune.http.svcfauth.forwardAuth.address=http://127.0.0.1:9091/api/verify?rd=https://$HOST_AUTHELIA"
      - "sozune.http.svcfauth.forwardAuth.responseHeaders=Remote-User,Remote-Groups,Remote-Name,Remote-Email"
      - "sozune.http.svcfauth.forwardAuth.trustForwardHeader=true"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-tcpecho:
    image: alpine/socat
    command: ["TCP-LISTEN:9000,fork,reuseaddr", "EXEC:cat"]
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.tcpecho.entrypoint=tcpecho"
      - "sozune.tcp.tcpecho.port=9000"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-tcprr-a:
    image: alpine/socat
    command: ["TCP-LISTEN:9000,fork,reuseaddr", "SYSTEM:'echo backend-a'"]
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.tcprr.entrypoint=tcprr"
      - "sozune.tcp.tcprr.port=9000"
      - "sozune.network=${COMPOSE_PROJECT}_default"

  svc-tcprr-b:
    image: alpine/socat
    command: ["TCP-LISTEN:9000,fork,reuseaddr", "SYSTEM:'echo backend-b'"]
    labels:
      - "sozune.enable=true"
      - "sozune.tcp.tcprr.entrypoint=tcprr"
      - "sozune.tcp.tcprr.port=9000"
      - "sozune.network=${COMPOSE_PROJECT}_default"
EOF

# -- Start backends --
log "Starting test containers..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90

# -- Start sozune --
log "Starting sozune (HTTP on :$HTTP_PORT, HTTPS on :$HTTPS_PORT)..."
CONFIG_PATH="$CONFIG_FILE" RUST_LOG=sozune=debug "$SOZUNE_BIN" &
SOZUNE_PID=$!
sleep "$STARTUP_DELAY"

if ! kill -0 "$SOZUNE_PID" 2>/dev/null; then
    fail "sozune process died on startup"
    exit 1
fi

log "Waiting for routes to propagate..."
# When the suite starts, Sozune is still emitting reload events triggered
# by individual Docker container `start` events. A naïve sleep, or even
# a per-host wait that returns as soon as the FIRST host responds, races
# against in-flight reloads — a route that was 200 a moment ago may be
# briefly 404 again as Sozune re-applies a cluster.
#
# We require every test host to respond non-404 SIMULTANEOUSLY in the
# same poll cycle. Any 404 restarts the cycle, capped at ~30s total.
declare -A WAIT_PATHS=(
    ["$HOST_A"]="/"
    ["$HOST_B"]="/"
    ["$HOST_AUTH"]="/"
    ["$HOST_HEADERS"]="/"
    ["$HOST_HEADERS_RESPONSE"]="/"
    ["$HOST_HEADERS_BOTH"]="/"
    ["$HOST_HEADERS_DELETE"]="/"
    ["$HOST_STRIP"]="/api"
    ["$HOST_ADD_PREFIX"]="/"
    ["$HOST_REDIRECT"]="/"
    ["$HOST_RATELIMIT"]="/"
    ["$HOST_COMPRESS"]="/"
    ["$HOST_TIMEOUT"]="/"
    ["$HOST_REGEX"]="/users/0"
    ["$HOST_ERRORPAGES"]="/"
    ["$HOST_WS"]="/"
    ["$HOST_SSE"]="/.well-known/mercure?topic=ready"
    ["$HOST_IPALLOW"]="/"
    ["$HOST_CLIENTIP"]="/"
    ["$HOST_LB"]="/"
    ["$HOST_RETRY"]="/"
)
ready=0
for _ in $(seq 1 60); do
    all_ok=1
    for host in "${!WAIT_PATHS[@]}"; do
        path="${WAIT_PATHS[$host]}"
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
            -H "Host: $host" "http://127.0.0.1:$HTTP_PORT$path" 2>/dev/null || echo "000")
        if [[ "$status" == "404" ]] || [[ "$status" == "000" ]]; then
            all_ok=0
            break
        fi
    done
    if [[ "$all_ok" == "1" ]]; then
        ready=1
        break
    fi
    sleep 0.5
done
if [[ "$ready" != "1" ]]; then
    fail "not all routes reached non-404 within 30s — Sozune did not finish reloading"
    exit 1
fi

# -- Run suites --
for suite in "$E2E_DIR"/[0-9][0-9]-*.sh; do
    echo ""
    source "$suite"
done

# -- Summary --
echo ""
echo "=============================="
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"
echo "=============================="

# Extended suites with heavier prerequisites (separate orchestrators).
# Not run by default — list them so a contributor knows they exist.
echo ""
echo "Extended suites (run separately, require extra setup):"
echo "  - bash tests/e2e/swarm/run-swarm.sh           (needs: docker swarm init)"
echo "  - bash tests/e2e/swarm-multinode/run-multinode.sh  (needs: multi-node swarm)"
echo "  - bash tests/e2e/nomad/run-nomad.sh           (needs: nomad agent + docker driver)"
echo "  - bash tests/e2e/k8s/run-k8s.sh               (needs: kind + kubectl)"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
