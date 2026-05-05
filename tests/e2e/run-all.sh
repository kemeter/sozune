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

cleanup() {
    log "Cleaning up..."
    if [[ -n "${SOZUNE_PID:-}" ]] && kill -0 "$SOZUNE_PID" 2>/dev/null; then
        kill "$SOZUNE_PID" 2>/dev/null || true
        wait "$SOZUNE_PID" 2>/dev/null || true
    fi
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    rm -f "$COMPOSE_FILE" "$CONFIG_FILE"
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
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d --wait

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
    ["$HOST_WS"]="/"
    ["$HOST_SSE"]="/.well-known/mercure?topic=ready"
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
