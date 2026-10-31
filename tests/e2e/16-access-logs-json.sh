#!/usr/bin/env bash
# Structured JSON logging (`log.format: json`).
#
# Validates the format→subscriber wiring end-to-end: a Sōzune process started
# with JSON logging must emit its log lines as valid JSON objects carrying the
# tracing fields (`timestamp`, `level`, `target`). This is an autonomous test —
# it starts its OWN short-lived Sōzune on dedicated ports so it never collides
# with the main suite's instance, and needs no backend.
#
# Sourced by run-all.sh. Relies on $SOZUNE_BIN and helpers from lib.sh.

log "[16] JSON logs: process started with log.format=json emits JSON lines"

JSON_CFG=$(mktemp /tmp/sozune-jsonlog-XXXXXX.yaml)
JSON_OUT=$(mktemp /tmp/sozune-jsonlog-out-XXXXXX.log)
JSON_ENTRYPOINTS=$(mktemp /tmp/sozune-jsonlog-ep-XXXXXX.yaml)

# One route through the middleware (a rate limit puts it there), so a request
# to it writes an access log line. Its backend refuses connections: the
# middleware answers 502, which is logged all the same.
cat >"$JSON_ENTRYPOINTS" <<'YAML'
entrypoints:
  - id: jsonlog
    name: jsonlog
    protocol: Http
    backends:
      - address: "127.0.0.1"
        port: 1
    config:
      hostnames:
        - "jsonlog.test"
      tls: false
      strip_prefix: false
      priority: 0
      rate_limit:
        average: 100
        burst: 100
YAML

# Dedicated ports, well clear of the main suite's (HTTP 18080 / API 18888).
cat >"$JSON_CFG" <<'YAML'
log:
  format: json
providers:
  docker:
    enabled: false
  config_file:
    enabled: true
    path: "__ENTRYPOINTS__"
    watch: false
api:
  enabled: true
  listen_address: "127.0.0.1:19888"
  users:
    - name: "admin"
      hash: "0000000000000000000000000000000000000000000000000000000000000000"
      role: admin
proxy:
  http:
    listen_address: 19080
  https:
    listen_address: 19443
middleware:
  port: 19081
dashboard:
  enabled: false
YAML
sed -i "s|__ENTRYPOINTS__|$JSON_ENTRYPOINTS|" "$JSON_CFG"

# Start it directly in the background. SOZUNE_LOG_FORMAT is left unset so we
# exercise the YAML `log.format` path specifically. Logs are captured to a
# file, so we read them after a short sleep without ever `wait`-ing on the
# process (a blocking wait on the embedded Sōzu workers can hang the suite —
# the orphan-sozune trap).
env -u RUST_LOG CONFIG_PATH="$JSON_CFG" "$SOZUNE_BIN" >"$JSON_OUT" 2>&1 &
JSON_PID=$!
# Wait for the route, then send the request the access log must record. RUST_LOG
# is left unset: the access log is on by default.
for _ in $(seq 1 20); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: jsonlog.test' http://127.0.0.1:19080/ || true)
    [[ "$code" != "404" && "$code" != "000" ]] && break
    sleep 0.5
done
sleep 1
# SIGKILL the process and any worker children it spawned. No graceful SIGTERM
# (workers linger), no wait (would block). pkill -P reaps the direct children.
pkill -9 -P "$JSON_PID" 2>/dev/null || true
kill -9 "$JSON_PID" 2>/dev/null || true
sleep 0.3

# Sōzune's own logs must all be JSON objects with the tracing fields. Note:
# the embedded Sōzu workers log through their own logger (not our tracing
# subscriber) and may emit a couple of plain-text lines at shutdown — those are
# out of our control, so we don't fail on them. What we DO require:
#   1. at least one Sōzune log line, rendered as JSON, and
#   2. no Sōzune log line leaking in the text format (`INFO sozune...`).
json_lines=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if jq -e 'has("timestamp") and has("level") and has("target") and (.target | startswith("sozune"))' \
        >/dev/null 2>&1 <<<"$line"; then
        json_lines=$((json_lines + 1))
    fi
done <"$JSON_OUT"

# A Sōzune log line in TEXT format would look like `<ts>  INFO sozune...`.
# `grep -c` returns 1 when there are no matches; under `set -e`/`pipefail` that
# would abort the suite, so guard with `|| true`.
text_leak=$(grep -cE '[0-9]Z[[:space:]]+(INFO|WARN|ERROR|DEBUG)[[:space:]]+sozune' "$JSON_OUT" 2>/dev/null || true)
text_leak=${text_leak:-0}

if (( json_lines > 0 )) && (( text_leak == 0 )); then
    pass "Sōzune logs render as JSON ($json_lines lines), none leaked as text"
else
    fail "expected JSON Sōzune logs with no text leak (json=$json_lines text_leak=$text_leak); see $JSON_OUT"
fi

log "[16] JSON logs: a known startup line is present as JSON"

# "Starting Sozune proxy" is logged at boot; in JSON its message field carries it.
if grep -F '"message"' "$JSON_OUT" 2>/dev/null | jq -e 'select(.message | test("Starting Sozune proxy"))' >/dev/null 2>&1; then
    pass "startup message present as a JSON message field"
else
    fail "could not find the startup message as JSON in $JSON_OUT"
fi

log "[16] Access log: on by default, one JSON line per request"

# Sōzu's own plain-text lines are not JSON: keep the access lines only.
if grep -F '"target":"access"' "$JSON_OUT" 2>/dev/null | jq -se 'any(.host == "jsonlog.test")' >/dev/null 2>&1; then
    pass "the request to jsonlog.test is in the access log"
else
    fail "no access log line for jsonlog.test in $JSON_OUT"
fi

rm -f "$JSON_CFG" "$JSON_OUT" "$JSON_ENTRYPOINTS"
