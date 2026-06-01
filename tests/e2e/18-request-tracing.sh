#!/usr/bin/env bash
# Distributed tracing boot (`tracing.enabled`).
#
# Autonomous test (own short-lived Sōzune on dedicated ports, no backend, no
# collector). Verifies that enabling OTLP tracing wires up cleanly:
#   - the process logs that tracing is enabled,
#   - it keeps running even though the configured collector is unreachable
#     (export errors must degrade gracefully, never crash the proxy).
#
# The W3C extract/inject round-trip is covered by unit tests in
# `src/tracing_otel.rs`; real OTLP export is demonstrated via the Tempo demo
# stack (compose.metrics.yaml), not here — the e2e suite ships no collector.
#
# Sourced by run-all.sh. Relies on $SOZUNE_BIN and helpers from lib.sh.

log "[18] Tracing: process boots with tracing.enabled and stays up"

TR_CFG=$(mktemp /tmp/sozune-trace-XXXXXX.yaml)
TR_OUT=$(mktemp /tmp/sozune-trace-out-XXXXXX.log)

# Dedicated ports (19xxx), clear of the main suite. The OTLP endpoint points at
# a closed port on purpose: export must fail silently, not bring Sōzune down.
cat >"$TR_CFG" <<'YAML'
log:
  format: json
tracing:
  enabled: true
  endpoint: "http://127.0.0.1:14317"
  service_name: "sozune-e2e"
  sampler: "always_on"
providers:
  docker:
    enabled: false
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

CONFIG_PATH="$TR_CFG" "$SOZUNE_BIN" >"$TR_OUT" 2>&1 &
TR_PID=$!
sleep 2

# Is it still alive after trying to reach an unreachable collector?
still_up=0
if kill -0 "$TR_PID" 2>/dev/null; then
    still_up=1
fi

# Kill the process and its worker children (no blocking wait — orphan trap).
pkill -9 -P "$TR_PID" 2>/dev/null || true
kill -9 "$TR_PID" 2>/dev/null || true
sleep 0.3

if [[ "$still_up" == "1" ]]; then
    pass "Sōzune stays up with tracing enabled and an unreachable collector"
else
    fail "Sōzune died on startup with tracing enabled; see $TR_OUT"
fi

log "[18] Tracing: startup log confirms tracing is enabled"

# init_tracing logs "Distributed tracing enabled, exporting OTLP to <endpoint>".
if grep -qi "tracing enabled" "$TR_OUT" 2>/dev/null; then
    pass "startup log reports tracing enabled"
else
    fail "did not find the 'tracing enabled' startup log; see $TR_OUT"
fi

rm -f "$TR_CFG" "$TR_OUT"
