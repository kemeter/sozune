#!/usr/bin/env bash
# gRPC health checks (healthCheck.mode=grpc): svc-etcd answers SERVING on
# grpc.health.v1.Health/Check, svc-grpc (grpcbin) has no health service and
# answers UNIMPLEMENTED. Sourced by run-all.sh.

log "[42] gRPC health checks: the probe calls grpc.health.v1.Health/Check"

# The reasons the API gives for the unhealthy backends of the route
# serving $1, one per line; "none" when it has none.
unhealthy_reasons() {
    curl -s --max-time 2 -H "Authorization: Basic $API_BASIC_AUTH" \
        "http://127.0.0.1:$API_PORT/entrypoints" 2>/dev/null \
        | python3 -c '
import json, sys
host = sys.argv[1]
data = json.load(sys.stdin)
routes = data if isinstance(data, list) else data.get("member", data.get("entrypoints", []))
for route in routes:
    if host in route.get("config", {}).get("hostnames", []):
        reasons = [b.get("message", "") for b in route.get("unhealthy_backends", [])]
        print("\n".join(reasons) if reasons else "none")
        break
' "$1" 2>/dev/null || true
}

# Probes run every second. Once the server without a health service is
# reported, etcd has been probed too.
reasons=""
for _ in $(seq 1 30); do
    reasons=$(unhealthy_reasons "$HOST_GRPC_HC_NONE")
    [[ "$reasons" == *UNIMPLEMENTED* ]] && break
    sleep 1
done
if [[ "$reasons" == *"UNIMPLEMENTED"*"no gRPC health service"* ]]; then
    pass "a server without the gRPC health service is unhealthy (UNIMPLEMENTED)"
else
    fail "the server without a health service reports '$reasons', expected UNIMPLEMENTED"
fi

reasons=$(unhealthy_reasons "$HOST_GRPC_HC")
if [[ "$reasons" == "none" ]]; then
    pass "a server answering SERVING is healthy"
else
    fail "the SERVING server reports '$reasons', expected none"
fi
