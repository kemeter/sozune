#!/usr/bin/env bash
# Nomad scaling: scale the job up and down, verify Sozune picks up the
# allocation changes through the blocking-query watcher.

log "[02] Wait for initial deployment to settle before scaling"
if ! wait_for_deployment_done; then
    fail "Initial deployment never reached a stable state — skipping scale tests"
    return 0
fi

log "[02] Scale to 5 — Nomad converges, Sozune stays routable"
nomad job scale -detach "$JOB_NAME" web 5 >/dev/null

if ! wait_for_service_instances 5; then
    fail "Nomad did not converge to 5 service instances in time"
    return 0
fi
# Service stays reachable through the whole scale-up. We don't assert
# distinct backends here (see -dev mode caveat in 01-discovery.sh).
if wait_for_status "$HOST_WHOAMI" "200"; then
    pass "after scale to 5, service still routable"
else
    fail "service became unroutable during scale-up"
fi

log "[02] Scale to 1 — Sozune sees the smaller pool"
wait_for_deployment_done || true
nomad job scale -detach "$JOB_NAME" web 1 >/dev/null

if ! wait_for_service_instances 1; then
    fail "Nomad did not converge to 1 service instance in time"
    return 0
fi
# Sozune needs a beat after Nomad converges; the blocking-query watcher
# wakes up on the services-list change but allocations may take a few seconds
# to actually drain.
sleep 5

if wait_for_status "$HOST_WHOAMI" "200"; then
    pass "after scale to 1, single backend still routable"
else
    fail "service unroutable after scale-down"
fi
