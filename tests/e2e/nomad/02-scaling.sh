#!/usr/bin/env bash
# Nomad scaling: scale the job up and down, verify Sozune picks up the
# allocation changes through the blocking-query watcher.

log "[02] Wait for initial deployment to settle before scaling"
if ! wait_for_deployment_done; then
    fail "Initial deployment never reached a stable state — skipping scale tests"
    return 0
fi

log "[02] Scale to 5 — backend list grows"
nomad job scale -detach "$JOB_NAME" web 5 >/dev/null

if ! wait_for_service_instances 5; then
    fail "Nomad did not converge to 5 service instances in time"
    return 0
fi

distinct=$(wait_for_distinct_backends "$HOST_WHOAMI" 5 30 || true)
if [[ "$distinct" -ge 5 ]]; then
    pass "after scale to 5, $distinct distinct allocations served traffic"
else
    fail "expected >=5 backends after scale-up, got $distinct"
fi

log "[02] Scale to 1 — backend list shrinks"
wait_for_deployment_done || true
nomad job scale -detach "$JOB_NAME" web 1 >/dev/null

if ! wait_for_service_instances 1; then
    fail "Nomad did not converge to 1 service instance in time"
    return 0
fi
# Sozune's blocking-query watcher wakes up on the services-list change but
# allocations may take a few seconds to actually drain.
sleep 5

distinct=$(count_distinct_hostnames "$HOST_WHOAMI" 12)
if [[ "$distinct" -le 1 ]]; then
    pass "after scale to 1, only $distinct distinct backend(s) served traffic"
else
    fail "expected <=1 backend after scale-down, got $distinct (stale allocations?)"
fi
