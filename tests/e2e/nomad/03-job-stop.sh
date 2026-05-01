#!/usr/bin/env bash
# Stopping the Nomad job tears down the route in Sozune.

log "[03] nomad job stop removes the entrypoint"
wait_for_deployment_done || true
nomad job stop -purge -detach "$JOB_NAME" >/dev/null

if ! wait_for_service_instances 0; then
    fail "Nomad did not deregister all service instances after stop"
    return 0
fi

# After the services list empties, Sozune's blocking-query watcher should
# wake up, see zero instances, drop the entrypoint, and reload Sōzu.
sleep 5

status=$(probe_http "$HOST_WHOAMI")
if [[ "$status" == "404" || "$status" == "000" ]]; then
    pass "after job stop, $HOST_WHOAMI no longer routes (status=$status)"
else
    fail "expected 404/000 after job stop, got HTTP $status"
fi
