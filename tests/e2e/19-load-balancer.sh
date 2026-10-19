#!/usr/bin/env bash
# Load-balancing algorithm selection (`loadBalancer` label) and backend weights.
#
# `svc-lb` is registered with `loadBalancer=least_connections`. The observable,
# deterministic contract here is that Sōzu *accepts* the algorithm and the
# route is served — an unsupported/garbled algorithm would fail cluster
# registration and the route would not answer 200. (The fallback-on-invalid
# behaviour is covered by unit tests.)
#
# Sourced by run-all.sh.

log "[19] Load balancer: route with least_connections is served"

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_LB" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "least_connections route is served (Sōzu accepted the algorithm)"
else
    fail "least_connections route returned $status, expected 200"
fi

# Names of the whoami containers serving 8 requests in a row, one per line.
served_by() {
    local host="$1"
    for _ in 1 2 3 4 5 6 7 8; do
        curl -s --max-time 2 -H "Host: $host" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null \
            | awk '/^Name:/ {print $2}'
    done
}

# Weighted round robin is exact: any 8 picks in a row over weights 3 and 1
# hold 6 of the first and 2 of the second.
for host in "$HOST_WEIGHT" "$HOST_WEIGHT_MW"; do
    log "[19] Load balancer: weights split the traffic ($host)"
    wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$host" "200" || true
    names=$(served_by "$host")
    heavy=$(grep -c 'heavy$' <<<"$names" || true)
    light=$(grep -c 'light$' <<<"$names" || true)
    if [[ "$heavy" == "6" && "$light" == "2" ]]; then
        pass "weights 3 and 1 serve 6 and 2 requests out of 8 on $host"
    else
        fail "weights 3 and 1 served $heavy and $light requests out of 8 on $host"
    fi
done

log "[19] Load balancer: a weight of 0 is a backup"

wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_BACKUP" "200" || true
backup=$(served_by "$HOST_BACKUP" | grep -c '^backup$' || true)
if [[ "$backup" == "0" ]]; then
    pass "the weight-0 backend takes no request while the other serves"
else
    fail "the weight-0 backend took $backup requests out of 8"
fi

# The only backend with a weight refuses connections: the backup serves.
for host in "$HOST_FAILOVER" "$HOST_FAILOVER_MW"; do
    log "[19] Load balancer: the backup takes over a refused backend ($host)"
    wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$host" "200" || true
    name=$(curl -s --max-time 5 -H "Host: $host" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null \
        | awk '/^Name:/ {print $2}')
    if [[ "$name" == "spare" ]]; then
        pass "the weight-0 backup serves when the other backend refuses ($host)"
    else
        fail "expected the backup to serve on $host, got '$name'"
    fi
done

