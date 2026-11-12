#!/usr/bin/env bash
# Key-value providers: a route written to etcd or Redis under `sozune/` is
# served, follows its servers as they change, and goes when its keys go.
# The servers are svc-kv-a and svc-kv-b, whoami containers without labels.
# Valkey speaks the Redis protocol: `sozune validate` reads a route from it.
# Sourced by run-all.sh.

log "[51] key-value providers: routes from etcd, Redis and Valkey"

KV_A=$(container_ip svc-kv-a)
KV_B=$(container_ip svc-kv-b)

etcdctl() {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" exec -T svc-etcd etcdctl "$@" >/dev/null
}
rediscli() {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" exec -T svc-redis redis-cli "$@" >/dev/null
}

# The whoami names that answer `host` over `tries` requests, sorted.
kv_names() {
    local host="$1" tries="${2:-10}"
    for _ in $(seq 1 "$tries"); do
        curl -s --max-time 2 -H "Host: $host" "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null \
            | sed -n 's/^Name: //p' || true
    done | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# Waits until `host` is answered by exactly `expected` (as kv_names prints it).
wait_for_names() {
    local host="$1" expected="$2" names=""
    for _ in $(seq 1 30); do
        names=$(kv_names "$host")
        [[ "$names" == "$expected" ]] && return 0
        sleep 0.5
    done
    echo "$names"
    return 1
}

# -- etcd --
etcdctl put sozune/kvetcd/labels/sozune.http.kvetcd.host "$HOST_KV_ETCD"
etcdctl put sozune/kvetcd/servers/a "$KV_A:80"
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_KV_ETCD" "200" \
    && [[ "$(kv_names "$HOST_KV_ETCD")" == "kv-a" ]]; then
    pass "etcd: a route written under sozune/ is served by its server"
else
    fail "etcd: $HOST_KV_ETCD is not served by kv-a"
fi

etcdctl put sozune/kvetcd/servers/b "$KV_B:80"
if got=$(wait_for_names "$HOST_KV_ETCD" "kv-a kv-b"); then
    pass "etcd: a server added to the store joins the route"
else
    fail "etcd: expected kv-a and kv-b behind the route, got '$got'"
fi

# A server without a port takes the one its labels set.
etcdctl put sozune/kvetcd/labels/sozune.http.kvetcd.port 80
etcdctl put sozune/kvetcd/servers/b "$KV_B"
etcdctl del sozune/kvetcd/servers/a
if got=$(wait_for_names "$HOST_KV_ETCD" "kv-b"); then
    pass "etcd: a removed server leaves the route, a bare IP takes the label's port"
else
    fail "etcd: expected kv-b alone behind the route, got '$got'"
fi

etcdctl del --prefix sozune/kvetcd/
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_KV_ETCD" "404"; then
    pass "etcd: the route goes with its keys"
else
    fail "etcd: $HOST_KV_ETCD still served after its keys were deleted"
fi

# -- Redis --
rediscli SET sozune/kvredis/labels/sozune.http.kvredis.host "$HOST_KV_REDIS"
rediscli SET sozune/kvredis/servers/a "$KV_A:80"
rediscli SET sozune/kvredis/servers/b "$KV_B:80"
# A key that holds no string is no route, and does not stop the others.
rediscli HSET sozune/kvredis/labels/hash field value
if got=$(wait_for_names "$HOST_KV_REDIS" "kv-a kv-b"); then
    pass "Redis: a route written under sozune/ is served by its servers"
else
    fail "Redis: expected kv-a and kv-b behind $HOST_KV_REDIS, got '$got'"
fi

rediscli DEL sozune/kvredis/labels/sozune.http.kvredis.host
if wait_for_status "http://127.0.0.1:$HTTP_PORT/" "$HOST_KV_REDIS" "404"; then
    pass "Redis: the route goes when its host is deleted"
else
    fail "Redis: $HOST_KV_REDIS still served after its host was deleted"
fi
rediscli DEL sozune/kvredis/servers/a sozune/kvredis/servers/b sozune/kvredis/labels/hash

# -- Valkey, through `sozune validate` --
VALKEY_IP=$(container_ip svc-valkey)
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" exec -T svc-valkey \
    valkey-cli SET sozune/kvvalkey/labels/sozune.http.kvvalkey.host "$HOST_KV_VALKEY" >/dev/null
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" exec -T svc-valkey \
    valkey-cli SET sozune/kvvalkey/servers/a "$KV_A:80" >/dev/null
# The suite's config has no Redis provider: `validate` reads it from the
# SOZUNE_PROVIDER_* variables, as sozune does.
validate_out=$(CONFIG_PATH="$CONFIG_FILE" \
    SOZUNE_PROVIDER_REDIS_ENABLED=true \
    SOZUNE_PROVIDER_REDIS_ENDPOINT="redis://$VALKEY_IP:6379" \
    "$SOZUNE_BIN" validate --provider redis 2>&1 || true)
if grep -q "$HOST_KV_VALKEY" <<<"$validate_out" && grep -q "$KV_A" <<<"$validate_out"; then
    pass "Valkey: the Redis provider reads a route from Valkey"
else
    fail "Valkey: sozune validate did not show the route: $validate_out"
fi
