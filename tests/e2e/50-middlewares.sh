#!/usr/bin/env bash
# Named middlewares: svc-middlewares's mwchain route references `both`, a
# chain of `shared` (static config) and `local` (its own labels); mwown
# references `shared` and sets the same header itself. Sourced by run-all.sh.

log "[50] Named middlewares: a route gets the options of the ones it references"

headers_of() {
    curl -s -D - -o /dev/null --max-time 3 -H "Host: $1" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z' || true
}

chain=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    chain=$(headers_of "$HOST_MW_CHAIN")
    [[ "$chain" == "http/1.1 200"* ]] && break
    sleep 0.5
done
if [[ "$chain" == *"x-shared: static"* && "$chain" == *"x-local: container"* ]]; then
    pass "a chain brings in a static config middleware and a workload's own"
else
    fail "the chained route's answer got: $chain"
fi

own=$(headers_of "$HOST_MW_OWN")
if [[ "$own" == *"x-shared: own"* && "$own" != *"x-shared: static"* ]]; then
    pass "a route's own label wins over its middleware's"
else
    fail "the route setting the header itself got: $own"
fi
