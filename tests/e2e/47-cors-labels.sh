#!/usr/bin/env bash
# CORS from labels: svc-cors's cors route allows pages of
# https://app.example with Sōzune's cors.* labels, its corstraefik route with
# Traefik's headers.accessControl* ones. Sourced by run-all.sh.

log "[47] CORS labels: pages of the allowed origins may call the route"

# The headers of a request to the route serving $1, with the extra curl
# arguments that follow, lowercase.
headers_of() {
    local host=$1
    shift
    curl -s -D - -o /dev/null --max-time 3 -H "Host: $host" "$@" \
        "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z' || true
}

preflight=""
for _ in $(seq 1 "$MAX_RETRIES"); do
    preflight=$(headers_of "$HOST_CORS" -X OPTIONS -H "Origin: https://app.example" \
        -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: x-request-id")
    [[ "$preflight" == *"access-control-allow-origin"* ]] && break
    sleep 0.5
done
if [[ "$preflight" == "http/1.1 204"* \
    && "$preflight" == *"access-control-allow-origin: https://app.example"* \
    && "$preflight" == *"access-control-allow-methods: get, post"* \
    && "$preflight" == *"access-control-allow-headers: x-request-id"* \
    && "$preflight" == *"access-control-max-age: 600"* ]]; then
    pass "the preflight of an allowed origin is answered with the policy"
else
    fail "the preflight got: $preflight"
fi

answer=$(headers_of "$HOST_CORS" -H "Origin: https://app.example")
if [[ "$answer" == "http/1.1 200"* \
    && "$answer" == *"access-control-allow-origin: https://app.example"* \
    && "$answer" == *"access-control-expose-headers: x-total-count"* ]]; then
    pass "the backend's answer to an allowed origin is marked"
else
    fail "the answer to an allowed origin got: $answer"
fi

other=$(headers_of "$HOST_CORS" -H "Origin: https://evil.example")
if [[ "$other" == "http/1.1 200"* && "$other" != *"access-control-allow-origin"* ]]; then
    pass "another origin gets no CORS header"
else
    fail "the answer to another origin got: $other"
fi

traefik=$(headers_of "$HOST_CORS_TRAEFIK" -X OPTIONS -H "Origin: https://app.example" \
    -H "Access-Control-Request-Method: GET")
if [[ "$traefik" == *"access-control-allow-origin: https://app.example"* \
    && "$traefik" == *"access-control-allow-methods: get"* ]]; then
    pass "Traefik's headers.accessControl* labels make the same policy"
else
    fail "the preflight with Traefik's labels got: $traefik"
fi
