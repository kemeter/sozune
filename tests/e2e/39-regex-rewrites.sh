#!/usr/bin/env bash
# replacePath, replacePathRegex and redirectRegex: the path whoami receives,
# and the redirects by regex. Sourced by run-all.sh.

log "[39] Path replacement and redirects by regex"

HOST_REPLACE="replace.func-test.localhost"
HOST_REGEX="replace-regex.func-test.localhost"
HOST_REDIRECT="redirect-regex.func-test.localhost"
NETWORK="${COMPOSE_PROJECT}_default"
URL="http://127.0.0.1:$HTTP_PORT"

# No `trap ... EXIT`: this file is sourced, so it would replace the cleanup
# trap run-all.sh relies on.
cleanup_rewrites() {
    docker rm -f sozune-replace sozune-replace-regex sozune-redirect-regex >/dev/null 2>&1 || true
}
cleanup_rewrites

docker run -d --name sozune-replace --network "$NETWORK" \
    --label "sozune.enable=true" \
    --label "sozune.network=$NETWORK" \
    --label "sozune.http.replace.host=$HOST_REPLACE" \
    --label "sozune.http.replace.port=80" \
    --label "sozune.http.replace.replacePath=/fixed" \
    traefik/whoami >/dev/null

# Behind a stripPrefix, which Sōzu applies first.
docker run -d --name sozune-replace-regex --network "$NETWORK" \
    --label "sozune.enable=true" \
    --label "sozune.network=$NETWORK" \
    --label "sozune.http.rregex.host=$HOST_REGEX" \
    --label "sozune.http.rregex.port=80" \
    --label "sozune.http.rregex.path=/api" \
    --label "sozune.http.rregex.stripPrefix=true" \
    --label 'sozune.http.rregex.replacePathRegex.regex=^/v1/(.*)' \
    --label 'sozune.http.rregex.replacePathRegex.replacement=/v2/$1' \
    traefik/whoami >/dev/null

docker run -d --name sozune-redirect-regex --network "$NETWORK" \
    --label "sozune.enable=true" \
    --label "sozune.network=$NETWORK" \
    --label "sozune.http.rdregex.host=$HOST_REDIRECT" \
    --label "sozune.http.rdregex.port=80" \
    --label 'sozune.http.rdregex.redirectRegex.regex=^http://([^/]+)/old/(.*)' \
    --label 'sozune.http.rdregex.redirectRegex.replacement=https://$1/new/$2' \
    --label "sozune.http.rdregex.redirectRegex.permanent=true" \
    traefik/whoami >/dev/null

for host in "$HOST_REPLACE" "$HOST_REDIRECT"; do
    wait_for_status "$URL/" "$host" "200" >/dev/null || true
done
wait_for_status "$URL/api/" "$HOST_REGEX" "200" >/dev/null || true

body=$(curl -s --max-time 2 -H "Host: $HOST_REPLACE" "$URL/some/path?x=1" 2>/dev/null || true)
if grep -q "^GET /fixed?x=1 " <<<"$body"; then
    pass "replacePath: the backend receives /fixed, query kept"
else
    fail "replacePath: the backend did not receive /fixed?x=1 (got: $(head -n 20 <<<"$body" | grep '^GET' || echo none))"
fi
if grep -qi "^X-Replaced-Path: /some/path" <<<"$body"; then
    pass "replacePath: X-Replaced-Path carries the original path"
else
    fail "replacePath: no X-Replaced-Path: /some/path header at the backend"
fi

body=$(curl -s --max-time 2 -H "Host: $HOST_REGEX" "$URL/api/v1/users?page=2" 2>/dev/null || true)
if grep -q "^GET /v2/users?page=2 " <<<"$body"; then
    pass "replacePathRegex: /api/v1/users stripped then rewritten to /v2/users"
else
    fail "replacePathRegex: the backend did not receive /v2/users?page=2 (got: $(grep '^GET' <<<"$body" || echo none))"
fi
body=$(curl -s --max-time 2 -H "Host: $HOST_REGEX" "$URL/api/other" 2>/dev/null || true)
if grep -q "^GET /other " <<<"$body"; then
    pass "replacePathRegex: a path the regex does not match is kept"
else
    fail "replacePathRegex: /api/other did not reach the backend as /other (got: $(grep '^GET' <<<"$body" || echo none))"
fi

headers=$(curl -s -o /dev/null -D - --max-time 2 -H "Host: $HOST_REDIRECT" "$URL/old/a?b=1" 2>/dev/null | tr -d '\r' || true)
location=$(grep -i "^location:" <<<"$headers" | cut -d' ' -f2- || true)
if grep -q "^HTTP/[0-9.]* 301" <<<"$headers" \
    && [[ "$location" == "https://$HOST_REDIRECT/new/a?b=1" ]]; then
    pass "redirectRegex: 301 to the rewritten URL"
else
    fail "redirectRegex: expected 301 to https://$HOST_REDIRECT/new/a?b=1 (got: $(head -n1 <<<"$headers"), location $location)"
fi
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST -H "Host: $HOST_REDIRECT" "$URL/old/a" 2>/dev/null || echo "000")
if [[ "$status" == "308" ]]; then
    pass "redirectRegex: a POST gets 308"
else
    fail "redirectRegex: a POST got $status, expected 308"
fi
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Host: $HOST_REDIRECT" -H "X-Forwarded-Proto: https" "$URL/old/a" 2>/dev/null || echo "000")
if [[ "$status" == "301" ]]; then
    pass "redirectRegex: the scheme is the listener's, not the client's X-Forwarded-Proto"
else
    fail "redirectRegex: with a spoofed X-Forwarded-Proto: https, /old/a answered $status, expected 301"
fi
body=$(curl -s --max-time 2 -H "Host: $HOST_REDIRECT" "$URL/other" 2>/dev/null || true)
if grep -q "^GET /other " <<<"$body"; then
    pass "redirectRegex: a URL the regex does not match reaches the backend"
else
    fail "redirectRegex: /other did not reach the backend"
fi
if grep -qi "^Sozune-" <<<"$body"; then
    fail "redirectRegex: the backend received an internal Sozune-* header"
else
    pass "redirectRegex: no internal Sozune-* header reaches the backend"
fi

cleanup_rewrites
