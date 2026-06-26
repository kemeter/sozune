#!/usr/bin/env bash
# API: health, auth, CRUD entrypoints.
# Sourced by run-all.sh.

log "[03] API: CRUD"

API_URL="http://127.0.0.1:$API_PORT"
AUTH_HEADER="Authorization: Basic $API_BASIC_AUTH"

health_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$API_URL/health" 2>/dev/null || echo "000")
if [[ "$health_status" == "200" ]]; then
    pass "API health endpoint returns 200"
else
    fail "API health endpoint returned $health_status instead of 200"
fi

noauth_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$API_URL/entrypoints" 2>/dev/null || echo "000")
if [[ "$noauth_status" == "401" ]]; then
    pass "API returns 401 without auth token"
else
    fail "API returned $noauth_status instead of 401 without auth"
fi

list_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "$AUTH_HEADER" "$API_URL/entrypoints" 2>/dev/null || echo "000")
if [[ "$list_status" == "200" ]]; then
    pass "API list entrypoints returns 200 with auth"
else
    fail "API list entrypoints returned $list_status instead of 200"
fi

create_response=$(curl -s -w "\n%{http_code}" --max-time 5 \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -X POST "$API_URL/entrypoints" \
    -d '{"name":"api-test","backends":[{"address":"127.0.0.1","port":9999,"weight":100}],"protocol":"Http","config":{"hostnames":["apitest.localhost"],"path":null,"tls":false,"strip_prefix":false,"https_redirect":false,"priority":0,"auth":null,"headers":[],"backend_timeout":null,"rate_limit":null,"sticky_session":false}}' \
    2>/dev/null || echo "000")
create_status=$(echo "$create_response" | tail -1)
create_body=$(echo "$create_response" | sed '$d')
if [[ "$create_status" == "201" ]]; then
    pass "API create entrypoint returns 201"
else
    fail "API create entrypoint returned $create_status instead of 201"
fi

ep_id=$(echo "$create_body" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -n "$ep_id" ]]; then
    get_response=$(curl -s --max-time 2 \
        -H "$AUTH_HEADER" "$API_URL/entrypoints/$ep_id" 2>/dev/null || echo "")
    get_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" "$API_URL/entrypoints/$ep_id" 2>/dev/null || echo "000")
    if [[ "$get_status" == "200" ]]; then
        pass "API get entrypoint by ID returns 200"
    else
        fail "API get entrypoint returned $get_status instead of 200"
    fi

    # Confirm the GET payload exposes `unhealthy_backends` as an array — the
    # field is now an array of objects (`{address, kind, message, since,
    # last_checked}`), not the legacy `string[]`. Content/kind classification
    # is exercised by Rust unit tests; this assertion only locks down the
    # response shape so dashboards and clients can rely on it.
    shape=$(echo "$get_response" | grep -o '"unhealthy_backends":\[[^]]*\]' || true)
    if [[ -n "$shape" ]]; then
        pass "API entrypoint payload exposes unhealthy_backends as an array"
    else
        fail "API entrypoint payload is missing the unhealthy_backends array (got: $get_response)"
    fi

    update_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -X PUT "$API_URL/entrypoints/$ep_id" \
        -d '{"name":"api-test-updated","backends":[{"address":"127.0.0.1","port":9999,"weight":100}],"protocol":"Http","config":{"hostnames":["apitest.localhost"],"path":null,"tls":false,"strip_prefix":false,"https_redirect":false,"priority":0,"auth":null,"headers":[],"backend_timeout":null,"rate_limit":null,"sticky_session":false}}' \
        2>/dev/null || echo "000")
    if [[ "$update_status" == "200" ]]; then
        pass "API update entrypoint returns 200"
    else
        fail "API update entrypoint returned $update_status instead of 200"
    fi

    delete_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" \
        -X DELETE "$API_URL/entrypoints/$ep_id" 2>/dev/null || echo "000")
    if [[ "$delete_status" == "204" ]]; then
        pass "API delete entrypoint returns 204"
    else
        fail "API delete entrypoint returned $delete_status instead of 204"
    fi

    get_deleted_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" "$API_URL/entrypoints/$ep_id" 2>/dev/null || echo "000")
    if [[ "$get_deleted_status" == "404" ]]; then
        pass "API get deleted entrypoint returns 404"
    else
        fail "API get deleted entrypoint returned $get_deleted_status instead of 404"
    fi
else
    fail "API create did not return an ID, skipping GET/PUT/DELETE tests"
fi

# --- GET /certificates ---------------------------------------------------
# Auth is required, and the response is a JSON object with a `certificates`
# array. With no ACME cert store on disk the array is empty — the shape is
# what we lock down here; per-cert metadata is covered by Rust unit tests.
certs_noauth_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "$API_URL/certificates" 2>/dev/null || echo "000")
if [[ "$certs_noauth_status" == "401" ]]; then
    pass "API /certificates returns 401 without auth token"
else
    fail "API /certificates returned $certs_noauth_status instead of 401 without auth"
fi

certs_response=$(curl -s --max-time 2 \
    -H "$AUTH_HEADER" "$API_URL/certificates" 2>/dev/null || echo "")
certs_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "$AUTH_HEADER" "$API_URL/certificates" 2>/dev/null || echo "000")
if [[ "$certs_status" == "200" ]]; then
    pass "API /certificates returns 200 with auth"
else
    fail "API /certificates returned $certs_status instead of 200"
fi

if echo "$certs_response" | grep -q '"certificates"'; then
    pass "API /certificates payload exposes a certificates array"
else
    fail "API /certificates payload is missing the certificates key (got: $certs_response)"
fi
