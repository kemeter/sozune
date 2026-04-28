#!/usr/bin/env bash
# API: health, auth, CRUD entrypoints.
# Sourced by run-all.sh.

log "[03] API: CRUD"

API_URL="http://127.0.0.1:$API_PORT"
AUTH_HEADER="Authorization: Bearer $API_TOKEN"

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
    -d '{"name":"api-test","backends":["127.0.0.1:9999"],"protocol":"Http","config":{"hostnames":["apitest.localhost"],"port":9999,"path":null,"tls":false,"strip_prefix":false,"https_redirect":false,"priority":0,"auth":null,"headers":[],"backend_timeout":null,"rate_limit":null,"sticky_session":false}}' \
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
    get_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" "$API_URL/entrypoints/$ep_id" 2>/dev/null || echo "000")
    if [[ "$get_status" == "200" ]]; then
        pass "API get entrypoint by ID returns 200"
    else
        fail "API get entrypoint returned $get_status instead of 200"
    fi

    update_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -X PUT "$API_URL/entrypoints/$ep_id" \
        -d '{"name":"api-test-updated","backends":["127.0.0.1:9999"],"protocol":"Http","config":{"hostnames":["apitest.localhost"],"port":9999,"path":null,"tls":false,"strip_prefix":false,"https_redirect":false,"priority":0,"auth":null,"headers":[],"backend_timeout":null,"rate_limit":null,"sticky_session":false}}' \
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
