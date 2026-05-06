#!/usr/bin/env bash
# Forward auth: a real Authelia hub gates a whoami backend through Sozune.
# Validates the three flows the doc describes:
#  - no session   → Sozune relays Authelia's 302 to the client
#  - valid cookie → Sozune forwards to backend with Remote-* headers populated
#  - bad cookie   → 302 again (Authelia treats it as no session)
# Sourced by run-all.sh.

log "[10] forward-auth: Authelia container is reachable through Sozune"

if wait_for_status "http://127.0.0.1:$HTTP_PORT/api/state" "$HOST_AUTHELIA" "200"; then
    pass "Authelia /api/state returns 200 through Sozune"
else
    fail "Authelia /api/state not reachable"
    return 0
fi

log "[10] forward-auth: unauthenticated request gets a 302 from Authelia"

unauth_response=$(curl -s -o /dev/null -w "status=%{http_code} location=%header{location}" \
    --max-time 3 -H "Host: $HOST_FAUTH" -H "X-Forwarded-Proto: https" \
    "http://127.0.0.1:$HTTP_PORT/")
if [[ "$unauth_response" == *"status=302"* ]] && [[ "$unauth_response" == *"location="* ]]; then
    pass "unauthenticated → 302 with Location header (Authelia login flow)"
else
    fail "expected 302 + Location, got: '$unauth_response'"
fi

log "[10] forward-auth: log in to Authelia and replay the session"

# Authelia rejects firstfactor requests whose Host doesn't match the cookie
# domain it serves. We always talk to it via $HOST_AUTHELIA through Sozune.
firstfactor_response=$(curl -s -i --max-time 5 \
    -H "Host: $HOST_AUTHELIA" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"password\":\"alicepass\",\"keepMeLoggedIn\":false,\"targetURL\":\"https://$HOST_FAUTH/\"}" \
    "http://127.0.0.1:$HTTP_PORT/api/firstfactor")

session=$(echo "$firstfactor_response" \
    | awk -F'authelia_session=' '/[Ss]et-[Cc]ookie/ {split($2, a, ";"); print a[1]; exit}')

if [[ -z "$session" ]]; then
    fail "no authelia_session cookie in /api/firstfactor response"
    echo "$firstfactor_response" | head -20
    return 0
fi
pass "Authelia /api/firstfactor returned a session cookie"

log "[10] forward-auth: authenticated request reaches the backend with Remote-* headers"

auth_body=$(curl -s --max-time 3 \
    -H "Host: $HOST_FAUTH" \
    -H "X-Forwarded-Proto: https" \
    -H "Cookie: authelia_session=$session" \
    "http://127.0.0.1:$HTTP_PORT/")

if [[ "$auth_body" == *"Remote-User: alice"* ]]; then
    pass "backend received Remote-User: alice"
else
    fail "Remote-User missing from backend response"
    echo "$auth_body" | head -20
fi

if [[ "$auth_body" == *"Remote-Email: alice@func-test.localhost"* ]]; then
    pass "backend received Remote-Email: alice@func-test.localhost"
else
    fail "Remote-Email missing from backend response"
fi

if [[ "$auth_body" == *"Remote-Groups: admins"* ]]; then
    pass "backend received Remote-Groups: admins"
else
    fail "Remote-Groups missing from backend response"
fi

log "[10] forward-auth: invalid cookie still triggers Authelia's 302 redirect"

invalid_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
    -H "Host: $HOST_FAUTH" \
    -H "X-Forwarded-Proto: https" \
    -H "Cookie: authelia_session=not-a-valid-session-value" \
    "http://127.0.0.1:$HTTP_PORT/")
if [[ "$invalid_status" == "302" ]]; then
    pass "bad cookie → 302 (Authelia rejects, Sozune relays)"
else
    fail "expected 302 with invalid cookie, got $invalid_status"
fi

log "[10] forward-auth: response headers from Authelia are NOT leaked to the client on 200"

# Authelia returns Remote-User in the verify response. The forward-auth
# middleware should copy these headers ONTO the request to the backend, not
# back to the client. Whoami echoes them in its body (which is what the
# previous test checks) but the client itself shouldn't see them as response
# headers — that would leak identity to the network.
client_headers=$(curl -s -i --max-time 3 \
    -H "Host: $HOST_FAUTH" \
    -H "X-Forwarded-Proto: https" \
    -H "Cookie: authelia_session=$session" \
    "http://127.0.0.1:$HTTP_PORT/" | head -20)
if echo "$client_headers" | grep -qiE "^remote-user:"; then
    fail "Remote-User header leaked into the client response"
    echo "$client_headers"
else
    pass "Remote-* headers stay request-side, not echoed to the client"
fi
