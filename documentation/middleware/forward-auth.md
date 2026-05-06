# Forward auth

Delegate authentication and authorization to an external service. For every incoming request, Sōzune calls a configured URL with the request's headers; the response decides whether the request reaches the backend or is rejected.

This is the same pattern as Traefik's `ForwardAuth` middleware and Envoy's `ext_authz` filter. It plugs into anything that exposes a verification endpoint over HTTP — Authelia, Authentik, OAuth2 Proxy, OPA, custom auth services, [Crowdsec's AppSec API](https://docs.crowdsec.net/docs/appsec/intro/), Keycloak with a thin adapter, etc.

## Labels

```yaml
labels:
  - "sozune.http.<svc>.forwardAuth.address=<url>"
  - "sozune.http.<svc>.forwardAuth.responseHeaders=<comma-separated>"
  - "sozune.http.<svc>.forwardAuth.trustForwardHeader=<true|false>"
```

| Label | Description |
|---|---|
| `forwardAuth.address` | URL of the verification endpoint. Required to enable forward auth. |
| `forwardAuth.responseHeaders` | Comma-separated list of headers to copy from the auth response onto the request before forwarding to the backend. Common: `X-User,X-Email,X-Groups`. |
| `forwardAuth.trustForwardHeader` | When `true`, the existing `X-Forwarded-*` headers from the client are forwarded to the auth service as-is. When `false` (default), Sōzune strips them and sets fresh ones based on its own observation of the connection. Set to `true` only if Sōzune sits behind another trusted proxy. |

If `forwardAuth.address` is absent, forward auth is disabled for the service.

## Example — Authelia

```yaml
services:
  app:
    image: my-app
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.tls=true"
      - "sozune.http.app.forwardAuth.address=http://authelia:9091/api/verify?rd=https://auth.example.com"
      - "sozune.http.app.forwardAuth.responseHeaders=Remote-User,Remote-Groups,Remote-Name,Remote-Email"

  authelia:
    image: authelia/authelia:latest
    # … Authelia config …
```

When a user requests `https://app.example.com/dashboard`:

1. Sōzune calls `GET http://authelia:9091/api/verify?rd=…` and forwards the client's request headers (Cookie, Authorization, etc.).
2. Authelia checks the session cookie. If valid, it responds `200 OK` with `Remote-User: alice` and friends. If not, it responds `401` (or `302` to the login portal, depending on configuration).
3. On `200`, Sōzune copies the four `Remote-*` headers onto the request and forwards it to the backend. The app reads `Remote-User` and trusts it.
4. On any other status, Sōzune **does not** call the backend. It returns the auth service's response (status, headers, body) to the client untouched, so a `302` becomes a real browser redirect to the login page.

## Example — Crowdsec AppSec

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.forwardAuth.address=http://crowdsec-appsec:7422/"
```

Crowdsec's AppSec component exposes an HTTP API that returns `200` for benign requests and `403` for matched attacks. Pointing forward auth at it gives Sōzune an in-line WAF without writing a Crowdsec-specific integration.

## Example — OAuth2 Proxy

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.forwardAuth.address=http://oauth2-proxy:4180/oauth2/auth"
  - "sozune.http.app.forwardAuth.responseHeaders=X-Auth-Request-User,X-Auth-Request-Email"
```

## Behaviour

### What Sōzune sends to the auth service

- Method: `GET`.
- Path: the path of the auth address (the path part of the **incoming** request is **not** rewritten onto the auth URL).
- Headers copied from the client request: every header except the hop-by-hop ones (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`).
- Headers Sōzune adds:
  - `X-Forwarded-Method` — original HTTP method
  - `X-Forwarded-Uri` — original request URI (path + query)
  - `X-Forwarded-Host` — original `Host` header
  - `X-Forwarded-Proto` — `http` or `https`
  - `X-Forwarded-For` — appended with the immediate client IP (or replaced with a fresh chain when `trustForwardHeader=false`)
- Body: empty. Forward auth never streams the request body to the auth service.

### How Sōzune interprets the response

- **Status `2xx`** → request is allowed. Headers listed in `responseHeaders` are copied from the auth response onto the request and the request is forwarded to the backend. All other headers are discarded.
- **Status `3xx`, `4xx` or `5xx`** → the auth response is returned to the client **as-is**: the same status code, the same headers (minus hop-by-hop), and the same body. This is what makes interactive login flows work — a `302 Location: https://auth.example.com/login` from the auth service becomes a real redirect for the browser.
- **Auth service unreachable or times out** → Sōzune returns `502 Bad Gateway`. The backend is **not** called: failing open would let unauthenticated traffic through. Adjust your alerting accordingly; an outage of the auth service takes the protected services down with it.

### Timeouts

The forward-auth call uses a fixed 5 second timeout. If you need long-lived auth checks (interactive challenges, MFA prompts), the auth service should respond with a `302` to a dedicated login endpoint quickly and finish the flow there — not block on a single forward-auth call.

### Order of evaluation

Forward auth runs **before** any other middleware (rate limit, headers, compression). A request rejected by the auth service is never rate-counted against the client's bucket, and no response is compressed. This matches Traefik's behaviour.

## Limitations

- **Per-route only.** There is no way to declare a forward-auth chain at the proxy level that applies to multiple services. Each service has to set its own `forwardAuth.address`. (Pattern is consistent with the rest of the middleware system.)
- **No request body forwarded.** The auth service sees only headers. If your auth logic needs to inspect the body, this is the wrong tool — handle it in the backend.
- **No method rewriting.** The auth service is always called with `GET`. If your auth service requires `POST` (rare), this won't work.
- **`X-Forwarded-Method` is informative.** Sōzune does not change the actual method sent to the backend based on the auth response.

## Errors and diagnostics

| Code | Meaning |
|---|---|
| `W019InvalidForwardAuth` | The `forwardAuth.address` value is not a valid URL. The forward-auth middleware is disabled for this service; routing still works. |
