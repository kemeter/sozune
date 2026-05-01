# Redirects

Sōzune exposes a few flavors of HTTP redirect, all handled natively by Sōzu (no extra hop, no middleware overhead).

| Goal | Label |
|---|---|
| Force HTTP → HTTPS | `httpsRedirect=true` |
| Override the port in the redirect target | `httpsRedirectPort` |
| Apply a permanent redirect (or block traffic) | `redirect=permanent` / `redirect=unauthorized` |
| Force a specific scheme on the redirect target | `redirectScheme=use_http\|use_https\|use_same` |
| Customise the `Location` header template | `redirectTemplate` |

## HTTPS redirect

Force HTTP traffic to HTTPS for a given service. Sōzune answers `301 Moved Permanently` on the HTTP listener and points the client to the matching HTTPS URL.

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
  - "sozune.http.app.httpsRedirect=true"
```

A request to `http://app.example.com/foo?bar=1` returns `301` with `Location: https://app.example.com/foo?bar=1`. The path and query string are preserved.

### Custom HTTPS port

When TLS is exposed on a non-standard port (e.g. behind another load balancer), force the redirect target to use that port:

```yaml
labels:
  - "sozune.http.app.httpsRedirect=true"
  - "sozune.http.app.httpsRedirectPort=8443"
```

A request to `http://app.example.com/` returns `Location: https://app.example.com:8443/`.

## `redirect` policy

The `redirect` label sets the per-frontend redirect policy. It accepts one of three values:

| Value | Behaviour |
|---|---|
| `forward` | Default. Forward the request to the backend. |
| `permanent` | Always answer `301 Moved Permanently`. The `Location` header follows `redirectScheme` and `redirectTemplate`. |
| `unauthorized` | Always answer `401 Unauthorized` without contacting the backend. Useful to gate a route while keeping it declared. |

```yaml
labels:
  - "sozune.http.legacy.host=legacy.example.com"
  - "sozune.http.legacy.redirect=permanent"
  - "sozune.http.legacy.redirectScheme=use_https"
```

## `redirectScheme`

Controls the scheme written into the `Location` header on a permanent redirect.

| Value | Result |
|---|---|
| `use_same` | Default. Preserve the request scheme. |
| `use_http` | Always write `http://`. |
| `use_https` | Always write `https://`. |

`httpsRedirect=true` is shorthand for `redirect=permanent` + `redirectScheme=use_https`.

## `redirectTemplate`

Override the `Location` header value with a custom template. Two placeholders are available:

- `%REDIRECT_LOCATION` — the URL Sōzu would have emitted by default
- `%STATUS_CODE` — the redirect status code

```yaml
labels:
  - "sozune.http.app.redirect=permanent"
  - "sozune.http.app.redirectTemplate=%REDIRECT_LOCATION?utm_source=redirect"
```

The default template (when `redirectTemplate` is unset) produces a standard `Location` header — you only need this for non-trivial cases like adding query parameters or pointing redirects to a different domain.

## Behaviour

- Redirects are applied by Sōzu, not by a Sōzune middleware. There is no extra processing cost.
- For HTTPS redirects, the service still needs to be declared on the HTTP entry to receive the request that gets redirected. If you only declare the service on HTTPS, the HTTP listener has no rule for it and the request returns `404` instead.
