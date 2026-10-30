# Redirects

> Since 0.6

Sōzune exposes a few flavors of HTTP redirect. Those set by labels are all handled natively by Sōzu (no extra hop, no middleware overhead).

| Goal | Label |
|---|---|
| Force HTTP → HTTPS | `httpsRedirect=true` |
| Override the port in the redirect target | `httpsRedirectPort` (since 0.11) |
| Apply a permanent redirect (or block traffic) (since 0.11) | `redirect=permanent` / `redirect=unauthorized` / `redirect=close` (since 0.16) |
| Force a specific scheme on the redirect target | `redirectScheme=use_http\|use_https\|use_same` (since 0.11) |
| Customise the `Location` header template | `redirectTemplate` (since 0.11) |
| Redirect to another host, path and query kept | `redirectHost` (since 0.16) |

## HTTPS redirect

Force HTTP traffic to HTTPS for a given service. Sōzune answers `301 Moved Permanently` on the HTTP listener and points the client to the matching HTTPS URL.

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
  - "sozune.http.app.httpsRedirect=true"
```

A request to `http://app.example.com/foo?bar=1` returns `301` with `Location: https://app.example.com/foo?bar=1`. The path and query string are preserved. Requests on the HTTPS listener are forwarded as usual.

`httpsRedirect=true` without `tls=true` raises a `W016` diagnostic (since 0.13): the route has no frontend on the HTTPS listener for the redirected request to land on.

### Custom HTTPS port

> Since 0.11

When TLS is exposed on a non-standard port (e.g. behind another load balancer), force the redirect target to use that port:

```yaml
labels:
  - "sozune.http.app.httpsRedirect=true"
  - "sozune.http.app.httpsRedirectPort=8443"
```

A request to `http://app.example.com/` returns `Location: https://app.example.com:8443/`.

## `redirect` policy

> Since 0.11

The `redirect` label sets the per-frontend redirect policy, on every listener the route is served on (HTTP, and HTTPS with `tls=true`). It accepts one of four values; any other raises a `W005` diagnostic and is ignored:

| Value | Behaviour |
|---|---|
| `forward` | Default. Forward the request to the backend. |
| `permanent` | Always answer `301 Moved Permanently`. The `Location` header follows `redirectScheme` and `redirectTemplate`. |
| `unauthorized` | Always answer `401 Unauthorized` without contacting the backend. Useful to gate a route while keeping it declared. |
| `close` | Close the connection without answering anything, like nginx's `444`. Useful against scanners and bots: they get no status, no header and no body to learn from. (since 0.16) |

```yaml
labels:
  - "sozune.http.legacy.host=legacy.example.com"
  - "sozune.http.legacy.redirect=permanent"
  - "sozune.http.legacy.redirectScheme=use_https"
```

`permanent`, `unauthorized` and `close` answer without reaching a backend, so such a route needs no `port`. To close the connections a scanner opens on a path, give the path a route of its own, with a priority above the application's route on the same host:

```yaml
labels:
  - "sozune.http.wp.host=app.example.com"
  - "sozune.http.wp.path=/wp-login.php"
  - "sozune.http.wp.redirect=close"
  - "sozune.http.wp.priority=10"
```

## `redirectHost`

> Since 0.16

Send clients to another host with a permanent redirect, keeping the path and the query: an old domain, an alias, `www` to the bare domain.

```yaml
labels:
  - "sozune.http.old.host=old.example.com,alias.example.com"
  - "sozune.http.old.tls=true"
  - "sozune.http.old.redirectHost=www.example.com"
  - "sozune.http.old.redirectScheme=use_https"
```

`https://old.example.com/docs?page=2` answers `301` with `Location: https://www.example.com/docs?page=2`.

`redirectHost` implies `redirect=permanent`, and the route needs no `port`: it never reaches a backend. The value is a bare hostname, without scheme, port or path; anything else, or a `redirect` set to `forward`, `unauthorized` or `close`, emits `W031` and the label is ignored. Without `redirectScheme`, the redirect keeps the request's scheme. With `stripPrefix` or `addPrefix`, the path in `Location` is rewritten the same way: `path=/blog` + `stripPrefix=true` sends `old.example.com/blog/post` to `www.example.com/post`.

## `redirectScheme`

> Since 0.11

Controls the scheme written into the `Location` header on a permanent redirect. Any other value raises a `W006` diagnostic and is ignored.

| Value | Result |
|---|---|
| `use_same` | Default. Preserve the request scheme. |
| `use_http` | Always write `http://`. |
| `use_https` | Always write `https://`. |

`httpsRedirect=true` is not the same as `redirect=permanent` + `redirectScheme=use_https`: `httpsRedirect` only redirects requests that arrive on the HTTP listener and serves those on HTTPS, while a `redirect=permanent` route answers `301` on both listeners and never reaches a backend.

## `redirectTemplate`

> Since 0.11

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

- Redirects set by labels are applied by Sōzu, not by a Sōzune middleware. There is no extra processing cost. A Gateway API `requestRedirect` with a status Sōzu has no answer for (`303`, `307`), or to a fixed path, is answered by the Sōzune middleware instead: see [Gateway API](/documentation/providers/kubernetes#gateway-api-httproute).
- A `tls=true` route gets a frontend on both the HTTP and the HTTPS listener, which is what `httpsRedirect` needs: one to redirect from, one to serve the redirected request. Without `tls=true`, the HTTPS listener has no rule for the host and the redirected request is not served (`W016`).

## REST / YAML surface

The same settings are fields of the entrypoint's `config`: `https_redirect` (`true`/`false`), `https_redirect_port`, `redirect` (`forward`, `permanent`, `unauthorized`, `close`), `redirect_scheme` (`use_same`, `use_http`, `use_https`), `redirect_template`, and `rewrite_host` for `redirectHost`.

```jsonc
{
  "name": "old",
  "protocol": "Http",
  "config": {
    "hostnames": ["old.example.com"],
    "redirect": "permanent",
    "redirect_scheme": "use_https",
    "rewrite_host": "www.example.com"
    // …
  }
}
```
