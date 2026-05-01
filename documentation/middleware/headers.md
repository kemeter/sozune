# Custom headers

Add, override, or delete headers on requests forwarded to the backend, on responses returned to the client, or on both directions. Applied natively by Sōzu — no extra hop.

## Label

```yaml
labels:
  - "sozune.http.<svc>.headers.<header-name>=<value>"
  - "sozune.http.<svc>.headers.response.<header-name>=<value>"
  - "sozune.http.<svc>.headers.both.<header-name>=<value>"
```

One label per header. The direction is determined by the prefix after `headers.`:

| Form | Direction |
|---|---|
| `headers.<name>=<value>` | Request (sent to the backend) |
| `headers.response.<name>=<value>` | Response (sent to the client) |
| `headers.both.<name>=<value>` | Both directions |

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.headers.X-Powered-By=sozune"
  - "sozune.http.api.headers.response.X-Frame-Options=DENY"
  - "sozune.http.api.headers.both.X-Trace-Id=abc-123"
```

The backend sees on the request:

```
X-Powered-By: sozune
X-Trace-Id: abc-123
```

The client sees on the response:

```
X-Frame-Options: DENY
X-Trace-Id: abc-123
```

## Deleting a header

An empty value deletes the header. Useful to strip headers added by an upstream component, or hide implementation details from the response.

```yaml
labels:
  # strip User-Agent before reaching the backend
  - "sozune.http.api.headers.User-Agent="

  # strip Server header from responses
  - "sozune.http.api.headers.response.Server="
```

## Behaviour

- An existing header with the same name is **overwritten** when a value is set.
- Empty value = delete (matches every existing header with that name on the chosen direction).
- Header names are case-insensitive (HTTP standard).
- Invalid header names or values (e.g. names with spaces) are skipped with a warning, the rest still apply.

## Blocked headers

For security, the following headers are dropped if injected from a Docker label (a warning is logged), regardless of direction:

`host`, `transfer-encoding`, `content-length`, `connection`, `upgrade`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-real-ip`, `forwarded`, `cookie`, `authorization`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`

This protects against request smuggling, host header attacks, and credential injection from a compromised label source.
