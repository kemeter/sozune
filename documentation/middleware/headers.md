# Custom headers

Inject one or more headers into the request before it reaches the backend. Useful for tagging traffic, propagating identity, or signalling environment.

## Label

```yaml
labels:
  - "sozune.http.<svc>.headers.<header-name>=<value>"
```

One label per header. The header name is the part after `headers.`.

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.headers.X-Powered-By=sozune"
  - "sozune.http.api.headers.X-Environment=production"
  - "sozune.http.api.headers.X-Tenant-Id=acme"
```

The backend receives:

```
X-Powered-By: sozune
X-Environment: production
X-Tenant-Id: acme
```

## Behaviour

- Headers are injected on the **request to the backend**, applied natively by Sōzu before the request hits the wire.
- An existing header with the same name is **overwritten**.
- Header names are case-insensitive (HTTP standard).
- Invalid header names or values (e.g. names with spaces) are skipped with a warning, the rest still apply.

## Blocked headers

For security, the following headers are dropped if injected from a Docker label (a warning is logged):

`host`, `transfer-encoding`, `content-length`, `connection`, `upgrade`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-real-ip`, `forwarded`, `cookie`, `authorization`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`

This protects against request smuggling, host header attacks, and credential injection from a compromised label source.

## Limitations

- **Request-only via labels**. The Docker label syntax sets headers on the request to the backend. Sōzu also supports response and bidirectional header edits natively — they are not yet exposed as Sozune labels.
- **Set-only via labels**. The label syntax overwrites or creates a header. Sōzu also supports header deletion (HAProxy `del-header` parity) — not yet exposed as a Sozune label either.
