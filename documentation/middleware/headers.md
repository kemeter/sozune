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

- Headers are injected on the **request to the backend**, not on the response to the client.
- An existing header with the same name is **overwritten**.
- Header names are case-insensitive (HTTP standard).
- Invalid header names or values (e.g. names with spaces) are skipped with a warning, the rest still apply.

## Blocked headers

For security, the following headers are dropped if injected from a Docker label (a warning is logged):

`host`, `transfer-encoding`, `content-length`, `connection`, `upgrade`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-real-ip`, `forwarded`, `cookie`, `authorization`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`

This protects against request smuggling, host header attacks, and credential injection from a compromised label source.

## Limitations

- **Request-only**. There is currently no label to set a header on the response back to the client.
- **No removal / rewrite**. You can only set a header to a fixed value; you cannot delete an existing one or rewrite it conditionally.
