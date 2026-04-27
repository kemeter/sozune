# Strip prefix

Remove the matched path prefix before forwarding the request to the backend. Useful when the backend is unaware of the public-facing prefix.

## Label

```yaml
labels:
  - "sozune.http.<svc>.path=<prefix>"
  - "sozune.http.<svc>.stripPrefix=true"
```

`stripPrefix` only takes effect when combined with a `path` (or `prefix`) rule.

## Example

```yaml
labels:
  - "sozune.http.api.host=example.com"
  - "sozune.http.api.path=/api"
  - "sozune.http.api.stripPrefix=true"
```

| Incoming request | Forwarded to backend |
|---|---|
| `/api/users` | `/users` |
| `/api/users/42` | `/users/42` |
| `/api` | `/` |
| `/api/` | `/` |

## Behaviour

- The match is **path-segment aware**: `/api` does NOT strip `/apiv2/...`. Only `/api`, `/api/`, and `/api/<more>` are stripped.
- Trailing slashes on the prefix are normalised: `/api/` and `/api` behave identically.
- If the path doesn't start with the prefix, it's forwarded unchanged.
- The remaining path always starts with `/`. An exact match on the prefix becomes `/`.

## Notes

- The `path` and `prefix` labels are interchangeable for this purpose.
- **Don't combine `stripPrefix` with `pathRegex`.** When both are set, Sozune tries to strip the literal regex string (e.g. `/users/[0-9]+`) from the request path, which never matches in practice — the request is forwarded unchanged. Use `path` or `prefix` if you want the strip to actually do something.
