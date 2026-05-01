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

- The match is **path-segment aware**: `/api` does NOT strip `/apiv2/...`. Only `/api`, `/api/`, and `/api/<more>` are stripped — anything else returns `404`.
- Trailing slashes on the prefix are normalised: `/api/` and `/api` behave identically.
- The remaining path always starts with `/`. An exact match on the prefix (`/api`) becomes `/`.

## Notes

- The `path` and `prefix` labels are interchangeable for this purpose.
- Internally, Sōzune turns the prefix into an anchored regex matcher on the Sōzu side. This is what enforces the segment boundary and guarantees a valid path is forwarded in every case.
- **`stripPrefix` is not supported with `pathRegex`.** When the path is declared via `pathRegex`, Sōzune skips the strip and logs a debug message — write your own rewrite via the `path`/`prefix` form if you need it.
