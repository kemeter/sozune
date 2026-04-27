# HTTPS redirect

Force HTTP traffic to HTTPS for a given service. Sozune answers `301 Moved Permanently` on the HTTP listener and points the client to the matching HTTPS URL.

## Label

```yaml
labels:
  - "sozune.http.<svc>.httpsRedirect=true"
```

## Example

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
  - "sozune.http.app.httpsRedirect=true"
```

A request to `http://app.example.com/foo?bar=1` returns `301` with `Location: https://app.example.com/foo?bar=1`.

## Behaviour

- The redirect is handled by Sōzu, not by a Sozune middleware. There is no extra hop or processing cost.
- Sōzu emits `301 Moved Permanently` by default. The path and query string are preserved.
- This only affects the HTTP listener. HTTPS requests are routed normally.

## When to use it

- For any public-facing service where you want to enforce TLS.
- Combined with `tls=true`, this ensures every connection ends up encrypted.

## Notes

- The service still needs to listen on the HTTP entry to receive the request that gets redirected. Just declaring the host on HTTP is enough.
- If you only declare the service on HTTPS, the HTTP listener has no rule for it and the request returns `404` instead.
