# Hostnames

The `host` label accepts a comma-separated list. Sozune passes each entry as-is to Sōzu, which classifies it as exact, wildcard, or regex based on its shape. The matching rules below are Sōzu's.

## Exact

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
```

A literal hostname. Matched against the request's `Host` header.

## Wildcard

A wildcard matches exactly one DNS label.

```yaml
labels:
  - "sozune.http.app.host=*.example.com"
```

`foo.example.com` matches; `bar.foo.example.com` does not. The leading `*` is required — patterns like `app*.example.com` are rejected.

The bare `*` matches everything (any host).

## Regex

A regex pattern is wrapped in `/.../`, applied to one DNS label.

```yaml
labels:
  - "sozune.http.cdn.host=/cdn[0-9]+/.example.com"
```

The example matches `cdn1.example.com`, `cdn42.example.com`, but not `cdnabc.example.com`. The `.` outside the regex segment is treated as a literal DNS separator (not a regex metacharacter).

You can have several regex segments in the same hostname, e.g. `/v[0-9]+/./api[a-z]/.example.com`.

## Mixed list

```yaml
labels:
  - "sozune.http.app.host=app.example.com,*.app.example.com"
```

Each item in the list is parsed on its own — you can mix exact, wildcard and regex freely.

## Priority

When several entrypoints could match the same request, Sozune applies them in `priority` descending order.

```yaml
labels:
  - "sozune.http.specific.host=admin.example.com"
  - "sozune.http.specific.priority=100"
  - "sozune.http.catchall.host=*.example.com"
  # priority defaults to 0
```

For `admin.example.com`, the `specific` entrypoint wins. Other subdomains hit `catchall`.

The default priority is `0`. Higher numbers win.

## Notes

- **Wildcard quirk**: due to an upstream issue ([sozu-proxy/sozu#1223](https://github.com/sozu-proxy/sozu/issues/1223)), wildcards combined with shorter hostnames on the same listener could panic the HTTP worker on early Sōzu builds. Sozune ships a patched build that guards against this.
- Hostnames are passed as-is to Sōzu, which is responsible for the actual matching at request time.
