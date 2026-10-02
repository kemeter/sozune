# Hostnames

The `host` label accepts a comma-separated list. Sōzune passes each entry as-is to Sōzu, which classifies it as exact, wildcard, or regex based on its shape. The matching rules below are Sōzu's.

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

A bare `*`, which would match every host, is refused: one service could otherwise take the traffic of every other route on the proxy.

## Regex

A regex pattern is wrapped in `/.../`, applied to one DNS label.

```yaml
labels:
  - "sozune.http.cdn.host=/cdn[0-9]+/.example.com"
```

The example matches `cdn1.example.com`, `cdn42.example.com`, but not `cdnabc.example.com`. The `.` outside the regex segment is treated as a literal DNS separator (not a regex metacharacter).

You can have several regex segments in the same hostname, e.g. `/v[0-9]+/./api[a-z]/.example.com`.

A regex hostname must stay inside one domain, so that it cannot match hosts given to other services:

- it ends with at least two literal labels (`.example.com`): `/.*/` and `/.*/.com` are refused;
- a regex segment does not alternate at its top level: write `/(?:eu|us)-cdn/.example.com`, not `/eu-cdn|us-cdn/.example.com`, whose alternation would escape the anchoring and match any host.

A refused hostname rejects the whole route, with `E002` from labels and `400` from the API.

## Mixed list

```yaml
labels:
  - "sozune.http.app.host=app.example.com,*.app.example.com"
```

Each item in the list is parsed on its own — you can mix exact, wildcard and regex freely.

## Priority

When several entrypoints could match the same request, Sōzune applies them in `priority` descending order.

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

- **Wildcard quirk**: due to an upstream issue ([sozu-proxy/sozu#1223](https://github.com/sozu-proxy/sozu/issues/1223)), wildcards combined with shorter hostnames on the same listener could panic the HTTP worker on early Sōzu builds. Sōzune ships a patched build that guards against this.
- Hostnames are passed as-is to Sōzu, which is responsible for the actual matching at request time.
