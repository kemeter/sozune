# Path matching

A path rule narrows down which paths under a hostname go to a service. By default, every path matches (`/` prefix).

## Three rule types

| Type | Label | Match |
|---|---|---|
| Prefix | `path` or `prefix` | Path starts with the value, segment-aware |
| Regex | `pathRegex` | Path matches the regex |
| Exact | (API only) | Path equals the value |

## Prefix

```yaml
labels:
  - "sozune.http.api.host=example.com"
  - "sozune.http.api.path=/api"
```

`path` and `prefix` are interchangeable; both produce a prefix rule.

| Request | Match? |
|---|---|
| `/api` | yes |
| `/api/` | yes |
| `/api/users` | yes |
| `/api?page=2` | yes |
| `/apidocs` | no — segment-aware |

## Regex

```yaml
labels:
  - "sozune.http.users.host=example.com"
  - "sozune.http.users.pathRegex=/users/[0-9]+"
```

`/users/42` matches; `/users/abc` does not. The regex is compiled once per route by Sōzu.

The regex is searched anywhere in what Sōzu matches, which is the path **with its query string**. `/users/[0-9]+` therefore also matches `/v1/users/42`, `/users/42/profile` and `/health?next=/users/42`. Start it with `^` to match from the beginning of the path, which keeps the query out: `^/users/[0-9]+` matches `/users/42`, `/users/42/profile` and `/users/42?page=2`, but neither `/v1/users/42` nor `/health?next=/users/42`. Add `$` only if the route must refuse a query: `^/users/[0-9]+$` does not match `/users/42?page=2`.

## Exact

There is no Docker label for exact path matches. Create the entrypoint through the [REST API](/documentation/configuration/api) with a `PathConfig` of `rule_type: Exact`.

An exact path is compared without the query string: `/login` matches `/login` and `/login?next=/`, but not `/login/` or `/login/reset`.

## Strip prefix

Paired with a prefix rule, `stripPrefix` removes the matched prefix before forwarding. See [strip prefix](/documentation/middleware/strip-prefix).

## When multiple labels are set

If several path labels are present on the same service, only one wins, in this order:

1. `path`
2. `prefix`
3. `pathRegex`

The others are silently ignored. Don't combine them — pick one.

## Default

If no path label is set, the rule is prefix `/` — every request to the matched hostname is accepted.
