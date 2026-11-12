# Replace path

> Since 0.17

Change the path the backend receives: replace it whole with `replacePath`, or rewrite the parts a regular expression matches with `replacePathRegex`. The query string is kept.

## `replacePath`

```yaml
labels:
  - "sozune.http.<svc>.replacePath=/new/path"
```

Every request of the route reaches the backend with that path:

```yaml
labels:
  - "sozune.http.legacy.host=legacy.example.com"
  - "sozune.http.legacy.replacePath=/index.php"
```

| Incoming request | Forwarded to backend |
|---|---|
| `/` | `/index.php` |
| `/users/42` | `/index.php` |
| `/search?q=x` | `/index.php?q=x` |

The value must start with `/` and hold no query, space or control character. Anything else emits `W032` and the label is ignored.

## `replacePathRegex`

```yaml
labels:
  - "sozune.http.<svc>.replacePathRegex.regex=<regex>"
  - "sozune.http.<svc>.replacePathRegex.replacement=<replacement>"
```

When the regex matches the path, each match is replaced by `replacement`, where `$1`, `$2`… and `${name}` stand for its groups. A path the regex does not match is forwarded unchanged.

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.replacePathRegex.regex=^/v1/(.*)"
  - "sozune.http.api.replacePathRegex.replacement=/v2/$$1"
```

| Incoming request | Forwarded to backend |
|---|---|
| `/v1/users` | `/v2/users` |
| `/v1/users?page=2` | `/v2/users?page=2` |
| `/health` | `/health` |

Both labels are needed, the regex must compile and the replacement must not be empty: otherwise `W032` and the rewrite is ignored. A result that does not start with `/` gets one. In Docker Compose, write `$$1` for `$1`, as Compose reads `$` itself.

The regex follows the syntax of the Rust [`regex`](https://docs.rs/regex/latest/regex/#syntax) crate, close to Go's RE2 syntax.

## Behaviour

- The path is matched as the client sent it, percent-encoding included, without the query.
- The backend receives the original path in an `X-Replaced-Path` header.
- `replacePath` applies before `replacePathRegex` when a route has both: the regex then works on the replaced path.
- They apply after `stripPrefix` and `addPrefix`, which Sōzu makes first: with `path=/api` and `stripPrefix=true`, `replacePathRegex` sees `/v1/users` for a request to `/api/v1/users`.
- The other middlewares of the route (auth, rate limit, plugins…) see the path the client sent; only the backend gets the new one.
- The route goes through the Sōzune middleware, unlike `stripPrefix` and `addPrefix`, which Sōzu applies itself.

## Provider support

| Provider | Supported | How |
|---|---|---|
| Docker / Swarm / Podman | yes | labels above |
| Nomad | yes | same labels, declared as Nomad tags |
| Kubernetes (Service) | yes | same labels as annotations |
| Kubernetes (Ingress) | yes | `sozune.replacePath`, `sozune.replacePathRegex.regex` and `.replacement` annotations on the Ingress, applied to each of its routes |
| Kubernetes (Gateway API) | no | rewrite the path with an HTTPRoute [`urlRewrite`](/documentation/providers/kubernetes#urlrewrite) filter instead |
| HTTP provider, YAML config file, REST API | yes | `replace_path` (a string) and `replace_path_regex` (`{ "regex": "…", "replacement": "…" }`) fields of the entrypoint config |
