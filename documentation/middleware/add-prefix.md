# Add prefix

> Since 0.14

Prepend a fixed path prefix to incoming requests before forwarding them to the backend. The reverse of [Strip prefix](/documentation/middleware/strip-prefix).

The typical use case is exposing a sub-path of an existing app under a dedicated subdomain — e.g. serving `example.com/foo/*` from a separate `foo.example.com` host.

## Label

```yaml
labels:
  - "sozune.http.<svc>.addPrefix=<prefix>"
```

A leading slash is added if missing, and any trailing slash is removed. `addPrefix=foo`, `addPrefix=/foo`, and `addPrefix=/foo/` all produce the same result.

## Example

```yaml
labels:
  - "sozune.http.expats.host=expats.example.com"
  - "sozune.http.expats.addPrefix=/foo"
```

| Incoming request | Forwarded to backend |
|---|---|
| `/` | `/foo` |
| `/bar` | `/foo/bar` |
| `/bar/baz` | `/foo/bar/baz` |

## Behaviour

- Without a `path` matcher, every request matches and the prefix is prepended verbatim.
- With a `path=/api` matcher, only requests under `/api` are routed; the prefix is then prepended to the full path.
- With an exact `path` matcher, the rewrite is static (`addPrefix=/foo` + `path=/health` → backend receives `/foo/health`).
- `addPrefix` and `stripPrefix` are mutually exclusive. If both are set, `addPrefix` wins and a warning is logged.

## Provider support

| Provider | Supported | How |
|---|---|---|
| Docker / Swarm / Podman | yes | `sozune.http.<svc>.addPrefix=/foo` label |
| Nomad | yes | same label, declared as a Nomad tag |
| HTTP provider | yes | `add_prefix` field on the entrypoint JSON |
| YAML config file | yes | `add_prefix` field on the entrypoint |
| REST API | yes | `add_prefix` field on the entrypoint payload |
| Kubernetes (Service) | yes | `sozune.http.<svc>.addPrefix=/foo` annotation |
| Kubernetes (Ingress) | yes | `sozune.addPrefix=/foo` annotation on the Ingress, applied to each of its routes (since 0.16) |
| Kubernetes (Gateway API) | no | rewrite the path with an HTTPRoute [`urlRewrite`](/documentation/providers/kubernetes#urlrewrite) filter instead |

## Notes

- The path is forwarded as-is to the backend — Sōzune does not rewrite `Location` headers, canonical tags, or absolute URLs returned by the backend. If the backend embeds absolute paths in its responses, the rewrite must be coordinated on the backend side.
- Internally, Sōzune translates the prefix into a regex matcher with a capture, plus a `rewrite_path` template on the Sōzu frontend.
