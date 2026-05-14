# Error pages

Serve a custom body when Sōzune returns an HTTP error (`404`, `503`, …). Two scopes are supported and they compose:

- **Listener-level** — global default applied to every request handled by the HTTP or HTTPS listener.
- **Entrypoint-level** — per-cluster override that takes precedence over the listener default for requests routed to that entrypoint.

Sōzune accepts three value shapes and turns them into a valid HTTP/1.1 response on your behalf:

| Shape | Example | Behaviour |
|---|---|---|
| **Inline body** | `<html><body>down</body></html>` | Wrapped into a minimal HTTP/1.1 response with `Content-Length`, `Content-Type: text/html; charset=utf-8`, `Connection: close`. |
| **Full HTTP response** | `HTTP/1.1 503 Service Unavailable\r\n...\r\n\r\n<body>` | Passed through unchanged. Use this if you need custom headers or templating placeholders (`%REQUEST_ID`, `%ROUTE`, `%DURATION`). |
| **File reference** | `file:///etc/sozune/templates/503.html` | The file is read off disk by Sōzu at listener-build time. Same wrap rules apply to its contents. Only allowed in static YAML config — provider labels reject `file://`. |

## Supported status codes

`301`, `400`, `401`, `404`, `408`, `413`, `421`, `429`, `502`, `503`, `504`, `507`. Any other code is dropped with a warning (`W020` for provider labels).

## Listener-level (static YAML)

```yaml
proxy:
  http:
    listen_address: 80
    error_pages:
      "404": "<html><body><h1>Not here</h1></body></html>"
      "503": "file:///etc/sozune/templates/503.html"
  https:
    listen_address: 443
    error_pages:
      "404": "<html><body><h1>Not here</h1></body></html>"
```

Each listener has its own map. Setting an entry on `proxy.http.error_pages` does not affect HTTPS and vice versa.

## Entrypoint-level (static YAML)

```yaml
entrypoints:
  - id: myapp
    config:
      hostnames: [app.example.com]
      error_pages:
        "503": "<html><body>maintenance — back in 5 min</body></html>"
```

The entrypoint-scoped map overrides matching status codes from the listener for that cluster only.

## Provider labels

```yaml
labels:
  - "sozune.http.<svc>.errorPages.503=<html><body>cluster down</body></html>"
  - "sozune.http.<svc>.errorPages.404=<html>missing</html>"
```

The label key is `errorPages.<code>`. Inline bodies only — `file://` is refused (`W020`) so a non-trusted workload cannot read arbitrary host files into a response body. Use the static YAML if you need on-disk templates.

## Provider support

| Provider | Supported | How |
|---|---|---|
| Docker / Swarm / Podman | yes | `sozune.http.<svc>.errorPages.<code>=<body>` label |
| Nomad | yes | same label, declared as a Nomad tag |
| HTTP provider | yes | `error_pages` map on the entrypoint JSON |
| YAML config file | yes | `error_pages` map on the entrypoint or on `proxy.http` / `proxy.https` |
| REST API | yes | `error_pages` map on the entrypoint payload |
| Kubernetes (Ingress / Gateway API) | yes | `error_pages` map on the resource spec |

## Notes

- The body is sent verbatim. Sōzune does not template inline bodies, but `%REQUEST_ID`, `%ROUTE` and `%DURATION` placeholders in a full HTTP/1.1 response are substituted by Sōzu at response time.
- When no `error_pages` entry matches the status code, Sōzu's built-in default templates are served.
- An empty value (`errorPages.503=`) is treated as "preserve current" and does not overwrite an inherited template — matches Sōzu's own semantics.
