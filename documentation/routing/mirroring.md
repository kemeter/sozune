# Mirroring

Send a copy of a route's traffic to another service, to try a new version on real requests before it serves any. The copy's answer is thrown away: clients only ever get the route's own answer, whatever the mirror does.

## Labels

The mirror declares which route it copies, by its service name. It serves no host of its own:

```yaml
services:
  app:
    image: my/app:1.4
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"

  app-next:
    image: my/app:1.5
    labels:
      - "sozune.enable=true"
      - "sozune.http.app-next.mirrorOf=app"
      - "sozune.http.app-next.port=80"
```

Each request `app` serves is copied to one container of `app-next`, picked by `weight` as for a backend, with the headers and the body `app`'s backend gets. A route can have several mirrors: each gets its own copy.

| Label | Description |
|---|---|
| `mirrorOf` | The service name of the route this service mirrors, from the same provider. The service then serves no route of its own: `host`, `path` and the other routing labels are ignored, `port` and `weight` still apply. |

## Behaviour

- The client's answer waits for no mirror. A mirror that is slow, down, or has no container left changes nothing for it.
- A copy gives up after the route's [`backendTimeout`](/documentation/middleware/backend-timeout), 30 s without one. At most 1024 copies are under way at once, all mirrors together: past that, a request is not copied.
- A mirrored route goes through the Sōzune middleware, which reads the whole request body before forwarding it.
- A WebSocket upgrade is not copied: the copy would open a tunnel on the mirror with nobody at the other end.
- A mirror naming a route that does not exist, or one of another provider, mirrors nothing.

## Kubernetes

On Kubernetes, the Gateway API `requestMirror` filter does the same for an HTTPRoute. See [requestMirror](/documentation/providers/kubernetes#requestmirror).
