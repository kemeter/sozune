# Sōzune

Sōzune (pronounce *Sozuné*) is a modern reverse proxy built on [Sōzu](https://github.com/sozu-proxy/sozu). It discovers your services through Docker labels, manages Let's Encrypt certificates automatically, and applies your changes without restarting.

## Features

- **Docker auto-discovery** — declare your routes through labels, Sōzune finds them.
- **Automatic HTTPS** — ACME (Let's Encrypt) provisioning and renewal, no intervention.
- **HTTP/2** — negotiated through ALPN on every TLS listener.
- **Hot reload** — REST API applies changes on the fly, no downtime.
- **Wildcard & regex hostnames** — `*.example.com`, `/cdn[0-9]+/.example.com`.
- **Multi-protocol** — HTTP, HTTPS, WebSocket, raw TCP passthrough.

## Quick start

```yaml
# compose.yaml
services:
  sozune:
    image: ghcr.io/kemeter/sozune:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config.yaml:/etc/sozune/config.yaml

  whoami:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.whoami.host=whoami.localhost"
```

```yaml
# config.yaml
providers:
  docker:
    enabled: true

proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
```

```bash
docker compose up -d
curl -H "Host: whoami.localhost" http://localhost
```

## Documentation

- [Installation](documentation/getting-started/installation.md) · [Quick start](documentation/getting-started/quick-start.md)
- [Docker labels reference](documentation/configuration/docker-labels.md)
- [Configuration file & env vars](documentation/configuration/overview.md)
- [REST API](documentation/configuration/api.md)
- Routing — [Hostnames](documentation/routing/hostnames.md) · [Path matching](documentation/routing/path-matching.md) · [Load balancing](documentation/routing/load-balancing.md) · [TCP](documentation/routing/tcp.md)
- TLS — [Overview](documentation/tls/overview.md) · [ACME / Let's Encrypt](documentation/tls/acme.md)
- Middleware — [Basic auth](documentation/middleware/auth.md) · [Custom headers](documentation/middleware/headers.md) · [Strip prefix](documentation/middleware/strip-prefix.md) · [Redirects](documentation/middleware/redirects.md) · [Rate limit](documentation/middleware/rate-limit.md) · [Response compression](documentation/middleware/compress.md) · [Backend timeout](documentation/middleware/backend-timeout.md)
- Advanced — [Health checks](documentation/advanced/health-checks.md) · [WebSocket](documentation/advanced/websocket.md) · [Access logs](documentation/advanced/access-logs.md) · [Debugging](documentation/advanced/debugging.md)

## Architecture

```
┌─────────────────┐       ┌─────────────────┐
│   Docker API    │ ────▶ │     Sōzune      │
│   (events)      │       │  (discovery)    │
└─────────────────┘       └─────────────────┘
                           ▲       │
┌─────────────────┐        │       │
│   Config file   │ ───────┘       │
│  (entrypoints)  │                │
└─────────────────┘                ▼
                           ┌─────────────────┐       ┌─────────────────┐
                           │     Storage     │ ────▶ │      Proxy      │
                           │  (entrypoints)  │       │     (Sōzu)      │
                           └─────────────────┘       └─────────────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │    REST API     │
                           │  (monitoring)   │
                           └─────────────────┘
```

## Default ports

| Port | Service |
|---|---|
| `80` | HTTP proxy |
| `443` | HTTPS proxy |
| `3035` | REST API |
| `3036` | ACME HTTP-01 challenge (loopback) |
| `3037` | Internal middleware proxy (loopback) |

## Contributing

Pull requests welcome.

## License

MIT — see [LICENSE.md](LICENSE.md).
