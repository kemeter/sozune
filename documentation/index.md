# Sozune

The modern reverse proxy, without the painful config.

Sozune is a reverse proxy built on [Sōzu](https://github.com/sozu-proxy/sozu). It discovers your services through Docker labels, manages Let's Encrypt certificates automatically, and applies your changes without restarting.

## Why Sozune

- **Docker auto-discovery** — declare your routes through labels, Sozune finds them.
- **Automatic HTTPS** — ACME provisioning and renewal, no intervention.
- **HTTP/2 by default** — negotiated through ALPN on every TLS listener.
- **Hot reload** — the REST API applies changes on the fly, no downtime.

## Get started

- [Installation](/documentation/getting-started/installation)
- [Quick start](/documentation/getting-started/quick-start)

## Configuration

- [Configuration overview](/documentation/configuration/overview)
- [Docker labels](/documentation/configuration/docker-labels)
- [HTTP provider](/documentation/configuration/http-provider)
- [REST API](/documentation/configuration/api)

## Routing

- [Hostnames](/documentation/routing/hostnames)
- [Path matching](/documentation/routing/path-matching)
- [Load balancing](/documentation/routing/load-balancing)

## TLS

- [TLS overview](/documentation/tls/overview)
- [ACME / Let's Encrypt](/documentation/tls/acme)

## Middleware

- [Basic auth](/documentation/middleware/auth)
- [Custom headers](/documentation/middleware/headers)
- [Strip prefix](/documentation/middleware/strip-prefix)
- [Redirects](/documentation/middleware/redirects)
- [Rate limit](/documentation/middleware/rate-limit)
- [Gzip compression](/documentation/middleware/compress)
- [Backend timeout](/documentation/middleware/backend-timeout)

## Advanced

- [Health checks](/documentation/advanced/health-checks)
- [WebSocket](/documentation/advanced/websocket)
- [Access logs](/documentation/advanced/access-logs)
