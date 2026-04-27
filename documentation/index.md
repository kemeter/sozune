# Sozune

The modern reverse proxy, without the painful config.

Sozune is a reverse proxy built on [Sōzu](https://github.com/sozu-proxy/sozu). It discovers your services through Docker labels, manages Let's Encrypt certificates automatically, and applies your changes without restarting.

## Why Sozune

- **Docker auto-discovery** — declare your routes through labels, Sozune finds them.
- **Automatic HTTPS** — ACME provisioning and renewal, no intervention.
- **HTTP/2 by default** — negotiated through ALPN on every TLS listener.
- **Hot reload** — the REST API applies changes on the fly, no downtime.

## Get started

- [Installation](/documentation/installation)
- [Quick start](/documentation/quick-start)

## Configuration

- [Configuration overview](/documentation/overview)
- [Docker labels](/documentation/docker-labels)
- [HTTP provider](/documentation/http-provider)
- [REST API](/documentation/api)

## Routing

- [Hostnames](/documentation/hostnames)
- [Path matching](/documentation/path-matching)
- [Load balancing](/documentation/load-balancing)

## TLS

- [TLS overview](/documentation/tls-overview)
- [ACME / Let's Encrypt](/documentation/acme)

## Middleware

- [Basic auth](/documentation/auth)
- [Custom headers](/documentation/headers)
- [Strip prefix](/documentation/strip-prefix)
- [HTTPS redirect](/documentation/https-redirect)
- [Rate limit](/documentation/rate-limit)
- [Gzip compression](/documentation/compress)
- [Backend timeout](/documentation/backend-timeout)

## Advanced

- [Health checks](/documentation/health-checks)
- [WebSocket](/documentation/websocket)
- [Access logs](/documentation/access-logs)
