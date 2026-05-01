# Sozune

The modern reverse proxy, without the painful config.

Sozune is a reverse proxy built on [Sōzu](https://github.com/sozu-proxy/sozu). It discovers your services across Docker, Swarm, Kubernetes, Nomad, or a YAML file, manages Let's Encrypt certificates automatically, and applies your changes without restarting.

![Sozune dashboard](/documentation/assets/dashboard-entrypoints.png)

## Why Sozune

- **Multi-platform service discovery** — Docker, Swarm, Kubernetes, Nomad, an HTTP endpoint, or a YAML file.
- **Automatic HTTPS** — ACME provisioning and renewal, no intervention.
- **HTTP/2 by default** — negotiated through ALPN on every TLS listener.
- **Hot reload** — the REST API applies changes on the fly, no downtime.

## Get started

- [Installation](/documentation/getting-started/installation)
- [Quick start](/documentation/getting-started/quick-start)

## Configuration

- [Configuration overview](/documentation/configuration/overview)
- [Docker labels](/documentation/configuration/docker-labels)
- [Swarm provider](/documentation/configuration/swarm-provider)
- [HTTP provider](/documentation/configuration/http-provider)
- [REST API](/documentation/configuration/api)
- [Dashboard](/documentation/configuration/dashboard)

## Routing

- [Hostnames](/documentation/routing/hostnames)
- [Path matching](/documentation/routing/path-matching)
- [Load balancing](/documentation/routing/load-balancing)
- [TCP](/documentation/routing/tcp)

## TLS

- [TLS overview](/documentation/tls/overview)
- [ACME / Let's Encrypt](/documentation/tls/acme)

## Middleware

- [Basic auth](/documentation/middleware/auth)
- [Custom headers](/documentation/middleware/headers)
- [Strip prefix](/documentation/middleware/strip-prefix)
- [Redirects](/documentation/middleware/redirects)
- [Rate limit](/documentation/middleware/rate-limit)
- [Response compression](/documentation/middleware/compress)
- [Backend timeout](/documentation/middleware/backend-timeout)

## Advanced

- [Health checks](/documentation/advanced/health-checks)
- [WebSocket](/documentation/advanced/websocket)
- [Access logs](/documentation/advanced/access-logs)
