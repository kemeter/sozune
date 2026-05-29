# Sōzune

The modern reverse proxy. Routing you can read, configured the way you already describe your services.

Sōzune is a reverse proxy built on [Sōzu](https://github.com/sozu-proxy/sozu). It discovers your services across Docker, Podman, Swarm, Kubernetes, Nomad, or a YAML file, manages Let's Encrypt certificates automatically, and applies your changes without restarting.

![Sōzune dashboard](/documentation/assets/dashboard-entrypoints.png)

## Why Sōzune

- **Multi-platform service discovery** — Docker, Podman, Swarm, Kubernetes, Nomad, an HTTP endpoint, or a YAML file.
- **Automatic HTTPS** — ACME provisioning and renewal, no intervention.
- **HTTP/2 by default** — negotiated through ALPN on every TLS listener.
- **Hot reload** — the REST API applies changes on the fly, no downtime.
- **Built-in diagnostics** — an `X-Sozune-Diagnostic` header on every routing failure, plus explanatory `502` bodies and a did-you-mean for mistyped hosts under `SOZUNE_DEBUG`.

## How it works

```
   From the Internet              Sōzune                       To your infrastructure

  ┌──────────────────┐               ┌───────────┐                ┌──────────────────┐
  │ api.domain.com   │── HTTPS ─┐    │ Security  │             ┌─▶│   Kubernetes     │
  └──────────────────┘          │    ├───────────┤             │  └──────────────────┘
  ┌──────────────────┐          │    │  Routing  │             │  ┌──────────────────┐
  │ domain.com       │── HTTP ──┼───▶│  Engine   │─────────────┼─▶│ Docker · Podman  │
  └──────────────────┘          │    ├───────────┤             │  │ Swarm · Nomad    │
  ┌──────────────────┐          │    │ ACME/TLS  │             │  └──────────────────┘
  │ shop.domain.com  │── TCP ───┘    │ Hot reload│             │  ┌──────────────────┐
  └──────────────────┘               └───────────┘             └─▶│ Bare metal / VM  │
                                                                   └──────────────────┘
```

Sōzune watches your platform for service definitions, builds routes from labels, tags,
or files, terminates TLS, and hands traffic to the right backend — reconfiguring live
as services come and go.

## New here?

Point Sōzune at your services and have your first route live in a couple of minutes.

<a class="doc-cta" href="/documentation/getting-started/quick-start">
  <span class="doc-cta-title">Quick start</span>
  <span class="doc-cta-desc">Install Sōzune and expose your first service.</span>
</a>

Already running? The full table of contents lives in the sidebar — pick a provider, dive into routing and TLS, or browse the middleware reference.
