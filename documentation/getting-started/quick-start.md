# Quick start

Expose a service through Sōzune with Docker Compose in two minutes.

## 1. Minimal compose file

```yaml
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

## 2. Sōzune config

`config.yaml`:

```yaml
providers:
  docker:
    enabled: true
    expose_by_default: false

proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
```

## 3. Run

```bash
docker compose up -d
curl -H "Host: whoami.localhost" http://localhost
```

## What's next

- [Full Docker labels reference](/documentation/providers/docker)
- [REST API](/documentation/configuration/api)
- [TCP routing](/documentation/routing/tcp) for non-HTTP services
