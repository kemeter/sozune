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
    group_add:
      - "${DOCKER_GID:?export DOCKER_GID=$(stat -c %g /var/run/docker.sock)}"
    environment:
      CONFIG_PATH: /etc/sozune/config.yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config.yaml:/etc/sozune/config.yaml

  whoami:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.whoami.host=whoami.localhost"
```

The image runs as a non-root user: `group_add` lets it open the Docker socket, and `CONFIG_PATH` points it at the mounted file, which it would otherwise not read. See [Running as non-root](/documentation/getting-started/installation#running-as-non-root).

## 2. Sōzune config

`config.yaml`:

```yaml
providers:
  docker:
    enabled: true
    expose_by_default: false

api: {}

proxy:
  http:
    listen_address: 80
  https:
    listen_address: 443
```

`providers`, `api` and `proxy` (with `http` and `https`) must be present, even empty: `api: {}` keeps the API off.

## 3. Run

```bash
export DOCKER_GID=$(stat -c %g /var/run/docker.sock)
docker compose up -d
curl -H "Host: whoami.localhost" http://localhost
```

## What's next

- [Full Docker labels reference](/documentation/providers/docker)
- [REST API](/documentation/configuration/api)
- [TCP routing](/documentation/routing/tcp) for non-HTTP services
