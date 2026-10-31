# Podman provider

> Since 0.12

The Podman provider discovers entrypoints from Podman containers. Sōzune connects to a Podman socket (which speaks the Docker API), lists running containers, and reads `sozune.*` labels declared at run time.

Podman exposes a Docker-compatible API, so this provider shares its label syntax and most of its semantics with the [Docker provider](docker.md). Use it when your containers run under Podman instead of (or alongside) Docker — for example rootless setups, or hosts that don't have a Docker daemon.

## Configuration

```yaml
providers:
  podman:
    enabled: true
    endpoint: "/run/user/1000/podman/podman.sock"
    expose_by_default: false
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Podman provider |
| `endpoint` | `$XDG_RUNTIME_DIR/podman/podman.sock`, or `/run/podman/podman.sock` when `XDG_RUNTIME_DIR` is unset | Podman API socket, as a path or a `unix://` URL, or a remote Podman over plain TCP, as a `tcp://` or `http://` URL (since 0.16). Must speak the Docker API (Podman v3+ does by default). |
| `expose_by_default` | `false` | If `true`, every running container is a candidate even without `sozune.enable=true` |

Any other value stops Sōzune at start-up (since 0.16): it used to reach the local Docker daemon instead, without a word.

## How it works

The Podman provider is the [Docker provider](docker.md) pointed at a Podman socket. It reuses the same label parser, the same event listener, and the same HEALTHCHECK gating contract. Anything documented for Docker labels works under Podman without modification. Its routes are tagged `source: "podman"`.

## Labels

See [Docker labels](docker.md) — every `sozune.*` label is recognised identically.

## Example

```bash
podman run -d --name my-api \
  --label sozune.enable=true \
  --label sozune.http.api.host=api.example.com \
  --label sozune.http.api.port=8080 \
  my-api:latest
```

Sōzune picks it up on the next `start` event without restart.

## Environment variables

| Field | Env var |
|---|---|
| `providers.podman.enabled` | `SOZUNE_PROVIDER_PODMAN_ENABLED` |
| `providers.podman.endpoint` | `SOZUNE_PROVIDER_PODMAN_ENDPOINT` |
| `providers.podman.expose_by_default` | `SOZUNE_PROVIDER_PODMAN_EXPOSE_BY_DEFAULT` |
