# Installation

## Docker (recommended)

```bash
docker run -d \
  --name sozune \
  -p 80:80 -p 443:443 \
  --group-add $(stat -c %g /var/run/docker.sock) \
  -e CONFIG_PATH=/etc/sozune/config.yaml \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/sozune/config.yaml \
  ghcr.io/kemeter/sozune:latest
```

The image does not set `CONFIG_PATH`: without it, Sōzune looks for `config.yaml` in its working directory (`/home/nonroot`), ignores the mounted file and starts with the default configuration. `--group-add` gives it the host's `docker` group, needed to open the Docker socket (see [Running as non-root](#running-as-non-root)).

### Image tags

| Tag | Content |
|---|---|
| `latest` | The latest release. Use this one. |
| `0.14.0` (any release) | That release, never updated. |
| `edge` | The current state of `main`, rebuilt after every merge that passes CI. For trying a fix or feature before it is released: it is not a release, and can break at any time. `linux/amd64` only. |
| `sha-<full commit hash>` | The `main` build of that commit, never rebuilt. |

## Kubernetes (Helm)

> Since 0.16

```bash
git clone https://github.com/kemeter/sozune
helm install sozune ./sozune/charts/sozune --namespace sozune --create-namespace
```

See [Deploying Sōzune in-cluster](/documentation/providers/kubernetes#deploying-sōzune-in-cluster) for its values.

## From source

Requirements: stable Rust, Cargo.

```bash
git clone https://github.com/kemeter/sozune
cd sozune
cargo build --release
./target/release/sozune
```

## Running as non-root

> Since 0.14

The image runs as the unprivileged `nonroot` user (UID `65532`) of its distroless base. Binding ports `80`/`443` inside the container works as is. Two things need care:

- **The Docker socket.** It is usually `root:docker` with mode `660` on the host, so the container needs the socket's group: `--group-add $(stat -c %g /var/run/docker.sock)` with `docker run`, `group_add` in Compose, which takes it from `DOCKER_GID`: `export DOCKER_GID=$(stat -c %g /var/run/docker.sock)` before `docker compose up`. Without it, the Docker provider fails with `client error (Connect)`.
- **Writable paths.** Anything Sōzune writes, such as the ACME `certs_dir`, must be a volume UID `65532` can write to.

```yaml
services:
  sozune:
    image: ghcr.io/kemeter/sozune:latest
    group_add:
      - "${DOCKER_GID:?export DOCKER_GID=$(stat -c %g /var/run/docker.sock)}"
    environment:
      CONFIG_PATH: /etc/sozune/config.yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config.yaml:/etc/sozune/config.yaml:ro
```

## Verify the install

`/health` is exposed by the [REST API](/documentation/configuration/api), not by the proxy itself. With the API enabled (default port `127.0.0.1:3035`):

```bash
curl http://127.0.0.1:3035/health
```

In a container, that address is the container's own loopback: set `api.listen_address: "0.0.0.0:3035"` and publish the port on the host's loopback (`-p 127.0.0.1:3035:3035`) to reach it from the host.

You should get `200 OK`. Next: [Quick start](/documentation/getting-started/quick-start).
