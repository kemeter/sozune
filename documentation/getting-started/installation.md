# Installation

## Docker (recommended)

```bash
docker run -d \
  --name sozune \
  -p 80:80 -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/sozune/config.yaml \
  ghcr.io/kemeter/sozune:latest
```

## From source

Requirements: stable Rust, Cargo.

```bash
git clone https://github.com/kemeter/sozune
cd sozune
cargo build --release
./target/release/sozune
```

## Running as non-root

The image runs as `root` by default so it works out of the box: it can bind to ports `80`/`443` and read `/var/run/docker.sock` without extra configuration.

If you'd rather run as the unprivileged `nonroot` user (UID `65532`) baked into the distroless base image, override `user` and grant the necessary capability + group:

```yaml
services:
  sozune:
    image: ghcr.io/kemeter/sozune:latest
    user: "65532:65532"
    cap_add:
      - NET_BIND_SERVICE
    group_add:
      - "997"  # GID of the `docker` group on the host (varies — check with `getent group docker`)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config.yaml:/config.yaml:ro
```

The `group_add` value must match your host's `docker` group GID. Without it, sozune cannot read the Docker socket.

## Verify the install

`/health` is exposed by the [REST API](/documentation/configuration/api), not by the proxy itself. With the API enabled (default port `127.0.0.1:3035`):

```bash
curl http://127.0.0.1:3035/health
```

You should get `200 OK`. Next: [Quick start](/documentation/getting-started/quick-start).
