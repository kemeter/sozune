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

## Verify the install

`/health` is exposed by the [REST API](/documentation/api), not by the proxy itself. With the API enabled (default port `127.0.0.1:3035`):

```bash
curl http://127.0.0.1:3035/health
```

You should get `200 OK`. Next: [Quick start](/documentation/quick-start).
