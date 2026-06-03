# syntax=docker/dockerfile:1.7

FROM oven/bun:1-debian AS dashboard
WORKDIR /dashboard
COPY dashboard/package.json dashboard/bun.lock ./
RUN bun install --frozen-lockfile
COPY dashboard/ ./
RUN bun run build

# Pinned to 1.95.0: rustc 1.96 SIGSEGVs in thin-LTO codegen on this dependency set.
FROM rust:1.95.0-bookworm AS builder
# protobuf-compiler: sozu's build.rs runs protoc to generate command.rs.
# rustfmt: that same build.rs calls prost_build with .format(true), which shells
# out to rustfmt — absent from the base image, so the generated module is never
# written (E0583 "file not found for module command").
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt
WORKDIR /app
COPY . .
COPY --from=dashboard /dashboard/build ./dashboard/build
# Cache mounts keep the cargo registry, git checkouts and build artifacts warm
# across builds, so only changed crates recompile. target/ is a mount, so the
# binary must be copied out within the same RUN before the mount is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && cp target/release/sozune /sozune

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /sozune /sozune

EXPOSE 80 443
ENTRYPOINT ["/sozune"]
