.PHONY: all build build-dashboard docker-build run test fmt clean

IMAGE ?= kemeter/sozune
TAG ?= latest
# Package version from Cargo.toml (first `version = "..."`, i.e. the [package] one).
VERSION := $(shell grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "(.*)"/\1/')

all: build

build: build-dashboard
	cargo build --release

build-dashboard:
	cd dashboard && bun install && bun run build

docker-build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):$(VERSION) .

run: build-dashboard
	cargo run

test:
	cargo test
	cd dashboard && bun run check && bun run lint

fmt:
	cargo fmt
	cd dashboard && bun run format

clean:
	cargo clean
	rm -rf dashboard/build dashboard/.svelte-kit
