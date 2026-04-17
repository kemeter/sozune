.PHONY: all build build-dashboard run test fmt clean

all: build

build: build-dashboard
	cargo build --release

build-dashboard:
	cd dashboard && bun install && bun run build

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
