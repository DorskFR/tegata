PUBLIC_URL ?= http://localhost:5173

.PHONY: build check test fmt lint ui ui/dev run image

ui:  ## Build the UI that the server embeds
	cd ui && npm ci && npm run build

build: ui  ## Release build with the UI embedded
	cargo build --release

check:
	cargo check

fmt:
	cargo +nightly fmt

lint:
	cargo +nightly fmt --check
	cargo clippy --all-targets -- -D warnings
	cd ui && npm run check && npm run lint

test:
	cargo test
	cd ui && npm test

run:  ## Server on :8080 with a local CA under ./data
	TEGATA_PUBLIC_URL=$(PUBLIC_URL) cargo run

ui/dev:  ## Vite on :5173, proxying the API to `make run`
	cd ui && npm run dev

image:
	docker build -f deploy/Dockerfile -t tegata:dev .
