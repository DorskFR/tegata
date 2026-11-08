# Development

The UI (SvelteKit, in `ui/`) is built by `make ui` and embedded into the binary.

```sh
make test          # cargo test + vitest
make lint          # rustfmt (nightly), clippy, svelte-check, prettier, eslint
make run           # server on :8080, public URL http://localhost:5173
make ui/dev        # in a second shell: Vite on :5173, proxying the API to :8080
```

## Screenshots

The images in `assets/` come from a Playwright script that registers a virtual passkey and
seeds fake devices against an empty in-memory instance:

```sh
TEGATA_BACKEND=memory TEGATA_DATA_DIR=$(mktemp -d) TEGATA_SETUP_TOKEN=readme-demo-token \
  TEGATA_LISTEN=127.0.0.1:5440 TEGATA_AUTHZ_LISTEN=127.0.0.1:5441 \
  TEGATA_PUBLIC_URL=http://localhost:5440 cargo run &
cd ui && npx playwright install chromium && npm run readme:shots
```
