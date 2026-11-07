# tegata

Mint, install, rotate and revoke mTLS client certificates for your own devices, from a web page.

[![CI](https://github.com/DorskFR/tegata/actions/workflows/ci.yml/badge.svg)](https://github.com/DorskFR/tegata/actions/workflows/ci.yml)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/devices-dark.png">
  <img alt="tegata device list: six fake devices with their owner, groups, status (pending, active, rotation waiting, revoked, expiring), expiry, last seen address and certificate fingerprint" src="docs/assets/devices-light.png" width="900">
</picture>

^ one certificate per device. "rotation waiting" means a replacement is issued and the old
certificate keeps working until the device downloads the new one.

You put a reverse proxy in front of your self-hosted apps and want it to ask for a client
certificate, but making a `.p12` with `openssl` and getting it onto a phone is the part
nobody enjoys. tegata runs the CA for you (its own, or an OpenBao PKI role), hands each
device its certificate through a QR code, and publishes the CA and CRL where the gateway
reads them. *Tegata* (手形) were the passes travellers showed at Edo-period checkpoints.

## Features

- One certificate per device, with an owner, groups and a validity you pick.
- One-scan install: a QR code and a one-time link that installs a configuration profile on
  iPhone and iPad and downloads a `.p12` elsewhere. The link works once and expires after
  30 minutes; the password is only shown on the admin screen.
- Rotation without downtime: the old certificate keeps working until the new one is
  downloaded, then it is revoked.
- Revocation the gateway enforces: tegata keeps a Kubernetes ConfigMap filled with its CA
  and CRL for Envoy Gateway, or anything that reads PEM.
- Last seen and instant revocation as an Envoy `ext_authz` service, plus per-app access by
  group.
- Passkey login for the admin UI, no passwords.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/enroll-dark.png">
  <img alt="Enrollment panel for a new device: QR code, one-time link, password and a 30 minute countdown" src="docs/assets/enroll-light.png" width="900">
</picture>

^ what you see after creating a device. Scan the code with the device; the link alone is
useless without the password shown here.

## Quick start

You need Rust 1.94+ and Node 26 (the UI is built and embedded into the binary).

```sh
git clone https://github.com/DorskFR/tegata && cd tegata
make ui
TEGATA_PUBLIC_URL=http://localhost:8080 cargo run
```

```text
WARN tegata::config: no passkey registered yet: open the app and use this setup token setup_token=tVaZ…
INFO tegata: tegata listening listen=0.0.0.0:8080 authz_listen=0.0.0.0:8081 public_url=http://localhost:8080/
```

Open http://localhost:8080, paste the setup token from the log and register a passkey: that
is the admin account. Then create a device and scan the QR code. The CA and all state are in
`./data` (`ca/ca.key`, `ca/ca.crt`, `state.json`); back up that folder.

Passkeys need HTTPS, or `localhost` as here. For a phone to install anything,
`TEGATA_PUBLIC_URL` must be an address the phone can reach.

## Run the container

The image is `ghcr.io/dorskfr/tegata:<version>`, built on every release tag.

```yaml
# compose.yaml
services:
  tegata:
    image: ghcr.io/dorskfr/tegata:0.6.0
    ports: ["8080:8080"]
    volumes: ["./data:/data"]
    environment:
      TEGATA_PUBLIC_URL: https://tegata.example.com
```

The container runs as uid 65532, so give it the data folder, then start it:

```sh
mkdir data && docker run --rm -v "$PWD/data:/data" busybox chown 65532:65532 /data
docker compose up -d
docker compose logs tegata | grep setup_token
```

To update, change the tag and run `docker compose up -d` again. Putting it behind Envoy Gateway, with OpenBao as the CA,
is covered in [docs/deployment.md](docs/deployment.md).

## Backends

| `TEGATA_BACKEND` | Certificates | State |
|---|---|---|
| `local` (default) | CA in `$TEGATA_DATA_DIR/ca`, valid 10 years | `$TEGATA_DATA_DIR/state.json` |
| `openbao` | OpenBao PKI role (the CA key never leaves OpenBao) | one KV v2 secret, check-and-set, shareable by replicas |
| `memory` | local CA | memory, for trying it out |

## Configuration

The settings most people touch. All of them are in
[docs/configuration.md](docs/configuration.md) and `tegata --help`.

| Variable | Default | Effect |
|---|---|---|
| `TEGATA_PUBLIC_URL` | required | URL browsers and devices use; passkeys are bound to its host |
| `TEGATA_BACKEND` | `local` | `local`, `openbao` or `memory` |
| `TEGATA_DATA_DIR` | `data` (`/data` in the image) | Where the local CA and state live |
| `TEGATA_DEFAULT_VALIDITY_DAYS` | `365` | Validity preselected for a new device |
| `TEGATA_ENROLLMENT_MINUTES` | `30` | Lifetime of a one-time install link |
| `TEGATA_TRUST_CONFIGMAP` | | `namespace/name` of the ConfigMap to fill with `ca.crt` and `ca.crl` |

The HTTP API is documented in [docs/api.md](docs/api.md).

## Limitations

- Any registered passkey is a full admin. There are no roles.
- tegata does not terminate TLS or check certificates itself; your gateway does that.
- Last seen, per-app access and instant revocation need a gateway that calls `/authz`
  (Envoy `ext_authz`). Without it, revocation takes effect when the gateway reloads the CRL.
- Publishing the trust bundle is built in only for a Kubernetes ConfigMap. Elsewhere, fetch
  `/ca.crt` and `/crl.pem`.
- PKCS#12 files use 3DES with a SHA-1 MAC on purpose: it is the one combination every iOS,
  Android, macOS, Windows and Firefox keystore imports.

## Development

```sh
make test          # cargo test + vitest
make lint          # rustfmt (nightly), clippy, svelte-check, prettier, eslint
make run           # server on :8080, public URL http://localhost:5173
make ui/dev        # in a second shell: Vite on :5173, proxying the API to :8080
```

To regenerate the screenshots in `docs/assets/`, start an empty in-memory instance and run
the Playwright script, which registers a virtual passkey and seeds fake devices:

```sh
TEGATA_BACKEND=memory TEGATA_DATA_DIR=$(mktemp -d) TEGATA_SETUP_TOKEN=readme-demo-token \
  TEGATA_LISTEN=127.0.0.1:5440 TEGATA_AUTHZ_LISTEN=127.0.0.1:5441 \
  TEGATA_PUBLIC_URL=http://localhost:5440 cargo run &
cd ui && npx playwright install chromium && npm run readme:shots
```

## License

[WTFPL](LICENSE)
