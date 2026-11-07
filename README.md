# tegata

Mint, install, rotate and revoke mTLS client certificates for your own devices, from a
web page.

*Tegata* (手形) were the passes travellers showed at Edo-period checkpoints. This is the
same thing for a reverse proxy that asks for a client certificate.

## What it does

- **One certificate per device.** You name it, assign an owner, pick a validity.
- **One-scan install.** Creating a device shows a QR code, a one-time link and a
  password. On an iPhone or iPad the link installs a configuration profile; elsewhere
  it downloads a `.p12`. The link works once and expires after 30 minutes; the
  password is only shown on the admin screen, so the link alone is useless.
- **Rotation without downtime.** Rotating issues a replacement; the old certificate keeps
  working until the new one is downloaded, then it is revoked. On Apple devices the new
  profile replaces the old one.
- **Revocation the gateway enforces.** tegata publishes its CA and CRL to a Kubernetes
  ConfigMap that Envoy Gateway (or anything that reads PEM) uses for client validation.
- **Last seen.** As an Envoy `ext_authz` service, tegata records when and from where each
  certificate was last used and rejects revoked ones immediately, before the CRL even
  propagates.
- **Passkey login.** The admin UI has no passwords. The first passkey is registered with
  a setup token printed in the log.

## Backends

| `TEGATA_BACKEND` | Certificates | State |
|---|---|---|
| `local` (default) | CA in `$TEGATA_DATA_DIR/ca` | `$TEGATA_DATA_DIR/state.json` |
| `openbao` | OpenBao PKI role (the CA key never leaves OpenBao) | one KV v2 secret, check-and-set |
| `memory` | local CA | memory, for trying it out |

PKCS#12 files use 3DES with a SHA-1 MAC on purpose: it is the one combination every
iOS, Android, macOS, Windows and Firefox keystore imports.

## Running it

```sh
make ui                                     # build the UI the binary embeds
TEGATA_PUBLIC_URL=http://localhost:8080 cargo run
```

Open the URL, enter the setup token from the log and register a passkey. For UI work,
run `make run` and `make ui/dev`, then use `http://localhost:5173`.

Every setting is a flag or an environment variable: `tegata --help`. On SIGTERM tegata
keeps serving for `TEGATA_SHUTDOWN_DELAY_SECONDS` (default 5) so a proxy calling `/authz`
can drop the endpoint first.

### OpenBao

The role tegata uses needs:

```hcl
path "<pki>/issue/<role>" { capabilities = ["create", "update"] }
path "<pki>/revoke"       { capabilities = ["create", "update"] }
path "<pki>/crl/rotate"   { capabilities = ["read"] }
path "<kv>/data/<path>"   { capabilities = ["create", "update", "read"] }
```

The PKI role should set `client_flag = true`, `server_flag = false` and
`allow_any_name = true`. Turn CRL `auto_rebuild` off: tegata rebuilds the CRL after every
revocation and on a timer (`TEGATA_CRL_REFRESH_MINUTES`), so keep the CRL `expiry`
comfortably longer than that.

### Envoy Gateway

Set `TEGATA_TRUST_CONFIGMAP=<namespace>/<name>` and reference that ConfigMap from the
listener's `ClientTrafficPolicy`:

```yaml
tls:
  clientValidation:
    mode: VerifyIfGiven            # new devices must reach /enroll without a certificate
    caCertificateRefs:
      - { kind: ConfigMap, name: tegata-trust }
    crl:
      refs:
        - { kind: ConfigMap, name: tegata-trust }
headers:
  xForwardedClientCert:
    mode: SanitizeSet
```

Route `/enroll/`, `/api/enroll/` and `/_app/` without a certificate requirement and
everything else with one. To enable last seen and instant revocation, add `extAuth`
to the `SecurityPolicy` of any route you protect:

```yaml
extAuth:
  failOpen: true                   # the CRL still applies if tegata is down
  headersToExtAuth: [x-forwarded-client-cert, x-forwarded-for, user-agent]
  http:
    backendRefs: [{ name: tegata, namespace: <ns>, port: 8081 }]
    path: /authz
```

Port 8081 (`TEGATA_AUTHZ_LISTEN`) only serves `/authz`; keep it off public routes.
While migrating from another CA, `TEGATA_AUTHZ_ALLOW_UNKNOWN=true` lets certificates
tegata did not issue through.

## API

See [docs/api.md](docs/api.md).

## License

WTFPL.
