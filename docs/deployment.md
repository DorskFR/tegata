# Deployment

How to run tegata behind a gateway that checks client certificates. The examples use
OpenBao for the CA and Envoy Gateway on Kubernetes; anything that reads a PEM CA and CRL
can do the gateway part.

## Container

The image is built from [`deploy/Dockerfile`](../deploy/Dockerfile) and published to
`ghcr.io/dorskfr/tegata:<version>` on every `v*` tag. It runs as non-root, listens on
`8080` (admin and enrollment) and `8081` (`/authz`), and keeps the `local` backend's data
in `/data`.

On SIGTERM tegata keeps serving for `TEGATA_SHUTDOWN_DELAY_SECONDS` (default 5) so a
proxy calling `/authz` can drop the endpoint first.

## OpenBao

With `TEGATA_BACKEND=openbao` certificates come from an OpenBao PKI role (the CA key never
leaves OpenBao) and the state is one KV v2 secret written with check-and-set, so several
replicas can share it. The role tegata uses needs:

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

Authenticate with `TEGATA_OPENBAO_TOKEN`, or with Kubernetes auth through
`TEGATA_OPENBAO_K8S_ROLE`. All OpenBao settings are in [configuration.md](configuration.md#backend).

## Envoy Gateway

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

## Per-app access

Every host seen on `/authz` shows up on the Apps page. An app is open to every valid
device until you restrict it to one or more groups; then only devices in one of those
groups pass. tegata refuses a change that would lock the current browser's certificate
out of tegata itself unless you confirm it. The API is in [api.md](api.md#apps).
