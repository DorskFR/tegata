# Configuration

Every setting is an environment variable, and all but `TEGATA_SHUTDOWN_DELAY_SECONDS` are also
flags: `tegata --help` lists them.

## Server

| Variable | Default | Effect |
|---|---|---|
| `TEGATA_PUBLIC_URL` | required | The URL browsers use. Passkeys are bound to its host, enrollment links start with it |
| `TEGATA_LISTEN` | `0.0.0.0:8080` | Admin UI, API and enrollment pages |
| `TEGATA_AUTHZ_LISTEN` | `0.0.0.0:8081` | Envoy `ext_authz` endpoint (`/authz`). Keep it off public routes |
| `TEGATA_RP_NAME` | `tegata` | Name shown in passkey prompts |
| `TEGATA_SETUP_TOKEN` | random, in `<data dir>/setup-token` | Token needed to register the first passkey. Must not be empty |
| `TEGATA_SESSION_HOURS` | `12` | Admin session lifetime |
| `TEGATA_SHUTDOWN_DELAY_SECONDS` | `5` | How long tegata keeps serving after SIGTERM, so a proxy calling `/authz` can drop the endpoint first |

## Backend

| Variable | Default | Effect |
|---|---|---|
| `TEGATA_BACKEND` | `local` | `local`, `openbao` or `memory` (see [Backends](../README.md#backends)) |
| `TEGATA_DATA_DIR` | `data` (`/data` in the image) | CA and state for `local`; CA only for `memory` |
| `TEGATA_CA_NAME` | `tegata device CA` | Subject of a newly generated local CA |
| `TEGATA_OPENBAO_ADDR` | | OpenBao address, required for `openbao` |
| `TEGATA_OPENBAO_TOKEN` | | Token auth |
| `TEGATA_OPENBAO_K8S_ROLE` | | Kubernetes auth role, used when no token is set |
| `TEGATA_OPENBAO_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount |
| `TEGATA_OPENBAO_CA_CERT` | | PEM file to trust for OpenBao's TLS |
| `TEGATA_OPENBAO_REQUIRE_TLS` | `false` | Refuse to start on a plain `http://` address that is not loopback. Without it tegata only warns |
| `TEGATA_OPENBAO_PKI_MOUNT` | `pki` | PKI secrets engine mount |
| `TEGATA_OPENBAO_PKI_ROLE` | `device` | PKI role that issues device certificates |
| `TEGATA_OPENBAO_KV_MOUNT` | `secret` | KV v2 mount for the state |
| `TEGATA_OPENBAO_KV_PATH` | `tegata/state` | Secret that holds the state |

## Certificates

| Variable | Default | Effect |
|---|---|---|
| `TEGATA_DEFAULT_VALIDITY_DAYS` | `365` | Validity preselected for a new device |
| `TEGATA_MAX_VALIDITY_DAYS` | what the CA has left | Longest validity offered |
| `TEGATA_EXPIRING_DAYS` | `14` | A device with fewer days left shows as `expiring` |
| `TEGATA_STALE_DAYS` | `30` | Flag a device in use but not seen for this long; `0` turns it off |
| `TEGATA_ENROLLMENT_MINUTES` | `30` | Lifetime of a one-time enrollment link |
| `TEGATA_CRL_REFRESH_MINUTES` | `60` | How often the CRL is rebuilt and republished |

## Gateway

| Variable | Default | Effect |
|---|---|---|
| `TEGATA_TRUST_CONFIGMAP` | | `namespace/name` of a ConfigMap kept filled with `ca.crt` and `ca.crl` |
| `TEGATA_EXTRA_CA_FILES` | | Comma-separated PEM files of more CAs to publish alongside tegata's own |
| `TEGATA_EXTRA_CRL_FILES` | | Comma-separated PEM CRLs to publish, one per extra CA |
| `TEGATA_AUTHZ_ALLOW_UNKNOWN` | `false` | Let `/authz` accept certificates tegata did not issue, e.g. while migrating from another CA |
| `TEGATA_MAX_STATE_AGE_SECONDS` | `30` | When the state could not be reloaded for this long, `/authz` answers 503 and `/healthz` on the main port reports not ready. `/healthz` on the authz port stays a liveness check |
| `TEGATA_TRUSTED_HOPS` | `0` | Proxies in front of the gateway that append to `X-Forwarded-For`. The last seen IP is the entry this many places from the end; earlier entries come from the client |
| `TEGATA_SERVICE_IDENTITIES` | | JSON file of [service identities](deployment.md#service-identities), re-read every 5 seconds |
