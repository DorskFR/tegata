# HTTP API

All JSON. Timestamps are RFC 3339 strings. The admin API (`/api/*` except
`/api/session`, `/api/auth/*` and `/api/enroll/*`) needs a session cookie set by a
passkey login. Mutating requests must send `Content-Type: application/json` and an
`Origin` matching the configured public URL.

Errors: non-2xx with `{ "error": "<message>" }`.

## Session and passkeys

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/session` | | `Session` |
| POST | `/api/auth/register/start` | `{ "name": string, "setup_token"?: string }` | `{ "publicKey": PublicKeyCredentialCreationOptionsJSON }` |
| POST | `/api/auth/register/finish` | `RegistrationResponseJSON` (from `credential.toJSON()`) | `204` |
| POST | `/api/auth/login/start` | `{}` | `{ "publicKey": PublicKeyCredentialRequestOptionsJSON }` |
| POST | `/api/auth/login/finish` | `AuthenticationResponseJSON` (from `credential.toJSON()`) | `204`, sets cookie |
| POST | `/api/auth/logout` | | `204` |
| GET | `/api/passkeys` | | `Passkey[]` |
| DELETE | `/api/passkeys/{id}` | | `204` (refused for the last passkey) |

Registration without a session is only allowed while no passkey exists, and needs the
setup token printed in the server log at startup. A successful first registration also
logs the browser in.

The options objects are WebAuthn JSON: feed them to
`PublicKeyCredential.parseCreationOptionsFromJSON(publicKey)` /
`parseRequestOptionsFromJSON(publicKey)`, then send `credential.toJSON()` back.

```ts
type Session = { authenticated: boolean; setup_required: boolean; rp_name: string };
type Passkey = { id: string; name: string; created_at: string; last_used_at: string | null };
```

## Devices

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/devices` | | `Device[]` |
| POST | `/api/devices` | `{ "name": string, "owner": string, "validity_days": number }` | `Created` |
| POST | `/api/devices/{id}/rotate` | `{ "validity_days"?: number }` | `Created` |
| POST | `/api/devices/{id}/enrollment` | | `Created` (new link + password for a still-pending cert) |
| POST | `/api/devices/{id}/revoke` | | `Device` |
| DELETE | `/api/devices/{id}` | | `204` (only when nothing is active or pending) |
| GET | `/api/config` | | `Config` |

```ts
type DeviceStatus = 'pending' | 'active' | 'expiring' | 'expired' | 'revoked';
type CertState = 'pending' | 'active' | 'superseded' | 'revoked' | 'expired';
type Cert = {
  serial: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  state: CertState;
  enrolled_at: string | null;
  revoked_at: string | null;
  enrollment_expires_at: string | null;
};
type Device = {
  id: string;
  name: string;
  owner: string;
  created_at: string;
  status: DeviceStatus;
  cert: Cert | null;        // the cert currently in use
  rotation: Cert | null;    // a replacement waiting to be installed
  history: Cert[];          // older certs, newest first
  last_seen: { at: string; ip: string | null; user_agent: string | null } | null;
};
type Created = {
  device: Device;
  enrollment: { url: string; password: string; expires_at: string };
};
type Config = {
  validity_days: { default: number; max: number; presets: number[] };
  expiring_days: number;
  enrollment_minutes: number;
  ca_subject: string;
};
```

`expiring` means active with fewer than `expiring_days` left. Rotation issues a new
cert; the old one is revoked automatically the first time the new one is downloaded.

## Enrollment (public, no session)

The enrollment URL is `/enroll/{token}`, a page of the UI.

| Method | Path | Response |
|---|---|---|
| GET | `/api/enroll/{token}` | `{ "device_name": string, "expires_at": string }` or `404` |
| GET | `/enroll/{token}/profile.mobileconfig` | Apple configuration profile (consumes the token) |
| GET | `/enroll/{token}/device.p12` | PKCS#12 bundle (consumes the token) |

The password protecting both files is only shown on the admin screen that created the
link. A token works for one download and expires after `enrollment_minutes`.

## Other

| Method | Path | Response |
|---|---|---|
| GET | `/ca.crt` | CA certificate, PEM |
| GET | `/crl.pem` | current CRL, PEM |
| GET | `/healthz` | `ok` |
| any | `/authz/*` | Envoy ext_authz check on the separate `TEGATA_AUTHZ_LISTEN` port (default `:8081`): `200` for an active device cert, `403` otherwise |
