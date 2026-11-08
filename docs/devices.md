# Devices

Each device has one client certificate, an owner, groups and a validity.

## Enrollment

Creating a device shows a QR code, a one-time link and a password.

- The link installs a configuration profile on iPhone and iPad and downloads a `.p12`
  elsewhere.
- It works once and expires after `TEGATA_ENROLLMENT_MINUTES` (default 30).
- The password is shown only on the admin screen; the link is useless without it.

## Status

| Status | Meaning |
|---|---|
| `pending` | Certificate issued, not yet downloaded |
| `active` | Certificate downloaded and valid |
| `expiring` | Active, fewer than `TEGATA_EXPIRING_DAYS` (default 14) left |
| `expired` | Last certificate past its expiry |
| `revoked` | Last certificate revoked |

"Rotation waiting" is an active device with a pending replacement. The old certificate stays
valid until the device downloads the new one, then it is revoked.

A device in use but not seen for `TEGATA_STALE_DAYS` (default 30) is flagged stale.

## Revocation

Revoked certificates go on the CRL, published with the CA to the ConfigMap named by
`TEGATA_TRUST_CONFIGMAP` and at `/ca.crt` and `/crl.pem`. A gateway calling `/authz`
(Envoy `ext_authz`) rejects them immediately and records last seen; see
[deployment.md](deployment.md#envoy-gateway).

## Name

*Tegata* (手形) were the passes travellers showed at Edo-period checkpoints.
