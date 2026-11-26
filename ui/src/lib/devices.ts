import type { Cert, Device, Enrollment } from './api';
import { isPast } from './format';

export function certsOf(device: Device): Cert[] {
	return [device.cert, device.rotation, ...device.history].filter((c): c is Cert => c !== null);
}

/** Revoked in tegata, but not yet on the CA's CRL. */
export function revocationPending(device: Device): boolean {
	return certsOf(device).some((c) => c.revocation_pending);
}

export type LinkState = 'installed' | 'expired' | 'revoked' | 'open';

/** What became of the certificate an enrollment link was issued for. */
export function linkState(device: Device, enrollment: Enrollment, now = Date.now()): LinkState {
	const issued = certsOf(device).find((c) => c.serial === enrollment.serial);
	if (issued?.enrolled_at) return 'installed';
	if (isPast(enrollment.expires_at, now)) return 'expired';
	if (issued && issued.state !== 'pending') return 'revoked';
	return 'open';
}
