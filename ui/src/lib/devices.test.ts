import { describe, expect, it } from 'vitest';
import type { Cert, Device, Enrollment } from './api';
import { linkState, revocationPending } from './devices';

const cert = (serial: string, over: Partial<Cert> = {}): Cert => ({
	serial,
	fingerprint_sha256: `fp-${serial}`,
	not_before: '2030-01-01T00:00:00Z',
	not_after: '2031-01-01T00:00:00Z',
	state: 'pending',
	enrolled_at: null,
	revoked_at: null,
	enrollment_expires_at: '2030-01-01T00:30:00Z',
	revocation_pending: false,
	...over
});

const device = (over: Partial<Device> = {}): Device => ({
	id: 'd',
	name: 'phone',
	owner: 'me',
	groups: [],
	created_at: '2030-01-01T00:00:00Z',
	status: 'pending',
	cert: null,
	rotation: null,
	history: [],
	last_seen: null,
	stale: false,
	...over
});

const link: Enrollment = {
	serial: 'new',
	url: 'https://tegata.test/enroll/x',
	password: 'abcd-efgh-ijkm-nopq',
	expires_at: '2030-01-01T00:30:00Z'
};
const before = Date.parse('2030-01-01T00:10:00Z');
const after = Date.parse('2030-01-01T01:00:00Z');

describe('linkState', () => {
	it('is open while the cert waits and the link is valid', () => {
		expect(linkState(device({ cert: cert('new') }), link, before)).toBe('open');
	});
	it('is installed once that cert was downloaded, even after the link time', () => {
		const done = cert('new', { state: 'active', enrolled_at: '2030-01-01T00:05:00Z' });
		expect(linkState(device({ status: 'active', cert: done }), link, after)).toBe('installed');
	});
	it('stays expired after the sweep revokes the unused cert', () => {
		const swept = cert('new', { state: 'revoked', revoked_at: '2030-01-01T00:31:00Z' });
		expect(linkState(device({ status: 'revoked', cert: swept }), link, after)).toBe('expired');
	});
	it('does not call a rotation installed when only the old cert is active', () => {
		const old = cert('old', { state: 'active', enrolled_at: '2029-01-01T00:00:00Z' });
		const swept = cert('new', { state: 'revoked', revoked_at: '2030-01-01T00:31:00Z' });
		const d = device({ status: 'active', cert: old, history: [swept] });
		expect(linkState(d, link, after)).toBe('expired');
	});
	it('is revoked when the admin revoked the device before the download', () => {
		const revoked = cert('new', { state: 'revoked', revoked_at: '2030-01-01T00:08:00Z' });
		expect(linkState(device({ status: 'revoked', cert: revoked }), link, before)).toBe('revoked');
	});
});

describe('revocationPending', () => {
	it('looks at every cert of the device', () => {
		expect(revocationPending(device({ cert: cert('a') }))).toBe(false);
		const waiting = cert('b', { state: 'revoked', revocation_pending: true });
		expect(revocationPending(device({ cert: cert('a'), history: [waiting] }))).toBe(true);
	});
});
