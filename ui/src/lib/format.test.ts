import { describe, expect, it } from 'vitest';
import { formatCountdown, relativeTime, shortFingerprint, statusLabel, statusTone } from './format';

const now = Date.parse('2026-01-01T12:00:00Z');
const shift = (ms: number) => new Date(now + ms).toISOString();

describe('relativeTime', () => {
	it('reads future days as "in N days"', () => {
		expect(relativeTime(shift(43 * 86_400_000), now)).toBe('in 43 days');
	});
	it('keeps days up to a year, then switches to years', () => {
		expect(relativeTime(shift(200 * 86_400_000), now)).toBe('in 200 days');
		expect(relativeTime(shift(400 * 86_400_000), now)).toBe('in 1 year');
	});
	it('reads past hours as "N hours ago"', () => {
		expect(relativeTime(shift(-3 * 3_600_000), now)).toBe('3 hours ago');
	});
	it('rounds to the nearest unit', () => {
		expect(relativeTime(shift(-(2 * 60_000 + 20_000)), now)).toBe('2 minutes ago');
	});
	it('collapses the last seconds', () => {
		expect(relativeTime(shift(-10_000), now)).toBe('just now');
		expect(relativeTime(shift(10_000), now)).toBe('in a moment');
	});
	it('handles missing or broken input', () => {
		expect(relativeTime(null, now)).toBe('—');
		expect(relativeTime('nope', now)).toBe('—');
	});
});

describe('status helpers', () => {
	it('maps every status to a label and tone', () => {
		expect(statusLabel('pending')).toBe('Pending');
		expect(statusLabel('expiring')).toBe('Expiring');
		expect(statusTone('active')).toBe('ok');
		expect(statusTone('revoked')).toBe('danger');
		expect(statusTone('expired')).toBe('neutral');
	});
});

describe('formatCountdown', () => {
	it('formats minutes and zero-padded seconds', () => {
		expect(formatCountdown(shift(14 * 60_000 + 5_000), now)).toBe('14:05');
	});
	it('never goes negative', () => {
		expect(formatCountdown(shift(-5_000), now)).toBe('0:00');
	});
});

describe('shortFingerprint', () => {
	it('accepts colon-separated and bare hex', () => {
		expect(shortFingerprint('AB:CD:EF:01:23:45:67:89')).toBe('abcd ef01 2345');
		expect(shortFingerprint('abcdef0123456789abcdef', 2)).toBe('abcd ef01');
	});
});
