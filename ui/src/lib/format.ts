import type { DeviceStatus } from './api';

export type Tone = 'neutral' | 'ok' | 'warn' | 'danger' | 'info' | 'accent';

export const STATUS: Record<DeviceStatus, { label: string; tone: Tone }> = {
	pending: { label: 'Pending', tone: 'info' },
	active: { label: 'Active', tone: 'ok' },
	expiring: { label: 'Expiring', tone: 'warn' },
	expired: { label: 'Expired', tone: 'neutral' },
	revoked: { label: 'Revoked', tone: 'danger' }
};

export function statusLabel(status: DeviceStatus): string {
	return STATUS[status]?.label ?? status;
}

export function statusTone(status: DeviceStatus): Tone {
	return STATUS[status]?.tone ?? 'neutral';
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
	['year', 365 * 86_400_000],
	['day', 86_400_000],
	['hour', 3_600_000],
	['minute', 60_000]
];

export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
	if (!iso) return '—';
	const t = Date.parse(iso);
	if (Number.isNaN(t)) return '—';
	const diff = t - now;
	const abs = Math.abs(diff);
	if (abs < 45_000) return diff <= 0 ? 'just now' : 'in a moment';
	const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'always' });
	for (const [unit, ms] of UNITS) {
		if (abs >= ms || unit === 'minute') {
			return rtf.format(Math.round(diff / ms), unit);
		}
	}
	return '—';
}

export function formatCountdown(expiresAt: string, now: number = Date.now()): string {
	const left = Math.max(0, Math.floor((Date.parse(expiresAt) - now) / 1000));
	const m = Math.floor(left / 60);
	const s = left % 60;
	return `${m}:${String(s).padStart(2, '0')}`;
}

export function isPast(iso: string, now: number = Date.now()): boolean {
	return Date.parse(iso) <= now;
}

export function shortFingerprint(fp: string, groups = 3): string {
	const hex = fp.replace(/[^0-9a-f]/gi, '').toLowerCase();
	const parts: string[] = [];
	for (let i = 0; i < hex.length && parts.length < groups; i += 4) parts.push(hex.slice(i, i + 4));
	return parts.join(' ');
}

export function formatDate(iso: string | null | undefined): string {
	if (!iso) return '—';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return '—';
	return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function pluralDays(n: number): string {
	return n === 1 ? '1 day' : `${n} days`;
}

export function validityLabel(days: number, max: number, caNotAfter: string | null): string {
	if (days === max && caNotAfter) {
		const d = new Date(caNotAfter);
		if (!Number.isNaN(d.getTime())) {
			return `Until the CA expires (${d.toLocaleDateString(undefined, { dateStyle: 'medium' })})`;
		}
	}
	if (days % 365 === 0) {
		const years = days / 365;
		return years === 1 ? '1 year' : `${years} years`;
	}
	return pluralDays(days);
}
