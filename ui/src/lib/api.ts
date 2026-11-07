export type Session = { authenticated: boolean; setup_required: boolean; rp_name: string };
export type Passkey = { id: string; name: string; created_at: string; last_used_at: string | null };

export type DeviceStatus = 'pending' | 'active' | 'expiring' | 'expired' | 'revoked';
export type CertState = 'pending' | 'active' | 'superseded' | 'revoked' | 'expired';
export type Cert = {
	serial: string;
	fingerprint_sha256: string;
	not_before: string;
	not_after: string;
	state: CertState;
	enrolled_at: string | null;
	revoked_at: string | null;
	enrollment_expires_at: string | null;
};
export type LastSeen = { at: string; ip: string | null; user_agent: string | null };
export type Device = {
	id: string;
	name: string;
	owner: string;
	created_at: string;
	status: DeviceStatus;
	cert: Cert | null;
	rotation: Cert | null;
	history: Cert[];
	last_seen: LastSeen | null;
};
export type Enrollment = { url: string; password: string; expires_at: string };
export type Created = { device: Device; enrollment: Enrollment };
export type Config = {
	validity_days: { default: number; max: number; presets: number[] };
	expiring_days: number;
	enrollment_minutes: number;
	ca_subject: string;
};
export type EnrollInfo = { device_name: string; expires_at: string };

export class ApiError extends Error {
	constructor(
		public readonly status: number,
		message: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

export async function parseError(res: Response): Promise<ApiError> {
	const fallback = res.statusText || `Request failed (${res.status})`;
	const text = await res.text().catch(() => '');
	if (!text) return new ApiError(res.status, fallback);
	const body = tryJson(text);
	if (body && typeof body.error === 'string' && body.error) {
		return new ApiError(res.status, body.error);
	}
	return new ApiError(res.status, fallback);
}

function tryJson(text: string): { error?: unknown } | null {
	try {
		const v: unknown = JSON.parse(text);
		return v && typeof v === 'object' ? (v as { error?: unknown }) : null;
	} catch {
		return null;
	}
}

type Method = 'GET' | 'POST' | 'DELETE';

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
	const init: RequestInit = { method, credentials: 'same-origin', headers: {} };
	if (method !== 'GET') {
		init.headers = { 'Content-Type': 'application/json' };
		init.body = JSON.stringify(body ?? {});
	}
	const res = await fetch(path, init);
	if (!res.ok) throw await parseError(res);
	if (res.status === 204 || res.headers.get('content-length') === '0') return undefined as T;
	return (await res.json()) as T;
}

export type RegisterStart = { publicKey: PublicKeyCredentialCreationOptionsJSON };
export type LoginStart = { publicKey: PublicKeyCredentialRequestOptionsJSON };

export const api = {
	session: () => request<Session>('GET', '/api/session'),
	auth: {
		registerStart: (name: string, setup_token?: string) =>
			request<RegisterStart>('POST', '/api/auth/register/start', {
				name,
				...(setup_token ? { setup_token } : {})
			}),
		registerFinish: (credential: unknown) =>
			request<void>('POST', '/api/auth/register/finish', credential),
		loginStart: () => request<LoginStart>('POST', '/api/auth/login/start', {}),
		loginFinish: (credential: unknown) =>
			request<void>('POST', '/api/auth/login/finish', credential),
		logout: () => request<void>('POST', '/api/auth/logout')
	},
	passkeys: {
		list: () => request<Passkey[]>('GET', '/api/passkeys'),
		remove: (id: string) => request<void>('DELETE', `/api/passkeys/${encodeURIComponent(id)}`)
	},
	devices: {
		list: () => request<Device[]>('GET', '/api/devices'),
		create: (body: { name: string; owner: string; validity_days: number }) =>
			request<Created>('POST', '/api/devices', body),
		rotate: (id: string, validity_days?: number) =>
			request<Created>(
				'POST',
				`/api/devices/${encodeURIComponent(id)}/rotate`,
				validity_days === undefined ? {} : { validity_days }
			),
		newEnrollment: (id: string) =>
			request<Created>('POST', `/api/devices/${encodeURIComponent(id)}/enrollment`),
		revoke: (id: string) =>
			request<Device>('POST', `/api/devices/${encodeURIComponent(id)}/revoke`),
		remove: (id: string) => request<void>('DELETE', `/api/devices/${encodeURIComponent(id)}`)
	},
	config: () => request<Config>('GET', '/api/config'),
	enroll: (token: string) => request<EnrollInfo>('GET', `/api/enroll/${encodeURIComponent(token)}`)
};

export function enrollFileUrl(token: string, kind: 'mobileconfig' | 'p12'): string {
	const file = kind === 'mobileconfig' ? 'profile.mobileconfig' : 'device.p12';
	return `/enroll/${encodeURIComponent(token)}/${file}`;
}
