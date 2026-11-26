import { afterEach, describe, expect, it, vi } from 'vitest';

const kagi = vi.hoisted(() => ({
	createPasskey: vi.fn(),
	getPasskey: vi.fn(),
	passkeysSupported: vi.fn(() => true)
}));

vi.mock('@dorsk/kagi', async (actual) => ({
	...(await actual<typeof import('@dorsk/kagi')>()),
	...kagi
}));

import { loginWithPasskey, registerPasskey } from './passkeys';

const options = { publicKey: { challenge: 'Y2g' } };

function recordFetch() {
	const calls: { url: string; body: unknown }[] = [];
	vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
		calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
		return url.endsWith('/start')
			? new Response(JSON.stringify(options), { status: 200 })
			: new Response(null, { status: 204 });
	});
	return calls;
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.clearAllMocks();
});

describe('passkeys over kagi', () => {
	it('signs in with the options the server started', async () => {
		const calls = recordFetch();
		kagi.getPasskey.mockResolvedValue({ id: 'cred' });
		await loginWithPasskey();
		expect(kagi.getPasskey).toHaveBeenCalledWith(options);
		expect(calls.map((c) => c.url)).toEqual(['/api/auth/login/start', '/api/auth/login/finish']);
		expect(calls[1]?.body).toEqual({ id: 'cred' });
	});

	it('sends the name with the new passkey', async () => {
		const calls = recordFetch();
		kagi.createPasskey.mockResolvedValue({ id: 'new' });
		await registerPasskey('laptop', 'token');
		expect(calls[0]?.body).toEqual({ name: 'laptop', setup_token: 'token' });
		expect(calls[1]).toEqual({
			url: '/api/auth/register/finish',
			body: { name: 'laptop', credential: { id: 'new' } }
		});
	});

	it('explains a cancelled prompt', async () => {
		recordFetch();
		kagi.getPasskey.mockRejectedValue(new DOMException('no', 'NotAllowedError'));
		await expect(loginWithPasskey()).rejects.toThrow(
			'The passkey request was cancelled or timed out.'
		);
	});
});
