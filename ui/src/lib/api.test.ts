import { describe, expect, it, vi } from 'vitest';
import { ApiError, api, enrollFileUrl, parseError } from './api';

const res = (status: number, body: string, statusText = '') =>
	new Response(body, { status, statusText, headers: { 'Content-Type': 'application/json' } });

describe('parseError', () => {
	it('uses the error field of a JSON body', async () => {
		const err = await parseError(res(409, '{"error":"device still has an active cert"}'));
		expect(err).toBeInstanceOf(ApiError);
		expect(err.status).toBe(409);
		expect(err.message).toBe('device still has an active cert');
	});
	it('falls back to the status text for non-JSON bodies', async () => {
		const err = await parseError(res(502, '<html>bad gateway</html>', 'Bad Gateway'));
		expect(err.message).toBe('Bad Gateway');
	});
	it('falls back to the status code when nothing else is available', async () => {
		const err = await parseError(res(500, ''));
		expect(err.message).toBe('Request failed (500)');
	});
	it('ignores a JSON body without a string error', async () => {
		const err = await parseError(res(400, '{"error":42}', 'Bad Request'));
		expect(err.message).toBe('Bad Request');
	});
});

describe('enrollFileUrl', () => {
	it('builds the download paths', () => {
		expect(enrollFileUrl('abc', 'mobileconfig')).toBe('/enroll/abc/profile.mobileconfig');
		expect(enrollFileUrl('a/b', 'p12')).toBe('/enroll/a%2Fb/device.p12');
	});
});

describe('api urls', () => {
	it('encodes hostnames and ids in paths', async () => {
		const calls: [string, RequestInit | undefined][] = [];
		vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
			calls.push([url, init]);
			return new Response('{}', { status: 200 });
		});
		try {
			await api.apps.update('a/b.example.com', { restricted: true, groups: ['x'] });
			await api.apps.remove('c d');
			await api.devices.setGroups('id/1', ['g']);
		} finally {
			vi.unstubAllGlobals();
		}
		expect(calls.map(([u]) => u)).toEqual([
			'/api/apps/a%2Fb.example.com',
			'/api/apps/c%20d',
			'/api/devices/id%2F1'
		]);
		expect(calls.map(([, init]) => init?.method)).toEqual(['PUT', 'DELETE', 'PATCH']);
		expect(calls.map(([, init]) => init?.body)).toEqual([
			'{"restricted":true,"groups":["x"]}',
			'{}',
			'{"groups":["g"]}'
		]);
	});
});
