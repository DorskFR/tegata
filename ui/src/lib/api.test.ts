import { describe, expect, it } from 'vitest';
import { ApiError, enrollFileUrl, parseError } from './api';

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
