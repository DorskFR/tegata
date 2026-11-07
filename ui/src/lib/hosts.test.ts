import { describe, expect, it } from 'vitest';
import { normalizeHost } from './hosts';

describe('normalizeHost', () => {
	it('lowercases and trims', () => {
		expect(normalizeHost(' Media.Example.COM ')).toBe('media.example.com');
	});
	it('strips scheme, port, path and trailing dot', () => {
		expect(normalizeHost('https://media.example.com:8443/path?q=1')).toBe('media.example.com');
		expect(normalizeHost('media.example.com.')).toBe('media.example.com');
	});
	it('accepts a bare label', () => {
		expect(normalizeHost('media')).toBe('media');
	});
	it('rejects junk', () => {
		expect(normalizeHost('')).toBeNull();
		expect(normalizeHost('a b.example.com')).toBeNull();
		expect(normalizeHost('-bad.example.com')).toBeNull();
		expect(normalizeHost('bad_.example.com')).toBeNull();
	});
});
