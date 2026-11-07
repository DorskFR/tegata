import { describe, expect, it } from 'vitest';
import { detectPlatform } from './platform';

const UA = {
	iphone:
		'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
	ipadDesktopMode:
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
	macChrome:
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
	android:
		'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
	linuxFirefox: 'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
	windowsEdge:
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'
};

describe('detectPlatform', () => {
	it('sends iOS and Safari on macOS to the profile', () => {
		expect(detectPlatform(UA.iphone)).toBe('apple');
		expect(detectPlatform(UA.ipadDesktopMode)).toBe('apple');
	});
	it('treats Chrome on macOS as a desktop browser', () => {
		expect(detectPlatform(UA.macChrome)).toBe('desktop');
	});
	it('detects Android', () => {
		expect(detectPlatform(UA.android)).toBe('android');
	});
	it('falls back to desktop', () => {
		expect(detectPlatform(UA.linuxFirefox)).toBe('desktop');
		expect(detectPlatform(UA.windowsEdge)).toBe('desktop');
		expect(detectPlatform('')).toBe('desktop');
	});
});
