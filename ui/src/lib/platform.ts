export type Platform = 'apple' | 'android' | 'desktop';

export function detectPlatform(ua: string): Platform {
	const u = ua.toLowerCase();
	if (/iphone|ipad|ipod/.test(u)) return 'apple';
	if (/android/.test(u)) return 'android';
	if (/macintosh|mac os x/.test(u)) {
		const safari = /safari/.test(u) && !/chrome|chromium|crios|firefox|fxios|edg/.test(u);
		const touchMac = /mobile/.test(u);
		if (safari || touchMac) return 'apple';
	}
	return 'desktop';
}

export const PLATFORM_LABEL: Record<Platform, string> = {
	apple: 'iPhone, iPad or Mac',
	android: 'Android',
	desktop: 'Desktop'
};
