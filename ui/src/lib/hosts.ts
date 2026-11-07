const HOST_PATTERN =
	/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export function normalizeHost(raw: string): string | null {
	let h = raw.trim().toLowerCase();
	h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
	h = h.split(/[/?#]/, 1)[0] ?? '';
	h = h.replace(/:\d+$/, '').replace(/\.$/, '');
	return HOST_PATTERN.test(h) ? h : null;
}
