import { avatarHue } from '@dorsk/tsumikit';

export const GROUP_PATTERN = /^[a-z0-9_-]+$/;
export const GROUP_HINT = 'Lowercase letters, digits, - and _.';

export function normalizeGroup(raw: string): string | null {
	const g = raw.trim().toLowerCase();
	return GROUP_PATTERN.test(g) ? g : null;
}

export function parseGroups(text: string): { groups: string[]; invalid: string[] } {
	const groups: string[] = [];
	const invalid: string[] = [];
	for (const part of text.split(/[,\s]+/)) {
		if (!part) continue;
		const g = normalizeGroup(part);
		if (g === null) invalid.push(part);
		else if (!groups.includes(g)) groups.push(g);
	}
	return { groups, invalid };
}

export function addGroups(
	current: readonly string[],
	text: string
): ReturnType<typeof parseGroups> {
	const parsed = parseGroups(text);
	const merged = [...current];
	for (const g of parsed.groups) if (!merged.includes(g)) merged.push(g);
	return { groups: merged.sort(), invalid: parsed.invalid };
}

/** A stable colour per group name that follows the theme. */
export function groupColor(group: string): string {
	return `hsl(${avatarHue(group)} var(--mach-fg-sl))`;
}
