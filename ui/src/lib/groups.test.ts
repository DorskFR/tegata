import { describe, expect, it } from 'vitest';
import { addGroups, normalizeGroup, parseGroups } from './groups';

describe('normalizeGroup', () => {
	it('lowercases and trims', () => {
		expect(normalizeGroup('  Family ')).toBe('family');
	});
	it('accepts letters, digits, - and _', () => {
		expect(normalizeGroup('team_a-2')).toBe('team_a-2');
	});
	it('rejects anything else', () => {
		expect(normalizeGroup('')).toBeNull();
		expect(normalizeGroup('a b')).toBeNull();
		expect(normalizeGroup('média')).toBeNull();
		expect(normalizeGroup('a.b')).toBeNull();
	});
});

describe('parseGroups', () => {
	it('splits on commas and whitespace and dedupes', () => {
		expect(parseGroups('family, Media media\nwork')).toEqual({
			groups: ['family', 'media', 'work'],
			invalid: []
		});
	});
	it('reports invalid entries separately', () => {
		expect(parseGroups('ok, bad!, fine')).toEqual({ groups: ['ok', 'fine'], invalid: ['bad!'] });
	});
	it('handles empty input', () => {
		expect(parseGroups('  ,, ')).toEqual({ groups: [], invalid: [] });
	});
});

describe('addGroups', () => {
	it('merges into the current list, sorted and unique', () => {
		expect(addGroups(['work'], 'Family work')).toEqual({ groups: ['family', 'work'], invalid: [] });
	});
	it('does not mutate the input', () => {
		const current = ['b'];
		addGroups(current, 'a');
		expect(current).toEqual(['b']);
	});
});
