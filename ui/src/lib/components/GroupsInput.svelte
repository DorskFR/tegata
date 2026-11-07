<script lang="ts">
	import GroupBadge from './GroupBadge.svelte';
	import { Badge, Input, Text } from '@dorsk/tsumikit';
	import { GROUP_HINT, addGroups } from '#lib/groups';

	let {
		value = $bindable([]),
		suggestions = [],
		id,
		invalid = false,
		disabled = false,
		placeholder = 'family, work…'
	}: {
		value?: string[];
		suggestions?: string[];
		id: string;
		invalid?: boolean;
		disabled?: boolean;
		placeholder?: string;
	} = $props();

	let draft = $state('');
	let rejected = $state<string[]>([]);

	const unused = $derived(suggestions.filter((g) => !value.includes(g)));

	function commit(): boolean {
		if (!draft.trim()) return false;
		const r = addGroups(value, draft);
		value = r.groups;
		rejected = r.invalid;
		draft = r.invalid.join(', ');
		return true;
	}

	export function flush(): boolean {
		commit();
		return rejected.length === 0;
	}

	function keydown(e: KeyboardEvent) {
		if (e.key === 'Enter' || e.key === ',') {
			if (commit()) e.preventDefault();
			else if (e.key === ',') e.preventDefault();
		} else if (e.key === 'Backspace' && !draft && value.length) {
			value = value.slice(0, -1);
		}
	}

	function add(g: string) {
		value = [...value, g].sort();
	}
	function remove(g: string) {
		value = value.filter((x) => x !== g);
	}
</script>

<div class="groups">
	{#if value.length}
		<ul class="chips" aria-label="Selected groups">
			{#each value as g (g)}
				<li>
					<GroupBadge group={g} removable onremove={() => remove(g)} aria-label={`Remove ${g}`} />
				</li>
			{/each}
		</ul>
	{/if}
	<Input
		{id}
		bind:value={draft}
		{placeholder}
		autocomplete="off"
		autocapitalize="off"
		spellcheck={false}
		{disabled}
		invalid={invalid || rejected.length > 0}
		onkeydown={keydown}
		onblur={() => commit()}
	/>
	{#if rejected.length}
		<Text size="xs" tone="danger" role="alert">
			Not a valid group: {rejected.join(', ')}. {GROUP_HINT}
		</Text>
	{/if}
	{#if unused.length && !disabled}
		<ul class="chips" aria-label="Suggested groups">
			{#each unused as g (g)}
				<li>
					<Badge as="button" tone="neutral" size="sm" icon="plus" onclick={() => add(g)}>
						{g}
					</Badge>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.groups {
		display: flex;
		flex-direction: column;
		gap: var(--sp-2);
	}
	.chips {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--sp-1);
	}
</style>
