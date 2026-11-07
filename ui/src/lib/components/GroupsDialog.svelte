<script lang="ts">
	import { Button, Field, Modal } from '@dorsk/tsumikit';
	import type { Device } from '#lib/api';
	import { api } from '#lib/api';
	import { GROUP_HINT } from '#lib/groups';
	import GroupsInput from './GroupsInput.svelte';

	let {
		open = $bindable(false),
		device,
		busy = false,
		onsubmit
	}: {
		open?: boolean;
		device: Device | null;
		busy?: boolean;
		onsubmit: (groups: string[]) => Promise<void>;
	} = $props();

	let groups = $state<string[]>([]);
	let suggestions = $state<string[]>([]);
	let error = $state('');
	let input = $state<GroupsInput | null>(null);

	$effect(() => {
		if (open) {
			groups = [...(device?.groups ?? [])];
			error = '';
			api.groups().then(
				(g) => (suggestions = g),
				() => (suggestions = [])
			);
		}
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!input?.flush()) return;
		error = '';
		try {
			await onsubmit(groups);
			open = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Something went wrong.';
		}
	}
</script>

<Modal title={`Groups of ${device?.name ?? 'device'}`} bind:open {busy} size="sm">
	{#snippet body()}
		<form id="groups-form" class="form" onsubmit={submit}>
			<Field
				label="Groups"
				for="groups-input"
				hint={`Restricted apps let this device in when it shares one of their groups. ${GROUP_HINT}`}
			>
				<GroupsInput bind:this={input} id="groups-input" bind:value={groups} {suggestions} />
			</Field>
			{#if error}
				<p class="error" role="alert">{error}</p>
			{/if}
		</form>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
		<Button variant="primary" type="submit" form="groups-form" loading={busy}>Save</Button>
	{/snippet}
</Modal>

<style>
	.form {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
	}
	.error {
		margin: 0;
		color: var(--danger);
		font-size: var(--fs-sm);
	}
</style>
