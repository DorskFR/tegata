<script lang="ts">
	import { Button, Field, Modal, Switch, Text } from '@dorsk/tsumikit';
	import { api, type App, type AppAccess } from '#lib/api';
	import { GROUP_HINT } from '#lib/groups';
	import GroupsInput from './GroupsInput.svelte';

	let {
		open = $bindable(false),
		apps,
		busy = false,
		onsubmit
	}: {
		open?: boolean;
		apps: App[];
		busy?: boolean;
		onsubmit: (access: AppAccess) => Promise<void>;
	} = $props();

	const title = $derived(
		apps.length === 1 ? `Access to ${apps[0]?.host}` : `Access to ${apps.length} apps`
	);

	function sharedAccess(list: App[]): AppAccess {
		const [first, ...others] = list;
		const same =
			first &&
			others.every(
				(a) => a.restricted === first.restricted && a.groups.join() === first.groups.join()
			);
		return same
			? { restricted: first.restricted, groups: [...first.groups] }
			: { restricted: false, groups: [] };
	}

	let restricted = $state(false);
	let groups = $state<string[]>([]);
	let suggestions = $state<string[]>([]);
	let error = $state('');
	let input = $state<GroupsInput | null>(null);

	$effect(() => {
		if (open) {
			({ restricted, groups } = sharedAccess(apps));
			error = '';
			api.groups().then(
				(g) => (suggestions = g),
				() => (suggestions = [])
			);
		}
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (restricted && input && !input.flush()) return;
		if (restricted && groups.length === 0) {
			error = 'Pick at least one group, or leave the app open.';
			return;
		}
		error = '';
		try {
			await onsubmit({ restricted, groups: restricted ? groups : [] });
			open = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Something went wrong.';
		}
	}
</script>

<Modal {title} bind:open {busy} size="sm">
	{#snippet body()}
		<form id="app-access-form" class="form" onsubmit={submit}>
			{#if apps.length > 1}
				<Text size="sm" tone="muted">
					Replaces the access of {apps.map((a) => a.host).join(', ')}.
				</Text>
			{/if}
			<div class="toggle">
				<Switch id="app-restricted" bind:checked={restricted} label="Restrict to groups" />
				<div class="toggle-text">
					<label for="app-restricted">Restrict to groups</label>
					<Text size="sm" tone="muted">
						{restricted
							? 'Only devices in one of the groups below pass.'
							: 'Every device with a valid certificate passes.'}
					</Text>
				</div>
			</div>
			{#if restricted}
				<Field label="Allowed groups" for="app-groups" hint={GROUP_HINT}>
					<GroupsInput
						bind:this={input}
						id="app-groups"
						bind:value={groups}
						{suggestions}
						invalid={error !== '' && groups.length === 0}
					/>
				</Field>
			{/if}
			{#if error}
				<p class="error" role="alert">{error}</p>
			{/if}
		</form>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
		<Button variant="primary" type="submit" form="app-access-form" loading={busy}>Save</Button>
	{/snippet}
</Modal>

<style>
	.form {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
	}
	.toggle {
		display: flex;
		align-items: flex-start;
		gap: var(--sp-3);
	}
	.toggle-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.toggle-text label {
		font-weight: 500;
	}
	.error {
		margin: 0;
		color: var(--danger);
		font-size: var(--fs-sm);
	}
</style>
