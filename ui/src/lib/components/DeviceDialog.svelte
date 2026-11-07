<script lang="ts">
	import { Button, Field, Input, Modal, Select, type SelectOption } from '@dorsk/tsumikit';
	import { api, type Config, type Device } from '#lib/api';
	import { validityLabel } from '#lib/format';
	import { GROUP_HINT } from '#lib/groups';
	import GroupsInput from './GroupsInput.svelte';

	type Values = { name: string; owner: string; groups: string[]; validity_days: number };

	let {
		open = $bindable(false),
		config,
		device = null,
		busy = false,
		onsubmit
	}: {
		open?: boolean;
		config: Config | null;
		device?: Device | null;
		busy?: boolean;
		onsubmit: (values: Values) => Promise<void>;
	} = $props();

	let name = $state('');
	let owner = $state('');
	let validity = $state('');
	let groups = $state<string[]>([]);
	let suggestions = $state<string[]>([]);
	let groupsInput = $state<GroupsInput | null>(null);
	let error = $state('');

	const rotating = $derived(device !== null);
	const title = $derived(rotating ? `Rotate ${device?.name ?? 'device'}` : 'New device');
	const presets = $derived.by(() => {
		if (!config) return [] as number[];
		const list = [...config.validity_days.presets];
		if (!list.includes(config.validity_days.default)) list.push(config.validity_days.default);
		return list.filter((d) => d <= config.validity_days.max).sort((a, b) => a - b);
	});
	const options: SelectOption[] = $derived(
		presets.map((d) => ({
			value: String(d),
			label: validityLabel(d, config?.validity_days.max ?? 0, config?.ca_not_after ?? null)
		}))
	);

	$effect(() => {
		if (open) {
			name = device?.name ?? '';
			owner = device?.owner ?? '';
			validity = String(config?.validity_days.default ?? presets[0] ?? 365);
			groups = [];
			error = '';
			if (!device) {
				api.groups().then(
					(g) => (suggestions = g),
					() => (suggestions = [])
				);
			}
		}
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		const days = Number(validity);
		if (!rotating && !name.trim()) {
			error = 'Give the device a name.';
			return;
		}
		if (!rotating && !owner.trim()) {
			error = 'Who owns this device?';
			return;
		}
		if (!Number.isFinite(days) || days < 1) {
			error = 'Pick how long the certificate stays valid.';
			return;
		}
		if (!rotating && groupsInput && !groupsInput.flush()) return;
		error = '';
		try {
			await onsubmit({ name: name.trim(), owner: owner.trim(), groups, validity_days: days });
			open = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Something went wrong.';
		}
	}
</script>

<Modal {title} bind:open {busy} size="sm">
	{#snippet body()}
		<form id="device-form" class="form" onsubmit={submit}>
			{#if !rotating}
				<Field label="Device name" for="device-name" hint="How it appears in the list.">
					<Input
						id="device-name"
						bind:value={name}
						placeholder="Phone, laptop, tablet…"
						autocomplete="off"
						required
					/>
				</Field>
				<Field label="Owner" for="device-owner">
					<Input id="device-owner" bind:value={owner} autocomplete="off" required />
				</Field>
				<Field
					label="Groups"
					for="device-groups"
					hint={`Optional. Restricted apps let the device in when it shares one of their groups. ${GROUP_HINT}`}
				>
					<GroupsInput
						bind:this={groupsInput}
						id="device-groups"
						bind:value={groups}
						{suggestions}
					/>
				</Field>
			{/if}
			<Field
				label="Valid for"
				for="device-validity"
				hint={rotating
					? 'A new certificate is issued; the old one is revoked once the new one is installed.'
					: undefined}
			>
				<Select id="device-validity" bind:value={validity} {options} />
			</Field>
			{#if error}
				<p class="error" role="alert">{error}</p>
			{/if}
		</form>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
		<Button variant="primary" type="submit" form="device-form" loading={busy}>
			{rotating ? 'Rotate' : 'Create'}
		</Button>
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
