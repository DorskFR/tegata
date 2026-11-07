<script lang="ts">
	import {
		Badge,
		Button,
		Callout,
		Checkbox,
		ConfirmModal,
		EmptyState,
		Field,
		Heading,
		Input,
		Modal,
		Text,
		Timestamp,
		toasts
	} from '@dorsk/tsumikit';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { ApiError, api, type App, type AppAccess, type Config } from '#lib/api';
	import AppAccessDialog from '#lib/components/AppAccessDialog.svelte';
	import GroupBadge from '#lib/components/GroupBadge.svelte';
	import LockoutConfirm from '#lib/components/LockoutConfirm.svelte';
	import { normalizeHost } from '#lib/hosts';

	let apps = $state<App[] | null>(null);
	let loadError = $state('');
	let config = $state<Config | null>(null);
	let selected = $state<string[]>([]);
	let accessOpen = $state(false);
	let accessApps = $state<App[]>([]);
	let accessBusy = $state(false);
	let lockout = $state<{ message: string; apply: () => Promise<void> } | null>(null);

	const thisDevice = $derived(config?.this_device ?? null);
	const allSelected = $derived(apps !== null && apps.length > 0 && selected.length === apps.length);
	let addOpen = $state(false);
	let addHost = $state('');
	let addError = $state('');
	let addBusy = $state(false);
	let removing = $state<App | null>(null);
	let removeBusy = $state(false);

	async function refresh() {
		try {
			apps = await api.apps.list();
			const hosts = new Set(apps.map((a) => a.host));
			selected = selected.filter((h) => hosts.has(h));
			loadError = '';
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				await goto(resolve('/login'));
				return;
			}
			loadError = e instanceof Error ? e.message : 'Could not load apps.';
		}
	}
	$effect(() => {
		refresh();
		api.config().then(
			(c) => (config = c),
			() => (config = null)
		);
	});

	function toggle(host: string, on: boolean) {
		selected = on ? [...selected, host] : selected.filter((h) => h !== host);
	}
	function toggleAll(on: boolean) {
		selected = on && apps ? apps.map((a) => a.host) : [];
	}

	function openAccess(list: App[]) {
		accessApps = list;
		accessOpen = true;
	}
	async function submitAccess(access: AppAccess) {
		const hosts = accessApps.map((a) => a.host);
		const what = hosts.length === 1 ? hosts[0] : `${hosts.length} apps`;
		const save = async (confirmed: boolean) => {
			await api.apps.updateMany(hosts, access, confirmed);
			toasts.ok(access.restricted ? `Restricted ${what}` : `Opened ${what}`);
			if (hosts.length > 1) selected = [];
			await refresh();
		};
		accessBusy = true;
		try {
			await save(false);
		} catch (e) {
			if (!(e instanceof ApiError && e.lockout)) throw e;
			lockout = { message: e.message, apply: () => save(true) };
		} finally {
			accessBusy = false;
		}
	}

	function openAdd() {
		addHost = '';
		addError = '';
		addOpen = true;
	}
	async function add(e: SubmitEvent) {
		e.preventDefault();
		const host = normalizeHost(addHost);
		if (!host) {
			addError = 'Enter a hostname such as media.example.com.';
			return;
		}
		addBusy = true;
		addError = '';
		try {
			await api.apps.create(host);
			addOpen = false;
			toasts.ok(`Added ${host}`);
			await refresh();
		} catch (err) {
			addError = err instanceof Error ? err.message : 'Could not add the app.';
		} finally {
			addBusy = false;
		}
	}

	async function remove() {
		if (!removing) return;
		removeBusy = true;
		try {
			await api.apps.remove(removing.host);
			toasts.ok(`Removed ${removing.host}`);
			removing = null;
			await refresh();
		} catch (e) {
			toasts.error(e instanceof Error ? e.message : 'Could not remove the app.');
		} finally {
			removeBusy = false;
		}
	}
</script>

<svelte:head>
	<title>Apps · tegata</title>
</svelte:head>

<div class="page">
	<header class="head">
		<div>
			<Heading level={1} size="xl">Apps</Heading>
			<Text as="p" tone="muted">
				Hostnames behind the gateway. Every app is open to all devices until you restrict it.
			</Text>
		</div>
		<Button variant="primary" onclick={openAdd}>Add app</Button>
	</header>

	<Callout tone="info" icon="lock" title="How restrictions work">
		A device passes a restricted app when it shares at least one group with it. Certificates not
		issued by tegata never pass restricted apps.
	</Callout>

	{#if thisDevice && thisDevice.name === null}
		<Callout tone="warn" icon="alert" title="This browser is not using a tegata certificate">
			The certificate it presents was not issued by tegata, so restricted apps refuse it. Install
			this device's own certificate and remove the old one before restricting {config?.own_host ??
				'tegata'}.
		</Callout>
	{:else if thisDevice}
		<p class="this-device">
			<Text size="sm" tone="muted">You are on</Text>
			<Text size="sm" weight="medium">{thisDevice.name}</Text>
			{#each thisDevice.groups as g (g)}
				<GroupBadge group={g} size="xs" />
			{:else}
				<Text size="sm" tone="faint">(no groups)</Text>
			{/each}
		</p>
	{/if}

	{#if loadError}
		<EmptyState
			tone="danger"
			title="Could not load apps"
			description={loadError}
			actionLabel="Retry"
			onAction={refresh}
		/>
	{:else if apps === null}
		<EmptyState loading title="Loading apps" />
	{:else if apps.length === 0}
		<EmptyState
			title="No apps yet"
			description="Apps appear here automatically once the gateway sends traffic through tegata. Every app is open to all devices until you restrict it. You can also add one ahead of time."
			actionLabel="Add app"
			onAction={openAdd}
		/>
	{:else}
		<div class="bulk" class:active={selected.length > 0}>
			<Checkbox
				checked={allSelected}
				indeterminate={selected.length > 0 && !allSelected}
				label={selected.length ? `${selected.length} selected` : 'Select all'}
				onchange={(e) => toggleAll(e.currentTarget.checked)}
			/>
			{#if selected.length}
				<div class="bulk-actions">
					<Button
						size="sm"
						variant="primary"
						onclick={() => openAccess(apps?.filter((a) => selected.includes(a.host)) ?? [])}
					>
						Edit access
					</Button>
					<Button size="sm" variant="ghost" onclick={() => (selected = [])}>Clear</Button>
				</div>
			{/if}
		</div>
		<ul class="apps">
			{#each apps as app (app.host)}
				<li class="app" class:selected={selected.includes(app.host)}>
					<div class="cell select">
						<Checkbox
							checked={selected.includes(app.host)}
							label={`Select ${app.host}`}
							labelHidden
							onchange={(e) => toggle(app.host, e.currentTarget.checked)}
						/>
					</div>
					<div class="cell host">
						<Text weight="medium" mono truncate>{app.host}</Text>
						<Text size="sm" tone="muted">
							{#if app.last_seen}
								Last seen <Timestamp
									value={app.last_seen}
									mode="relative"
									details={false}
									tone="inherit"
								/>
							{:else}
								No traffic yet
							{/if}
						</Text>
					</div>
					<div class="cell access">
						{#if app.restricted}
							<span class="access-row">
								<Badge tone="warn" size="sm" icon="lock">Restricted to</Badge>
								<ul class="groups" aria-label="Allowed groups">
									{#each app.groups as g (g)}
										<li><GroupBadge group={g} /></li>
									{/each}
								</ul>
							</span>
						{:else}
							<Badge tone="ok" size="sm" icon="unlock">Open to every device</Badge>
						{/if}
					</div>
					<div class="cell actions">
						<Button size="sm" variant="ghost" onclick={() => openAccess([app])}>Edit access</Button>
						<Button size="sm" variant="ghost" hoverDanger onclick={() => (removing = app)}>
							Remove
						</Button>
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<AppAccessDialog
	bind:open={accessOpen}
	apps={accessApps}
	busy={accessBusy}
	onsubmit={submitAccess}
/>

<LockoutConfirm bind:pending={lockout} />

<Modal title="Add app" bind:open={addOpen} busy={addBusy} size="sm">
	{#snippet body()}
		<form id="add-app-form" class="form" onsubmit={add}>
			<Field
				label="Hostname"
				for="app-host"
				hint="As the gateway sends it, without scheme or path."
				error={addError || undefined}
			>
				<Input
					id="app-host"
					bind:value={addHost}
					placeholder="media.example.com"
					autocomplete="off"
					autocapitalize="off"
					spellcheck={false}
					mono
					invalid={addError !== ''}
					required
				/>
			</Field>
		</form>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (addOpen = false)} disabled={addBusy}>Cancel</Button>
		<Button variant="primary" type="submit" form="add-app-form" loading={addBusy}>Add</Button>
	{/snippet}
</Modal>

<ConfirmModal
	open={removing !== null}
	title="Remove app?"
	message={`"${removing?.host ?? ''}" and its access rule will be removed. It reappears, open to every device, as soon as traffic continues.`}
	tone="danger"
	confirmLabel="Remove"
	busy={removeBusy}
	onconfirm={remove}
	oncancel={() => (removing = null)}
/>

<style>
	.page {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
	}
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--sp-3);
		flex-wrap: wrap;
	}
	.apps {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--sp-3);
	}
	.this-device {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--sp-1);
		margin: 0;
	}
	.bulk {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--sp-3);
		min-height: 2.25rem;
		padding: 0 var(--sp-4);
	}
	.bulk-actions {
		display: flex;
		gap: var(--sp-1);
	}
	.app.selected {
		border-color: var(--accent);
	}
	.select {
		grid-area: select;
	}
	.app {
		display: grid;
		grid-template-columns: auto minmax(0, 1.2fr) minmax(0, 2fr) auto;
		grid-template-areas: 'select host access actions';
		align-items: center;
		gap: var(--sp-3) var(--sp-4);
		padding: var(--sp-3) var(--sp-4);
		border: 1px solid var(--c-border);
		border-radius: var(--radius-lg);
		background: var(--c-surface);
	}
	.cell {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.host {
		grid-area: host;
	}
	.access {
		grid-area: access;
		align-items: flex-start;
	}
	.access-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--sp-1);
	}
	.groups {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--sp-1);
	}
	.actions {
		grid-area: actions;
		flex-direction: row;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--sp-1);
	}
	.form {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
	}
	@media (max-width: 48rem) {
		.app {
			grid-template-columns: auto minmax(0, 1fr);
			grid-template-areas:
				'select host'
				'. access'
				'. actions';
			align-items: start;
		}
		.actions {
			justify-content: flex-start;
			padding-top: var(--sp-1);
			border-top: 1px solid var(--c-border);
		}
		.actions :global(button) {
			min-height: 2.75rem;
		}
	}
</style>
