<script lang="ts">
	import {
		Badge,
		Button,
		Callout,
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
	import { ApiError, api, type App, type AppAccess } from '#lib/api';
	import AppAccessDialog from '#lib/components/AppAccessDialog.svelte';
	import { normalizeHost } from '#lib/hosts';

	let apps = $state<App[] | null>(null);
	let loadError = $state('');
	let accessOpen = $state(false);
	let accessApp = $state<App | null>(null);
	let accessBusy = $state(false);
	let addOpen = $state(false);
	let addHost = $state('');
	let addError = $state('');
	let addBusy = $state(false);
	let removing = $state<App | null>(null);
	let removeBusy = $state(false);

	async function refresh() {
		try {
			apps = await api.apps.list();
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
	});

	function openAccess(app: App) {
		accessApp = app;
		accessOpen = true;
	}
	async function submitAccess(access: AppAccess) {
		if (!accessApp) return;
		accessBusy = true;
		try {
			await api.apps.update(accessApp.host, access);
			toasts.ok(access.restricted ? `Restricted ${accessApp.host}` : `Opened ${accessApp.host}`);
			await refresh();
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
		<ul class="apps">
			{#each apps as app (app.host)}
				<li class="app">
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
										<li><Badge tone="accent" size="sm">{g}</Badge></li>
									{/each}
								</ul>
							</span>
						{:else}
							<Badge tone="ok" size="sm" icon="unlock">Open to every device</Badge>
						{/if}
					</div>
					<div class="cell actions">
						<Button size="sm" variant="ghost" onclick={() => openAccess(app)}>Edit access</Button>
						<Button size="sm" variant="ghost" hoverDanger onclick={() => (removing = app)}>
							Remove
						</Button>
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<AppAccessDialog bind:open={accessOpen} app={accessApp} busy={accessBusy} onsubmit={submitAccess} />

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
	.app {
		display: grid;
		grid-template-columns: minmax(0, 1.2fr) minmax(0, 2fr) auto;
		grid-template-areas: 'host access actions';
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
			grid-template-columns: minmax(0, 1fr);
			grid-template-areas:
				'host'
				'access'
				'actions';
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
