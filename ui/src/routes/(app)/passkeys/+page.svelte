<script lang="ts">
	import {
		Button,
		Card,
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
	import { ApiError, api, type Passkey } from '#lib/api';
	import { registerPasskey } from '#lib/webauthn';

	let passkeys = $state<Passkey[] | null>(null);
	let loadError = $state('');
	let addOpen = $state(false);
	let addName = $state('');
	let addError = $state('');
	let addBusy = $state(false);
	let removing = $state<Passkey | null>(null);
	let removeBusy = $state(false);

	async function refresh() {
		try {
			passkeys = await api.passkeys.list();
			loadError = '';
		} catch (e) {
			loadError = e instanceof Error ? e.message : 'Could not load passkeys.';
		}
	}
	$effect(() => {
		refresh();
	});

	function openAdd() {
		addName = '';
		addError = '';
		addOpen = true;
	}

	async function add(e: SubmitEvent) {
		e.preventDefault();
		if (!addName.trim()) {
			addError = 'Give the passkey a name.';
			return;
		}
		addBusy = true;
		addError = '';
		try {
			await registerPasskey(addName.trim());
			addOpen = false;
			toasts.ok('Passkey added');
			await refresh();
		} catch (err) {
			addError = err instanceof Error ? err.message : 'Could not add the passkey.';
		} finally {
			addBusy = false;
		}
	}

	async function remove() {
		if (!removing) return;
		removeBusy = true;
		try {
			await api.passkeys.remove(removing.id);
			toasts.ok(`Removed ${removing.name}`);
			removing = null;
			await refresh();
		} catch (e) {
			toasts.error(e instanceof ApiError ? e.message : 'Could not remove the passkey.');
		} finally {
			removeBusy = false;
		}
	}
</script>

<svelte:head>
	<title>Passkeys · tegata</title>
</svelte:head>

<div class="page">
	<header class="head">
		<div>
			<Heading level={1} size="xl">Passkeys</Heading>
			<Text as="p" tone="muted">Every passkey here can sign in and manage devices.</Text>
		</div>
		<Button variant="primary" onclick={openAdd}>Add passkey</Button>
	</header>

	{#if loadError}
		<EmptyState
			tone="danger"
			title="Could not load passkeys"
			description={loadError}
			actionLabel="Retry"
			onAction={refresh}
		/>
	{:else if passkeys === null}
		<EmptyState loading title="Loading passkeys" />
	{:else}
		<ul class="list">
			{#each passkeys as pk (pk.id)}
				<li>
					<Card>
						<div class="entry">
							<div class="info">
								<Text weight="medium">{pk.name}</Text>
								<Text size="sm" tone="muted">
									Added <Timestamp
										value={pk.created_at}
										mode="date"
										details={false}
										tone="inherit"
									/>
									·
									{#if pk.last_used_at}
										last used <Timestamp
											value={pk.last_used_at}
											mode="relative"
											details={false}
											tone="inherit"
										/>
									{:else}
										never used
									{/if}
								</Text>
							</div>
							<Button
								variant="ghost"
								size="sm"
								hoverDanger
								disabled={passkeys.length < 2}
								title={passkeys.length < 2 ? 'The last passkey cannot be removed' : undefined}
								onclick={() => (removing = pk)}
							>
								Remove
							</Button>
						</div>
					</Card>
				</li>
			{/each}
		</ul>
		{#if passkeys.length < 2}
			<Text as="p" size="sm" tone="muted">
				Add a second passkey before removing this one, so you cannot lock yourself out.
			</Text>
		{/if}
	{/if}
</div>

<Modal title="Add passkey" bind:open={addOpen} busy={addBusy} size="sm">
	{#snippet body()}
		<form id="add-passkey" class="form" onsubmit={add}>
			<Field label="Name" for="new-passkey-name" hint="Where this passkey lives.">
				<Input
					id="new-passkey-name"
					bind:value={addName}
					placeholder="Laptop, phone, security key…"
					autocomplete="off"
					required
				/>
			</Field>
			{#if addError}
				<Text as="p" tone="danger" size="sm" role="alert">{addError}</Text>
			{/if}
		</form>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (addOpen = false)} disabled={addBusy}>Cancel</Button>
		<Button variant="primary" type="submit" form="add-passkey" loading={addBusy}>Register</Button>
	{/snippet}
</Modal>

<ConfirmModal
	open={removing !== null}
	title="Remove passkey?"
	message={`"${removing?.name ?? ''}" will no longer be able to sign in.`}
	tone="danger"
	confirmLabel="Remove"
	busy={removeBusy}
	onconfirm={remove}
	oncancel={() => (removing = null)}
/>

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--sp-3);
		flex-wrap: wrap;
	}
	.list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--sp-3);
	}
	.entry {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--sp-3);
	}
	.info {
		display: flex;
		flex-direction: column;
		gap: var(--sp-1);
		min-width: 0;
	}
	.form {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
	}
</style>
