<script lang="ts">
	import {
		Badge,
		Button,
		ConfirmModal,
		CopyButton,
		EmptyState,
		Heading,
		Text,
		Timestamp,
		toasts
	} from '@dorsk/tsumikit';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { ApiError, api, type Config, type Created, type Device } from '#lib/api';
	import DeviceDialog from '#lib/components/DeviceDialog.svelte';
	import EnrollmentPanel from '#lib/components/EnrollmentPanel.svelte';
	import GroupsDialog from '#lib/components/GroupsDialog.svelte';
	import StatusBadge from '#lib/components/StatusBadge.svelte';
	import { formatDate, relativeTime, shortFingerprint } from '#lib/format';

	let devices = $state<Device[] | null>(null);
	let config = $state<Config | null>(null);
	let loadError = $state('');
	let dialogOpen = $state(false);
	let dialogDevice = $state<Device | null>(null);
	let dialogBusy = $state(false);
	let groupsOpen = $state(false);
	let groupsDevice = $state<Device | null>(null);
	let groupsBusy = $state(false);
	let panel = $state<Created | null>(null);
	let confirm = $state<{ kind: 'revoke' | 'delete'; device: Device } | null>(null);
	let confirmBusy = $state(false);
	let pendingAction = $state<string | null>(null);

	async function refresh() {
		try {
			devices = await api.devices.list();
			loadError = '';
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				await goto(resolve('/login'));
				return;
			}
			loadError = e instanceof Error ? e.message : 'Could not load devices.';
		}
	}

	$effect(() => {
		refresh();
		api.config().then(
			(c) => (config = c),
			(e: unknown) => toasts.error(e instanceof Error ? e.message : 'Could not load config.')
		);
	});

	$effect(() => {
		if (!panel) return;
		const id = setInterval(refresh, 5000);
		return () => clearInterval(id);
	});

	const panelDevice = $derived.by(() => {
		if (!panel) return null;
		const id = panel.device.id;
		return devices?.find((d) => d.id === id) ?? panel.device;
	});

	function openCreate() {
		dialogDevice = null;
		dialogOpen = true;
	}
	function openRotate(device: Device) {
		dialogDevice = device;
		dialogOpen = true;
	}

	function openGroups(device: Device) {
		groupsDevice = device;
		groupsOpen = true;
	}

	async function submitGroups(groups: string[]) {
		if (!groupsDevice) return;
		groupsBusy = true;
		try {
			await api.devices.setGroups(groupsDevice.id, groups);
			toasts.ok(`Updated groups of ${groupsDevice.name}`);
			await refresh();
		} finally {
			groupsBusy = false;
		}
	}

	async function submitDialog(values: {
		name: string;
		owner: string;
		groups: string[];
		validity_days: number;
	}) {
		dialogBusy = true;
		try {
			const created = dialogDevice
				? await api.devices.rotate(dialogDevice.id, values.validity_days)
				: await api.devices.create(values);
			panel = created;
			toasts.ok(dialogDevice ? 'Rotation started' : `Created ${created.device.name}`);
			await refresh();
		} finally {
			dialogBusy = false;
		}
	}

	async function newLink(device: Device) {
		pendingAction = device.id;
		try {
			panel = await api.devices.newEnrollment(device.id);
			await refresh();
		} catch (e) {
			toasts.error(e instanceof Error ? e.message : 'Could not create a new link.');
		} finally {
			pendingAction = null;
		}
	}

	async function runConfirm() {
		if (!confirm) return;
		const { kind, device } = confirm;
		confirmBusy = true;
		try {
			if (kind === 'revoke') {
				await api.devices.revoke(device.id);
				toasts.ok(`Revoked ${device.name}`);
			} else {
				await api.devices.remove(device.id);
				toasts.ok(`Deleted ${device.name}`);
				if (panel?.device.id === device.id) panel = null;
			}
			confirm = null;
			await refresh();
		} catch (e) {
			toasts.error(e instanceof Error ? e.message : 'The action failed.');
		} finally {
			confirmBusy = false;
		}
	}

	function canDelete(d: Device): boolean {
		return (
			d.status !== 'active' && d.status !== 'expiring' && d.status !== 'pending' && !d.rotation
		);
	}
	function canRevoke(d: Device): boolean {
		return (
			d.status === 'active' || d.status === 'expiring' || d.status === 'pending' || !!d.rotation
		);
	}
	function hasPendingCert(d: Device): boolean {
		return d.status === 'pending' || d.rotation?.state === 'pending';
	}
	function currentCert(d: Device) {
		return d.cert ?? d.rotation ?? d.history[0] ?? null;
	}
</script>

<svelte:head>
	<title>Devices · tegata</title>
</svelte:head>

<div class="page">
	<header class="head">
		<div>
			<Heading level={1} size="xl">Devices</Heading>
			<Text as="p" tone="muted">
				Client certificates for your devices. Each one can be rotated or revoked at any time.
			</Text>
		</div>
		<Button variant="primary" onclick={openCreate} disabled={!config}>New device</Button>
	</header>

	{#if panel && panelDevice}
		<EnrollmentPanel
			device={panelDevice}
			enrollment={panel.enrollment}
			onclose={() => (panel = null)}
		/>
	{/if}

	{#if loadError}
		<EmptyState
			tone="danger"
			title="Could not load devices"
			description={loadError}
			actionLabel="Retry"
			onAction={refresh}
		/>
	{:else if devices === null}
		<EmptyState loading title="Loading devices" />
	{:else if devices.length === 0}
		<EmptyState
			title="No devices yet"
			description="Create the first device to get an enrollment link and QR code."
			actionLabel="New device"
			onAction={openCreate}
		/>
	{:else}
		<ul class="devices">
			{#each devices as d (d.id)}
				{@const cert = currentCert(d)}
				<li class="device" data-status={d.status}>
					<div class="cell title">
						<Text weight="medium" truncate>{d.name}</Text>
						<Text size="sm" tone="muted" truncate>{d.owner}</Text>
						{#if d.groups.length}
							<ul class="groups" aria-label="Groups">
								{#each d.groups as g (g)}
									<li><Badge tone="accent" size="xs">{g}</Badge></li>
								{/each}
							</ul>
						{/if}
					</div>
					<div class="cell status">
						<StatusBadge status={d.status} />
						{#if d.rotation}
							<Text size="xs" tone="muted">rotation waiting</Text>
						{/if}
					</div>
					<div class="cell expiry">
						<span class="label">Expires</span>
						{#if cert}
							<Text size="sm" title={formatDate(cert.not_after)}>
								{d.status === 'expired' ? 'expired ' : ''}{relativeTime(cert.not_after)}
							</Text>
						{:else}
							<Text size="sm" tone="faint">—</Text>
						{/if}
					</div>
					<div class="cell seen">
						<span class="label">Last seen</span>
						{#if d.last_seen}
							<Text size="sm">
								<Timestamp value={d.last_seen.at} mode="relative" details={false} tone="inherit" />
								{#if d.last_seen.ip}
									<Text tone="muted" mono size="xs">· {d.last_seen.ip}</Text>
								{/if}
							</Text>
						{:else}
							<Text size="sm" tone="faint">never</Text>
						{/if}
						{#if d.stale}
							<Badge
								tone="warn"
								size="sm"
								title="In use but no traffic for {config?.stale_days ??
									'many'} days: revoke it if the device is gone"
							>
								not seen for {config?.stale_days ?? 'many'}+ days
							</Badge>
						{/if}
					</div>
					<div class="cell fp">
						<span class="label">Fingerprint</span>
						{#if cert}
							<span class="fp-value">
								<Text mono size="xs" title={cert.fingerprint_sha256}>
									{shortFingerprint(cert.fingerprint_sha256)}
								</Text>
								<CopyButton
									text={cert.fingerprint_sha256}
									label="Copy fingerprint"
									box="xs"
									variant="ghost"
								/>
							</span>
						{:else}
							<Text size="xs" tone="faint">—</Text>
						{/if}
					</div>
					<div class="cell actions">
						{#if hasPendingCert(d)}
							<Button size="sm" onclick={() => newLink(d)} loading={pendingAction === d.id}>
								New link
							</Button>
						{/if}
						<Button size="sm" variant="ghost" onclick={() => openGroups(d)}>Edit groups</Button>
						{#if d.status !== 'revoked'}
							<Button size="sm" variant="ghost" onclick={() => openRotate(d)} disabled={!config}>
								Rotate
							</Button>
						{/if}
						{#if canRevoke(d)}
							<Button
								size="sm"
								variant="ghost"
								hoverDanger
								onclick={() => (confirm = { kind: 'revoke', device: d })}
							>
								Revoke
							</Button>
						{/if}
						{#if canDelete(d)}
							<Button
								size="sm"
								variant="ghost"
								hoverDanger
								onclick={() => (confirm = { kind: 'delete', device: d })}
							>
								Delete
							</Button>
						{/if}
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<DeviceDialog
	bind:open={dialogOpen}
	{config}
	device={dialogDevice}
	busy={dialogBusy}
	onsubmit={submitDialog}
/>

<GroupsDialog
	bind:open={groupsOpen}
	device={groupsDevice}
	busy={groupsBusy}
	onsubmit={submitGroups}
/>

<ConfirmModal
	open={confirm !== null}
	title={confirm?.kind === 'delete' ? 'Delete device?' : 'Revoke certificate?'}
	message={confirm?.kind === 'delete'
		? `"${confirm?.device.name ?? ''}" and its certificate history will be removed.`
		: `"${confirm?.device.name ?? ''}" will lose access as soon as the revocation list is picked up. This cannot be undone.`}
	tone="danger"
	confirmLabel={confirm?.kind === 'delete' ? 'Delete' : 'Revoke'}
	busy={confirmBusy}
	onconfirm={runConfirm}
	oncancel={() => (confirm = null)}
/>

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--sp-3);
		flex-wrap: wrap;
	}
	.devices {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--sp-3);
	}
	.device {
		display: grid;
		grid-template-columns: minmax(0, 1.4fr) auto minmax(0, 1fr) minmax(0, 1.2fr) auto auto;
		grid-template-areas: 'title status expiry seen fp actions';
		align-items: center;
		gap: var(--sp-3) var(--sp-4);
		padding: var(--sp-3) var(--sp-4);
		border: 1px solid var(--c-border);
		border-radius: var(--radius-lg);
		background: var(--c-surface);
	}
	.device[data-status='revoked'],
	.device[data-status='expired'] {
		opacity: 0.75;
	}
	.cell {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.title {
		grid-area: title;
	}
	.groups {
		list-style: none;
		margin: 2px 0 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--sp-1);
	}
	.status {
		grid-area: status;
		align-items: flex-start;
	}
	.expiry {
		grid-area: expiry;
	}
	.seen {
		grid-area: seen;
	}
	.fp {
		grid-area: fp;
	}
	.fp-value {
		display: inline-flex;
		align-items: center;
		gap: var(--sp-1);
	}
	.actions {
		grid-area: actions;
		flex-direction: row;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--sp-1);
	}
	.label {
		display: none;
		font-size: var(--fs-xs);
		color: var(--text-muted);
	}
	@media (max-width: 64rem) {
		.device {
			grid-template-columns: minmax(0, 1fr) auto;
			grid-template-areas:
				'title status'
				'expiry seen'
				'fp fp'
				'actions actions';
			align-items: start;
		}
		.label {
			display: block;
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
