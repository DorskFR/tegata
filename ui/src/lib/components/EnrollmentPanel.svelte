<script lang="ts">
	import { Button, Callout, CopyButton, Heading, Text } from '@dorsk/tsumikit';
	import type { Device, Enrollment } from '#lib/api';
	import { formatCountdown, isPast } from '#lib/format';
	import Qr from './Qr.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		device,
		enrollment,
		onclose
	}: { device: Device; enrollment: Enrollment; onclose: () => void } = $props();

	let now = $state(Date.now());
	$effect(() => {
		const id = setInterval(() => (now = Date.now()), 1000);
		return () => clearInterval(id);
	});

	const expired = $derived(isPast(enrollment.expires_at, now));
	const countdown = $derived(formatCountdown(enrollment.expires_at, now));
	const installed = $derived(device.status !== 'pending' && device.rotation === null);
</script>

<section class="panel" aria-labelledby="enroll-title">
	<header class="head">
		<div>
			<Text variant="eyebrow" tone="muted">Enrollment link</Text>
			<Heading level={2} size="lg" id="enroll-title">{device.name}</Heading>
		</div>
		<div class="head-side">
			<StatusBadge status={device.status} />
			<Button variant="ghost" size="sm" onclick={onclose}>Close</Button>
		</div>
	</header>

	{#if installed}
		<Callout tone="ok" title="Certificate installed">
			The device downloaded its certificate. You can close this panel.
		</Callout>
	{:else if expired}
		<Callout tone="warn" title="Link expired">
			Nobody downloaded the certificate in time. Use "New link" on the device to issue another one.
		</Callout>
	{:else}
		<div class="body">
			<div class="qr-wrap">
				<Qr value={enrollment.url} label="QR code for the enrollment link" />
			</div>
			<div class="details">
				<div class="item">
					<Text variant="label" tone="muted">Link</Text>
					<div class="value">
						<Text mono size="sm" wrap="anywhere" class="url">{enrollment.url}</Text>
						<CopyButton text={enrollment.url} label="Copy link" box="sm" />
					</div>
				</div>
				<div class="item">
					<Text variant="label" tone="muted">Password</Text>
					<div class="value">
						<output class="password" aria-label="Certificate password">{enrollment.password}</output
						>
						<CopyButton text={enrollment.password} label="Copy password" box="sm" />
					</div>
				</div>
				<div class="item">
					<Text variant="label" tone="muted">Expires</Text>
					<Text numeric size="lg" weight="medium" aria-live="polite">
						in {countdown}
					</Text>
				</div>
			</div>
		</div>
		<Callout tone="info" title="How to install">
			Scan the code on the device. iPhone or iPad: tap Install profile, then open Settings and
			choose Profile Downloaded. Android or desktop: download the .p12 and import it, entering the
			password shown here. The link works once and this password is not shown again.
		</Callout>
	{/if}
</section>

<style>
	.panel {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
		padding: var(--sp-4);
		border: 1px solid var(--c-border);
		border-radius: var(--radius-lg);
		background: var(--c-bg-elev);
		box-shadow: var(--shadow-sm);
	}
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--sp-3);
		flex-wrap: wrap;
	}
	.head-side {
		display: flex;
		align-items: center;
		gap: var(--sp-2);
	}
	.body {
		display: grid;
		grid-template-columns: minmax(0, 16rem) 1fr;
		gap: var(--sp-5);
		align-items: start;
	}
	.qr-wrap {
		padding: var(--sp-2);
		background: #fff;
		border-radius: var(--radius-md);
	}
	.details {
		display: flex;
		flex-direction: column;
		gap: var(--sp-4);
		min-width: 0;
	}
	.item {
		display: flex;
		flex-direction: column;
		gap: var(--sp-1);
	}
	.value {
		display: flex;
		align-items: center;
		gap: var(--sp-2);
		min-width: 0;
	}
	.value :global(.url) {
		flex: 1 1 auto;
		min-width: 0;
	}
	.password {
		flex: 1 1 auto;
		min-width: 0;
		font-family: var(--font-mono);
		font-size: var(--fs-xl);
		font-weight: 600;
		letter-spacing: 0.08em;
		overflow-wrap: anywhere;
		padding: var(--sp-2) var(--sp-3);
		border: 1px dashed var(--c-border-strong);
		border-radius: var(--radius-md);
		background: var(--c-bg);
		user-select: all;
	}
	@media (max-width: 40rem) {
		.body {
			grid-template-columns: 1fr;
		}
		.qr-wrap {
			max-width: 18rem;
			margin-inline: auto;
		}
	}
</style>
