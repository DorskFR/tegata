<script lang="ts">
	import { Button, Callout, Card, EmptyState, Heading, Text } from '@dorsk/tsumikit';
	import { enrollFileUrl } from '#lib/api';
	import { formatDate, relativeTime } from '#lib/format';
	import { detectPlatform } from '#lib/platform';

	let { data } = $props();

	const platform = detectPlatform(navigator.userAgent);
	const profileUrl = $derived(enrollFileUrl(data.token, 'mobileconfig'));
	const p12Url = $derived(enrollFileUrl(data.token, 'p12'));
	const applePrimary = platform === 'apple';

	let now = $state(Date.now());
	$effect(() => {
		const id = setInterval(() => (now = Date.now()), 15_000);
		return () => clearInterval(id);
	});
	const expired = $derived(data.info ? Date.parse(data.info.expires_at) <= now : false);
	let used = $state(false);
</script>

<svelte:head>
	<title>Install certificate · tegata</title>
</svelte:head>

<div class="wrap">
	{#if data.error}
		<EmptyState
			tone="danger"
			title="Could not reach the server"
			description={data.error}
			actionLabel="Try again"
			onAction={() => location.reload()}
		/>
	{:else if !data.info || expired}
		<EmptyState
			tone="warn"
			title="This link has expired or was already used"
			description="Each enrollment link works once and for a short time. Ask the person who sent it for a new one."
		/>
	{:else}
		<Card padding="lg">
			<div class="col">
				<div>
					<Text variant="eyebrow" tone="muted">Certificate for</Text>
					<Heading level={1} size="xl" wrap="balance">{data.info.device_name}</Heading>
					<Text as="p" tone="muted" size="sm" title={formatDate(data.info.expires_at)}>
						Link expires {relativeTime(data.info.expires_at, now)}
					</Text>
				</div>

				{#if used}
					<Callout tone="ok" title="Download started">
						If nothing happened, the link may already be used up. Ask for a new one rather than
						reloading.
					</Callout>
				{:else}
					<Callout tone="warn">
						Downloading uses this link up. Make sure you are on the device that should get the
						certificate, and have the password from the admin screen ready.
					</Callout>
				{/if}

				<div class="actions">
					<Button
						as="a"
						href={applePrimary ? profileUrl : p12Url}
						variant="primary"
						size="lg"
						block
						onclick={() => (used = true)}
					>
						{applePrimary ? 'Install profile' : 'Download certificate (.p12)'}
					</Button>
					<Button
						as="a"
						href={applePrimary ? p12Url : profileUrl}
						variant="ghost"
						size="md"
						block
						onclick={() => (used = true)}
					>
						{applePrimary ? 'Download .p12 instead' : 'Install Apple profile instead'}
					</Button>
				</div>

				<div class="hints">
					<Heading level={2} size="md">How to install</Heading>
					<Text as="p" size="sm" tone="muted">
						Both files are protected by the password shown on the admin screen next to the QR code.
						It is not stored anywhere else.
					</Text>
					{#if platform === 'apple'}
						<ol>
							<li>Tap <strong>Install profile</strong> and allow the download.</li>
							<li>
								iPhone or iPad: open <strong>Settings</strong>, tap
								<strong>Profile Downloaded</strong>, then <strong>Install</strong>. Mac: open
								<strong>System Settings → Privacy &amp; Security → Profiles</strong>.
							</li>
							<li>Enter the certificate password when asked.</li>
						</ol>
					{:else if platform === 'android'}
						<ol>
							<li>Download the .p12 file.</li>
							<li>
								Open <strong
									>Settings → Security → Encryption &amp; credentials → Install a certificate → VPN
									&amp; app user certificate</strong
								> and pick the file.
							</li>
							<li>Enter the certificate password and give it a name.</li>
						</ol>
					{:else}
						<ol>
							<li>Download the .p12 file.</li>
							<li>
								Chrome and Edge: <strong
									>Settings → Privacy and security → Security → Manage certificates → Your
									certificates → Import</strong
								>. Firefox:
								<strong
									>Settings → Privacy &amp; Security → Certificates → View Certificates → Your
									Certificates → Import</strong
								>. Safari: double-click the file to add it to Keychain.
							</li>
							<li>Enter the certificate password when asked.</li>
						</ol>
					{/if}
				</div>
			</div>
		</Card>
	{/if}
</div>

<style>
	.wrap {
		display: flex;
		flex-direction: column;
		gap: var(--sp-5);
		max-width: 30rem;
		margin: var(--sp-6) auto 0;
		padding-bottom: var(--sp-8);
	}
	.col {
		display: flex;
		flex-direction: column;
		gap: var(--sp-5);
	}
	.actions {
		display: flex;
		flex-direction: column;
		gap: var(--sp-2);
	}
	.hints {
		display: flex;
		flex-direction: column;
		gap: var(--sp-2);
	}
	.hints ol {
		margin: 0;
		padding-inline-start: 1.25rem;
		display: flex;
		flex-direction: column;
		gap: var(--sp-2);
		font-size: var(--fs-sm);
		line-height: 1.5;
	}
</style>
