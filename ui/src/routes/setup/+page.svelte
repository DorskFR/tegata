<script lang="ts">
	import { Button, Card, Field, Heading, Input, Text } from '@dorsk/tsumikit';
	import { goto, invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { passkeysSupported, registerPasskey } from '#lib/webauthn';

	let token = $state('');
	let name = $state('');
	let busy = $state(false);
	let error = $state('');
	const supported = passkeysSupported();

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!token.trim() || !name.trim()) {
			error = 'Both fields are needed.';
			return;
		}
		busy = true;
		error = '';
		try {
			await registerPasskey(name.trim(), token.trim());
			await invalidateAll();
			await goto(resolve('/(app)'));
		} catch (err) {
			error = err instanceof Error ? err.message : 'Setup failed.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>First-run setup · tegata</title>
</svelte:head>

<div class="center-card">
	<Card padding="lg">
		<form class="col" onsubmit={submit}>
			<div>
				<Heading level={1} size="xl">Welcome to tegata</Heading>
				<Text as="p" tone="muted">
					No passkey exists yet. Paste the setup token printed in the server log at startup and
					register the first passkey for this browser.
				</Text>
			</div>
			<Field label="Setup token" for="setup-token">
				<Input id="setup-token" bind:value={token} mono autocomplete="off" required />
			</Field>
			<Field label="Passkey name" for="passkey-name" hint="Where this passkey lives.">
				<Input
					id="passkey-name"
					bind:value={name}
					placeholder="Laptop, phone, security key…"
					autocomplete="off"
					required
				/>
			</Field>
			<Button variant="primary" size="lg" block type="submit" loading={busy} disabled={!supported}>
				Register passkey
			</Button>
			{#if !supported}
				<Text as="p" tone="danger" size="sm" role="alert">
					This browser does not support passkeys. Try a current Safari, Chrome, Edge or Firefox.
				</Text>
			{:else if error}
				<Text as="p" tone="danger" size="sm" role="alert">{error}</Text>
			{/if}
		</form>
	</Card>
</div>

<style>
	.col {
		display: flex;
		flex-direction: column;
		gap: var(--sp-5);
	}
</style>
