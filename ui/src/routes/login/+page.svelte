<script lang="ts">
	import { Button, Card, Heading, Text } from '@dorsk/tsumikit';
	import { goto, invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { loginWithPasskey, passkeysSupported } from '#lib/webauthn';

	let busy = $state(false);
	let error = $state('');
	const supported = passkeysSupported();

	async function signIn() {
		busy = true;
		error = '';
		try {
			await loginWithPasskey();
			await invalidateAll();
			await goto(resolve('/(app)'));
		} catch (e) {
			error = e instanceof Error ? e.message : 'Sign-in failed.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Sign in · tegata</title>
</svelte:head>

<div class="center-card">
	<Card padding="lg">
		<div class="col">
			<div>
				<Heading level={1} size="xl">Sign in</Heading>
				<Text as="p" tone="muted">Use the passkey you registered for this server.</Text>
			</div>
			<Button
				variant="primary"
				size="lg"
				block
				onclick={signIn}
				loading={busy}
				disabled={!supported}
			>
				Sign in with passkey
			</Button>
			{#if !supported}
				<Text as="p" tone="danger" size="sm" role="alert">
					This browser does not support passkeys. Try a current Safari, Chrome, Edge or Firefox.
				</Text>
			{:else if error}
				<Text as="p" tone="danger" size="sm" role="alert">{error}</Text>
			{/if}
		</div>
	</Card>
</div>

<style>
	.col {
		display: flex;
		flex-direction: column;
		gap: var(--sp-5);
	}
</style>
