<script lang="ts">
	import '../app.css';
	import { Button, Container, Icon, ThemePicker, Toaster, theme, toasts } from '@dorsk/tsumikit';
	import { goto, invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { api } from '#lib/api';
	import Brand from '#lib/components/Brand.svelte';

	let { children } = $props();

	if (!localStorage.getItem('tsumikit-theme')) {
		theme.hydrate({ mode: 'auto', light: 'light', dark: 'dark' });
	}

	const authed = $derived(page.data.session?.authenticated === true);
	const path = $derived(page.url.pathname);

	let loggingOut = $state(false);
	async function logout() {
		loggingOut = true;
		try {
			await api.auth.logout();
			await invalidateAll();
			await goto(resolve('/login'));
		} catch (e) {
			toasts.error(e instanceof Error ? e.message : 'Could not log out.');
		} finally {
			loggingOut = false;
		}
	}
</script>

<svelte:head>
	<title>tegata</title>
</svelte:head>

<header class="top">
	<div class="bar">
		<Brand to={authed ? '/(app)' : '/login'} />
		{#if authed}
			<nav class="nav" aria-label="Main">
				<a href={resolve('/(app)')} aria-current={path === '/' ? 'page' : undefined}>Devices</a>
				<a
					href={resolve('/(app)/passkeys')}
					aria-current={path.startsWith('/passkeys') ? 'page' : undefined}
				>
					Passkeys
				</a>
			</nav>
		{/if}
		<div class="tools">
			<ThemePicker auto variant="ghost" box="sm" />
			{#if authed}
				<Button
					variant="ghost"
					size="sm"
					collapseLabel="mobile"
					onclick={logout}
					loading={loggingOut}
				>
					<Icon name="log-out" />
					<span data-label>Log out</span>
				</Button>
			{/if}
		</div>
	</div>
</header>
<Container as="main">
	{@render children()}
</Container>
<Toaster />

<style>
	.top {
		position: sticky;
		top: 0;
		z-index: 10;
		background: var(--c-bg-elev);
		border-bottom: 1px solid var(--c-border);
		padding-top: env(safe-area-inset-top);
	}
	.bar {
		display: flex;
		align-items: center;
		gap: var(--sp-4);
		max-width: var(--content-max);
		margin-inline: auto;
		padding: var(--sp-2) var(--sp-4);
		min-height: 3.25rem;
	}
	.nav {
		display: flex;
		gap: var(--sp-1);
	}
	.nav a {
		display: inline-flex;
		align-items: center;
		min-height: 2.5rem;
		padding: 0 var(--sp-3);
		border-radius: var(--radius-md);
		color: var(--text-muted);
		font-weight: 500;
		text-decoration: none;
	}
	.nav a:hover {
		color: var(--text);
		background: var(--c-bg-elev-2);
	}
	.nav a[aria-current='page'] {
		color: var(--text);
		background: var(--c-bg-elev-2);
	}
	.tools {
		display: flex;
		align-items: center;
		gap: var(--sp-2);
		margin-inline-start: auto;
		flex: none;
	}
	@media (max-width: 30rem) {
		.bar {
			gap: var(--sp-2);
		}
		.nav a {
			padding-inline: var(--sp-2);
		}
	}
</style>
