<script lang="ts">
	import { resolve } from '$app/paths';

	let { to = '/(app)' }: { to?: '/(app)' | '/login' } = $props();
</script>

<a class="brand" href={resolve(to)} aria-label="tegata home">
	<svg viewBox="0 0 32 32" aria-hidden="true">
		<rect width="32" height="32" rx="7" fill="var(--accent)" />
		<g stroke="var(--c-accent-ink)" stroke-linecap="round" stroke-linejoin="round" fill="none">
			<path d="M10 9 13 6h6l3 3v17H10z" stroke-width="2" />
			<path d="M14 13v7M18 13v4" stroke-width="1.6" />
		</g>
		<circle cx="16" cy="9.5" r="1.2" fill="var(--c-accent-ink)" />
		<rect x="16.5" y="19.5" width="3.2" height="3.2" rx=".4" fill="#e0533d" />
	</svg>
	<span>tegata</span>
</a>
