<script lang="ts">
	import { resolve } from '$app/paths';

	let { to = '/(app)' }: { to?: '/(app)' | '/login' } = $props();
</script>

<a class="brand" href={resolve(to)} aria-label="tegata home">
	<svg viewBox="0 0 32 32" aria-hidden="true">
		<rect width="32" height="32" rx="7" fill="var(--accent)" />
		<path
			d="M9 11h14M16 11v11M12 22h8"
			stroke="var(--c-accent-ink)"
			stroke-width="3"
			stroke-linecap="round"
			fill="none"
		/>
	</svg>
	<span>tegata</span>
</a>
