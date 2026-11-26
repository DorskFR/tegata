<script lang="ts">
	import { asset, resolve } from '$app/paths';

	let { to = '/(app)' }: { to?: '/(app)' | '/login' } = $props();
</script>

<a class="brand" href={resolve(to)} aria-label="tegata home">
	<img src={asset('/favicon.svg')} alt="" />
	<span>tegata</span>
</a>
