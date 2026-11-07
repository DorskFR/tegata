<script lang="ts">
	import { EmptyState } from '@dorsk/tsumikit';
	import { page } from '$app/state';

	const title = $derived(page.status === 404 ? 'Page not found' : 'Something went wrong');
	const description = $derived(
		page.status === 404
			? 'There is nothing at this address.'
			: (page.error?.message ?? 'Please try again.')
	);
</script>

<div class="page">
	<EmptyState
		{title}
		{description}
		tone={page.status === 404 ? 'neutral' : 'danger'}
		actionLabel="Go to devices"
		onAction={() => (location.href = '/')}
	/>
</div>
