<script lang="ts">
	import { ConfirmModal } from '@dorsk/tsumikit';

	let {
		pending = $bindable(null)
	}: {
		pending?: { message: string; apply: () => Promise<void> } | null;
	} = $props();

	let busy = $state(false);

	async function confirm() {
		if (!pending) return;
		busy = true;
		try {
			await pending.apply();
			pending = null;
		} finally {
			busy = false;
		}
	}
</script>

<ConfirmModal
	open={pending !== null}
	title="Lock yourself out of tegata?"
	message={`${pending?.message ?? ''} Afterwards this browser gets a refusal page here, and only another allowed device can undo it.`}
	tone="danger"
	confirmLabel="Apply anyway"
	{busy}
	onconfirm={confirm}
	oncancel={() => (pending = null)}
/>
