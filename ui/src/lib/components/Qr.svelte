<script lang="ts">
	import { encode } from 'uqr';

	let { value, label = 'QR code' }: { value: string; label?: string } = $props();

	const qr = $derived(encode(value, { ecc: 'M', border: 2 }));
	const path = $derived.by(() => {
		let d = '';
		qr.data.forEach((row, y) => {
			row.forEach((on, x) => {
				if (on) d += `M${x} ${y}h1v1h-1z`;
			});
		});
		return d;
	});
</script>

<svg
	class="qr"
	viewBox="0 0 {qr.size} {qr.size}"
	role="img"
	aria-label={label}
	shape-rendering="crispEdges"
>
	<rect width={qr.size} height={qr.size} fill="#fff" />
	<path d={path} fill="#000" />
</svg>

<style>
	.qr {
		display: block;
		width: 100%;
		height: auto;
		border-radius: var(--radius-md);
	}
</style>
