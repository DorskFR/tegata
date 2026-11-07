<script lang="ts">
	import { Badge } from '@dorsk/tsumikit';
	import type { DeviceStatus } from '#lib/api';
	import { statusLabel, statusTone } from '#lib/format';

	let { status }: { status: DeviceStatus } = $props();
</script>

<Badge tone={statusTone(status)} dot size="sm">{statusLabel(status)}</Badge>
