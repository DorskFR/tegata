<script lang="ts">
	import { Badge } from '@dorsk/tsumikit';
	import type { ComponentProps } from 'svelte';
	import { groupColor } from '#lib/groups';

	let { group, ...rest }: { group: string } & Omit<ComponentProps<typeof Badge>, 'children'> =
		$props();
</script>

<Badge size="sm" {...rest} color={groupColor(group)}>{group}</Badge>
