<script lang="ts">
	import type { GeoPoint } from '$lib/types';

	let { points = [] }: { points: GeoPoint[] } = $props();

	const top = $derived(points.slice(0, 6));
	const total = $derived(points.reduce((sum, p) => sum + p.count, 0));

	const COUNTRY_COLORS = ['#4ade80', '#60a5fa', '#fbbf24', '#f87171', '#a78bfa', '#fb923c'];
</script>

<div class="card flex-1">
	<h3 class="text-[13px] font-semibold text-text-secondary mb-4">Top Origins</h3>

	{#if top.length === 0}
		<p class="text-text-muted text-[12px] py-4 text-center">No data</p>
	{:else}
		<div class="space-y-3">
			{#each top as point, i (point.label + i)}
				<div class="flex items-center gap-2.5">
					<div class="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0"
						style="background: {COUNTRY_COLORS[i]}20; color: {COUNTRY_COLORS[i]};"
					>
						{i + 1}
					</div>
					<div class="flex-1 min-w-0">
						<div class="flex items-center justify-between">
							<span class="text-[11px] text-text-secondary truncate">{point.label}</span>
							<span class="text-[11px] font-bold tabular-nums text-text ml-2">{point.count}</span>
						</div>
						<div class="w-full h-1 rounded-full bg-surface-2 overflow-hidden mt-1">
							{#if total > 0}
								<div
									class="h-full rounded-full transition-all duration-500"
									style="width: {(point.count / total) * 100}%; background: {COUNTRY_COLORS[i]};"
								></div>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>
