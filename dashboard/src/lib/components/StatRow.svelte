<script lang="ts">
	import type { GeoPoint } from '$lib/types';

	let {
		geoPoints = [],
		httpsRedirects = 0
	}: {
		geoPoints: GeoPoint[];
		httpsRedirects: number;
	} = $props();

	const topOrigin = $derived(geoPoints.length > 0 ? geoPoints[0] : null);
	const totalAttackIps = $derived(geoPoints.length);
</script>

<div class="grid grid-cols-2 gap-4">
	<!-- New customers style card -->
	<div class="card flex items-center gap-3">
		<div class="w-10 h-10 rounded-xl bg-accent/10 flex items-center justify-center shrink-0">
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-accent">
				<circle cx="12" cy="12" r="10" /><path d="M2 12h20" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
			</svg>
		</div>
		<div>
			<p class="text-[11px] text-text-muted">Attack origins</p>
			<p class="text-lg font-bold tabular-nums text-text">{totalAttackIps}</p>
		</div>
		{#if topOrigin}
			<div class="ml-auto text-right">
				<p class="text-[10px] text-text-muted">Top:</p>
				<p class="text-[11px] font-medium text-accent">{topOrigin.label}</p>
			</div>
		{/if}
	</div>

	<!-- Total profit style card -->
	<div class="card flex items-center gap-3">
		<div class="w-10 h-10 rounded-xl bg-info/10 flex items-center justify-center shrink-0">
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-info">
				<path d="M12 22V8" /><path d="m5 12 7-7 7 7" /><path d="M5 22h14" />
			</svg>
		</div>
		<div>
			<p class="text-[11px] text-text-muted">HTTPS redirects</p>
			<p class="text-lg font-bold tabular-nums text-text">{httpsRedirects.toLocaleString('pt-BR')}</p>
		</div>
	</div>
</div>
