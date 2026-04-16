<script lang="ts">
	import { store } from '$lib/stores.svelte';
	import Globe from '$lib/components/Globe.svelte';
	import KpiCard from '$lib/components/KpiCard.svelte';
	import AttackBreakdown from '$lib/components/AttackBreakdown.svelte';
	import Timeline from '$lib/components/Timeline.svelte';
	import EventFeed from '$lib/components/EventFeed.svelte';
	import StatRow from '$lib/components/StatRow.svelte';
	import GeoTable from '$lib/components/GeoTable.svelte';
</script>

<div class="p-5 space-y-4 animate-in">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div>
			<div class="flex items-center gap-2 text-[12px] text-text-muted mb-1">
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" />
				</svg>
				<span>Dashboards</span>
				<span>/</span>
				<span class="text-text font-medium">Overview</span>
			</div>
			<h2 class="text-lg font-bold text-text">Overview</h2>
		</div>
		<div class="flex items-center gap-3">
			{#if store.error}
				<span class="text-[10px] text-warning bg-warning/10 px-2 py-1 rounded-md font-medium border border-warning/20">
					Demo mode
				</span>
			{/if}
			<span class="text-[11px] text-text-muted">Today</span>
		</div>
	</div>

	<!-- KPI Cards -->
	<div class="grid grid-cols-4 gap-3">
		<KpiCard
			label="Total requests"
			value={store.metrics?.requests_total ?? 0}
			previousValue={store.previousMetrics?.requests_total}
			color="text"
			subtitle="vs last poll"
		/>
		<KpiCard
			label="Attacks blocked"
			value={store.totalBlocked}
			previousValue={store.previousTotalBlocked}
			color="danger"
			subtitle="vs last poll"
		/>
		<KpiCard
			label="Protection rate"
			value={store.protectionRate.toFixed(1)}
			suffix="%"
			color="accent"
			subtitle="clean traffic"
		/>
		<KpiCard
			label="Active threats"
			value={store.metrics?.recent_events?.length ?? 0}
			color="warning"
			subtitle="last 100 events"
		/>
	</div>

	<!-- Middle Row -->
	<div class="grid grid-cols-12 gap-3">
		<!-- Donut + Stats -->
		<div class="col-span-4 flex flex-col gap-3">
			<AttackBreakdown categories={store.attackCategories} />
			<StatRow geoPoints={store.geoPoints} httpsRedirects={store.metrics?.https_redirect ?? 0} />
		</div>

		<!-- Globe -->
		<div class="col-span-5">
			<div class="card overflow-hidden h-full flex flex-col">
				<div class="flex items-center justify-between mb-1">
					<h3 class="text-[13px] font-semibold text-text-secondary">Global Threat Map</h3>
					<span class="text-[10px] text-accent font-medium pulse">&#x25CF; Live</span>
				</div>
				<div class="flex-1 min-h-0">
					<Globe markers={store.geoPoints} />
				</div>
			</div>
		</div>

		<!-- Top Origins -->
		<div class="col-span-3">
			<GeoTable points={store.geoPoints} />
		</div>
	</div>

	<!-- Timeline -->
	<Timeline data={store.timeline} />

	<!-- Event Feed -->
	<EventFeed events={store.metrics?.recent_events ?? []} />
</div>
