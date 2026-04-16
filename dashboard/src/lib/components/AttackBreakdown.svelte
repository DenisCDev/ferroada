<script lang="ts">
	import { onMount } from 'svelte';
	import type { AttackCategory } from '$lib/types';

	let { categories = [] }: { categories: AttackCategory[] } = $props();

	let canvasEl: HTMLCanvasElement;
	let chart: any = null;

	const COLORS = ['#4ade80', '#facc15', '#60a5fa', '#f87171', '#a78bfa', '#fb923c', '#2dd4bf', '#94a3b8'];

	const totalCount = $derived(categories.reduce((s, c) => s + c.count, 0));

	async function renderDonut() {
		if (!canvasEl || categories.length === 0) return;

		const { Chart, registerables } = await import('chart.js');
		Chart.register(...registerables);
		if (chart) chart.destroy();

		chart = new Chart(canvasEl, {
			type: 'doughnut',
			data: {
				labels: categories.map((c) => c.label),
				datasets: [{
					data: categories.map((c) => c.count),
					backgroundColor: categories.map((_, i) => COLORS[i % COLORS.length]),
					borderColor: '#111827',
					borderWidth: 2,
					hoverBorderColor: '#1a2332',
					borderRadius: 3,
				}]
			},
			options: {
				responsive: false,
				cutout: '70%',
				plugins: {
					legend: { display: false },
					tooltip: {
						backgroundColor: '#1a2332',
						titleColor: '#F1F5F9',
						bodyColor: '#94A3B8',
						borderColor: '#334155',
						borderWidth: 1,
						padding: 10,
						cornerRadius: 8,
						displayColors: true,
						boxWidth: 8,
						boxHeight: 8,
						boxPadding: 4,
					}
				}
			}
		});
	}

	onMount(() => () => { if (chart) chart.destroy(); });

	$effect(() => {
		if (categories.length > 0) renderDonut();
	});
</script>

<div class="card">
	<h3 class="text-[13px] font-semibold text-text-secondary mb-4">Threat Overview</h3>

	<div class="flex justify-center mb-4">
		<div class="relative">
			<canvas bind:this={canvasEl} width="150" height="150"></canvas>
			<div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
				<span class="text-xl font-extrabold tabular-nums text-text">{totalCount.toLocaleString('pt-BR')}</span>
				<span class="text-[10px] text-text-muted">Blocked</span>
			</div>
		</div>
	</div>

	<div class="grid grid-cols-2 gap-x-4 gap-y-1.5">
		{#each categories.slice(0, 6) as cat, i (cat.key)}
			<div class="flex items-center gap-2 min-w-0">
				<div class="w-2 h-2 rounded-full shrink-0" style="background: {COLORS[i % COLORS.length]}"></div>
				<span class="text-[11px] text-text-secondary truncate">{cat.label}</span>
				<span class="text-[11px] font-semibold tabular-nums text-text ml-auto">{cat.count.toLocaleString('pt-BR')}</span>
			</div>
		{/each}
	</div>
</div>
