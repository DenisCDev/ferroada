<script lang="ts">
	import { onMount } from 'svelte';
	import type { TimelinePoint } from '$lib/types';

	let { data = [] }: { data: TimelinePoint[] } = $props();

	let canvasEl: HTMLCanvasElement;
	let chart: any = null;

	async function renderChart() {
		if (!canvasEl) return;

		const { Chart, registerables } = await import('chart.js');
		Chart.register(...registerables);
		if (chart) chart.destroy();

		const labels = data.map((d) =>
			d.time.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
		);
		const values = data.map((d) => d.blocked);

		chart = new Chart(canvasEl, {
			type: 'line',
			data: {
				labels,
				datasets: [{
					label: 'Blocked',
					data: values,
					borderColor: '#4ade80',
					backgroundColor: (ctx: any) => {
						const gradient = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height);
						gradient.addColorStop(0, 'rgba(74, 222, 128, 0.15)');
						gradient.addColorStop(1, 'rgba(74, 222, 128, 0.0)');
						return gradient;
					},
					borderWidth: 2,
					fill: true,
					tension: 0.4,
					pointRadius: 0,
					pointHoverRadius: 4,
					pointHoverBackgroundColor: '#4ade80',
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				interaction: { intersect: false, mode: 'index' },
				plugins: {
					legend: { display: false },
					tooltip: {
						backgroundColor: '#1a2332',
						titleColor: '#F1F5F9',
						bodyColor: '#94A3B8',
						borderColor: '#2a3a50',
						borderWidth: 1,
						padding: 10,
						cornerRadius: 8,
						displayColors: false,
						callbacks: {
							label: (ctx: any) => `${ctx.parsed.y} blocked`
						}
					}
				},
				scales: {
					x: {
						display: true,
						grid: { display: false },
						ticks: {
							color: '#5a6a7e',
							font: { size: 10, family: "'JetBrains Mono', monospace" },
							maxTicksLimit: 6,
							maxRotation: 0
						},
						border: { display: false }
					},
					y: {
						display: true,
						beginAtZero: true,
						grid: { color: 'rgba(30, 41, 59, 0.4)', drawTicks: false },
						ticks: {
							color: '#5a6a7e',
							font: { size: 10, family: "'JetBrains Mono', monospace" },
							padding: 8,
							maxTicksLimit: 4
						},
						border: { display: false }
					}
				}
			}
		});
	}

	onMount(() => () => { if (chart) chart.destroy(); });

	$effect(() => {
		if (data.length > 2) renderChart();
	});
</script>

<div class="card">
	<div class="flex items-center justify-between mb-3">
		<h3 class="text-[13px] font-semibold text-text-secondary">Real-time Activity</h3>
		{#if data.length <= 2}
			<span class="text-[10px] text-text-muted pulse">Collecting data...</span>
		{/if}
	</div>

	<div class="h-36">
		{#if data.length > 2}
			<canvas bind:this={canvasEl}></canvas>
		{:else}
			<div class="flex items-center justify-center h-full">
				<div class="flex items-center gap-2 text-text-muted text-[12px]">
					<div class="w-1.5 h-1.5 rounded-full bg-accent pulse"></div>
					Waiting for data points...
				</div>
			</div>
		{/if}
	</div>
</div>
