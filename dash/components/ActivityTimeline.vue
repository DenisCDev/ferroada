<script setup lang="ts">
import type { TimelinePoint } from '~/types';

const props = defineProps<{ data: TimelinePoint[] }>();

const canvas = ref<HTMLCanvasElement>();
let chart: any = null;

async function render() {
  if (!canvas.value || props.data.length < 3) return;
  const { Chart, registerables } = await import('chart.js');
  Chart.register(...registerables);
  if (chart) chart.destroy();

  const labels = props.data.map(d =>
    d.time.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  );

  chart = new Chart(canvas.value, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Blocked',
        data: props.data.map(d => d.blocked),
        borderColor: '#4ade80',
        backgroundColor: (ctx: any) => {
          const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height);
          g.addColorStop(0, 'rgba(74,222,128,0.12)');
          g.addColorStop(1, 'rgba(74,222,128,0)');
          return g;
        },
        borderWidth: 2, fill: true, tension: 0.4,
        pointRadius: 0, pointHoverRadius: 4,
        pointHoverBackgroundColor: '#4ade80',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#172038',
          titleColor: '#e2e8f0', bodyColor: '#8b9dc3',
          borderColor: '#253660', borderWidth: 1,
          padding: 10, cornerRadius: 6, displayColors: false,
          callbacks: { label: (ctx: any) => `${ctx.parsed.y} blocked` },
        },
      },
      scales: {
        x: {
          display: true,
          grid: { display: false },
          ticks: { color: '#4a5f8a', font: { size: 10, family: "'JetBrains Mono'" }, maxTicksLimit: 6, maxRotation: 0 },
          border: { display: false },
        },
        y: {
          display: true, beginAtZero: true,
          grid: { color: 'rgba(26,40,68,0.5)', drawTicks: false },
          ticks: { color: '#4a5f8a', font: { size: 10, family: "'JetBrains Mono'" }, padding: 8, maxTicksLimit: 4 },
          border: { display: false },
        },
      },
    },
  });
}

watch(() => props.data.length, render);
onMounted(render);
onUnmounted(() => { if (chart) chart.destroy(); });
</script>

<template>
  <div class="card p-5">
    <div class="flex items-center justify-between mb-3">
      <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider">Real-time Activity</p>
      <span v-if="data.length <= 2" class="text-[10px] text-txt-3 pulse font-mono">Collecting...</span>
    </div>
    <div class="h-32">
      <canvas v-if="data.length > 2" ref="canvas" />
      <div v-else class="flex items-center justify-center h-full">
        <div class="flex items-center gap-2 text-txt-3 text-xs">
          <div class="w-1.5 h-1.5 rounded-full bg-green pulse" />
          <span class="font-mono">Waiting for data points...</span>
        </div>
      </div>
    </div>
  </div>
</template>
