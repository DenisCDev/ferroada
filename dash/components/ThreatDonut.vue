<script setup lang="ts">
import type { AttackCategory } from '~/types';

const props = defineProps<{ categories: AttackCategory[] }>();

const canvas = ref<HTMLCanvasElement>();
let chart: any = null;

const COLORS = ['#4ade80', '#f59e0b', '#3b82f6', '#ef4444', '#a78bfa', '#fb923c', '#2dd4bf', '#94a3b8'];

const total = computed(() => props.categories.reduce((s, c) => s + c.count, 0));

async function render() {
  if (!canvas.value || props.categories.length === 0) return;
  const { Chart, registerables } = await import('chart.js');
  Chart.register(...registerables);
  if (chart) chart.destroy();

  chart = new Chart(canvas.value, {
    type: 'doughnut',
    data: {
      labels: props.categories.map(c => c.label),
      datasets: [{
        data: props.categories.map(c => c.count),
        backgroundColor: props.categories.map((_, i) => COLORS[i % COLORS.length]),
        borderColor: '#111a2e',
        borderWidth: 2,
        borderRadius: 3,
      }],
    },
    options: {
      responsive: false,
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#172038',
          titleColor: '#e2e8f0',
          bodyColor: '#8b9dc3',
          borderColor: '#253660',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 6,
          displayColors: true,
          boxWidth: 8, boxHeight: 8, boxPadding: 4,
        },
      },
    },
  });
}

watch(() => props.categories, () => render(), { deep: true });
onMounted(render);
onUnmounted(() => { if (chart) chart.destroy(); });
</script>

<template>
  <div class="card p-5">
    <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider mb-4">Threat Breakdown</p>

    <!-- Donut -->
    <div class="flex justify-center mb-4">
      <div class="relative">
        <canvas ref="canvas" width="140" height="140" />
        <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span class="font-display text-xl font-bold tabular text-txt">{{ total.toLocaleString('pt-BR') }}</span>
          <span class="text-[9px] text-txt-3 uppercase tracking-wider">blocked</span>
        </div>
      </div>
    </div>

    <!-- Legend -->
    <div class="grid grid-cols-2 gap-x-3 gap-y-1">
      <div v-for="(cat, i) in categories.slice(0, 6)" :key="cat.key" class="flex items-center gap-1.5 min-w-0">
        <div class="w-2 h-2 rounded-full shrink-0" :style="{ background: COLORS[i % COLORS.length] }" />
        <span class="text-[11px] text-txt-2 truncate">{{ cat.label }}</span>
        <span class="text-[11px] font-mono font-semibold tabular text-txt ml-auto">{{ cat.count }}</span>
      </div>
    </div>
  </div>
</template>
