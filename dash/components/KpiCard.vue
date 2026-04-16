<script setup lang="ts">
const props = defineProps<{
  label: string;
  value: number | string;
  previousValue?: number;
  suffix?: string;
  color?: string;
  subtitle?: string;
}>();

const displayValue = ref(typeof props.value === 'number' ? 0 : props.value);
const flashing = ref(false);

watch(() => props.value, (val) => {
  if (typeof val === 'number') {
    const from = typeof displayValue.value === 'number' ? displayValue.value : 0;
    const to = val;
    if (from === to) return;
    flashing.value = true;
    setTimeout(() => flashing.value = false, 400);
    const steps = 14;
    const inc = (to - from) / steps;
    let step = 0;
    const t = setInterval(() => {
      step++;
      if (step >= steps) { displayValue.value = to; clearInterval(t); }
      else displayValue.value = Math.round(from + inc * step);
    }, 25);
  } else {
    displayValue.value = val;
  }
}, { immediate: true });

const delta = computed(() => {
  if (props.previousValue === undefined || typeof props.value !== 'number') return 0;
  return props.value - props.previousValue;
});

const pct = computed(() => {
  if (!props.previousValue || props.previousValue <= 0 || typeof props.value !== 'number') return null;
  return (((props.value - props.previousValue) / props.previousValue) * 100).toFixed(1);
});

const colorVar = computed(() => `var(--color-${props.color ?? 'green'})`);
</script>

<template>
  <div class="card px-5 py-4 group">
    <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider mb-2">{{ label }}</p>
    <p
      class="font-display text-[26px] font-bold tabular leading-none tracking-tight transition-colors duration-300"
      :style="{ color: colorVar }"
      :class="flashing ? 'brightness-150' : ''"
    >
      {{ typeof displayValue === 'number' ? displayValue.toLocaleString('pt-BR') : displayValue }}{{ suffix ?? '' }}
    </p>
    <div class="mt-2 flex items-center gap-2">
      <span
        v-if="delta !== 0 && pct"
        class="inline-flex items-center gap-0.5 text-[10px] font-mono font-medium tabular px-1.5 py-0.5 rounded"
        :style="{
          background: delta > 0 ? 'rgba(74,222,128,0.08)' : 'rgba(239,68,68,0.08)',
          color: delta > 0 ? 'var(--color-green)' : 'var(--color-red)',
        }"
      >
        {{ delta > 0 ? '+' : '' }}{{ pct }}%
      </span>
      <span v-if="subtitle" class="text-[10px] text-txt-3">{{ subtitle }}</span>
    </div>
  </div>
</template>
