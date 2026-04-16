<script setup lang="ts">
defineProps<{
  label: string;
  value: string | number;
  detail?: string;
  color?: string;
}>();
</script>

<template>
  <div class="card px-4 py-3 flex items-center gap-3">
    <slot name="icon" />
    <div class="min-w-0">
      <p class="text-[10px] text-txt-3 uppercase tracking-wider">{{ label }}</p>
      <p class="font-display text-lg font-bold tabular text-txt leading-tight">
        {{ typeof value === 'number' ? value.toLocaleString('pt-BR') : value }}
      </p>
    </div>
    <p v-if="detail" class="ml-auto text-right">
      <span class="text-[9px] text-txt-3 block">Top:</span>
      <span class="text-[11px] font-medium" :style="{ color: color ?? 'var(--color-green)' }">{{ detail }}</span>
    </p>
  </div>
</template>
