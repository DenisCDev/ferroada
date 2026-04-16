<script setup lang="ts">
import type { GeoPoint } from '~/types';

const props = defineProps<{ points: GeoPoint[] }>();

const top = computed(() => props.points.slice(0, 5));
const maxCount = computed(() => top.value.length > 0 ? top.value[0].count : 1);

const BAR_COLORS = ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444', '#a78bfa'];
</script>

<template>
  <div class="card p-5 h-full flex flex-col overflow-hidden">
    <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider mb-4">Top Origins</p>

    <div v-if="top.length === 0" class="flex-1 flex items-center justify-center">
      <p class="text-txt-3 text-xs">No data</p>
    </div>

    <div v-else class="space-y-3 flex-1 overflow-hidden">
      <div v-for="(p, i) in top" :key="p.label" class="flex items-center gap-2.5 min-w-0">
        <span
          class="w-5 h-5 rounded flex items-center justify-center text-[9px] font-mono font-bold shrink-0"
          :style="{ background: BAR_COLORS[i] + '15', color: BAR_COLORS[i] }"
        >{{ i + 1 }}</span>
        <div class="min-w-0 flex-1 overflow-hidden">
          <div class="flex justify-between items-baseline mb-0.5">
            <span class="text-[12px] text-txt-2 truncate">{{ p.label }}</span>
            <span class="text-[11px] font-mono font-semibold tabular text-txt ml-2 shrink-0">{{ p.count }}</span>
          </div>
          <div class="h-1 rounded-full bg-surface-hi overflow-hidden">
            <div
              class="h-full rounded-full transition-all duration-500"
              :style="{ width: (p.count / maxCount * 100) + '%', background: BAR_COLORS[i] }"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
