<script setup lang="ts">
import type { SecurityEvent } from '~/types';

const props = defineProps<{ events: SecurityEvent[] }>();

const TAG: Record<string, { bg: string; fg: string }> = {
  sqli:           { bg: 'rgba(239,68,68,0.1)',   fg: '#ef4444' },
  body_sqli:      { bg: 'rgba(239,68,68,0.1)',   fg: '#ef4444' },
  xss:            { bg: 'rgba(245,158,11,0.1)',   fg: '#f59e0b' },
  body_xss:       { bg: 'rgba(245,158,11,0.1)',   fg: '#f59e0b' },
  path_traversal: { bg: 'rgba(251,146,60,0.1)',   fg: '#fb923c' },
  rate_limit:     { bg: 'rgba(59,130,246,0.1)',   fg: '#3b82f6' },
  sensitive_path: { bg: 'rgba(167,139,250,0.1)',  fg: '#a78bfa' },
};

function fmt(ts: string) {
  try { return new Date(ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return ts.slice(11, 19); }
}
function trunc(s: string, n: number) { return s.length > n ? s.slice(0, n) + '...' : s; }
function tag(t: string) { return TAG[t] ?? { bg: 'rgba(148,163,184,0.1)', fg: '#94a3b8' }; }
</script>

<template>
  <div class="card overflow-hidden p-0">
    <div class="px-5 py-3 flex items-center justify-between border-b border-border">
      <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider">Event Log</p>
      <span class="text-[10px] font-mono text-txt-3 tabular">{{ events.length }} events</span>
    </div>

    <div v-if="events.length === 0" class="px-5 py-10 text-center text-txt-3 text-xs">
      No events recorded
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full">
        <thead>
          <tr class="bg-surface-lo/50">
            <th class="px-5 py-2 text-left text-[9px] font-semibold uppercase tracking-wider text-txt-3">Time</th>
            <th class="px-5 py-2 text-left text-[9px] font-semibold uppercase tracking-wider text-txt-3">Type</th>
            <th class="px-5 py-2 text-left text-[9px] font-semibold uppercase tracking-wider text-txt-3">Source</th>
            <th class="px-5 py-2 text-left text-[9px] font-semibold uppercase tracking-wider text-txt-3">URI</th>
            <th class="px-5 py-2 text-left text-[9px] font-semibold uppercase tracking-wider text-txt-3">Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(ev, i) in events.slice(0, 10)" :key="ev.timestamp + ev.client_ip + i"
              class="border-t border-border/40 hover:bg-surface-hi/20 transition-colors duration-100">
            <td class="px-5 py-2 text-[11px] font-mono text-txt-3 whitespace-nowrap">{{ fmt(ev.timestamp) }}</td>
            <td class="px-5 py-2">
              <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold"
                    :style="{ background: tag(ev.event_type).bg, color: tag(ev.event_type).fg }">
                {{ ev.event_type }}
              </span>
            </td>
            <td class="px-5 py-2 text-[11px] font-mono text-txt-2 whitespace-nowrap">{{ ev.client_ip }}</td>
            <td class="px-5 py-2 text-[11px] font-mono text-txt-3 max-w-[200px]">
              <span :title="ev.uri">{{ trunc(ev.uri, 30) }}</span>
            </td>
            <td class="px-5 py-2 text-[11px] text-txt-3 max-w-[200px]">
              <span :title="ev.detail">{{ trunc(ev.detail, 35) }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
