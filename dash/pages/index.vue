<script setup lang="ts">
import { useMetrics } from '~/composables/useMetrics';

const {
  metrics, previousMetrics, error,
  totalBlocked, previousTotalBlocked,
  protectionRate, geoPoints, attackCategories, timeline,
} = useMetrics();
</script>

<template>
  <div class="px-6 py-5 space-y-4 w-full overflow-hidden">
    <!-- Header -->
    <div class="flex items-end justify-between stagger-in">
      <div>
        <div class="flex items-center gap-1.5 text-[11px] text-txt-3 mb-1">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
          <span>Dashboards</span>
          <span class="opacity-40">/</span>
          <span class="text-txt font-medium">Overview</span>
        </div>
        <h1 class="font-display text-2xl font-bold text-txt tracking-tight">Overview</h1>
      </div>
      <div class="flex items-center gap-3">
        <span v-if="error" class="text-[10px] text-amber bg-amber/8 px-2 py-1 rounded font-mono font-medium border border-amber/15">
          demo mode
        </span>
        <span class="text-[10px] font-mono text-txt-3">Today</span>
      </div>
    </div>

    <!-- KPI Row -->
    <div class="grid grid-cols-4 gap-3 stagger-in" style="animation-delay: 50ms">
      <KpiCard
        label="Total requests"
        :value="metrics?.requests_total ?? 0"
        :previous-value="previousMetrics?.requests_total"
        color="txt"
        subtitle="vs last poll"
      />
      <KpiCard
        label="Attacks blocked"
        :value="totalBlocked"
        :previous-value="previousTotalBlocked"
        color="red"
        subtitle="vs last poll"
      />
      <KpiCard
        label="Protection rate"
        :value="protectionRate.toFixed(1)"
        suffix="%"
        color="green"
        subtitle="clean traffic"
      />
      <KpiCard
        label="Active threats"
        :value="metrics?.recent_events?.length ?? 0"
        color="amber"
        subtitle="last 100 events"
      />
    </div>

    <!-- Bento row: Donut | Globe | Origins -->
    <div class="grid grid-cols-12 gap-3 stagger-in overflow-hidden" style="animation-delay: 100ms">
      <div class="col-span-3 min-w-0 overflow-hidden">
        <ThreatDonut :categories="attackCategories" />
      </div>
      <div class="col-span-6 min-w-0 overflow-hidden">
        <GlobeMap :markers="geoPoints" />
      </div>
      <div class="col-span-3 min-w-0 overflow-hidden">
        <TopOrigins :points="geoPoints" />
      </div>
    </div>

    <!-- Stats row -->
    <div class="grid grid-cols-3 gap-3 stagger-in" style="animation-delay: 150ms">
      <StatCard
        label="Attack origins"
        :value="geoPoints.length"
        :detail="geoPoints[0]?.label"
      >
        <template #icon>
          <div class="w-9 h-9 rounded-lg bg-green/8 flex items-center justify-center shrink-0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="text-green"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          </div>
        </template>
      </StatCard>
      <StatCard
        label="HTTPS redirects"
        :value="metrics?.https_redirect ?? 0"
      >
        <template #icon>
          <div class="w-9 h-9 rounded-lg bg-blue/8 flex items-center justify-center shrink-0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="text-blue"><path d="M12 22V8"/><path d="m5 12 7-7 7 7"/><path d="M5 22h14"/></svg>
          </div>
        </template>
      </StatCard>
      <StatCard
        label="DLP actions"
        :value="(metrics?.dlp?.cpf_masked ?? 0) + (metrics?.dlp?.tokens_masked ?? 0)"
        :detail="`${metrics?.dlp?.cpf_masked ?? 0} CPFs`"
        color="var(--color-violet)"
      >
        <template #icon>
          <div class="w-9 h-9 rounded-lg bg-violet/8 flex items-center justify-center shrink-0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="text-violet"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
          </div>
        </template>
      </StatCard>
    </div>

    <!-- Timeline -->
    <div class="stagger-in" style="animation-delay: 200ms">
      <ActivityTimeline :data="timeline" />
    </div>

    <!-- Event Feed -->
    <div class="stagger-in" style="animation-delay: 250ms">
      <EventTable :events="metrics?.recent_events ?? []" />
    </div>
  </div>
</template>
