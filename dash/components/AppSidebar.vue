<script setup lang="ts">
const open = defineModel<boolean>('open', { default: false });
const collapsed = ref(false);

const navItems = [
  { id: 'overview', label: 'Overview', icon: 'grid' },
  { id: 'attacks', label: 'Ataques', icon: 'shield' },
  { id: 'analytics', label: 'Analytics', icon: 'chart' },
  { id: 'sites', label: 'Sites', icon: 'globe' },
];

const bottomItems = [
  { id: 'dlp', label: 'DLP', icon: 'lock' },
  { id: 'settings', label: 'Settings', icon: 'gear' },
];

const active = ref('overview');

function navigate(id: string) {
  active.value = id;
  if (window.innerWidth < 768) open.value = false;
}
</script>

<template>
  <!-- Mobile trigger -->
  <button
    class="fixed top-4 left-4 z-50 p-2 rounded-lg bg-surface border border-border md:hidden
           hover:bg-surface-hi active:scale-95 transition-all duration-150"
    @click="open = !open"
  >
    <svg v-if="!open" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-txt-2"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
    <svg v-else width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-txt-2"><path d="M18 6 6 18M6 6l12 12"/></svg>
  </button>

  <!-- Overlay -->
  <Transition name="fade">
    <div v-if="open" class="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 md:hidden" @click="open = false" />
  </Transition>

  <!-- Sidebar -->
  <aside
    class="fixed top-0 left-0 h-full z-40 flex flex-col bg-surface-lo border-r border-border
           transition-all duration-300 ease-out
           md:static md:z-auto"
    :class="[
      open ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
      collapsed ? 'w-16' : 'w-56',
    ]"
  >
    <!-- Brand -->
    <div class="flex items-center gap-3 px-4 h-14 shrink-0 border-b border-border">
      <div class="w-8 h-8 rounded-lg bg-green/10 border border-green/20 flex items-center justify-center shrink-0">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="text-green">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <template v-if="!collapsed">
        <div class="min-w-0 flex-1">
          <p class="font-display text-sm font-bold text-txt leading-none tracking-tight">Ferroada</p>
          <p class="text-[9px] font-semibold uppercase tracking-[0.15em] text-green/60 mt-0.5">Shield</p>
        </div>
        <button
          class="p-1 rounded hover:bg-surface transition-colors hidden md:block"
          @click="collapsed = true"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-txt-3"><path d="m15 18-6-6 6-6"/></svg>
        </button>
      </template>
    </div>

    <!-- Expand button (collapsed) -->
    <button
      v-if="collapsed"
      class="absolute -right-3 top-[18px] w-6 h-6 rounded-full bg-surface border border-border
             flex items-center justify-center hover:bg-surface-hi transition-colors hidden md:flex"
      @click="collapsed = false"
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="text-txt-2"><path d="m9 18 6-6-6-6"/></svg>
    </button>

    <!-- Search -->
    <div v-if="!collapsed" class="px-3 py-2.5 shrink-0">
      <div class="flex items-center gap-2 bg-bg/60 rounded-lg px-3 py-1.5 border border-border/50
                  text-txt-3 hover:border-border-hi transition-colors cursor-pointer">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="shrink-0 opacity-60"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <span class="text-xs">Search...</span>
        <span class="ml-auto text-[9px] font-mono bg-surface rounded px-1 py-0.5 border border-border/40 opacity-50">⌘K</span>
      </div>
    </div>
    <div v-else class="flex justify-center py-2.5 shrink-0">
      <button class="p-1.5 rounded-lg hover:bg-surface transition-colors">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-txt-3"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      </button>
    </div>

    <!-- Nav -->
    <nav class="flex-1 overflow-y-auto px-2 min-h-0">
      <p v-if="!collapsed" class="px-2.5 mt-1 mb-1.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-txt-3/60">
        Dashboards
      </p>
      <ul class="space-y-0.5" :class="collapsed ? '' : 'mb-5'">
        <li v-for="item in navItems" :key="item.id" class="relative group">
          <button
            class="w-full flex items-center gap-2.5 rounded-lg text-[13px] transition-all duration-150"
            :class="[
              collapsed ? 'justify-center p-2' : 'px-2.5 py-[7px]',
              active === item.id
                ? 'bg-green/8 text-green'
                : 'text-txt-3 hover:text-txt-2 hover:bg-surface/60',
            ]"
            @click="navigate(item.id)"
          >
            <!-- Icons -->
            <svg v-if="item.icon==='grid'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>
            <svg v-else-if="item.icon==='shield'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <svg v-else-if="item.icon==='chart'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg>
            <svg v-else-if="item.icon==='globe'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>

            <span v-if="!collapsed" :class="active === item.id ? 'font-medium' : ''">{{ item.label }}</span>
          </button>
          <!-- Tooltip -->
          <div v-if="collapsed"
            class="absolute left-full ml-2 top-1/2 -translate-y-1/2 px-2.5 py-1 bg-surface-hi text-txt text-xs rounded-md border border-border
                   opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 whitespace-nowrap z-50 pointer-events-none"
          >{{ item.label }}</div>
        </li>
      </ul>

      <p v-if="!collapsed" class="px-2.5 mb-1.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-txt-3/60">
        Config
      </p>
      <ul class="space-y-0.5">
        <li v-for="item in bottomItems" :key="item.id" class="relative group">
          <button
            class="w-full flex items-center gap-2.5 rounded-lg text-[13px] transition-all duration-150"
            :class="[
              collapsed ? 'justify-center p-2' : 'px-2.5 py-[7px]',
              active === item.id
                ? 'bg-green/8 text-green'
                : 'text-txt-3 hover:text-txt-2 hover:bg-surface/60',
            ]"
            @click="navigate(item.id)"
          >
            <svg v-if="item.icon==='lock'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            <svg v-else width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0"><circle cx="12" cy="12" r="3"/><path d="M12 1v2m0 18v2m-9-11h2m18 0h2"/><path d="m18.4 5.6-1.4 1.4M7 17l-1.4 1.4m0-13.4L7 7m10 10 1.4 1.4"/></svg>
            <span v-if="!collapsed" :class="active === item.id ? 'font-medium' : ''">{{ item.label }}</span>
          </button>
          <div v-if="collapsed"
            class="absolute left-full ml-2 top-1/2 -translate-y-1/2 px-2.5 py-1 bg-surface-hi text-txt text-xs rounded-md border border-border
                   opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 whitespace-nowrap z-50 pointer-events-none"
          >{{ item.label }}</div>
        </li>
      </ul>
    </nav>

    <!-- Status footer -->
    <div class="shrink-0 border-t border-border px-3 py-2.5 flex items-center" :class="collapsed ? 'justify-center' : 'gap-2'">
      <div class="w-[5px] h-[5px] rounded-full bg-green pulse shrink-0" />
      <template v-if="!collapsed">
        <span class="text-[10px] text-txt-3/50">Ferroada v0.4</span>
        <span class="ml-auto text-[10px] font-mono text-txt-3/30 tabular">5s</span>
      </template>
    </div>
  </aside>
</template>

<style scoped>
.fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
