<script setup lang="ts">
const sidebarOpen = ref(false);
</script>

<template>
  <div class="flex h-screen w-full overflow-hidden bg-bg">
    <AppSidebar v-model:open="sidebarOpen" />
    <main class="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
      <slot />
    </main>
  </div>
</template>
