<script setup lang="ts">
import type { GeoPoint } from '~/types';

const props = defineProps<{ markers: GeoPoint[] }>();

const container = ref<HTMLDivElement>();
const canvas = ref<HTMLCanvasElement>();
let destroy: (() => void) | null = null;
let phi = 0;

async function create() {
  if (!canvas.value || !container.value) return;
  if (destroy) { destroy(); destroy = null; }

  const cobe = await import('cobe');
  const size = Math.min(container.value.offsetWidth, 480);

  destroy = cobe.default(canvas.value, {
    devicePixelRatio: Math.min(window.devicePixelRatio, 2),
    width: size * 2, height: size * 2,
    phi, theta: 0.25,
    dark: 0, diffuse: 2,
    mapSamples: 36000, mapBrightness: 6,
    baseColor: [0.04, 0.08, 0.16],
    markerColor: [1, 0.5, 0.2],
    glowColor: [0.06, 0.14, 0.08],
    markers: props.markers.map(m => ({
      location: [m.lat, m.lng] as [number, number],
      size: Math.min(0.14, Math.max(0.04, m.count / 12)),
    })),
    onRender: (state: any) => { state.phi = phi; phi += 0.002; },
  });

  canvas.value.style.width = `${size}px`;
  canvas.value.style.height = `${size}px`;
}

let lastCount = 0;
watch(() => props.markers.length, (n) => {
  if (n !== lastCount) { lastCount = n; create(); }
});

onMounted(create);
onUnmounted(() => { if (destroy) destroy(); });
</script>

<template>
  <div class="card p-5 flex flex-col h-full">
    <div class="flex items-center justify-between mb-2">
      <p class="text-[11px] font-medium text-txt-3 uppercase tracking-wider">Global Threat Map</p>
      <span class="text-[10px] text-green font-mono font-medium pulse">&#x25CF; Live</span>
    </div>
    <div ref="container" class="flex-1 flex items-center justify-center min-h-0">
      <canvas ref="canvas" class="block max-w-full" />
    </div>
    <div class="flex justify-between text-[10px] text-txt-3 mt-2">
      <span>{{ markers.length }} origins</span>
      <span class="text-green pulse">&#x25CF; ao vivo</span>
    </div>
  </div>
</template>
