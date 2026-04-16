<script lang="ts">
	import { onMount } from 'svelte';
	import type { GeoPoint } from '$lib/types';

	let { markers = [] }: { markers: GeoPoint[] } = $props();

	let canvasEl: HTMLCanvasElement;
	let containerEl: HTMLDivElement;
	let destroy: (() => void) | null = null;
	let currentPhi = 0;

	function createGlobeInstance(cobeModule: any, width: number) {
		if (destroy) {
			destroy();
			destroy = null;
		}

		const size = Math.min(width, 520);

		destroy = cobeModule.default(canvasEl, {
			devicePixelRatio: Math.min(window.devicePixelRatio, 2),
			width: size * 2,
			height: size * 2,
			phi: currentPhi,
			theta: 0.25,
			dark: 0,
			diffuse: 2,
			mapSamples: 40000,
			mapBrightness: 6,
			baseColor: [0.05, 0.15, 0.08],
			markerColor: [1, 0.5, 0.2],
			glowColor: [0.08, 0.22, 0.1],
			markers: markers.map((m) => ({
				location: [m.lat, m.lng] as [number, number],
				size: Math.min(0.15, Math.max(0.04, m.count / 10))
			})),
			onRender: (state: any) => {
				state.phi = currentPhi;
				currentPhi += 0.002;
			}
		});

		canvasEl.style.width = `${size}px`;
		canvasEl.style.height = `${size}px`;
	}

	onMount(async () => {
		const cobe = await import('cobe');
		const width = containerEl.offsetWidth;
		createGlobeInstance(cobe, width);

		return () => {
			if (destroy) destroy();
		};
	});

	// Recreate globe when markers change significantly
	let lastMarkerCount = 0;
	$effect(() => {
		const markerCount = markers.length;
		if (markerCount !== lastMarkerCount && canvasEl && containerEl) {
			lastMarkerCount = markerCount;
			import('cobe').then((cobe) => {
				createGlobeInstance(cobe, containerEl.offsetWidth);
			});
		}
	});
</script>

<div bind:this={containerEl} class="relative flex items-center justify-center w-full">
	<canvas bind:this={canvasEl} class="block max-w-full"></canvas>

	<!-- Overlay stats on globe -->
	<div class="absolute bottom-4 left-4 right-4 flex justify-between text-xs text-text-secondary">
		<span>{markers.length} origens</span>
		<span class="pulse text-accent">● ao vivo</span>
	</div>
</div>
