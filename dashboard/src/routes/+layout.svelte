<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import RightPanel from '$lib/components/RightPanel.svelte';
	import { store } from '$lib/stores.svelte';

	let { children } = $props();

	onMount(() => {
		store.startPolling();
		return () => store.stopPolling();
	});
</script>

<div class="flex h-screen w-screen overflow-hidden">
	<Sidebar totalBlocked={store.totalBlocked} protectionRate={store.protectionRate} />

	<main class="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
		{@render children()}
	</main>

	<RightPanel
		events={store.metrics?.recent_events ?? []}
		dlp={store.metrics?.dlp ?? null}
	/>
</div>
