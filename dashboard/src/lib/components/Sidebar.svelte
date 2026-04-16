<script lang="ts">
	import { onMount } from 'svelte';

	let { totalBlocked = 0, protectionRate = 100 }: { totalBlocked: number; protectionRate: number } =
		$props();

	let isCollapsed = $state(false);
	let isMobileOpen = $state(false);
	let activeItem = $state('overview');

	onMount(() => {
		const handleResize = () => {
			if (window.innerWidth < 768) isMobileOpen = false;
		};
		window.addEventListener('resize', handleResize);
		return () => window.removeEventListener('resize', handleResize);
	});

	function handleNav(id: string) {
		activeItem = id;
		if (window.innerWidth < 768) isMobileOpen = false;
	}

	const dashItems = $derived([
		{ id: 'overview', label: 'Overview', badge: '' },
		{ id: 'attacks', label: 'Ataques', badge: totalBlocked > 0 ? String(totalBlocked) : '' },
		{ id: 'analytics', label: 'Analytics', badge: '' },
		{ id: 'sites', label: 'Sites', badge: '' },
	]);

	const settItems = [
		{ id: 'dlp', label: 'DLP' },
		{ id: 'settings', label: 'Settings' },
	];
</script>

<!-- Mobile hamburger -->
<button
	onclick={() => (isMobileOpen = !isMobileOpen)}
	class="fixed top-4 left-4 z-50 p-2.5 rounded-lg bg-surface border border-border md:hidden hover:bg-surface-2 transition-colors"
	aria-label="Toggle sidebar"
>
	{#if isMobileOpen}
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-text-secondary"><path d="M18 6 6 18M6 6l12 12"/></svg>
	{:else}
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-text-secondary"><path d="M3 12h18M3 6h18M3 18h18"/></svg>
	{/if}
</button>

<!-- Mobile overlay -->
{#if isMobileOpen}
	<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
	<div class="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 md:hidden" onclick={() => (isMobileOpen = false)}></div>
{/if}

<!-- Sidebar -->
<aside
	class="fixed top-0 left-0 h-full z-40 flex flex-col transition-all duration-300 ease-in-out
		bg-surface border-r border-border
		md:static md:z-auto
		{isMobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
		{isCollapsed ? 'w-[68px]' : 'w-[240px]'}"
>
	<!-- Brand -->
	<div class="flex items-center gap-3 px-4 h-[60px] shrink-0 border-b border-border">
		<div class="w-8 h-8 rounded-lg bg-accent/15 flex items-center justify-center shrink-0">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="text-accent">
				<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
			</svg>
		</div>
		{#if !isCollapsed}
			<div class="min-w-0">
				<h1 class="text-sm font-bold text-text leading-none">Ferroada</h1>
				<span class="text-[9px] font-semibold uppercase tracking-widest text-accent/70">Shield</span>
			</div>
			<button
				onclick={() => (isCollapsed = true)}
				class="ml-auto p-1 rounded hover:bg-surface-2 transition-colors hidden md:block"
				aria-label="Collapse sidebar"
			>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-text-muted"><path d="m15 18-6-6 6-6"/></svg>
			</button>
		{:else}
			<button
				onclick={() => (isCollapsed = false)}
				class="absolute -right-3 top-5 w-6 h-6 rounded-full bg-surface-2 border border-border flex items-center justify-center hover:bg-border transition-colors hidden md:flex"
				aria-label="Expand sidebar"
			>
				<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="text-text-secondary"><path d="m9 18 6-6-6-6"/></svg>
			</button>
		{/if}
	</div>

	<!-- Search -->
	{#if !isCollapsed}
		<div class="px-3 py-3 shrink-0">
			<div class="flex items-center gap-2 bg-surface-2/60 rounded-lg px-3 py-2 border border-border/60 text-text-muted hover:border-border-light transition-colors cursor-pointer">
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="shrink-0 opacity-60">
					<circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
				</svg>
				<span class="text-[12px]">Search...</span>
				<span class="ml-auto text-[9px] bg-bg/80 rounded px-1.5 py-0.5 font-mono border border-border/40">⌘K</span>
			</div>
		</div>
	{:else}
		<div class="px-2 py-3 shrink-0 flex justify-center">
			<button class="p-2 rounded-lg hover:bg-surface-2 transition-colors" aria-label="Search">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-text-muted">
					<circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
				</svg>
			</button>
		</div>
	{/if}

	<!-- Navigation -->
	<nav class="flex-1 overflow-y-auto px-2 min-h-0">
		{#if !isCollapsed}
			<p class="px-3 mb-1.5 mt-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted/50">
				Dashboards
			</p>
		{/if}
		<ul class="space-y-0.5 {isCollapsed ? '' : 'mb-5'}">
			{#each dashItems as item}
				<li class="relative group">
					<button
						onclick={() => handleNav(item.id)}
						class="w-full flex items-center gap-2.5 rounded-lg text-[13px] transition-all duration-150
							{isCollapsed ? 'justify-center p-2.5' : 'px-3 py-2'}
							{activeItem === item.id
								? 'bg-accent/10 text-accent'
								: 'text-text-muted hover:text-text-secondary hover:bg-surface-2/50'}"
					>
						{#if item.id === 'overview'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" />
							</svg>
						{:else if item.id === 'attacks'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
							</svg>
						{:else if item.id === 'analytics'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<path d="M3 3v18h18" /><path d="m19 9-5 5-4-4-3 3" />
							</svg>
						{:else if item.id === 'sites'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<circle cx="12" cy="12" r="10" /><path d="M2 12h20" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
							</svg>
						{/if}
						{#if !isCollapsed}
							<span class="{activeItem === item.id ? 'font-medium' : ''}">{item.label}</span>
							{#if item.badge}
								<span class="ml-auto text-[10px] font-medium tabular-nums px-1.5 py-0.5 rounded-full
									{activeItem === item.id ? 'bg-accent/15 text-accent' : 'bg-surface-2 text-text-muted'}">
									{item.badge}
								</span>
							{/if}
						{/if}
					</button>
					<!-- Tooltip collapsed -->
					{#if isCollapsed}
						<div class="absolute left-full ml-2 top-1/2 -translate-y-1/2 px-2.5 py-1.5 bg-surface-2 text-text text-xs rounded-lg border border-border
							opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 whitespace-nowrap z-50 pointer-events-none">
							{item.label}
							{#if item.badge}
								<span class="ml-1.5 text-[10px] text-text-muted">{item.badge}</span>
							{/if}
						</div>
					{/if}
				</li>
			{/each}
		</ul>

		{#if !isCollapsed}
			<p class="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-text-muted/50">
				Settings
			</p>
		{/if}
		<ul class="space-y-0.5">
			{#each settItems as item}
				<li class="relative group">
					<button
						onclick={() => handleNav(item.id)}
						class="w-full flex items-center gap-2.5 rounded-lg text-[13px] transition-all duration-150
							{isCollapsed ? 'justify-center p-2.5' : 'px-3 py-2'}
							{activeItem === item.id
								? 'bg-accent/10 text-accent'
								: 'text-text-muted hover:text-text-secondary hover:bg-surface-2/50'}"
					>
						{#if item.id === 'dlp'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
							</svg>
						{:else}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="shrink-0">
								<circle cx="12" cy="12" r="3" /><path d="M12 1v2m0 18v2m-9-11h2m18 0h2" /><path d="m18.4 5.6-1.4 1.4M7 17l-1.4 1.4m0-13.4L7 7m10 10 1.4 1.4" />
							</svg>
						{/if}
						{#if !isCollapsed}
							<span class="{activeItem === item.id ? 'font-medium' : ''}">{item.label}</span>
						{/if}
					</button>
					{#if isCollapsed}
						<div class="absolute left-full ml-2 top-1/2 -translate-y-1/2 px-2.5 py-1.5 bg-surface-2 text-text text-xs rounded-lg border border-border
							opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 whitespace-nowrap z-50 pointer-events-none">
							{item.label}
						</div>
					{/if}
				</li>
			{/each}
		</ul>
	</nav>

	<!-- Protection status -->
	<div class="shrink-0 border-t border-border px-3 py-3">
		{#if !isCollapsed}
			<div class="flex items-center justify-between mb-1.5">
				<span class="text-[10px] text-text-muted">Protection</span>
				<span class="text-[11px] font-bold tabular-nums text-accent">{protectionRate.toFixed(1)}%</span>
			</div>
			<div class="w-full h-1 bg-bg rounded-full overflow-hidden">
				<div class="h-full bg-accent/60 rounded-full transition-all duration-500" style="width: {Math.min(protectionRate, 100)}%"></div>
			</div>
		{:else}
			<div class="flex flex-col items-center gap-1">
				<span class="text-[10px] font-bold tabular-nums text-accent">{protectionRate.toFixed(0)}%</span>
				<div class="w-6 h-1 bg-bg rounded-full overflow-hidden">
					<div class="h-full bg-accent/60 rounded-full" style="width: {Math.min(protectionRate, 100)}%"></div>
				</div>
			</div>
		{/if}
	</div>

	<!-- Profile -->
	<div class="shrink-0 border-t border-border {isCollapsed ? 'px-2 py-3' : 'px-3 py-3'}">
		{#if !isCollapsed}
			<div class="flex items-center gap-2.5 px-2 py-2 rounded-lg hover:bg-surface-2/50 transition-colors cursor-pointer">
				<div class="relative shrink-0">
					<div class="w-8 h-8 rounded-full bg-surface-2 flex items-center justify-center">
						<span class="text-text-secondary font-medium text-xs">AD</span>
					</div>
					<div class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-accent rounded-full border-2 border-surface"></div>
				</div>
				<div class="min-w-0 flex-1">
					<p class="text-[12px] font-medium text-text truncate">Admin</p>
					<p class="text-[10px] text-text-muted truncate">admin@ferroada.io</p>
				</div>
			</div>
		{:else}
			<div class="flex justify-center">
				<div class="relative">
					<div class="w-8 h-8 rounded-full bg-surface-2 flex items-center justify-center">
						<span class="text-text-secondary font-medium text-xs">AD</span>
					</div>
					<div class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-accent rounded-full border-2 border-surface"></div>
				</div>
			</div>
		{/if}
	</div>

	<!-- Version -->
	<div class="shrink-0 px-3 py-2 border-t border-border/50 flex items-center {isCollapsed ? 'justify-center' : 'gap-2'}">
		<div class="w-[5px] h-[5px] rounded-full bg-accent pulse shrink-0"></div>
		{#if !isCollapsed}
			<span class="text-[10px] text-text-muted/60">Ferroada v0.4</span>
			<span class="ml-auto text-[10px] text-text-muted/40 tabular-nums">5s</span>
		{/if}
	</div>
</aside>
