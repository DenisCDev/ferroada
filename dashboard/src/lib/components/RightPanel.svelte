<script lang="ts">
	import type { SecurityEvent, DlpMetrics } from '$lib/types';

	let {
		events = [],
		dlp = null
	}: {
		events: SecurityEvent[];
		dlp: DlpMetrics | null;
	} = $props();

	const tagColors: Record<string, string> = {
		sqli: '#f87171', xss: '#fbbf24', path_traversal: '#fb923c',
		rate_limit: '#60a5fa', sensitive_path: '#a78bfa',
		body_sqli: '#f87171', body_xss: '#fbbf24',
	};

	function formatAgo(ts: string): string {
		try {
			const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
			if (diff < 60) return 'now';
			if (diff < 3600) return `${Math.floor(diff / 60)}m`;
			return `${Math.floor(diff / 3600)}h`;
		} catch { return ''; }
	}

	function formatTime(ts: string): string {
		try {
			return new Date(ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
		} catch { return ts.slice(11, 16); }
	}

	function eventLabel(type: string): string {
		const labels: Record<string, string> = {
			sqli: 'SQL injection', body_sqli: 'SQL injection',
			xss: 'XSS blocked', body_xss: 'XSS blocked',
			path_traversal: 'Path traversal', rate_limit: 'Rate limited',
			sensitive_path: 'Sensitive path',
		};
		return labels[type] ?? type;
	}
</script>

<aside class="w-[260px] shrink-0 h-full border-l border-border bg-surface flex flex-col overflow-hidden">
	<!-- Header -->
	<div class="h-[60px] flex items-center px-5 border-b border-border shrink-0">
		<h3 class="text-[13px] font-semibold text-text">Activity Feed</h3>
		<span class="ml-auto text-[10px] text-accent font-medium pulse">&#x25CF; Live</span>
	</div>

	<!-- Notifications -->
	<div class="px-4 py-3 border-b border-border overflow-y-auto" style="max-height: 38%">
		<p class="text-[10px] font-semibold uppercase tracking-wider text-text-muted/50 mb-3">Recent Alerts</p>
		<div class="space-y-2.5">
			{#each events.slice(0, 5) as event, i (event.timestamp + i)}
				<div class="flex gap-2 items-start">
					<div class="w-1.5 h-1.5 rounded-full mt-[6px] shrink-0 pulse" style="background: {tagColors[event.event_type] ?? '#64748b'}"></div>
					<div class="flex-1 min-w-0">
						<p class="text-[11px] text-text-secondary leading-snug">{eventLabel(event.event_type)}</p>
						<p class="text-[9px] text-text-muted mt-0.5 font-mono truncate">{event.client_ip}</p>
					</div>
					<span class="text-[9px] text-text-muted/60 shrink-0">{formatAgo(event.timestamp)}</span>
				</div>
			{/each}
		</div>
	</div>

	<!-- Activities -->
	<div class="px-4 py-3 border-b border-border flex-1 overflow-y-auto min-h-0">
		<p class="text-[10px] font-semibold uppercase tracking-wider text-text-muted/50 mb-3">Activity Log</p>
		<div class="space-y-2.5">
			{#each events.slice(5, 14) as event, i (event.timestamp + 'act' + i)}
				<div class="flex gap-2 items-start">
					<div class="w-5 h-5 rounded bg-surface-2 flex items-center justify-center shrink-0 mt-0.5">
						<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="{tagColors[event.event_type] ?? '#64748b'}" stroke-width="2.5">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
					</div>
					<div class="flex-1 min-w-0">
						<p class="text-[11px] text-text-secondary leading-snug">
							<span class="text-text font-medium">{event.event_type}</span>
						</p>
						<p class="text-[9px] text-text-muted mt-0.5 font-mono truncate">{event.client_ip} · {formatTime(event.timestamp)}</p>
					</div>
				</div>
			{/each}
		</div>
	</div>

	<!-- DLP Stats -->
	{#if dlp}
		<div class="px-4 py-3 shrink-0 border-t border-border/50">
			<p class="text-[10px] font-semibold uppercase tracking-wider text-text-muted/50 mb-2.5">Data Protection</p>
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<div class="w-5 h-5 rounded bg-purple/10 flex items-center justify-center">
							<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-purple">
								<rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
							</svg>
						</div>
						<span class="text-[11px] text-text-secondary">CPFs masked</span>
					</div>
					<span class="text-[11px] font-bold tabular-nums text-purple">{dlp.cpf_masked}</span>
				</div>
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<div class="w-5 h-5 rounded bg-purple/10 flex items-center justify-center">
							<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-purple">
								<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
							</svg>
						</div>
						<span class="text-[11px] text-text-secondary">Tokens masked</span>
					</div>
					<span class="text-[11px] font-bold tabular-nums text-purple">{dlp.tokens_masked}</span>
				</div>
			</div>
		</div>
	{/if}
</aside>
