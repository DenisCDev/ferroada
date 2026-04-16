<script lang="ts">
	import type { SecurityEvent } from '$lib/types';

	let { events = [] }: { events: SecurityEvent[] } = $props();

	const tagColors: Record<string, { bg: string; text: string }> = {
		sqli: { bg: 'rgba(248,113,113,0.12)', text: '#f87171' },
		xss: { bg: 'rgba(251,191,36,0.12)', text: '#fbbf24' },
		path_traversal: { bg: 'rgba(251,146,60,0.12)', text: '#fb923c' },
		rate_limit: { bg: 'rgba(96,165,250,0.12)', text: '#60a5fa' },
		sensitive_path: { bg: 'rgba(167,139,250,0.12)', text: '#a78bfa' },
		body_sqli: { bg: 'rgba(248,113,113,0.12)', text: '#f87171' },
		body_xss: { bg: 'rgba(251,191,36,0.12)', text: '#fbbf24' },
		method: { bg: 'rgba(96,165,250,0.12)', text: '#60a5fa' },
		size_limit: { bg: 'rgba(148,163,184,0.12)', text: '#94a3b8' },
		host: { bg: 'rgba(167,139,250,0.12)', text: '#a78bfa' },
		dlp: { bg: 'rgba(167,139,250,0.12)', text: '#a78bfa' },
	};

	function formatTime(ts: string): string {
		try {
			const d = new Date(ts);
			return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
		} catch {
			return ts.slice(11, 19);
		}
	}

	function truncate(s: string, max: number): string {
		return s.length > max ? s.slice(0, max) + '...' : s;
	}
</script>

<div class="card-flush">
	<div class="px-5 py-4 flex items-center justify-between">
		<h3 class="text-[13px] font-semibold text-text-secondary">Event Log</h3>
		<span class="text-[11px] text-text-muted tabular-nums">{events.length} events</span>
	</div>

	{#if events.length === 0}
		<div class="px-5 py-10 text-center text-text-muted text-[12px]">No events recorded</div>
	{:else}
		<div class="overflow-x-auto">
			<table class="w-full">
				<thead>
					<tr>
						<th class="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-text-muted bg-surface-2/50">Time</th>
						<th class="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-text-muted bg-surface-2/50">Type</th>
						<th class="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-text-muted bg-surface-2/50">Source IP</th>
						<th class="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-text-muted bg-surface-2/50">URI</th>
						<th class="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-text-muted bg-surface-2/50">Detail</th>
					</tr>
				</thead>
				<tbody>
					{#each events.slice(0, 12) as event, i (event.timestamp + event.client_ip + i)}
						<tr class="border-t border-border/50 hover:bg-surface-2/30 transition-colors">
							<td class="px-5 py-2 text-[11px] font-mono text-text-muted whitespace-nowrap">
								{formatTime(event.timestamp)}
							</td>
							<td class="px-5 py-2">
								{#if tagColors[event.event_type]}
									<span
										class="inline-block px-2 py-0.5 rounded-md text-[10px] font-semibold"
										style="background: {tagColors[event.event_type].bg}; color: {tagColors[event.event_type].text};"
									>
										{event.event_type}
									</span>
								{:else}
									<span class="inline-block px-2 py-0.5 rounded-md text-[10px] font-semibold" style="background: rgba(148,163,184,0.12); color: #94a3b8;">
										{event.event_type}
									</span>
								{/if}
							</td>
							<td class="px-5 py-2 text-[11px] font-mono text-text-secondary whitespace-nowrap">
								{event.client_ip}
							</td>
							<td class="px-5 py-2 text-[11px] font-mono text-text-muted max-w-[180px]">
								<span title={event.uri}>{truncate(event.uri, 30)}</span>
							</td>
							<td class="px-5 py-2 text-[11px] text-text-muted max-w-[180px]">
								<span title={event.detail}>{truncate(event.detail, 35)}</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
