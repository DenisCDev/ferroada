<script lang="ts">
	import type { DlpMetrics } from '$lib/types';

	let { dlp }: { dlp: DlpMetrics | null } = $props();
</script>

<div class="bg-surface border border-border rounded-xl p-5">
	<h3 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">
		Data Loss Prevention
	</h3>

	{#if !dlp}
		<p class="text-text-muted text-sm">Carregando...</p>
	{:else}
		<div class="grid grid-cols-2 gap-4">
			<div class="bg-surface-2 rounded-lg p-4">
				<div class="flex items-center gap-2 mb-2">
					<div class="w-6 h-6 rounded bg-purple/15 flex items-center justify-center">
						<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-purple">
							<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
							<path d="M7 11V7a5 5 0 0110 0v4" />
						</svg>
					</div>
					<span class="text-xs text-text-muted">CPFs Protegidos</span>
				</div>
				<span class="text-2xl font-bold tabular-nums text-purple">
					{dlp.cpf_masked.toLocaleString('pt-BR')}
				</span>
			</div>

			<div class="bg-surface-2 rounded-lg p-4">
				<div class="flex items-center gap-2 mb-2">
					<div class="w-6 h-6 rounded bg-purple/15 flex items-center justify-center">
						<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-purple">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
					</div>
					<span class="text-xs text-text-muted">Tokens Mascarados</span>
				</div>
				<span class="text-2xl font-bold tabular-nums text-purple">
					{dlp.tokens_masked.toLocaleString('pt-BR')}
				</span>
			</div>
		</div>
	{/if}
</div>
