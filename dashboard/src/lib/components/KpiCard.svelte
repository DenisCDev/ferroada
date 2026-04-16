<script lang="ts">
	let {
		label,
		value,
		previousValue = undefined,
		suffix = '',
		color = 'accent',
		subtitle = ''
	}: {
		label: string;
		value: number | string;
		previousValue?: number;
		suffix?: string;
		color?: string;
		subtitle?: string;
	} = $props();

	let displayValue = $state(typeof value === 'number' ? 0 : value);
	let changed = $state(false);

	$effect(() => {
		if (typeof value === 'number') {
			const target = value;
			const current = typeof displayValue === 'number' ? displayValue : 0;
			const diff = target - current;
			if (diff === 0) return;

			changed = true;
			setTimeout(() => (changed = false), 500);

			const steps = 16;
			const increment = diff / steps;
			let step = 0;
			const timer = setInterval(() => {
				step++;
				if (step >= steps) {
					displayValue = target;
					clearInterval(timer);
				} else {
					displayValue = Math.round(current + increment * step);
				}
			}, 30);
			return () => clearInterval(timer);
		} else {
			displayValue = value;
		}
	});

	const delta = $derived(
		previousValue !== undefined && typeof value === 'number' ? value - previousValue : 0
	);

	const deltaPercent = $derived(
		previousValue && previousValue > 0 && typeof value === 'number'
			? (((value - previousValue) / previousValue) * 100).toFixed(1)
			: null
	);
</script>

<div class="card group">
	<div class="flex items-center justify-between mb-1">
		<span class="text-[12px] font-medium text-text-muted">{label}</span>
	</div>

	<div class="flex items-baseline gap-1.5">
		<span
			class="text-2xl font-extrabold tabular-nums leading-none tracking-tight"
			class:flash={changed}
			style="color: var(--color-{color});"
		>
			{typeof displayValue === 'number' ? displayValue.toLocaleString('pt-BR') : displayValue}{suffix}
		</span>
	</div>

	<div class="mt-2 flex items-center gap-2">
		{#if delta !== 0 && deltaPercent}
			<span
				class="inline-flex items-center gap-0.5 text-[11px] font-medium tabular-nums px-1.5 py-0.5 rounded-md"
				style="background: {delta > 0 ? 'rgba(74,222,128,0.1)' : 'rgba(248,113,113,0.1)'}; color: {delta > 0 ? 'var(--color-accent)' : 'var(--color-danger)'};"
			>
				{#if delta > 0}
					<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M7 17l5-5 5 5M7 7l5 5 5-5"/></svg>
				{/if}
				{deltaPercent}%
			</span>
		{/if}
		{#if subtitle}
			<span class="text-[11px] text-text-muted">{subtitle}</span>
		{/if}
	</div>
</div>
