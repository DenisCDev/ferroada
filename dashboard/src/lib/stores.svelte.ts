import type { FerroaMetrics, GeoPoint, TimelinePoint, AttackCategory } from './types';
import { fetchMetricsWithFallback } from './api';
import { aggregateGeoPoints } from './geo';

const POLL_INTERVAL = 5000;
const MAX_TIMELINE_POINTS = 60; // 5 minutes at 5s intervals

class MetricsStore {
	metrics = $state<FerroaMetrics | null>(null);
	previousMetrics = $state<FerroaMetrics | null>(null);
	loading = $state(true);
	error = $state<string | null>(null);
	geoPoints = $state<GeoPoint[]>([]);
	timeline = $state<TimelinePoint[]>([]);
	private intervalId: ReturnType<typeof setInterval> | null = null;

	get totalBlocked(): number {
		if (!this.metrics) return 0;
		const b = this.metrics.blocked;
		return (
			b.sqli + b.xss + b.path_traversal + b.rate_limit +
			b.sensitive_path + b.body_sqli + b.body_xss +
			b.method + b.size_limit + b.host
		);
	}

	get previousTotalBlocked(): number {
		if (!this.previousMetrics) return 0;
		const b = this.previousMetrics.blocked;
		return (
			b.sqli + b.xss + b.path_traversal + b.rate_limit +
			b.sensitive_path + b.body_sqli + b.body_xss +
			b.method + b.size_limit + b.host
		);
	}

	get protectionRate(): number {
		if (!this.metrics || this.metrics.requests_total === 0) return 100;
		return (
			((this.metrics.requests_total - this.totalBlocked) /
				this.metrics.requests_total) *
			100
		);
	}

	get attackCategories(): AttackCategory[] {
		if (!this.metrics) return [];
		const b = this.metrics.blocked;
		return [
			{ key: 'rate_limit', label: 'Rate Limited', count: b.rate_limit, color: '#F59E0B' },
			{ key: 'sqli', label: 'SQL Injection', count: b.sqli + b.body_sqli, color: '#EF4444' },
			{ key: 'sensitive_path', label: 'Sensitive Paths', count: b.sensitive_path, color: '#8B5CF6' },
			{ key: 'xss', label: 'Cross-Site Scripting', count: b.xss + b.body_xss, color: '#F97316' },
			{ key: 'path_traversal', label: 'Path Traversal', count: b.path_traversal, color: '#EC4899' },
			{ key: 'host', label: 'Host Spoofing', count: b.host, color: '#6366F1' },
			{ key: 'method', label: 'Method Blocked', count: b.method, color: '#14B8A6' },
			{ key: 'size_limit', label: 'Oversize Request', count: b.size_limit, color: '#64748B' },
		]
			.filter((c) => c.count > 0)
			.sort((a, b) => b.count - a.count);
	}

	async fetch() {
		try {
			this.previousMetrics = this.metrics;
			const data = await fetchMetricsWithFallback();
			this.metrics = data;
			this.error = null;

			// Update geo points from events
			if (data.recent_events.length > 0) {
				this.geoPoints = aggregateGeoPoints(data.recent_events);
			}

			// Update timeline
			const now = new Date();
			const blocked = this.totalBlocked;
			const prevBlocked = this.previousTotalBlocked;
			const delta = this.previousMetrics ? blocked - prevBlocked : 0;

			this.timeline = [
				...this.timeline.slice(-(MAX_TIMELINE_POINTS - 1)),
				{ time: now, blocked: Math.max(0, delta), requests: data.requests_total },
			];
		} catch (e) {
			this.error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			this.loading = false;
		}
	}

	startPolling() {
		this.fetch();
		this.intervalId = setInterval(() => this.fetch(), POLL_INTERVAL);
	}

	stopPolling() {
		if (this.intervalId) {
			clearInterval(this.intervalId);
			this.intervalId = null;
		}
	}
}

export const store = new MetricsStore();
