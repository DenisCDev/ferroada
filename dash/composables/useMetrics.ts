import { ref, computed, onMounted, onUnmounted } from 'vue';
import { fetchMetricsWithFallback } from '~/utils/api';
import { aggregateGeoPoints } from '~/utils/geo';
import type { FerroaMetrics, GeoPoint, AttackCategory, TimelinePoint } from '~/types';

export function useMetrics() {
  const metrics = ref<FerroaMetrics | null>(null);
  const previousMetrics = ref<FerroaMetrics | null>(null);
  const error = ref(false);
  const timeline = ref<TimelinePoint[]>([]);
  let interval: ReturnType<typeof setInterval> | null = null;

  const totalBlocked = computed(() => {
    if (!metrics.value) return 0;
    return Object.values(metrics.value.blocked).reduce((a, b) => a + b, 0);
  });

  const previousTotalBlocked = computed(() => {
    if (!previousMetrics.value) return undefined;
    return Object.values(previousMetrics.value.blocked).reduce((a, b) => a + b, 0);
  });

  const protectionRate = computed(() => {
    if (!metrics.value || metrics.value.requests_total === 0) return 100;
    return ((metrics.value.requests_total - totalBlocked.value) / metrics.value.requests_total) * 100;
  });

  const geoPoints = computed<GeoPoint[]>(() => {
    if (!metrics.value?.recent_events) return [];
    return aggregateGeoPoints(metrics.value.recent_events);
  });

  const attackCategories = computed<AttackCategory[]>(() => {
    if (!metrics.value) return [];
    const labels: Record<string, string> = {
      sqli: 'SQL Injection', xss: 'Cross-Site Scripting', path_traversal: 'Path Traversal',
      rate_limit: 'Rate Limited', sensitive_path: 'Sensitive Paths', body_sqli: 'Body SQL Injection',
      body_xss: 'Body XSS', method: 'Method Block', size_limit: 'Size Limit', host: 'Host Spoofing',
      crlf: 'CRLF Injection', smuggling: 'Request Smuggling', jndi: 'Log4Shell/JNDI', bad_bot: 'Bad Bots',
    };
    return Object.entries(metrics.value.blocked)
      .map(([key, count]) => ({ key, label: labels[key] ?? key, count }))
      .filter(c => c.count > 0)
      .sort((a, b) => b.count - a.count);
  });

  async function poll() {
    try {
      const data = await fetchMetricsWithFallback();
      previousMetrics.value = metrics.value;
      metrics.value = data;
      error.value = false;

      // Add timeline point
      const blocked = Object.values(data.blocked).reduce((a, b) => a + b, 0);
      timeline.value = [...timeline.value.slice(-59), { time: new Date(), blocked }];
    } catch {
      error.value = true;
    }
  }

  onMounted(() => {
    poll();
    interval = setInterval(poll, 5000);
  });

  onUnmounted(() => {
    if (interval) clearInterval(interval);
  });

  return {
    metrics, previousMetrics, error, totalBlocked, previousTotalBlocked,
    protectionRate, geoPoints, attackCategories, timeline,
  };
}
