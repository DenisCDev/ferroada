import { demoMetrics } from "./demo";
import { ferroadaMetricsSchema, type MetricsResult } from "./types";

export async function getMetrics(): Promise<MetricsResult> {
  const upstream = process.env.FERROADA_URL ?? "http://127.0.0.1:9000";
  const token = process.env.FERROADA_TOKEN;
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const res = await fetch(`${upstream}/api/metrics`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });
    if (!res.ok) {
      return {
        ...demoMetrics(),
        demo: true,
        demo_reason: res.status === 401 ? "unauthorized" : "unavailable",
      };
    }
    const json: unknown = await res.json();
    const parsed = ferroadaMetricsSchema.safeParse(json);
    if (!parsed.success) {
      return { ...demoMetrics(), demo: true, demo_reason: "invalid_response" };
    }
    return { ...parsed.data, demo: false };
  } catch {
    return { ...demoMetrics(), demo: true, demo_reason: "unavailable" };
  }
}
