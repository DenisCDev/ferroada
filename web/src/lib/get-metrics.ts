import { demoMetrics } from "./demo";
import type { FerroadaMetrics } from "./types";

function isMetrics(value: unknown): value is FerroadaMetrics {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.requests_total === "number" && typeof v.blocked === "object" && v.blocked !== null;
}

export async function getMetrics(): Promise<FerroadaMetrics & { demo: boolean }> {
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
    if (!res.ok) return { ...demoMetrics(), demo: true };
    const json: unknown = await res.json();
    if (!isMetrics(json)) return { ...demoMetrics(), demo: true };
    return { ...json, demo: false };
  } catch {
    return { ...demoMetrics(), demo: true };
  }
}
