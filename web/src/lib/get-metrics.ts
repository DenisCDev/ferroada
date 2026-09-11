import { demoMetrics } from "./demo";
import { ferroadaMetricsSchema, type MetricsResult } from "./types";

function allowDemo(): boolean {
  return process.env.FERROADA_ALLOW_DEMO === "true";
}

export function unavailableMetrics(): MetricsResult {
  return {
    policy_version: "",
    policy_signed: false,
    requests_total: 0,
    blocked: {},
    https_redirect: 0,
    waf_inspection: {
      complete: 0,
      truncated: 0,
      unsupported_encoding: 0,
      unsupported_content_type: 0,
    },
    waf_monitored: 0,
    dlp: { cpf_masked: 0, tokens_masked: 0 },
    recent_events: [],
    demo: false,
    unavailable: true,
  };
}

function fallback(reason: NonNullable<MetricsResult["demo_reason"]>): MetricsResult {
  // Invented totals look like live traffic. Only an explicit opt-in may do that.
  if (allowDemo()) {
    return { ...demoMetrics(), demo: true, unavailable: false, demo_reason: reason };
  }
  return { ...unavailableMetrics(), demo_reason: reason };
}

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
      return fallback(res.status === 401 ? "unauthorized" : "unavailable");
    }
    const json: unknown = await res.json();
    const parsed = ferroadaMetricsSchema.safeParse(json);
    if (!parsed.success) {
      return fallback("invalid_response");
    }
    return { ...parsed.data, demo: false, unavailable: false };
  } catch {
    return fallback("unavailable");
  }
}
