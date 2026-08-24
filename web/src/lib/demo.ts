import type { FerroadaMetrics, SecurityEvent } from "./types";

const URIS = [
  "/login?user=admin'--",
  "/.env",
  "/../../etc/passwd",
  "/wp-admin/",
  "/api/users?q=<script>alert(1)</script>",
  "/.git/config",
];

const TYPES = ["sqli", "xss", "path_traversal", "sensitive_path", "rate_limit", "bad_bot"];

export function demoMetrics(): FerroadaMetrics {
  const recent_events: SecurityEvent[] = Array.from({ length: 12 }, (_, i) => ({
    timestamp: new Date(Date.now() - (11 - i) * 45_000).toISOString(),
    event_type: TYPES[i % TYPES.length] ?? "sqli",
    client_ip: `177.71.244.${60 + i}`,
    uri: URIS[i % URIS.length] ?? "/",
    detail: "bloqueado",
  }));

  return {
    requests_total: 12840,
    blocked: {
      sqli: 42,
      xss: 18,
      path_traversal: 27,
      rate_limit: 91,
      sensitive_path: 14,
      body_sqli: 6,
      body_xss: 3,
      method: 2,
      size_limit: 1,
      host: 4,
      crlf: 0,
      smuggling: 0,
      jndi: 1,
      bad_bot: 11,
      behavioral_throttle: 5,
      behavioral_block: 1,
    },
    https_redirect: 220,
    dlp: { cpf_masked: 8, tokens_masked: 3 },
    recent_events,
  };
}
