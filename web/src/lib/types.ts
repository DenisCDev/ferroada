import { z } from "zod";

export type BlockedKey =
  | "sqli"
  | "xss"
  | "path_traversal"
  | "rate_limit"
  | "sensitive_path"
  | "body_sqli"
  | "body_xss"
  | "method"
  | "size_limit"
  | "host"
  | "crlf"
  | "smuggling"
  | "jndi"
  | "bad_bot"
  | "behavioral_throttle"
  | "behavioral_block"
  | "request_buffer_limit"
  | "dlp_partial_block";

const countSchema = z.number().finite().nonnegative();

export const securityEventSchema = z.object({
  timestamp: z.string().datetime(),
  event_type: z.string(),
  client_ip: z.string(),
  uri: z.string(),
  detail: z.string(),
});

export const ferroadaMetricsSchema = z.object({
  requests_total: countSchema,
  blocked: z.record(z.string(), countSchema),
  https_redirect: countSchema,
  waf_inspection: z.object({
    complete: countSchema,
    truncated: countSchema,
    unsupported_encoding: countSchema,
    unsupported_content_type: countSchema,
  }),
  waf_monitored: countSchema,
  dlp: z.object({ cpf_masked: countSchema, tokens_masked: countSchema }),
  recent_events: z.array(securityEventSchema),
});

export const metricsResultSchema = ferroadaMetricsSchema.extend({
  demo: z.boolean(),
  unavailable: z.boolean(),
  demo_reason: z.enum(["unauthorized", "unavailable", "invalid_response"]).optional(),
});

export type SecurityEvent = z.infer<typeof securityEventSchema>;
export type FerroadaMetrics = z.infer<typeof ferroadaMetricsSchema>;
export type MetricsResult = z.infer<typeof metricsResultSchema>;
