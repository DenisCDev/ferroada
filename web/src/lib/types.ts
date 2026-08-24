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
  | "behavioral_block";

export interface SecurityEvent {
  timestamp: string;
  event_type: string;
  client_ip: string;
  uri: string;
  detail: string;
}

export interface FerroadaMetrics {
  requests_total: number;
  blocked: Record<string, number>;
  https_redirect: number;
  dlp: { cpf_masked: number; tokens_masked: number };
  recent_events: SecurityEvent[];
}
