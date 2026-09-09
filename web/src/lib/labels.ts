export const EVENT_LABELS: Record<string, string> = {
  sqli: "injeção SQL",
  xss: "XSS",
  path_traversal: "path traversal",
  rate_limit: "limite de taxa",
  sensitive_path: "caminho sensível",
  body_sqli: "SQL no corpo",
  body_xss: "XSS no corpo",
  method: "método HTTP",
  size_limit: "tamanho",
  host: "host",
  crlf: "CRLF",
  smuggling: "smuggling",
  jndi: "JNDI",
  bad_bot: "bot",
  behavioral_throttle: "comportamento (freio)",
  behavioral_block: "comportamento (ban)",
  waf_incomplete: "inspeção WAF incompleta",
  inspection_parse_error: "JSON inválido",
  inspection_timeout: "tempo esgotado na inspeção",
  inspection_budget: "orçamento de inspeção esgotado",
  header_limit: "limite de headers",
  concurrency_limit: "limite de concorrência",
  connection_limit: "limite de conexões",
  request_buffer_limit: "memória de inspeção de entrada",
  spool_limit: "limite de spool",
  dlp_partial_block: "resposta parcial bloqueada pelo DLP",
  range_removed: "range removido para inspeção DLP",
  waf_monitor: "monitoramento WAF",
  waf_l1: "WAF L1 (CRS)",
  waf_l1_shadow: "WAF L1 (sombra)",
  waf_engine_unavailable: "motor WAF L1 indisponível",
  dlp_skip: "DLP não aplicado",
  dlp: "DLP",
  https_redirect: "redirecionamento HTTPS",
};

export function eventLabel(type: string): string {
  return EVENT_LABELS[type] ?? type.replaceAll("_", " ");
}

export function formatInt(n: number): string {
  return new Intl.NumberFormat("pt-BR").format(n);
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(d);
}

export function totalBlocked(blocked: Record<string, number>): number {
  return Object.values(blocked).reduce((s, n) => s + n, 0);
}
