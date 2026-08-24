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
