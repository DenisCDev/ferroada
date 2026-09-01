use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics;

pub fn validate_exposure(bind: std::net::IpAddr, token: Option<&str>) -> Result<(), &'static str> {
    if !bind.is_loopback()
        && token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err("DASHBOARD_TOKEN é obrigatório quando DASHBOARD_BIND não é loopback");
    }
    Ok(())
}

pub struct DashboardService {
    token: Option<Arc<str>>,
    upstreams: Arc<[SocketAddr]>,
}

impl DashboardService {
    pub fn new(token: Option<String>, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            token: token.map(Arc::from),
            upstreams: upstreams.into(),
        }
    }

    async fn upstreams_ready(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        for address in self.upstreams.iter().copied() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let timeout = remaining.min(Duration::from_millis(250));
            let result =
                tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await;
            if !matches!(result, Ok(Ok(_))) {
                return false;
            }
        }
        !self.upstreams.is_empty()
    }
}

pub struct DashboardCtx;

#[async_trait]
impl ProxyHttp for DashboardService {
    type CTX = DashboardCtx;

    fn new_ctx(&self) -> Self::CTX {
        DashboardCtx
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        if method == "OPTIONS" {
            respond(session, 204, "text/plain", "").await?;
            return Ok(true);
        }

        if method != "GET" && method != "HEAD" {
            respond(
                session,
                405,
                "text/plain; charset=utf-8",
                "405 Método não permitido\n",
            )
            .await?;
            return Ok(true);
        }

        if path == "/healthz" {
            respond(session, 200, "text/plain; charset=utf-8", "ok\n").await?;
            return Ok(true);
        }

        if path == "/readyz" {
            let (status, body) = if self.upstreams_ready().await {
                (200, "pronto\n")
            } else {
                (503, "backend indisponível\n")
            };
            respond(session, status, "text/plain; charset=utf-8", body).await?;
            return Ok(true);
        }

        let protected = matches!(path, "/api/metrics" | "/metrics");
        let provided_token = session
            .req_header()
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let authorized = self.token.as_deref().is_none_or(|expected| {
            provided_token
                .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
        });
        if protected && !authorized {
            respond(session, 401, "text/plain", "401 Não autorizado\n").await?;
            return Ok(true);
        }

        let (status, content_type, body) = match path {
            "/api/metrics" => (200, "application/json", metrics::snapshot_json()),
            "/metrics" => (
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                metrics::snapshot_prometheus(),
            ),
            _ => (200, "text/html; charset=utf-8", dashboard_html()),
        };

        respond(session, status, content_type, &body).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        unreachable!("Dashboard never proxies to upstream")
    }
}

fn constant_time_eq(provided: &[u8], expected: &[u8]) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    provided
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn respond(session: &mut Session, status: u16, content_type: &str, body: &str) -> Result<()> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", content_type)?;
    header.insert_header("Content-Length", body.len().to_string())?;
    header.insert_header("Cache-Control", "no-cache")?;
    header.insert_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")?;
    header.insert_header("Referrer-Policy", "no-referrer")?;
    header.insert_header("X-Content-Type-Options", "nosniff")?;
    header.insert_header("X-Frame-Options", "DENY")?;
    if let Ok(origin) = std::env::var("DASHBOARD_CORS") {
        if !origin.is_empty() {
            header.insert_header("Access-Control-Allow-Origin", origin)?;
            header.insert_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type",
            )?;
            header.insert_header("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        }
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body.to_string())), true)
        .await?;
    Ok(())
}

fn dashboard_html() -> String {
    r##"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ferroada</title>
<style>
  :root { --fg:#171717; --muted:#737373; --line:#eaeaea; --font:ui-sans-serif,system-ui,sans-serif; --mono:ui-monospace,Menlo,Consolas,monospace; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:var(--font); color:var(--fg); background:#fff; font-size:14px; line-height:1.5; }
  main { max-width:880px; margin:0 auto; padding:40px 24px 80px; }
  h1 { font-size:22px; font-weight:600; letter-spacing:-.03em; margin:0 0 8px; }
  .lede { color:var(--muted); margin:0 0 28px; }
  .kpis { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line); border:1px solid var(--line); border-radius:8px; overflow:hidden; margin-bottom:28px; }
  .kpi { background:#fff; padding:16px 18px; }
  .kpi dt { color:var(--muted); font-size:12px; margin:0 0 6px; }
  .kpi dd { margin:0; font-size:22px; font-weight:600; letter-spacing:-.03em; font-variant-numeric:tabular-nums; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:500; font-size:12px; }
  .wrap { border:1px solid var(--line); border-radius:8px; overflow:auto; }
  .mono { font-family:var(--mono); font-size:12px; }
  .empty { color:var(--muted); padding:32px; text-align:center; }
  .notice { border:1px solid #f1c40f; background:#fffbea; border-radius:8px; padding:12px 14px; margin:0 0 20px; }
  .auth { display:flex; gap:8px; align-items:center; }
  .auth input { min-width:280px; padding:8px 10px; border:1px solid var(--line); border-radius:6px; }
  .auth button { padding:8px 12px; border:0; border-radius:6px; background:#171717; color:#fff; cursor:pointer; }
  .auth button:disabled { opacity:.45; cursor:not-allowed; }
  [hidden] { display:none !important; }
  @media (max-width:720px) { .kpis { grid-template-columns:1fr 1fr; } }
</style>
</head>
<body>
<main>
  <h1>Visão geral</h1>
  <p class="lede">O que o proxy viu. Esta página atualiza a cada cinco segundos. O painel Next fica em <code>web/</code>.</p>
  <form class="auth notice" id="auth" hidden>
    <label for="token">Token do dashboard</label>
    <input id="token" type="password" autocomplete="current-password" required>
    <button id="auth-submit" type="submit" disabled>Entrar</button>
  </form>
  <p class="notice" id="status" role="status">Carregando métricas...</p>
  <dl class="kpis" id="kpis"></dl>
  <div class="wrap">
    <table>
      <thead><tr><th>Hora</th><th>Tipo</th><th>IP</th><th>URI</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</main>
<script>
const labels = { sqli:'injeção SQL', xss:'XSS', path_traversal:'path traversal', rate_limit:'limite de taxa', sensitive_path:'caminho sensível', body_sqli:'SQL no corpo', body_xss:'XSS no corpo', method:'método HTTP', size_limit:'tamanho', header_limit:'limite de headers', concurrency_limit:'limite de concorrência', connection_limit:'limite de conexões', request_buffer_limit:'memória de inspeção de entrada', dlp_partial_block:'resposta parcial bloqueada pelo DLP', host:'host', crlf:'CRLF', smuggling:'smuggling', jndi:'JNDI', bad_bot:'bot', behavioral_throttle:'comportamento (freio)', behavioral_block:'comportamento (ban)', waf_incomplete:'inspeção WAF incompleta', waf_monitor:'monitoramento WAF', dlp_skip:'DLP não aplicado', range_removed:'range removido para inspeção DLP', dlp:'DLP' };
const auth = document.getElementById('auth');
const status = document.getElementById('status');
const tokenInput = document.getElementById('token');
const authSubmit = document.getElementById('auth-submit');
let token = sessionStorage.getItem('ferroada_dashboard_token') || '';
function fmt(n){ return new Intl.NumberFormat('pt-BR').format(n); }
function hour(iso){ const d=new Date(iso); return Number.isNaN(d.getTime())?iso:new Intl.DateTimeFormat('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(d); }
function cell(tag, text, cls){
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  n.textContent = text;
  return n;
}
function kpi(dt, dd){
  const wrap = document.createElement('div');
  wrap.className = 'kpi';
  wrap.appendChild(cell('dt', dt));
  wrap.appendChild(cell('dd', dd));
  return wrap;
}
async function tick(){
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  const res = await fetch('/api/metrics', { headers, signal: AbortSignal.timeout(4000) });
  if(res.status === 401){
    auth.hidden = false;
    status.hidden = false;
    status.textContent = 'Informe o token configurado em DASHBOARD_TOKEN.';
    throw new Error('unauthorized');
  }
  if(!res.ok) throw new Error('metrics');
  const m = await res.json();
  auth.hidden = true;
  status.hidden = true;
  const blocked = Object.values(m.blocked||{}).reduce((s,n)=>s+n,0);
  const rate = m.requests_total===0?0:(1-blocked/Math.max(m.requests_total,blocked))*100;
  const kpis = document.getElementById('kpis');
  kpis.replaceChildren(
    kpi('Requisições', fmt(m.requests_total)),
    kpi('Bloqueios', fmt(blocked)),
    kpi('Tráfego limpo', new Intl.NumberFormat('pt-BR',{maximumFractionDigits:1}).format(rate)+'%'),
    kpi('DLP', fmt((m.dlp&&m.dlp.cpf_masked||0)+(m.dlp&&m.dlp.tokens_masked||0)))
  );
  const events = m.recent_events||[];
  const tb = document.getElementById('rows');
  tb.replaceChildren();
  if(!events.length){
    const tr = document.createElement('tr');
    const td = cell('td', 'Nenhum evento de segurança recente.', 'empty');
    td.colSpan = 4;
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  events.forEach(function(e){
    const tr = document.createElement('tr');
    tr.appendChild(cell('td', hour(e.timestamp), 'mono'));
    tr.appendChild(cell('td', labels[e.event_type]||e.event_type));
    tr.appendChild(cell('td', e.client_ip, 'mono'));
    tr.appendChild(cell('td', e.uri, 'mono'));
    tb.appendChild(tr);
  });
}
auth.addEventListener('submit', function(event){
  event.preventDefault();
  token = tokenInput.value.trim();
  if(!token) return;
  sessionStorage.setItem('ferroada_dashboard_token', token);
  status.hidden = false;
  status.textContent = 'Validando token...';
  tick().catch(showError);
});
tokenInput.addEventListener('input', function(){
  authSubmit.disabled = !tokenInput.value.trim();
});
function showError(error){
  if(error.message === 'unauthorized') return;
  status.hidden = false;
  status.textContent = 'Não foi possível atualizar as métricas. Tentaremos novamente em cinco segundos.';
}
tick().catch(showError);
setInterval(function(){ tick().catch(showError); }, 5000);
</script>
</body>
</html>
"##
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_token_comparison_requires_exact_value() {
        assert!(constant_time_eq(b"segredo", b"segredo"));
        assert!(!constant_time_eq(b"segredo", b"segreda"));
        assert!(!constant_time_eq(b"curto", b"segredo"));
    }

    #[test]
    fn external_dashboard_requires_authentication() {
        assert!(validate_exposure("127.0.0.1".parse().unwrap(), None).is_ok());
        assert!(validate_exposure("0.0.0.0".parse().unwrap(), None).is_err());
        assert!(validate_exposure("0.0.0.0".parse().unwrap(), Some("token")).is_ok());
    }
}
