use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::metrics;

pub struct DashboardService;

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

        if let Ok(expected_token) = std::env::var("DASHBOARD_TOKEN") {
            if !expected_token.is_empty() {
                let authorized = session
                    .req_header()
                    .headers
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == expected_token)
                    .unwrap_or(false);

                if !authorized {
                    respond(session, 401, "text/plain", "401 Unauthorized\n").await?;
                    return Ok(true);
                }
            }
        }

        let (status, content_type, body) = match path {
            "/api/metrics" => (200, "application/json", metrics::snapshot_json()),
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

async fn respond(session: &mut Session, status: u16, content_type: &str, body: &str) -> Result<()> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", content_type)?;
    header.insert_header("Content-Length", body.len().to_string())?;
    header.insert_header("Cache-Control", "no-cache")?;
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
  @media (max-width:720px) { .kpis { grid-template-columns:1fr 1fr; } }
</style>
</head>
<body>
<main>
  <h1>Visão geral</h1>
  <p class="lede">O que o proxy viu. Esta página atualiza a cada cinco segundos. O painel Next fica em <code>web/</code>.</p>
  <dl class="kpis" id="kpis"></dl>
  <div class="wrap">
    <table>
      <thead><tr><th>Hora</th><th>Tipo</th><th>IP</th><th>URI</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</main>
<script>
const labels = { sqli:'injeção SQL', xss:'XSS', path_traversal:'path traversal', rate_limit:'limite de taxa', sensitive_path:'caminho sensível', body_sqli:'SQL no corpo', body_xss:'XSS no corpo', method:'método HTTP', size_limit:'tamanho', host:'host', crlf:'CRLF', smuggling:'smuggling', jndi:'JNDI', bad_bot:'bot', behavioral_throttle:'comportamento (freio)', behavioral_block:'comportamento (ban)', dlp:'DLP' };
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
  const res = await fetch('/api/metrics', { signal: AbortSignal.timeout(4000) });
  if(!res.ok) throw new Error('metrics');
  const m = await res.json();
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
    const td = cell('td', 'Nenhum evento recente. Quando o WAF bloquear, aparece aqui.', 'empty');
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
tick().catch(function(err){ console.error(err); });
setInterval(function(){ tick().catch(function(err){ console.error(err); }); }, 5000);
</script>
</body>
</html>
"##
    .to_string()
}
