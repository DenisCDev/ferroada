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

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Dashboard token auth (if DASHBOARD_TOKEN is set)
        if let Ok(expected_token) = std::env::var("DASHBOARD_TOKEN") {
            if !expected_token.is_empty() {
                let authorized = session
                    .req_header()
                    .headers
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == expected_token)
                    .unwrap_or(false)
                    || session
                        .req_header()
                        .uri
                        .query()
                        .and_then(|q| {
                            q.split('&')
                                .find_map(|pair| pair.strip_prefix("token="))
                        })
                        .map(|t| t == expected_token)
                        .unwrap_or(false);

                if !authorized {
                    respond(session, 401, "text/plain", "401 Unauthorized\n").await?;
                    return Ok(true);
                }
            }
        }

        let path = session.req_header().uri.path();

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

async fn respond(
    session: &mut Session,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", content_type)?;
    header.insert_header("Content-Length", body.len().to_string())?;
    header.insert_header("Cache-Control", "no-cache")?;
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
<title>Ferroada — Security Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0a0e17;
    color: #e2e8f0;
    min-height: 100vh;
    padding: 24px;
  }
  .header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 32px;
    padding-bottom: 16px;
    border-bottom: 1px solid #1e293b;
  }
  .header h1 { font-size: 24px; font-weight: 700; color: #f8fafc; }
  .header .badge {
    background: #10b981; color: #022c22;
    font-size: 11px; font-weight: 600;
    padding: 3px 10px; border-radius: 12px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .header .refresh { margin-left: auto; color: #64748b; font-size: 13px; }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }
  .card {
    background: #111827; border: 1px solid #1e293b;
    border-radius: 12px; padding: 20px;
  }
  .card .label {
    font-size: 12px; color: #64748b;
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;
  }
  .card .value {
    font-size: 32px; font-weight: 700; font-variant-numeric: tabular-nums;
  }
  .card.total .value { color: #60a5fa; }
  .card.blocked .value { color: #f87171; }
  .card.dlp .value { color: #a78bfa; }
  .card.rate .value { color: #fbbf24; }
  .section-title {
    font-size: 16px; font-weight: 600;
    margin-bottom: 16px; color: #94a3b8;
  }
  table {
    width: 100%; border-collapse: collapse;
    background: #111827; border: 1px solid #1e293b;
    border-radius: 12px; overflow: hidden;
  }
  thead th {
    background: #1e293b; padding: 12px 16px; text-align: left;
    font-size: 12px; font-weight: 600; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  tbody td {
    padding: 10px 16px; font-size: 13px; border-top: 1px solid #1e293b;
    font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
  }
  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 6px;
    font-size: 11px; font-weight: 600;
  }
  .tag-sqli { background: #7f1d1d; color: #fca5a5; }
  .tag-xss { background: #78350f; color: #fde68a; }
  .tag-path_traversal { background: #713f12; color: #fde047; }
  .tag-rate_limit { background: #422006; color: #fdba74; }
  .tag-sensitive_path { background: #581c87; color: #e9d5ff; }
  .tag-body_sqli { background: #7f1d1d; color: #fca5a5; }
  .tag-body_xss { background: #78350f; color: #fde68a; }
  .tag-crlf { background: #064e3b; color: #6ee7b7; }
  .tag-smuggling { background: #1e3a5f; color: #93c5fd; }
  .tag-jndi { background: #4a1d96; color: #d8b4fe; }
  .tag-bad_bot { background: #3f3f46; color: #d4d4d8; }
  .tag-behavioral_throttle { background: #854d0e; color: #fef08a; }
  .tag-behavioral_block { background: #991b1b; color: #fecaca; }
  .tag-dlp { background: #312e81; color: #c4b5fd; }
  .card.sensitive .value { color: #c084fc; }
  .empty { text-align: center; padding: 40px; color: #475569; }
</style>
</head>
<body>
<div class="header">
  <h1>Ferroada</h1>
  <span class="badge">Active</span>
  <span class="refresh">Updating every 5s</span>
</div>

<div class="cards">
  <div class="card total">
    <div class="label">Total Requests</div>
    <div class="value" id="requests_total">-</div>
  </div>
  <div class="card blocked">
    <div class="label">SQLi Blocked</div>
    <div class="value" id="blocked_sqli">-</div>
  </div>
  <div class="card blocked">
    <div class="label">XSS Blocked</div>
    <div class="value" id="blocked_xss">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Path Traversal</div>
    <div class="value" id="blocked_path_traversal">-</div>
  </div>
  <div class="card rate">
    <div class="label">Rate Limited</div>
    <div class="value" id="blocked_rate_limit">-</div>
  </div>
  <div class="card sensitive">
    <div class="label">Sensitive Paths</div>
    <div class="value" id="blocked_sensitive_path">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Body SQLi</div>
    <div class="value" id="blocked_body_sqli">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Body XSS</div>
    <div class="value" id="blocked_body_xss">-</div>
  </div>
  <div class="card blocked">
    <div class="label">CRLF Injection</div>
    <div class="value" id="blocked_crlf">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Smuggling</div>
    <div class="value" id="blocked_smuggling">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Log4Shell/JNDI</div>
    <div class="value" id="blocked_jndi">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Bad Bots</div>
    <div class="value" id="blocked_bad_bot">-</div>
  </div>
  <div class="card rate">
    <div class="label">Behavioral Throttle</div>
    <div class="value" id="blocked_behavioral_throttle">-</div>
  </div>
  <div class="card blocked">
    <div class="label">Behavioral Block</div>
    <div class="value" id="blocked_behavioral_block">-</div>
  </div>
  <div class="card dlp">
    <div class="label">CPFs Masked</div>
    <div class="value" id="dlp_cpf">-</div>
  </div>
  <div class="card dlp">
    <div class="label">Tokens Masked</div>
    <div class="value" id="dlp_tokens">-</div>
  </div>
  <div class="card rate">
    <div class="label">Method Blocked</div>
    <div class="value" id="blocked_method">-</div>
  </div>
  <div class="card rate">
    <div class="label">Size Limited</div>
    <div class="value" id="blocked_size_limit">-</div>
  </div>
  <div class="card total">
    <div class="label">HTTPS Redirects</div>
    <div class="value" id="https_redirect">-</div>
  </div>
</div>

<div class="section-title">Recent Security Events</div>
<table>
  <thead>
    <tr>
      <th>Time</th>
      <th>Type</th>
      <th>Client IP</th>
      <th>URI</th>
      <th>Detail</th>
    </tr>
  </thead>
  <tbody id="events">
    <tr><td colspan="5" class="empty">Loading...</td></tr>
  </tbody>
</table>

<script>
const TAG_CLASSES = {
  sqli: 'tag-sqli', xss: 'tag-xss',
  path_traversal: 'tag-path_traversal',
  rate_limit: 'tag-rate_limit',
  sensitive_path: 'tag-sensitive_path',
  body_sqli: 'tag-body_sqli',
  body_xss: 'tag-body_xss',
  method: 'tag-rate_limit',
  size_limit: 'tag-rate_limit',
  https_redirect: 'tag-sensitive_path',
  crlf: 'tag-crlf',
  smuggling: 'tag-smuggling',
  jndi: 'tag-jndi',
  bad_bot: 'tag-bad_bot',
  behavioral_throttle: 'tag-behavioral_throttle',
  behavioral_block: 'tag-behavioral_block',
  dlp: 'tag-dlp'
};

function setText(id, val) {
  document.getElementById(id).textContent = val.toLocaleString();
}

function createCell(text) {
  const td = document.createElement('td');
  td.textContent = text;
  return td;
}

function createTagCell(eventType) {
  const td = document.createElement('td');
  const span = document.createElement('span');
  span.className = 'tag ' + (TAG_CLASSES[eventType] || '');
  span.textContent = eventType;
  td.appendChild(span);
  return td;
}

async function refresh() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();

    setText('requests_total', data.requests_total);
    setText('blocked_sqli', data.blocked.sqli);
    setText('blocked_xss', data.blocked.xss);
    setText('blocked_path_traversal', data.blocked.path_traversal);
    setText('blocked_rate_limit', data.blocked.rate_limit);
    setText('blocked_sensitive_path', data.blocked.sensitive_path);
    setText('blocked_body_sqli', data.blocked.body_sqli);
    setText('blocked_body_xss', data.blocked.body_xss);
    setText('blocked_method', data.blocked.method || 0);
    setText('blocked_size_limit', data.blocked.size_limit || 0);
    setText('blocked_crlf', data.blocked.crlf || 0);
    setText('blocked_smuggling', data.blocked.smuggling || 0);
    setText('blocked_jndi', data.blocked.jndi || 0);
    setText('blocked_bad_bot', data.blocked.bad_bot || 0);
    setText('blocked_behavioral_throttle', data.blocked.behavioral_throttle || 0);
    setText('blocked_behavioral_block', data.blocked.behavioral_block || 0);
    setText('https_redirect', data.https_redirect || 0);
    setText('dlp_cpf', data.dlp.cpf_masked);
    setText('dlp_tokens', data.dlp.tokens_masked);

    const tbody = document.getElementById('events');
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (!data.recent_events || data.recent_events.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'empty';
      td.textContent = 'No events yet';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    data.recent_events.forEach(function(e) {
      const tr = document.createElement('tr');
      tr.appendChild(createCell(e.timestamp));
      tr.appendChild(createTagCell(e.event_type));
      tr.appendChild(createCell(e.client_ip));
      tr.appendChild(createCell(e.uri));
      tr.appendChild(createCell(e.detail));
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed to fetch metrics:', err);
  }
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"##.to_string()
}
