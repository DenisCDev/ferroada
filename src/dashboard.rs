use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dashboard_auth::{
    credentials_in_query, form_field, query_param, AuthMethod, Authn, ClientCertIdentity,
};
use crate::metrics;
use crate::policy::PolicyStore;

pub use crate::dashboard_audit::AdminAudit;
pub use crate::dashboard_auth::{
    production_enabled, validate_exposure, AdminAuth, DashboardAuthSetup, Role,
};

/// GET/HEAD after method checks. HTML, `/healthz` and `/readyz` stay public so
/// the token form in the document remains reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardGet {
    Health,
    Ready,
    Unauthorized,
    MetricsJson,
    MetricsPrometheus,
    Html,
}

fn classify_dashboard_get(path: &str, authorized: bool) -> DashboardGet {
    match path {
        "/healthz" => DashboardGet::Health,
        "/readyz" => DashboardGet::Ready,
        "/api/metrics" if authorized => DashboardGet::MetricsJson,
        "/metrics" if authorized => DashboardGet::MetricsPrometheus,
        "/api/metrics" | "/metrics" => DashboardGet::Unauthorized,
        _ => DashboardGet::Html,
    }
}

pub struct DashboardService {
    admin: Arc<AdminAuth>,
    audit: Arc<AdminAudit>,
    policy: Option<Arc<PolicyStore>>,
    upstreams: Arc<[SocketAddr]>,
    tls: bool,
}

impl DashboardService {
    pub fn new(token: Option<String>, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            admin: AdminAuth::with_token(token),
            audit: Arc::new(AdminAudit::disabled()),
            policy: None,
            upstreams: upstreams.into(),
            tls: false,
        }
    }

    pub fn with_policy(policy: Arc<PolicyStore>) -> Self {
        Self {
            admin: AdminAuth::disabled(),
            audit: Arc::new(AdminAudit::disabled()),
            policy: Some(policy),
            upstreams: Arc::from([]),
            tls: false,
        }
    }

    pub fn with_admin(mut self, admin: Arc<AdminAuth>, audit: AdminAudit, tls: bool) -> Self {
        self.admin = admin;
        self.audit = Arc::new(audit);
        self.tls = tls;
        self
    }

    fn backend_addresses(&self) -> Vec<SocketAddr> {
        if let Some(policy) = &self.policy {
            policy.config().backend_addresses()
        } else {
            self.upstreams.iter().copied().collect()
        }
    }

    async fn upstreams_ready(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        let groups = if let Some(policy) = &self.policy {
            policy.config().origin_groups()
        } else {
            let addrs = self.backend_addresses();
            if addrs.is_empty() {
                Vec::new()
            } else {
                vec![addrs]
            }
        };
        if groups.is_empty() {
            return false;
        }
        for group in groups {
            if group.is_empty() {
                return false;
            }
            let mut any_up = false;
            for address in group {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return false;
                };
                let timeout = remaining.min(Duration::from_millis(250));
                let result =
                    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await;
                if matches!(result, Ok(Ok(_))) {
                    any_up = true;
                    break;
                }
            }
            if !any_up {
                return false;
            }
        }
        true
    }

    fn authenticate(&self, session: &Session, peer: &PeerInfo) -> Option<Authn> {
        let cookie = session
            .req_header()
            .headers
            .get("cookie")
            .and_then(|value| value.to_str().ok());
        let authorization = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        self.admin
            .authenticate(cookie, authorization, peer.cn.as_deref(), peer.loopback)
    }

    fn authorization<'a>(&self, session: &'a Session) -> Option<&'a str> {
        session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
    }
}

struct PeerInfo {
    ip: Option<IpAddr>,
    label: String,
    loopback: bool,
    cn: Option<String>,
}

fn peer_info(session: &Session) -> PeerInfo {
    let inet = session
        .client_addr()
        .and_then(|addr| addr.as_inet().copied());
    let ip = inet.map(|addr| addr.ip());
    let label = ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let loopback = ip.map(|ip| ip.is_loopback()).unwrap_or(false);
    let cn = session
        .as_downstream()
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<ClientCertIdentity>())
        .and_then(|identity| identity.common_name.clone());
    PeerInfo {
        ip,
        label,
        loopback,
        cn,
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
        let method = session.req_header().method.as_str().to_string();
        let path = session.req_header().uri.path().to_string();
        let query = session.req_header().uri.query().map(str::to_string);
        let peer = peer_info(session);

        if method == "OPTIONS" {
            respond(session, 204, "text/plain", "", None, None).await?;
            return Ok(true);
        }

        if !self.admin.api_allowed(&path, peer.ip) {
            respond(
                session,
                429,
                "text/plain; charset=utf-8",
                "429 demasiados pedidos\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }

        if credentials_in_query(&path, query.as_deref()) {
            self.audit
                .auth_failure("unknown", &peer.label, "query_credential");
            respond(
                session,
                400,
                "text/plain; charset=utf-8",
                "400 credencial não pode ir na query string\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }

        match (method.as_str(), path.as_str()) {
            ("GET" | "HEAD", "/oidc/login") => self.handle_oidc_login(session, &peer).await,
            ("GET" | "HEAD", "/oidc/callback") => {
                self.handle_oidc_callback(session, query.as_deref(), &peer)
                    .await
            }
            ("POST", "/api/login") => self.handle_login(session, &peer).await,
            ("POST", "/api/reload") => self.handle_reload(session, &peer).await,
            ("GET" | "HEAD", _) => self.handle_get(session, &path, &peer).await,
            _ => {
                respond(
                    session,
                    405,
                    "text/plain; charset=utf-8",
                    "405 Método não permitido\n",
                    None,
                    None,
                )
                .await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        unreachable!("Dashboard never proxies to upstream")
    }
}

impl DashboardService {
    async fn handle_get(&self, session: &mut Session, path: &str, peer: &PeerInfo) -> Result<bool> {
        let mut authn = self.authenticate(session, peer);
        if authn.is_none()
            && self
                .admin
                .token_presented_and_wrong(self.authorization(session))
        {
            self.audit.auth_failure("token", &peer.label, "bad_token");
        }
        let mut set_cookie = None;
        if let Some(current) = authn.as_ref() {
            if current.method == AuthMethod::Mtls {
                if let Ok(issued) = self.admin.issue(current.role, current.subject.clone()) {
                    set_cookie = Some(issued.cookie(self.admin.ttl(), self.tls));
                    authn = Some(Authn {
                        role: issued.role,
                        method: AuthMethod::Session,
                        csrf: Some(issued.csrf),
                        subject: issued.subject,
                    });
                }
            }
        }
        let (status, content_type, body) = match classify_dashboard_get(path, authn.is_some()) {
            DashboardGet::Health => (200, "text/plain; charset=utf-8", "ok\n".to_string()),
            DashboardGet::Ready => {
                let (status, body) = if self.upstreams_ready().await {
                    (200, "pronto\n")
                } else {
                    (503, "backend indisponível\n")
                };
                (status, "text/plain; charset=utf-8", body.to_string())
            }
            DashboardGet::Unauthorized => (401, "text/plain", "401 Não autorizado\n".to_string()),
            DashboardGet::MetricsJson => {
                let snapshot = metrics::snapshot_json();
                let body = authn
                    .as_ref()
                    .map(|authn| with_admin(snapshot.clone(), authn))
                    .unwrap_or(snapshot);
                (200, "application/json", body)
            }
            DashboardGet::MetricsPrometheus => (
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                metrics::snapshot_prometheus(),
            ),
            DashboardGet::Html => (
                200,
                "text/html; charset=utf-8",
                dashboard_html(self.admin.oidc_enabled()),
            ),
        };
        respond(session, status, content_type, &body, None, set_cookie).await?;
        Ok(true)
    }

    async fn handle_login(&self, session: &mut Session, peer: &PeerInfo) -> Result<bool> {
        let body = match read_body(session, 8192).await {
            Ok(body) => body,
            Err(status) => {
                let text = match status {
                    408 => "408 tempo esgotado\n",
                    413 => "413 corpo demasiado grande\n",
                    _ => "400 pedido inválido\n",
                };
                respond(
                    session,
                    status,
                    "text/plain; charset=utf-8",
                    text,
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        let text = String::from_utf8_lossy(&body);
        let Some(token) = form_field(&text, "token").filter(|value| !value.is_empty()) else {
            self.audit
                .auth_failure("token", &peer.label, "missing_token");
            respond(
                session,
                401,
                "text/plain; charset=utf-8",
                "401 Não autorizado\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        match self.admin.login_with_token(&token, peer.loopback) {
            Ok(issued) => {
                self.audit
                    .login_ok("token", issued.role.as_str(), &peer.label, None);
                let cookie = issued.cookie(self.admin.ttl(), self.tls);
                let payload = json!({
                    "ok": true,
                    "role": issued.role.as_str(),
                    "csrf": issued.csrf
                })
                .to_string();
                respond(
                    session,
                    200,
                    "application/json",
                    &payload,
                    None,
                    Some(cookie),
                )
                .await?;
            }
            Err("token_off_loopback") => {
                self.audit
                    .auth_failure("token", &peer.label, "token_off_loopback");
                respond(
                    session,
                    401,
                    "text/plain; charset=utf-8",
                    "401 Não autorizado\n",
                    None,
                    None,
                )
                .await?;
            }
            Err(_) => {
                self.audit.auth_failure("token", &peer.label, "bad_token");
                respond(
                    session,
                    401,
                    "text/plain; charset=utf-8",
                    "401 Não autorizado\n",
                    None,
                    None,
                )
                .await?;
            }
        }
        Ok(true)
    }

    async fn handle_reload(&self, session: &mut Session, peer: &PeerInfo) -> Result<bool> {
        let authn = self.authenticate(session, peer);
        let body = match read_body(session, 8192).await {
            Ok(body) => body,
            Err(status) => {
                let text = match status {
                    408 => "408 tempo esgotado\n",
                    413 => "413 corpo demasiado grande\n",
                    _ => "400 pedido inválido\n",
                };
                respond(
                    session,
                    status,
                    "text/plain; charset=utf-8",
                    text,
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        let text = String::from_utf8_lossy(&body);
        let csrf = form_field(&text, "csrf");
        let Some(authn) = authn else {
            self.audit
                .auth_failure("unknown", &peer.label, "reload_unauthenticated");
            respond(
                session,
                401,
                "text/plain; charset=utf-8",
                "401 Não autorizado\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        if !authn.role.can_reload() {
            self.audit.reload(
                authn.method.as_str(),
                authn.role.as_str(),
                &peer.label,
                "denied",
                Some("not_operator".into()),
            );
            respond(
                session,
                403,
                "text/plain; charset=utf-8",
                "403 Sem permissão\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }
        if !self.admin.csrf_ok(&authn, csrf.as_deref()) {
            self.audit
                .auth_failure(authn.method.as_str(), &peer.label, "csrf");
            respond(
                session,
                403,
                "text/plain; charset=utf-8",
                "403 CSRF em falta\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }
        let Some(policy) = &self.policy else {
            respond(
                session,
                503,
                "text/plain; charset=utf-8",
                "503 política indisponível\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        match policy.try_reload() {
            Ok(outcome) => {
                self.audit.reload(
                    authn.method.as_str(),
                    authn.role.as_str(),
                    &peer.label,
                    "ok",
                    Some(format!("versão {}", outcome.version)),
                );
                let payload = json!({
                    "ok": true,
                    "policy_version": outcome.version,
                    "previous": outcome.previous
                })
                .to_string();
                respond(session, 200, "application/json", &payload, None, None).await?;
            }
            Err(_) => {
                self.audit.reload(
                    authn.method.as_str(),
                    authn.role.as_str(),
                    &peer.label,
                    "rejected",
                    Some("last-known-good".into()),
                );
                let payload = json!({
                    "ok": false,
                    "error": "Reload recusado; a política anterior permanece."
                })
                .to_string();
                respond(session, 409, "application/json", &payload, None, None).await?;
            }
        }
        Ok(true)
    }

    async fn handle_oidc_login(&self, session: &mut Session, peer: &PeerInfo) -> Result<bool> {
        if !self.admin.oidc_enabled() {
            respond(
                session,
                404,
                "text/plain; charset=utf-8",
                "404 não encontrado\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }
        match self.admin.begin_oidc() {
            Ok((url, _)) => {
                respond(session, 302, "text/plain", "", Some(url), None).await?;
            }
            Err(_) => {
                self.audit.auth_failure("oidc", &peer.label, "oidc_start");
                respond(
                    session,
                    503,
                    "text/plain; charset=utf-8",
                    "503 identidade indisponível\n",
                    None,
                    None,
                )
                .await?;
            }
        }
        Ok(true)
    }

    async fn handle_oidc_callback(
        &self,
        session: &mut Session,
        query: Option<&str>,
        peer: &PeerInfo,
    ) -> Result<bool> {
        if !self.admin.oidc_enabled() {
            respond(
                session,
                404,
                "text/plain; charset=utf-8",
                "404 não encontrado\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        }
        if query_param(query, "error").is_some() {
            self.audit.auth_failure("oidc", &peer.label, "idp_error");
            respond(session, 302, "text/plain", "", Some("/".into()), None).await?;
            return Ok(true);
        }
        let Some(state) = query_param(query, "state") else {
            self.audit.auth_failure("oidc", &peer.label, "oidc_state");
            respond(session, 302, "text/plain", "", Some("/".into()), None).await?;
            return Ok(true);
        };
        let Some(code) = query_param(query, "code") else {
            self.audit.auth_failure("oidc", &peer.label, "oidc_code");
            respond(session, 302, "text/plain", "", Some("/".into()), None).await?;
            return Ok(true);
        };
        let Some(pending) = self.admin.take_pending(&state) else {
            self.audit.auth_failure("oidc", &peer.label, "oidc_state");
            respond(session, 302, "text/plain", "", Some("/".into()), None).await?;
            return Ok(true);
        };
        let admin = Arc::clone(&self.admin);
        let issued =
            match tokio::task::spawn_blocking(move || admin.complete_oidc(&code, &pending)).await {
                Ok(Ok(issued)) => issued,
                _ => {
                    self.audit
                        .auth_failure("oidc", &peer.label, "oidc_exchange");
                    respond(session, 302, "text/plain", "", Some("/".into()), None).await?;
                    return Ok(true);
                }
            };
        self.audit.login_ok(
            "oidc",
            issued.role.as_str(),
            &peer.label,
            issued.subject.clone(),
        );
        let cookie = issued.cookie(self.admin.ttl(), self.tls);
        respond(
            session,
            302,
            "text/plain",
            "",
            Some("/".into()),
            Some(cookie),
        )
        .await?;
        Ok(true)
    }
}

fn with_admin(snapshot: String, authn: &Authn) -> String {
    let mut value: Value = serde_json::from_str(&snapshot).unwrap_or_else(|_| json!({}));
    let mut admin = serde_json::Map::new();
    admin.insert("role".into(), json!(authn.role.as_str()));
    if let Some(csrf) = &authn.csrf {
        admin.insert("csrf".into(), json!(csrf));
    }
    value["admin"] = Value::Object(admin);
    serde_json::to_string_pretty(&value).unwrap_or(snapshot)
}

async fn read_body(session: &mut Session, max: usize) -> std::result::Result<Vec<u8>, u16> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = Vec::new();
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(408);
        };
        let next =
            tokio::time::timeout(remaining, session.as_downstream_mut().read_request_body()).await;
        let chunk = match next {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(_)) => return Err(400),
            Err(_) => return Err(408),
        };
        if out.len().saturating_add(chunk.len()) > max {
            return Err(413);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn respond(
    session: &mut Session,
    status: u16,
    content_type: &str,
    body: &str,
    location: Option<String>,
    set_cookie: Option<String>,
) -> Result<()> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", content_type)?;
    header.insert_header("Content-Length", body.len().to_string())?;
    header.insert_header("Cache-Control", "no-cache")?;
    header.insert_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")?;
    header.insert_header("Referrer-Policy", "no-referrer")?;
    header.insert_header("X-Content-Type-Options", "nosniff")?;
    header.insert_header("X-Frame-Options", "DENY")?;
    if let Some(location) = location {
        header.insert_header("Location", location)?;
    }
    if let Some(cookie) = set_cookie {
        header.insert_header("Set-Cookie", cookie)?;
    }
    if let Ok(origin) = std::env::var("DASHBOARD_CORS") {
        if !origin.is_empty() {
            header.insert_header("Access-Control-Allow-Origin", origin)?;
            header.insert_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type",
            )?;
            header.insert_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
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

fn dashboard_html(oidc: bool) -> String {
    const TEMPLATE: &str = r##"<!DOCTYPE html>
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
  .auth { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .auth input { min-width:280px; padding:8px 10px; border:1px solid var(--line); border-radius:6px; }
  .auth button, .reload button { padding:8px 12px; border:0; border-radius:6px; background:#171717; color:#fff; cursor:pointer; }
  .auth button:disabled, .reload button:disabled { opacity:.45; cursor:not-allowed; }
  [hidden] { display:none !important; }
  @media (max-width:720px) { .kpis { grid-template-columns:1fr 1fr; } }
</style>
</head>
<body>
<main>
  <h1>Visão geral</h1>
  <p class="lede">O que o proxy viu. Esta página atualiza a cada cinco segundos. O painel Next fica em <code>web/</code>. Política <code id="policy-version">—</code>.</p>
  <form class="auth notice" id="auth" hidden>
    <label for="token">Token do dashboard</label>
    <input id="token" type="password" autocomplete="current-password" required>
    <button id="auth-submit" type="submit" disabled>Entrar</button>
  </form>
  <p class="notice" id="oidc-wrap" hidden><a href="/oidc/login">Entrar com identidade</a></p>
  <form class="reload notice" id="reload-form" hidden>
    <button id="reload-btn" type="submit" disabled>Recarregar política</button>
    <p id="reload-status" role="status" hidden></p>
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
const oidcEnabled = __OIDC__;
const labels = { sqli:'injeção SQL', xss:'XSS', path_traversal:'path traversal', rate_limit:'limite de taxa', sensitive_path:'caminho sensível', body_sqli:'SQL no corpo', body_xss:'XSS no corpo', method:'método HTTP', size_limit:'tamanho', header_limit:'limite de headers', concurrency_limit:'limite de concorrência', connection_limit:'limite de conexões', request_buffer_limit:'memória de inspeção de entrada', spool_limit:'limite de spool', dlp_partial_block:'resposta parcial bloqueada pelo DLP', host:'host', crlf:'CRLF', smuggling:'smuggling', jndi:'JNDI', bad_bot:'bot', behavioral_throttle:'comportamento (freio)', behavioral_block:'comportamento (ban)', waf_incomplete:'inspeção WAF incompleta', waf_monitor:'monitoramento WAF', waf_l1:'WAF L1 (CRS)', waf_l1_shadow:'WAF L1 (sombra)', waf_engine_unavailable:'motor WAF L1 indisponível', dlp_skip:'DLP não aplicado', range_removed:'range removido para inspeção DLP', dlp:'DLP', inspection_parse_error:'JSON inválido', inspection_timeout:'tempo esgotado na inspeção', inspection_budget:'orçamento de inspeção esgotado', openapi:'validação OpenAPI', openapi_observe:'OpenAPI (observação)', jwt:'JWT inválido', jwt_binding:'JWT (binding)', graphql:'limite GraphQL', grpc:'método gRPC', policy_reload:'política recarregada', policy_reload_rejected:'reload de política recusado', abuse:'abuso' };
const auth = document.getElementById('auth');
const status = document.getElementById('status');
const tokenInput = document.getElementById('token');
const authSubmit = document.getElementById('auth-submit');
const oidcWrap = document.getElementById('oidc-wrap');
const reloadForm = document.getElementById('reload-form');
const reloadBtn = document.getElementById('reload-btn');
const reloadStatus = document.getElementById('reload-status');
let token = sessionStorage.getItem('ferroada_dashboard_token') || '';
let csrf = '';
let role = '';
if (oidcWrap && oidcEnabled) oidcWrap.hidden = false;
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
function syncReload(){
  const canReload = role === 'operator';
  if (reloadForm) reloadForm.hidden = !canReload;
  if (reloadBtn) reloadBtn.disabled = !canReload;
}
async function tick(){
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  const res = await fetch('/api/metrics', { headers, credentials: 'same-origin', signal: AbortSignal.timeout(4000) });
  if(res.status === 401){
    auth.hidden = false;
    if (oidcWrap && oidcEnabled) oidcWrap.hidden = false;
    status.hidden = false;
    status.textContent = 'Informe o token configurado em DASHBOARD_TOKEN.';
    throw new Error('unauthorized');
  }
  if(!res.ok) throw new Error('metrics');
  const m = await res.json();
  auth.hidden = true;
  if (oidcWrap) oidcWrap.hidden = true;
  status.hidden = true;
  csrf = (m.admin && m.admin.csrf) || '';
  role = (m.admin && m.admin.role) || '';
  syncReload();
  const policyEl = document.getElementById('policy-version');
  if (policyEl) policyEl.textContent = m.policy_version || '—';
  const blocked = Object.values(m.blocked||{}).reduce((s,n)=>s+n,0);
  const rate = m.requests_total===0?0:(1-blocked/Math.max(m.requests_total,blocked))*100;
  const kpis = document.getElementById('kpis');
  kpis.replaceChildren(
    kpi('Requisições', fmt(m.requests_total)),
    kpi('Bloqueios', fmt(blocked)),
    kpi('Tráfego limpo', new Intl.NumberFormat('pt-BR',{maximumFractionDigits:1}).format(rate)+'%'),
    kpi('DLP', fmt((m.dlp&&m.dlp.cpf_masked||0)+(m.dlp&&m.dlp.cnpj_masked||0)+(m.dlp&&m.dlp.card_masked||0)+(m.dlp&&m.dlp.tokens_masked||0)))
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
  const value = tokenInput.value.trim();
  if(!value) return;
  token = value;
  sessionStorage.setItem('ferroada_dashboard_token', token);
  status.hidden = false;
  status.textContent = 'Validando token...';
  const body = new URLSearchParams();
  body.set('token', value);
  fetch('/api/login', { method: 'POST', body, credentials: 'same-origin', signal: AbortSignal.timeout(4000) })
    .then(function(res){
      if(res.status === 401){
        auth.hidden = false;
        status.hidden = false;
        status.textContent = 'Token recusado. Confira DASHBOARD_TOKEN.';
        throw new Error('unauthorized');
      }
      if(!res.ok) throw new Error('login');
      return tick();
    })
    .catch(showError);
});
if (reloadForm) reloadForm.addEventListener('submit', function(event){
  event.preventDefault();
  if (role !== 'operator') return;
  if (!csrf && !token) {
    reloadStatus.hidden = false;
    reloadStatus.textContent = 'A sessão expirou. Entre de novo para recarregar a política.';
    return;
  }
  reloadBtn.disabled = true;
  reloadStatus.hidden = false;
  reloadStatus.textContent = 'Recarregando a política…';
  const body = new URLSearchParams();
  if (csrf) body.set('csrf', csrf);
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  fetch('/api/reload', { method: 'POST', headers, body, credentials: 'same-origin', signal: AbortSignal.timeout(8000) })
    .then(function(res){
      if (res.status === 401) {
        reloadStatus.textContent = 'A sessão expirou. Entre de novo para recarregar a política.';
        throw new Error('unauthorized');
      }
      if (res.status === 403) {
        reloadStatus.textContent = 'Sem permissão para recarregar a política.';
        throw new Error('forbidden');
      }
      if (!res.ok) throw new Error('reload');
      reloadStatus.textContent = 'Política recarregada.';
      return tick();
    })
    .catch(function(error){
      if (error.message === 'forbidden' || error.message === 'unauthorized') return;
      reloadStatus.textContent = 'Não foi possível recarregar a política. A versão anterior permanece.';
    })
    .finally(function(){ syncReload(); });
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
"##;
    TEMPLATE.replace("__OIDC__", if oidc { "true" } else { "false" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_token_comparison_requires_exact_value() {
        use crate::dashboard_auth::constant_time_eq;
        assert!(constant_time_eq(b"segredo", b"segredo"));
        assert!(!constant_time_eq(b"segredo", b"segreda"));
        assert!(!constant_time_eq(b"curto", b"segredo"));
    }

    #[test]
    fn external_dashboard_requires_authentication() {
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let unspecified: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(validate_exposure(loopback, None, false, false), Ok(()));
        assert!(validate_exposure(unspecified, None, false, false).is_err());
        assert_eq!(
            validate_exposure(unspecified, Some("token"), false, false),
            Ok(())
        );
        assert_eq!(validate_exposure(unspecified, None, false, true), Ok(()));
    }

    #[test]
    fn production_requires_dashboard_token_on_loopback() {
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let v6: std::net::IpAddr = "::1".parse().unwrap();
        assert!(validate_exposure(loopback, None, true, false).is_err());
        assert!(validate_exposure(loopback, Some("   "), true, false).is_err());
        assert!(validate_exposure(v6, None, true, false).is_err());
        assert_eq!(
            validate_exposure(loopback, Some("token"), true, false),
            Ok(())
        );
        assert_eq!(
            validate_exposure(loopback, None, true, true),
            Err("DASHBOARD_TOKEN é obrigatório quando FERROADA_PRODUCTION=true")
        );
    }

    #[test]
    fn dashboard_document_stays_public_without_bearer() {
        assert_eq!(classify_dashboard_get("/", false), DashboardGet::Html);
        assert_eq!(classify_dashboard_get("/index", false), DashboardGet::Html);
        assert_eq!(
            classify_dashboard_get("/healthz", false),
            DashboardGet::Health
        );
        let html = dashboard_html(false);
        assert!(html.contains("Token do dashboard"));
        assert!(html.contains("id=\"auth\""));
        assert!(html.contains("id=\"policy-version\""));
        assert!(html.contains("const oidcEnabled = false"));
        assert!(html.contains("Entrar com identidade"));
        assert!(html.contains("Recarregar política"));
        assert!(!html.contains("/api/login?"));
        let oidc_html = dashboard_html(true);
        assert!(oidc_html.contains("const oidcEnabled = true"));
    }

    #[test]
    fn metrics_without_bearer_stay_unauthorized_when_token_exists() {
        assert_eq!(
            classify_dashboard_get("/api/metrics", false),
            DashboardGet::Unauthorized
        );
        assert_eq!(
            classify_dashboard_get("/metrics", false),
            DashboardGet::Unauthorized
        );
        assert_eq!(
            classify_dashboard_get("/api/metrics", true),
            DashboardGet::MetricsJson
        );
        assert_eq!(
            classify_dashboard_get("/metrics", true),
            DashboardGet::MetricsPrometheus
        );
        assert_eq!(classify_dashboard_get("/", true), DashboardGet::Html);
    }
}
