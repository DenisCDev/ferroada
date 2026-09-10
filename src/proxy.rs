use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::{Error, ErrorType};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

fn env_secs(var: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(default),
    )
}

static UPSTREAM_CONNECT_TIMEOUT: Lazy<Duration> =
    Lazy::new(|| env_secs("UPSTREAM_CONNECT_TIMEOUT", 5));
static UPSTREAM_READ_TIMEOUT: Lazy<Duration> = Lazy::new(|| env_secs("UPSTREAM_READ_TIMEOUT", 30));
static UPSTREAM_WRITE_TIMEOUT: Lazy<Duration> =
    Lazy::new(|| env_secs("UPSTREAM_WRITE_TIMEOUT", 30));
static BODY_READ_TIMEOUT: Lazy<Duration> = Lazy::new(|| env_secs("BODY_READ_TIMEOUT", 10));
static DOWNSTREAM_WRITE_TIMEOUT: Lazy<Duration> =
    Lazy::new(|| env_secs("DOWNSTREAM_WRITE_TIMEOUT", 30));
static DOWNSTREAM_KEEPALIVE_SECS: Lazy<u64> = Lazy::new(|| {
    std::env::var("DOWNSTREAM_KEEPALIVE_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(30)
});
static DOWNSTREAM_KEEPALIVE_REQUESTS: Lazy<u32> = Lazy::new(|| {
    std::env::var("DOWNSTREAM_KEEPALIVE_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
});
static RISK_SESSION_COOKIE: Lazy<String> =
    Lazy::new(|| std::env::var("RISK_SESSION_COOKIE").unwrap_or_else(|_| "session".to_string()));
static RISK_API_KEY_HEADER: Lazy<String> =
    Lazy::new(|| std::env::var("RISK_API_KEY_HEADER").unwrap_or_else(|_| "X-API-Key".to_string()));
static HTTPS_REDIRECT_HOST: Lazy<Option<String>> = Lazy::new(|| {
    std::env::var("HTTPS_REDIRECT_HOST").ok().map(|value| {
        let value = value.trim();
        if value.is_empty()
            || value.contains(['/', '\\', '@'])
            || value.chars().any(char::is_whitespace)
        {
            panic!("HTTPS_REDIRECT_HOST deve conter apenas host e porta opcionais");
        }
        value.to_string()
    })
});

use crate::behavioral::{self, BehavioralVerdict};
use crate::client_ip::{ClientIpConfig, RiskIdentity, TrustedProxies};
use crate::config::{Config, InspectionDisposition, InspectionPolicy};
use crate::dlp::{self, DlpAction};
use crate::headers;
use crate::jwt::{self, JwtFailure, JwtPrincipal};
use crate::metrics;
use crate::openapi::{BodyVerdict, EnvelopeVerdict, MatchedOp};
use crate::protocol::{self, ProtocolVerdict, RequestFacts};
use crate::rate_limit::RateLimiter;
use crate::shield::{self, ShieldVerdict};
use crate::spool::{SpoolError, SpoolHandle, SpoolRuntime};
use crate::waf::{self, InspectionOutcome, WafVerdict};
use crate::waf_engine::{self, InspectRequest, L1Verdict, WafEngine};
use crate::waf_l1;
use std::io::{Read, Write};

fn parse_ip(addr: &str) -> Option<IpAddr> {
    addr.parse::<std::net::SocketAddr>()
        .map(|s| s.ip())
        .or_else(|_| addr.parse::<IpAddr>())
        .ok()
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|cookie| {
        let (cookie_name, value) = cookie.trim().split_once('=')?;
        (cookie_name == name).then_some(value)
    })
}

fn raw_framing_header_counts(raw_headers: &[u8]) -> (usize, usize) {
    let mut content_length = 0;
    let mut transfer_encoding = 0;
    for line in raw_headers.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"content-length") {
            content_length += 1;
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encoding += 1;
        }
    }
    (content_length, transfer_encoding)
}

fn request_inspection_reservation(
    content_length: Option<usize>,
    max_body_size: usize,
    content_encoding: Option<&str>,
) -> Option<usize> {
    let body_size = content_length.unwrap_or(max_body_size).min(max_body_size);
    let mut bytes = body_size.checked_mul(2)?;
    if reserves_inflated_body(content_encoding) {
        bytes = bytes.checked_add(waf::max_inflate_buffer_bytes())?;
    }
    Some(bytes)
}

fn spool_inspection_reservation(
    content_length: Option<usize>,
    max_decoded: usize,
    content_encoding: Option<&str>,
) -> Option<usize> {
    let body_size = content_length.unwrap_or(max_decoded).min(max_decoded);
    let mut bytes = body_size;
    if reserves_inflated_body(content_encoding) {
        bytes = bytes.checked_add(waf::inflate_buffer_bytes(max_decoded as u64))?;
    }
    Some(bytes)
}

fn reserves_inflated_body(content_encoding: Option<&str>) -> bool {
    content_encoding.is_some_and(|encoding| {
        matches!(
            encoding.trim().to_ascii_lowercase().as_str(),
            "gzip" | "x-gzip" | "deflate"
        )
    })
}

#[derive(Clone)]
pub struct FerroadaProxy {
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
    pub trusted_proxies: TrustedProxies,
    client_ip: ClientIpConfig,
    proxy_protocol: bool,
    concurrency: Arc<ConcurrencyState>,
    dlp_budget: Arc<ByteBudget>,
    request_budget: Arc<ByteBudget>,
    spool: Arc<SpoolRuntime>,
    dlp_action: DlpAction,
    origin_secret: OriginSecretConfig,
    waf_engine: WafEngine,
}

pub struct BoundedBodyBuffer {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedBodyBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> bool {
        if self
            .bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > self.max)
        {
            return false;
        }
        self.bytes.extend_from_slice(chunk);
        true
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

struct ByteBudget {
    current: AtomicUsize,
    max: usize,
}

impl ByteBudget {
    fn from_env(name: &str, default: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max: env_bytes(name, default),
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(bytes).filter(|next| *next <= self.max)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        if bytes > 0 {
            self.current.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct ConcurrencyState {
    current: AtomicUsize,
    max: usize,
}

struct ConcurrencyGuard {
    state: Arc<ConcurrencyState>,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.state.current.fetch_sub(1, Ordering::Release);
    }
}

impl ConcurrencyState {
    fn from_env() -> Self {
        let max = std::env::var("MAX_IN_FLIGHT_REQUESTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1_024);
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    fn acquire(self: &Arc<Self>) -> Option<ConcurrencyGuard> {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.max).then_some(current + 1)
            })
            .ok()
            .map(|_| ConcurrencyGuard {
                state: Arc::clone(self),
            })
    }
}

impl FerroadaProxy {
    pub fn new(
        config: Arc<Config>,
        rate_limiter: Arc<RateLimiter>,
        trusted_proxies: TrustedProxies,
        client_ip: ClientIpConfig,
        proxy_protocol: bool,
    ) -> Self {
        let origin_secret = origin_secret_from_env();
        if origin_secret.value.is_some() {
            info!(
                header = %origin_secret.header,
                "Origin secret header will be injected on upstream requests"
            );
        }
        Self {
            spool: Arc::new(SpoolRuntime::from_config(&config)),
            config,
            rate_limiter,
            trusted_proxies,
            client_ip,
            proxy_protocol,
            concurrency: Arc::new(ConcurrencyState::from_env()),
            dlp_budget: Arc::new(ByteBudget::from_env(
                "DLP_MAX_IN_FLIGHT_BYTES",
                64 * 1024 * 1024,
            )),
            request_budget: Arc::new(ByteBudget::from_env(
                "WAF_MAX_IN_FLIGHT_BYTES",
                64 * 1024 * 1024,
            )),
            dlp_action: dlp::action(),
            origin_secret,
            waf_engine: WafEngine::native(),
        }
    }

    pub fn with_waf_engine(mut self, engine: WafEngine) -> Self {
        self.waf_engine = engine;
        self
    }

    pub fn with_dlp_action(mut self, action: DlpAction) -> Self {
        self.dlp_action = action;
        self
    }

    pub fn with_origin_secret(
        mut self,
        header: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.origin_secret = OriginSecretConfig {
            header: header.into(),
            value: Some(value.into()),
        };
        self
    }
}

static MAX_RESPONSE_BUFFER: Lazy<usize> =
    Lazy::new(|| env_bytes("DLP_MAX_RESPONSE_BYTES", 1024 * 1024));

fn env_bytes(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub struct FerroadaCtx {
    pub body_buffer: BoundedBodyBuffer,
    pub request_body: BoundedBodyBuffer,
    pub request_uri: String,
    pub site_scope: String,
    pub client_addr: String,
    pub content_type: Option<String>,
    pub response_content_encoding: Option<String>,
    pub request_content_type: Option<String>,
    pub request_content_encoding: Option<String>,
    pub skip_dlp: bool,
    pub skip_body_waf: bool,
    pub inspect_request_body: bool,
    pub request_https: bool,
    pub backend: Option<crate::config::Backend>,
    pub risk_identity: Option<RiskIdentity>,
    inspection_policy: InspectionPolicy,
    openapi_match: Option<MatchedOp>,
    jwt: Option<JwtPrincipal>,
    spool: Option<SpoolHandle>,
    concurrency_guard: Option<ConcurrencyGuard>,
    dlp_budget: Arc<ByteBudget>,
    dlp_reserved: usize,
    request_budget: Arc<ByteBudget>,
    request_reserved: usize,
}

impl FerroadaCtx {
    fn reserve_dlp(&mut self, bytes: usize) -> bool {
        if self.dlp_budget.reserve(bytes) {
            self.dlp_reserved += bytes;
            true
        } else {
            false
        }
    }

    fn release_dlp(&mut self) {
        self.dlp_budget.release(self.dlp_reserved);
        self.dlp_reserved = 0;
    }

    fn reserve_request(&mut self, bytes: usize) -> bool {
        if self.request_budget.reserve(bytes) {
            self.request_reserved += bytes;
            true
        } else {
            false
        }
    }

    fn release_request(&mut self) {
        self.request_budget.release(self.request_reserved);
        self.request_reserved = 0;
    }
}

impl Drop for FerroadaCtx {
    fn drop(&mut self) {
        self.release_dlp();
        self.release_request();
    }
}

#[async_trait]
impl ProxyHttp for FerroadaProxy {
    type CTX = FerroadaCtx;

    fn new_ctx(&self) -> Self::CTX {
        FerroadaCtx {
            body_buffer: BoundedBodyBuffer::new(*MAX_RESPONSE_BUFFER),
            request_body: BoundedBodyBuffer::new(shield::max_body_size()),
            request_uri: String::new(),
            site_scope: String::new(),
            client_addr: String::new(),
            content_type: None,
            response_content_encoding: None,
            request_content_type: None,
            request_content_encoding: None,
            skip_dlp: false,
            skip_body_waf: false,
            inspect_request_body: false,
            request_https: false,
            backend: None,
            risk_identity: None,
            inspection_policy: InspectionPolicy::open(),
            openapi_match: None,
            jwt: None,
            spool: None,
            concurrency_guard: None,
            dlp_budget: Arc::clone(&self.dlp_budget),
            dlp_reserved: 0,
            request_budget: Arc::clone(&self.request_budget),
            request_reserved: 0,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        metrics::increment_requests();

        let uri = session
            .req_header()
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let socket_addr = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let socket_ip = parse_ip(&socket_addr);
        // PROXY v2 already rewrote SocketDigest; the hop that spoke v2 is trusted
        // for proto/header walks even when the rewritten client IP is not in
        // TRUSTED_PROXIES (Caddy/HAProxy terminated TLS in front).
        let peer_is_trusted = self.proxy_protocol
            || socket_ip
                .map(|ip| self.trusted_proxies.is_trusted(ip))
                .unwrap_or(false);
        let header_map = &session.req_header().headers;
        let forwarded_for = header_map
            .get("X-Forwarded-For")
            .and_then(|value| value.to_str().ok());
        let forwarded = header_map
            .get("Forwarded")
            .and_then(|value| value.to_str().ok());
        let extra_header = self.client_ip.extra_header.as_ref().and_then(|name| {
            header_map
                .get(name.as_str())
                .and_then(|value| value.to_str().ok())
        });
        let client_addr = self
            .trusted_proxies
            .resolve_sources(
                socket_ip,
                forwarded_for,
                forwarded,
                extra_header,
                &self.client_ip,
            )
            .map(|ip| ip.to_string())
            .unwrap_or(socket_addr);

        let Some(concurrency_guard) = self.concurrency.acquire() else {
            metrics::record_block(
                "concurrency_limit",
                &client_addr,
                &uri,
                "Maximum in-flight requests reached",
            );
            return self.send_503(session).await;
        };
        ctx.concurrency_guard = Some(concurrency_guard);
        session.set_keepalive(Some(*DOWNSTREAM_KEEPALIVE_SECS));
        session.set_keepalive_reuses_remaining(Some(*DOWNSTREAM_KEEPALIVE_REQUESTS));
        session.set_write_timeout(Some(*DOWNSTREAM_WRITE_TIMEOUT));

        // Store in ctx for body filter
        ctx.request_uri = uri.clone();
        ctx.client_addr = client_addr.clone();
        let transport_https = session
            .digest()
            .as_ref()
            .map(|digest| digest.ssl_digest.is_some())
            .unwrap_or(false);
        let forwarded_https = peer_is_trusted
            && session
                .req_header()
                .headers
                .get("X-Forwarded-Proto")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(|value| value.trim().eq_ignore_ascii_case("https"))
                .unwrap_or(false);
        ctx.request_https = transport_https || forwarded_https;

        let header_count = session.req_header().headers.len();
        let header_bytes = session
            .req_header()
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len().saturating_add(value.as_bytes().len()))
            .sum();
        if matches!(
            shield::check_headers(header_count, header_bytes, &uri, &client_addr),
            ShieldVerdict::BlockHeaders
        ) {
            return self.send_431(session).await;
        }

        // Host header validation (DNS rebinding protection)
        let host_val = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let uri_authority = session
            .req_header()
            .uri
            .authority()
            .map(|authority| authority.as_str().to_string());
        if matches!(
            shield::check_host_authority(
                host_val.as_deref(),
                uri_authority.as_deref(),
                &uri,
                &client_addr,
            ),
            ShieldVerdict::BlockHost
        ) {
            return self
                .send_400(session, "Host e :authority divergentes")
                .await;
        }

        if host_val.as_ref().is_some_and(|hv| {
            matches!(
                shield::check_host(hv, &uri, &client_addr),
                ShieldVerdict::BlockHost
            )
        }) {
            let body = "421 Destino incorreto\n";
            let mut header = ResponseHeader::build(421, None)?;
            header.insert_header("Content-Type", "text/plain")?;
            header.insert_header("Content-Length", body.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }

        // Multi-site routing: resolve backend by Host header
        let host_for_resolve = host_val.as_deref().unwrap_or("");
        match self.config.resolve(host_for_resolve) {
            Some(backend) => {
                ctx.backend = Some(backend.clone());
            }
            None => {
                // No matching site and no default backend → 421
                let body = "421 Destino incorreto\n";
                let mut header = ResponseHeader::build(421, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;
                metrics::record_block(
                    "host",
                    &client_addr,
                    &uri,
                    &format!("No site for host: {}", host_for_resolve),
                );
                return Ok(true);
            }
        }
        let site = ctx
            .backend
            .as_ref()
            .expect("backend resolved")
            .site_scope
            .clone();
        ctx.site_scope = site.clone();
        ctx.inspection_policy = ctx
            .backend
            .as_ref()
            .map(|backend| backend.inspection_policy(&uri))
            .unwrap_or_else(InspectionPolicy::open);

        // Host must be validated and routed before it can control Location.
        let force_https = std::env::var("FORCE_HTTPS")
            .map(|v| v == "true")
            .unwrap_or(false);
        if force_https && !ctx.request_https {
            let host = ctx
                .backend
                .as_ref()
                .and_then(|backend| backend.redirect_host.as_deref())
                .or(HTTPS_REDIRECT_HOST.as_deref());
            let Some(host) = host else {
                metrics::record_block_in(
                    &ctx.site_scope,
                    "host",
                    &client_addr,
                    &uri,
                    "No trusted HTTPS redirect host configured",
                );
                let body = "421 Destino incorreto\n";
                let mut header = ResponseHeader::build(421, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;
                return Ok(true);
            };
            let location = format!("https://{host}{uri}");
            let body = "301 Movido permanentemente\n";
            let mut header = ResponseHeader::build(301, None)?;
            header.insert_header("Location", &location)?;
            header.insert_header("Content-Type", "text/plain")?;
            header.insert_header("Content-Length", body.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            metrics::record_block_in(
                &ctx.site_scope,
                "https_redirect",
                &client_addr,
                &uri,
                "redirecionamento HTTP→HTTPS",
            );
            return Ok(true);
        }

        if self.apply_jwt_identity(session, ctx, &uri).await? {
            return Ok(true);
        }

        let session_id = session
            .req_header()
            .headers
            .get("Cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| cookie_value(value, &RISK_SESSION_COOKIE));
        let api_key = session
            .req_header()
            .headers
            .get(RISK_API_KEY_HEADER.as_str())
            .and_then(|value| value.to_str().ok());
        ctx.risk_identity = parse_ip(&client_addr).map(|ip| {
            let mut identity = RiskIdentity::new(&site, ip, &uri, session_id, api_key);
            if let Some(principal) = ctx.jwt.as_ref() {
                identity.set_jwt(Some(principal.sub.as_str()), principal.tenant.as_deref());
            }
            identity
        });

        if let Some(identity) = ctx.risk_identity.as_ref() {
            let ua = session
                .req_header()
                .headers
                .get("User-Agent")
                .and_then(|v| v.to_str().ok());
            match behavioral::check_and_record(identity, &uri, ua, &client_addr) {
                BehavioralVerdict::Block => {
                    return self
                        .send_403(session, "Bloqueado temporariamente por atividade suspeita")
                        .await;
                }
                BehavioralVerdict::Throttle => {
                    return self
                        .send_429(session, "Muitas requisições suspeitas", 30)
                        .await;
                }
                BehavioralVerdict::Allow => {}
            }
        }

        // Pingora removes Content-Length when Transfer-Encoding is also present,
        // so framing counts must use the retained raw header block.
        let raw_headers = session.as_downstream().to_h1_raw();
        let (cl_count, te_count) = raw_framing_header_counts(&raw_headers);
        let has_cl = cl_count > 0;
        let te = session
            .req_header()
            .headers
            .get("Transfer-Encoding")
            .and_then(|v| v.to_str().ok());
        if matches!(
            shield::check_smuggling(
                has_cl,
                cl_count,
                te_count,
                te,
                &uri,
                &client_addr,
                &ctx.site_scope,
            ),
            ShieldVerdict::BlockSmuggling
        ) {
            return self
                .send_400(
                    session,
                    "Requisição inválida: inconsistência nos cabeçalhos HTTP",
                )
                .await;
        }

        // Bad Bot User-Agent check
        let ua = session
            .req_header()
            .headers
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if matches!(
            shield::check_user_agent(ua, &uri, &client_addr, &ctx.site_scope),
            ShieldVerdict::BlockBadBot
        ) {
            return self
                .send_403(session, "Bloqueado: identificação de cliente suspeita")
                .await;
        }

        // Method restriction check
        let method = session.req_header().method.as_str().to_string();
        if matches!(
            shield::check_method(&method, &uri, &client_addr, &ctx.site_scope),
            ShieldVerdict::BlockMethod
        ) {
            let body = "405 Método não permitido\n";
            let mut header = ResponseHeader::build(405, None)?;
            header.insert_header("Content-Type", "text/plain")?;
            header.insert_header("Content-Length", body.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }

        // URI length check
        if matches!(
            shield::check_uri_length(&uri, &client_addr, &ctx.site_scope),
            ShieldVerdict::BlockUriLength
        ) {
            let body = "414 URI muito longa\n";
            let mut header = ResponseHeader::build(414, None)?;
            header.insert_header("Content-Type", "text/plain")?;
            header.insert_header("Content-Length", body.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }

        // Body size check (via Content-Length header). Spool routes use
        // max_decoded_body as the wire ceiling; everyone else stays at 64 KiB.
        let content_length = session
            .req_header()
            .headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        let route_body_limit = ctx
            .inspection_policy
            .max_decoded_body
            .unwrap_or_else(shield::max_body_size);
        if let Some(cl) = content_length {
            if cl > route_body_limit {
                return self
                    .send_413(
                        session,
                        &uri,
                        &client_addr,
                        route_body_limit,
                        &ctx.site_scope,
                    )
                    .await;
            }
        }

        // Rate limiting check (before WAF to save CPU on floods)
        if let Some(identity) = ctx.risk_identity.as_ref() {
            if !self.rate_limiter.check(identity, &uri) {
                let body = "429 Muitas requisições\n";
                let mut header = ResponseHeader::build(429, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                header.insert_header("Retry-After", self.rate_limiter.window_secs().to_string())?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;
                return Ok(true);
            }
        }

        ctx.request_content_type = session
            .req_header()
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        ctx.request_content_encoding = session
            .req_header()
            .headers
            .get("Content-Encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let upgrade = session
            .req_header()
            .headers
            .get("Upgrade")
            .and_then(|v| v.to_str().ok());
        let inspection_policy = ctx.inspection_policy;
        let protocol_verdict = self.config.protocols.evaluate(&RequestFacts {
            version: session.req_header().version,
            upgrade,
            content_encoding: ctx.request_content_encoding.as_deref(),
            content_type: ctx.request_content_type.as_deref(),
            require_complete: inspection_policy.require_complete,
        });
        protocol::record(protocol_verdict, &client_addr, &uri, &ctx.site_scope);
        if protocol_verdict.blocked_status().is_some() {
            let reason = match protocol_verdict {
                ProtocolVerdict::Unsupported { protocol, .. } => protocol.deny_reason(),
                ProtocolVerdict::Inspect => "protocolo não suportado",
            };
            return self.send_403(session, reason).await;
        }
        ctx.skip_body_waf = protocol_verdict.skips_body_waf();

        // WAF inspection on URI + headers. Authorization is identity, not a
        // WAF input — matching it would put the token in the event detail.
        let header_values: Vec<String> = session
            .req_header()
            .headers
            .iter()
            .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("authorization"))
            .filter_map(|(_, value)| value.to_str().ok().map(|s| s.to_string()))
            .collect();

        let waf_profile = ctx.backend.as_ref().expect("backend resolved").waf_profile;
        match waf::inspect_request_with_profile(
            &uri,
            &header_values,
            &client_addr,
            waf_profile,
            &ctx.site_scope,
        ) {
            WafVerdict::Allow => {}
            WafVerdict::Block(reason) => {
                if let Some(identity) = ctx.risk_identity.as_ref() {
                    behavioral::record_waf_block(identity);
                }
                return self.send_403(session, &reason).await;
            }
        }

        if self
            .apply_openapi_envelope(session, ctx, &method, &uri)
            .await?
        {
            return Ok(true);
        }

        // Read and approve the complete body before Pingora opens the upstream.
        // Spool routes hold in SpoolHandle and do not call enable_retry_buffering.
        if !session.as_mut().is_body_empty() {
            session.set_read_timeout(Some(*BODY_READ_TIMEOUT));
            let spooling = inspection_policy.uses_spool();
            let max_body = inspection_policy
                .max_decoded_body
                .unwrap_or_else(shield::max_body_size);
            let reservation = if spooling {
                spool_inspection_reservation(
                    content_length,
                    max_body,
                    ctx.request_content_encoding.as_deref(),
                )
            } else {
                request_inspection_reservation(
                    content_length,
                    shield::max_body_size(),
                    ctx.request_content_encoding.as_deref(),
                )
            }
            .unwrap_or(usize::MAX);
            if !ctx.reserve_request(reservation) {
                record_inspection_outcome(
                    InspectionOutcome::BudgetExceeded,
                    &ctx.client_addr,
                    &ctx.request_uri,
                    true,
                    &ctx.site_scope,
                );
                metrics::record_block_in(
                    &ctx.site_scope,
                    "request_buffer_limit",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    "Global request-body buffer budget exhausted",
                );
                return self.send_503(session).await;
            }

            let expects_continue = session
                .req_header()
                .headers
                .get("Expect")
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"));
            if expects_continue {
                session
                    .write_response_header(Box::new(ResponseHeader::build(100, None)?), false)
                    .await?;
                session
                    .as_downstream_mut()
                    .req_header_mut()
                    .remove_header("Expect");
            }

            if spooling {
                ctx.spool = Some(SpoolHandle::new(max_body, Arc::clone(&self.spool)));
            } else {
                session.as_downstream_mut().enable_retry_buffering();
            }
            let deadline = Instant::now() + *BODY_READ_TIMEOUT;
            loop {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return self.send_body_timeout(session, ctx).await;
                };
                let next = tokio::time::timeout(
                    remaining,
                    session.as_downstream_mut().read_request_body(),
                )
                .await;
                let chunk = match next {
                    Ok(result) => result?,
                    Err(_) => return self.send_body_timeout(session, ctx).await,
                };
                let Some(chunk) = chunk else {
                    break;
                };

                if spooling {
                    match ctx.spool.as_mut().expect("spool handle").push(&chunk).await {
                        Ok(()) => {}
                        Err(SpoolError::Overflow) => {
                            return self
                                .send_413(
                                    session,
                                    &ctx.request_uri,
                                    &ctx.client_addr,
                                    max_body,
                                    &ctx.site_scope,
                                )
                                .await;
                        }
                        Err(_) => {
                            metrics::record_block(
                                "spool_limit",
                                &ctx.client_addr,
                                &ctx.request_uri,
                                "Spool budget exhausted",
                            );
                            return self.send_503(session).await;
                        }
                    }
                } else if !ctx.request_body.push(&chunk) {
                    return self
                        .send_413(
                            session,
                            &ctx.request_uri,
                            &ctx.client_addr,
                            shield::max_body_size(),
                            &ctx.site_scope,
                        )
                        .await;
                }
            }

            if spooling {
                if ctx.spool.as_ref().is_some_and(SpoolHandle::is_empty) {
                    let request = session.as_downstream_mut().req_header_mut();
                    request.remove_header("Transfer-Encoding");
                    request.insert_header("Content-Length", "0")?;
                }
            } else if ctx.request_body.is_empty() {
                let request = session.as_downstream_mut().req_header_mut();
                request.remove_header("Transfer-Encoding");
                request.insert_header("Content-Length", "0")?;
            } else {
                let replay_matches = session
                    .as_downstream()
                    .get_retry_buffer()
                    .is_some_and(|buffer| buffer.as_ref() == ctx.request_body.as_slice());
                if !replay_matches {
                    metrics::record_block_in(
                        &ctx.site_scope,
                        "request_buffer_limit",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "Pingora request replay buffer was incomplete",
                    );
                    return self.send_503(session).await;
                }
            }

            if !ctx.skip_body_waf {
                let text_limit = inspection_policy
                    .max_decoded_body
                    .unwrap_or_else(waf::default_inspect_text_limit);
                let inflate_limit = inspection_policy
                    .max_decoded_body
                    .map(|n| n as u64)
                    .unwrap_or_else(waf::default_inflate_limit);
                let wire = if spooling {
                    match ctx
                        .spool
                        .as_mut()
                        .expect("spool handle")
                        .inspect_bytes()
                        .await
                    {
                        Ok(bytes) => bytes.to_vec(),
                        Err(_) => {
                            metrics::record_block(
                                "spool_limit",
                                &ctx.client_addr,
                                &ctx.request_uri,
                                "Spool inspect read failed",
                            );
                            return self.send_503(session).await;
                        }
                    }
                } else {
                    ctx.request_body.as_slice().to_vec()
                };
                let inspect_body = waf::inflate_for_inspect_limited(
                    &wire,
                    ctx.request_content_encoding.as_deref(),
                    inflate_limit,
                );
                let inspection = waf::inspect_body_limited(
                    &inspect_body.bytes,
                    &ctx.request_uri,
                    &ctx.client_addr,
                    ctx.request_content_type.as_deref(),
                    text_limit,
                    &ctx.site_scope,
                );
                let inspection_status = inspect_body.status.combine(inspection.status);
                match inspection.verdict {
                    WafVerdict::Allow => match inspection_policy.disposition(inspection_status) {
                        InspectionDisposition::Allow => {
                            record_inspection_outcome(
                                inspection_status,
                                &ctx.client_addr,
                                &ctx.request_uri,
                                false,
                                &ctx.site_scope,
                            );
                        }
                        InspectionDisposition::Monitor => {
                            record_inspection_outcome(
                                inspection_status,
                                &ctx.client_addr,
                                &ctx.request_uri,
                                false,
                                &ctx.site_scope,
                            );
                            tracing::warn!(
                                client = %ctx.client_addr,
                                uri = %ctx.request_uri,
                                inspection_status = inspection_status.as_str(),
                                "Request body was not completely inspected"
                            );
                        }
                        InspectionDisposition::Deny => {
                            record_inspection_outcome(
                                inspection_status,
                                &ctx.client_addr,
                                &ctx.request_uri,
                                true,
                                &ctx.site_scope,
                            );
                            if let Some(identity) = ctx.risk_identity.as_ref() {
                                behavioral::record_waf_block(identity);
                            }
                            return self
                                .send_403(session, incomplete_inspection_reason(inspection_status))
                                .await;
                        }
                    },
                    WafVerdict::Block(reason) => {
                        record_inspection_outcome(
                            inspection_status,
                            &ctx.client_addr,
                            &ctx.request_uri,
                            false,
                            &ctx.site_scope,
                        );
                        if let Some(identity) = ctx.risk_identity.as_ref() {
                            behavioral::record_waf_block(identity);
                        }
                        return self.send_403(session, &reason).await;
                    }
                }
                let l1_decoded =
                    ctx.request_content_encoding.as_deref().is_some_and(|enc| {
                        matches!(
                            enc.trim().to_ascii_lowercase().as_str(),
                            "gzip" | "x-gzip" | "deflate"
                        )
                    }) && !matches!(inspect_body.status, InspectionOutcome::UnsupportedEncoding);
                let l1_body = if l1_decoded {
                    inspect_body.bytes.as_ref()
                } else {
                    wire.as_slice()
                };
                if self
                    .apply_l1(session, ctx, &method, &uri, l1_body, l1_decoded)
                    .await?
                {
                    return Ok(true);
                }
                if self.apply_openapi_body(session, ctx, l1_body).await? {
                    return Ok(true);
                }
                if self.apply_jwt_body(session, ctx, l1_body).await? {
                    return Ok(true);
                }
            } else if ctx.openapi_match.is_some()
                || ctx
                    .backend
                    .as_ref()
                    .and_then(|backend| backend.jwt.as_ref())
                    .is_some_and(|policy| policy.has_body_bindings())
            {
                let wire = if spooling {
                    match ctx
                        .spool
                        .as_mut()
                        .expect("spool handle")
                        .inspect_bytes()
                        .await
                    {
                        Ok(bytes) => bytes.to_vec(),
                        Err(_) => {
                            metrics::record_block(
                                "spool_limit",
                                &ctx.client_addr,
                                &ctx.request_uri,
                                "Spool inspect read failed",
                            );
                            return self.send_503(session).await;
                        }
                    }
                } else {
                    ctx.request_body.as_slice().to_vec()
                };
                if self.apply_openapi_body(session, ctx, &wire).await? {
                    return Ok(true);
                }
                if self.apply_jwt_body(session, ctx, &wire).await? {
                    return Ok(true);
                }
            }

            // Keep the global reservation until the request finishes: Pingora now
            // owns the replay copy even though our inspection copy can be dropped.
            if spooling {
                if ctx.spool.as_ref().is_some_and(|handle| !handle.is_empty()) {
                    return self.replay_spool_to_origin(session, ctx).await;
                }
            } else if self.dlp_action != DlpAction::Block {
                // Keep the global reservation until the request finishes: Pingora
                // owns the replay copy even though our inspection copy can be dropped.
                ctx.inspect_request_body = !ctx.request_body.is_empty();
                let _ = ctx.request_body.take();
            }
        } else {
            if self
                .apply_l1(session, ctx, &method, &uri, &[], false)
                .await?
            {
                return Ok(true);
            }
            if self.apply_openapi_body(session, ctx, &[]).await? {
                return Ok(true);
            }
            if self.apply_jwt_body(session, ctx, &[]).await? {
                return Ok(true);
            }
        }

        if self.dlp_action == DlpAction::Block
            && !session.req_header().headers.contains_key("Upgrade")
        {
            // Commit-point: inspect the origin response before any downstream
            // byte. Pingora writes headers before body filters, so block
            // cannot stream — including GET (empty request body).
            let body = ctx.request_body.take();
            return self.commit_origin_response(session, ctx, body).await;
        }

        tracing::debug!(client = %client_addr, uri = %uri, "Request filters passed");
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(spool) = ctx.spool.as_mut() {
            match spool.next_replay_chunk().await {
                Ok(chunk) => {
                    *body = chunk;
                    Ok(())
                }
                Err(_) => {
                    metrics::record_block(
                        "spool_limit",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "Spool replay failed",
                    );
                    Error::e_explain(ErrorType::HTTPStatus(503), "spool replay")
                }
            }
        } else {
            if ctx.inspect_request_body {
                debug_assert!(end_of_stream, "pre-buffered bodies must be replayed at EOS");
                debug_assert!(body.is_some(), "approved body replay must contain bytes");
            }
            Ok(())
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            _ => 502,
        };
        if session.response_written().is_none() {
            if let Err(err) = session.respond_error(code).await {
                tracing::warn!(error = %err, status = code, "failed to write error response");
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, error: &Error) -> bool {
        matches!(error.etype(), ErrorType::HTTPStatus(403 | 413))
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let backend = ctx
            .backend
            .as_ref()
            .expect("backend must be resolved in request_filter");
        info!(addr = %backend.addr, tls = backend.tls, host = %backend.host, "Connecting to upstream");
        let mut peer = HttpPeer::new(backend.addr, backend.tls, backend.host.clone());
        peer.options.connection_timeout = Some(*UPSTREAM_CONNECT_TIMEOUT);
        peer.options.read_timeout = Some(*UPSTREAM_READ_TIMEOUT);
        peer.options.write_timeout = Some(*UPSTREAM_WRITE_TIMEOUT);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        stamp_upstream_request(upstream_request, ctx, &self.origin_secret);
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.decorate_origin_response(upstream_response, ctx)
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        // If we already decided to skip DLP, pass body through directly
        if ctx.skip_dlp {
            return Ok(None);
        }

        if let Some(b) = body.take() {
            // Check if buffering this chunk would exceed the limit
            let previous_len = ctx.body_buffer.len();
            let exceeds_response_limit = !ctx.body_buffer.push(&b);
            if exceeds_response_limit || !ctx.reserve_dlp(b.len()) {
                ctx.body_buffer.bytes.truncate(previous_len);
                ctx.release_dlp();
                if self.dlp_action.reject_incomplete_response() {
                    *body = None;
                    metrics::record_block(
                        "dlp_partial_block",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "DLP buffer limit reached",
                    );
                    return Error::e_explain(
                        ErrorType::HTTPStatus(502),
                        "DLP buffer limit reached",
                    );
                }
                // Too large — flush what we have and skip DLP for the rest
                ctx.skip_dlp = true;
                let mut flushed = ctx.body_buffer.take();
                flushed.extend_from_slice(&b);
                *body = Some(Bytes::from(flushed));
                metrics::record_observation(
                    "dlp_skip",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    "DLP buffer limit reached",
                );
                return Ok(None);
            }
        }

        if end_of_stream {
            let ct = ctx.content_type.as_deref();
            let buffered = ctx.body_buffer.take();
            let result = dlp::sanitize_encoded_body_with(
                &buffered,
                ct,
                ctx.response_content_encoding.as_deref(),
                *MAX_RESPONSE_BUFFER,
                self.dlp_action,
            );
            ctx.release_dlp();
            if self.dlp_action.reject_incomplete_response()
                && (!result.inspection_complete || result.found_sensitive())
            {
                *body = None;
                let detail = if !result.inspection_complete {
                    "Compressed response could not be inspected within the configured limit"
                } else {
                    "DLP blocked a response with sensitive data"
                };
                metrics::record_block(
                    "dlp_partial_block",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    detail,
                );
                return Error::e_explain(ErrorType::HTTPStatus(502), detail);
            }
            if !result.inspection_complete {
                tracing::warn!(
                    client = %ctx.client_addr,
                    uri = %ctx.request_uri,
                    "DLP response inspection was incomplete"
                );
                metrics::record_observation(
                    "dlp_skip",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    "Compressed response could not be inspected within the configured limit",
                );
            }
            *body = Some(result.bytes);
        }

        Ok(None)
    }
}

fn request_header_pairs(session: &Session) -> Vec<(String, String)> {
    session
        .req_header()
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect()
}

fn l1_header_pairs(session: &Session, body: &[u8], body_is_decoded: bool) -> Vec<(String, String)> {
    let raw = session
        .req_header()
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("authorization"))
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        });
    adjust_l1_headers(raw, body.len(), body_is_decoded)
}

fn adjust_l1_headers(
    headers: impl IntoIterator<Item = (String, String)>,
    body_len: usize,
    body_is_decoded: bool,
) -> Vec<(String, String)> {
    if !body_is_decoded {
        return headers.into_iter().collect();
    }
    let mut out = Vec::new();
    let mut wrote_length = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            out.push(("content-length".to_string(), body_len.to_string()));
            wrote_length = true;
            continue;
        }
        out.push((name, value));
    }
    if !wrote_length {
        out.push(("content-length".to_string(), body_len.to_string()));
    }
    out
}

fn http_version_token(version: http::Version) -> &'static str {
    if version == http::Version::HTTP_10 {
        "HTTP/1.0"
    } else if version == http::Version::HTTP_2 {
        "HTTP/2.0"
    } else {
        "HTTP/1.1"
    }
}

fn incomplete_inspection_reason(outcome: InspectionOutcome) -> &'static str {
    match outcome {
        InspectionOutcome::ParseError => "JSON inválido (ParseError)",
        InspectionOutcome::TimedOut => "tempo esgotado (TimedOut)",
        InspectionOutcome::BudgetExceeded => "orçamento de inspeção esgotado (BudgetExceeded)",
        _ => "Inspeção WAF completa obrigatória nesta rota",
    }
}

fn outcome_detail(outcome: InspectionOutcome) -> &'static str {
    match outcome {
        InspectionOutcome::ParseError => "ParseError",
        InspectionOutcome::TimedOut => "TimedOut",
        InspectionOutcome::BudgetExceeded => "BudgetExceeded",
        other => other.as_str(),
    }
}

fn on_body_read_timeout(client_addr: &str, uri: &str, site_scope: &str) -> InspectionOutcome {
    let outcome = InspectionOutcome::TimedOut;
    record_inspection_outcome(outcome, client_addr, uri, true, site_scope);
    outcome
}

fn record_inspection_outcome(
    outcome: InspectionOutcome,
    client_addr: &str,
    uri: &str,
    denied: bool,
    site_scope: &str,
) {
    metrics::record_waf_inspection(outcome.as_str());
    if outcome.is_complete() {
        return;
    }
    let detail = outcome_detail(outcome);
    if denied {
        match outcome {
            InspectionOutcome::TimedOut | InspectionOutcome::BudgetExceeded => {
                metrics::record_observation_in(
                    site_scope,
                    outcome.event_type(),
                    client_addr,
                    uri,
                    detail,
                );
            }
            _ => {
                metrics::record_block_in(
                    site_scope,
                    outcome.event_type(),
                    client_addr,
                    uri,
                    detail,
                );
            }
        }
        return;
    }
    // Truncated/unsupported on an open route already warn; do not fill the
    // event ring with every upload that merely exceeds the inspect window.
    if matches!(outcome, InspectionOutcome::ParseError) {
        metrics::record_observation_in(site_scope, outcome.event_type(), client_addr, uri, detail);
    }
}

fn http11_request_head(req: &RequestHeader) -> Vec<u8> {
    let path = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut out = format!("{} {path} HTTP/1.1\r\n", req.method).into_bytes();
    for (name, value) in req.headers.iter() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn origin_roundtrip_blocking(
    addr: std::net::SocketAddr,
    tls_sni: Option<String>,
    head: &[u8],
    body: &[u8],
    max_response: usize,
) -> std::io::Result<(ResponseHeader, Vec<u8>)> {
    let tcp = std::net::TcpStream::connect_timeout(&addr, *UPSTREAM_CONNECT_TIMEOUT)?;
    tcp.set_read_timeout(Some(*UPSTREAM_READ_TIMEOUT))?;
    tcp.set_write_timeout(Some(*UPSTREAM_WRITE_TIMEOUT))?;
    tcp.set_nodelay(true)?;
    if let Some(sni) = tls_sni {
        let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if let Some(ca) = openssl_probe::probe().cert_file {
            let _ = builder.set_ca_file(ca);
        }
        let connector = builder.build();
        let mut tls = connector
            .connect(&sni, tcp)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        tls.write_all(head)?;
        tls.write_all(body)?;
        tls.flush()?;
        read_http11_response_sync(&mut tls, max_response)
    } else {
        let mut stream = tcp;
        stream.write_all(head)?;
        stream.write_all(body)?;
        stream.flush()?;
        read_http11_response_sync(&mut stream, max_response)
    }
}

fn read_http11_response_sync<S: Read>(
    stream: &mut S,
    max_response: usize,
) -> std::io::Result<(ResponseHeader, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end;
    loop {
        let read = stream.read(&mut tmp)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "origin closed before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "origin headers too large",
            ));
        }
    }
    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        .to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);
    let mut resp = ResponseHeader::build(status, None)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            if line.is_empty() {
                return None;
            }
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        let _ = resp.append_header(name, value);
    }
    let mut body = buf[header_end..].to_vec();
    if chunked {
        read_capped(stream, &mut body, max_response)?;
        body = match decode_chunked(&body) {
            Some(decoded) => decoded,
            None if body.len() >= max_response => body,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "origin chunked body is incomplete",
                ));
            }
        };
    } else if let Some(cl) = content_length {
        read_capped(stream, &mut body, cl.min(max_response))?;
    } else {
        read_capped(stream, &mut body, max_response)?;
    }
    resp.remove_header("Transfer-Encoding");
    Ok((resp, body))
}

fn read_capped<S: Read>(stream: &mut S, body: &mut Vec<u8>, cap: usize) -> std::io::Result<()> {
    let mut tmp = [0u8; 8192];
    while body.len() < cap {
        let read = stream.read(&mut tmp)?;
        if read == 0 {
            break;
        }
        let take = (cap - body.len()).min(read);
        body.extend_from_slice(&tmp[..take]);
    }
    Ok(())
}

fn decode_chunked(input: &[u8]) -> Option<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    loop {
        let line_end = input[index..]
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let size_line = std::str::from_utf8(&input[index..index + line_end]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        index += line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if index + size + 2 > input.len() {
            return None;
        }
        out.extend_from_slice(&input[index..index + size]);
        if &input[index + size..index + size + 2] != b"\r\n" {
            return None;
        }
        index += size + 2;
    }
}

fn response_content_length(response: &ResponseHeader) -> Option<usize> {
    response
        .headers
        .get("Content-Length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginSecretConfig {
    header: String,
    value: Option<String>,
}

impl Default for OriginSecretConfig {
    fn default() -> Self {
        Self {
            header: "X-Ferroada-Origin".to_string(),
            value: None,
        }
    }
}

pub fn parse_origin_secret(
    header: Option<&str>,
    secret: Option<&str>,
) -> Result<OriginSecretConfig, String> {
    let value = secret
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string);
    if let Some(raw) = value.as_deref() {
        if !is_safe_header_value(raw) {
            return Err("ORIGIN_SECRET inválido".into());
        }
    }
    let named = header.map(str::trim).filter(|item| !item.is_empty());
    let header = match named {
        None => "X-Ferroada-Origin".to_string(),
        Some(name) => {
            if !is_http_token(name) || is_reserved_upstream_header(name) {
                return Err("ORIGIN_SECRET_HEADER inválido: nome de header HTTP recusado".into());
            }
            name.to_string()
        }
    };
    Ok(OriginSecretConfig { header, value })
}

fn is_reserved_upstream_header(name: &str) -> bool {
    [
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "x-real-ip",
        "x-forwarded-for",
        "x-forwarded-proto",
    ]
    .iter()
    .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn is_http_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
}

fn is_safe_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn origin_secret_from_env() -> OriginSecretConfig {
    parse_origin_secret(
        std::env::var("ORIGIN_SECRET_HEADER").ok().as_deref(),
        std::env::var("ORIGIN_SECRET").ok().as_deref(),
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

fn apply_origin_secret(request: &mut RequestHeader, config: &OriginSecretConfig) {
    request.remove_header("X-Ferroada-Origin");
    request.remove_header(config.header.as_str());
    if let Some(value) = &config.value {
        let _ = request.insert_header(config.header.clone(), value.clone());
    }
}

fn stamp_upstream_request(
    upstream_request: &mut RequestHeader,
    ctx: &FerroadaCtx,
    origin_secret: &OriginSecretConfig,
) {
    let backend = ctx.backend.as_ref().expect("backend must be resolved");
    strip_hop_by_hop_headers(upstream_request);
    strip_untrusted_forwarding_headers(upstream_request);
    upstream_request
        .insert_header("Host", &backend.host)
        .unwrap();
    upstream_request
        .insert_header("X-Real-IP", &ctx.client_addr)
        .unwrap();
    upstream_request
        .insert_header("X-Forwarded-For", &ctx.client_addr)
        .unwrap();
    upstream_request
        .insert_header(
            "X-Forwarded-Proto",
            if ctx.request_https { "https" } else { "http" },
        )
        .unwrap();
    if upstream_request.headers.contains_key("Range") {
        upstream_request.remove_header("Range");
        upstream_request.remove_header("If-Range");
        metrics::record_observation(
            "range_removed",
            &ctx.client_addr,
            &ctx.request_uri,
            "Range removed so DLP can inspect the complete representation",
        );
    }
    apply_origin_secret(upstream_request, origin_secret);
}

fn strip_hop_by_hop_headers(request: &mut RequestHeader) {
    let connection_values: Vec<String> = request
        .headers
        .get_all("Connection")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    for name in shield::connection_hop_by_hop_names(connection_values.iter().map(String::as_str)) {
        request.remove_header(name.as_str());
    }
    request.remove_header("Connection");
}

fn strip_untrusted_forwarding_headers(request: &mut RequestHeader) {
    for header in [
        "Forwarded",
        "X-Forwarded-Host",
        "X-Forwarded-Port",
        "X-Forwarded-Ssl",
        "X-Forwarded-Server",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Ferroada-Origin",
    ] {
        request.remove_header(header);
    }
}

impl FerroadaProxy {
    async fn replay_spool_to_origin(
        &self,
        session: &mut Session,
        ctx: &mut FerroadaCtx,
    ) -> Result<bool> {
        let body = match ctx.spool.as_mut() {
            Some(spool) => match spool.inspect_bytes().await {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => {
                    metrics::record_block(
                        "spool_limit",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "Spool replay read failed",
                    );
                    return self.send_503(session).await;
                }
            },
            None => Vec::new(),
        };
        self.commit_origin_response(session, ctx, body).await
    }

    async fn commit_origin_response(
        &self,
        session: &mut Session,
        ctx: &mut FerroadaCtx,
        body: Vec<u8>,
    ) -> Result<bool> {
        let backend = ctx
            .backend
            .as_ref()
            .expect("backend must be resolved")
            .clone();
        let mut req = session.req_header().clone();
        stamp_upstream_request(&mut req, ctx, &self.origin_secret);
        req.remove_header("Transfer-Encoding");
        req.insert_header("Content-Length", body.len().to_string())?;
        let head = http11_request_head(&req);
        let addr = backend.addr;
        let tls_sni = backend.tls.then_some(backend.host.clone());
        let max_response = *MAX_RESPONSE_BUFFER;
        let roundtrip = tokio::task::spawn_blocking(move || {
            origin_roundtrip_blocking(addr, tls_sni, &head, &body, max_response)
        })
        .await;
        let (mut resp, origin_body) = match roundtrip {
            Ok(Ok(parsed)) => parsed,
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "origin roundtrip failed");
                return self.send_503(session).await;
            }
            Err(error) => {
                tracing::warn!(error = %error, "origin roundtrip task failed");
                return self.send_503(session).await;
            }
        };
        let declared_len = response_content_length(&resp);
        if let Err(error) = self.decorate_origin_response(&mut resp, ctx) {
            if matches!(error.etype(), ErrorType::HTTPStatus(502)) {
                return self.send_502(session).await;
            }
            return Err(error);
        }

        let truncated = declared_len.is_some_and(|cl| cl > origin_body.len())
            || (declared_len.is_none() && origin_body.len() >= max_response);
        if self.dlp_action.reject_incomplete_response() && truncated {
            metrics::record_block(
                "dlp_partial_block",
                &ctx.client_addr,
                &ctx.request_uri,
                "DLP buffer limit reached",
            );
            return self.send_502(session).await;
        }
        let out_bytes = if ctx.skip_dlp {
            Bytes::from(origin_body)
        } else {
            let result = dlp::sanitize_encoded_body_with(
                &origin_body,
                ctx.content_type.as_deref(),
                ctx.response_content_encoding.as_deref(),
                *MAX_RESPONSE_BUFFER,
                self.dlp_action,
            );
            if self.dlp_action.reject_incomplete_response()
                && (!result.inspection_complete || result.found_sensitive())
            {
                metrics::record_block(
                    "dlp_partial_block",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    "DLP buffer limit reached",
                );
                return self.send_502(session).await;
            }
            if !result.inspection_complete {
                metrics::record_observation(
                    "dlp_skip",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    "Compressed response could not be inspected within the configured limit",
                );
            }
            result.bytes
        };
        resp.insert_header("Content-Length", out_bytes.len().to_string())?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(out_bytes), true).await?;
        Ok(true)
    }

    fn decorate_origin_response(
        &self,
        upstream_response: &mut ResponseHeader,
        ctx: &mut FerroadaCtx,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if matches!(status, 401 | 403 | 404) {
            if let Some(identity) = ctx.risk_identity.as_ref() {
                behavioral::record_response(identity, status);
            }
        }
        ctx.content_type = upstream_response
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        ctx.response_content_encoding = upstream_response
            .headers
            .get("Content-Encoding")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        let signed_response = upstream_response.headers.contains_key("Signature")
            || upstream_response.headers.contains_key("Signature-Input")
            || upstream_response.headers.contains_key("Content-Signature");
        let partial_response =
            status == 206 || upstream_response.headers.contains_key("Content-Range");
        let upgraded_response = status == 101 || upstream_response.headers.contains_key("Upgrade");
        let dlp_skip_reason = if signed_response {
            Some("Signed response was not transformed")
        } else if upgraded_response {
            Some("Upgraded response was not transformed")
        } else {
            dlp::skip_reason(
                ctx.content_type.as_deref(),
                ctx.response_content_encoding.as_deref(),
            )
        };
        let dlp_capable = dlp_skip_reason.is_none();
        if dlp_capable && self.dlp_action.reject_incomplete_response() {
            if let Some(cl) = response_content_length(upstream_response) {
                if cl > *MAX_RESPONSE_BUFFER {
                    metrics::record_block(
                        "dlp_partial_block",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "DLP buffer limit reached",
                    );
                    return Error::e_explain(
                        ErrorType::HTTPStatus(502),
                        "DLP buffer limit reached",
                    );
                }
            }
        }
        if partial_response && dlp_capable {
            metrics::record_block(
                "dlp_partial_block",
                &ctx.client_addr,
                &ctx.request_uri,
                "Textual partial response cannot be inspected safely",
            );
            return Error::e_explain(
                ErrorType::HTTPStatus(502),
                "textual partial response rejected by DLP",
            );
        }
        ctx.skip_dlp = dlp_skip_reason.is_some();

        if !ctx.skip_dlp {
            upstream_response.remove_header("Content-Length");
            upstream_response.remove_header("ETag");
            upstream_response.remove_header("Content-MD5");
            upstream_response.remove_header("Digest");
            upstream_response.remove_header("Content-Digest");
            upstream_response.remove_header("Repr-Digest");
        } else if let Some(reason) = dlp_skip_reason {
            metrics::record_observation("dlp_skip", &ctx.client_addr, &ctx.request_uri, reason);
        }

        headers::strip_server_headers(upstream_response);
        headers::apply_security_headers(upstream_response);
        Ok(())
    }

    async fn send_429(
        &self,
        session: &mut Session,
        reason: &str,
        retry_after: u64,
    ) -> Result<bool> {
        let body = format!("429 Muitas requisições: {reason}\n");
        let mut header = ResponseHeader::build(429, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Retry-After", retry_after.to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_400(&self, session: &mut Session, reason: &str) -> Result<bool> {
        session.set_keepalive(None);
        let body = format!("400 Requisição inválida: {reason}\n");
        let mut header = ResponseHeader::build(400, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn apply_jwt_identity(
        &self,
        session: &mut Session,
        ctx: &mut FerroadaCtx,
        uri: &str,
    ) -> Result<bool> {
        let Some(policy) = ctx
            .backend
            .as_ref()
            .and_then(|backend| backend.jwt.clone())
        else {
            return Ok(false);
        };
        let authorization = session
            .req_header()
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok());
        match policy.authenticate(authorization, jwt::unix_now()) {
            Ok(principal) => {
                let path = uri.split('?').next().unwrap_or(uri);
                let extra = ctx
                    .backend
                    .as_ref()
                    .and_then(|backend| backend.openapi.as_ref())
                    .map(|spec| spec.path_params(path))
                    .unwrap_or_default();
                if let Err(failure) = policy.bind_path(&principal, path, &extra) {
                    return self.reject_jwt(session, ctx, uri, failure).await;
                }
                ctx.jwt = Some(principal);
                Ok(false)
            }
            Err(failure) => self.reject_jwt(session, ctx, uri, failure).await,
        }
    }

    async fn apply_jwt_body(
        &self,
        session: &mut Session,
        ctx: &FerroadaCtx,
        body: &[u8],
    ) -> Result<bool> {
        let Some(policy) = ctx
            .backend
            .as_ref()
            .and_then(|backend| backend.jwt.as_ref())
        else {
            return Ok(false);
        };
        if !policy.has_body_bindings() {
            return Ok(false);
        }
        let Some(principal) = ctx.jwt.as_ref() else {
            return Ok(false);
        };
        match policy.bind_body(principal, body) {
            Ok(()) => Ok(false),
            Err(failure) => self.reject_jwt(session, ctx, &ctx.request_uri, failure).await,
        }
    }

    async fn reject_jwt(
        &self,
        session: &mut Session,
        ctx: &FerroadaCtx,
        uri: &str,
        failure: JwtFailure,
    ) -> Result<bool> {
        metrics::record_block_in(
            &ctx.site_scope,
            failure.event_type(),
            &ctx.client_addr,
            uri,
            failure.reason(),
        );
        match failure {
            JwtFailure::Unauthorized(_) => {
                self.send_401(session, "token inválido ou ausente").await
            }
            JwtFailure::Forbidden(_) => {
                self.send_403(session, "identidade não corresponde ao recurso")
                    .await
            }
        }
    }

    async fn apply_openapi_envelope(
        &self,
        session: &mut Session,
        ctx: &mut FerroadaCtx,
        method: &str,
        uri: &str,
    ) -> Result<bool> {
        let Some(policy) = ctx
            .backend
            .as_ref()
            .and_then(|backend| backend.openapi.as_ref())
        else {
            return Ok(false);
        };
        let path = uri.split('?').next().unwrap_or(uri);
        let query = uri.split_once('?').map(|(_, query)| query);
        let headers = request_header_pairs(session);
        match policy.validate_envelope(
            method,
            path,
            query,
            &headers,
            ctx.request_content_type.as_deref(),
            ctx.inspection_policy.require_complete,
        ) {
            EnvelopeVerdict::Allow(matched) => {
                ctx.openapi_match = Some(matched);
                Ok(false)
            }
            EnvelopeVerdict::Observe { detail } => {
                metrics::record_observation_in(
                    &ctx.site_scope,
                    "openapi_observe",
                    &ctx.client_addr,
                    uri,
                    &detail,
                );
                Ok(false)
            }
            EnvelopeVerdict::Deny { detail } => {
                metrics::record_block_in(
                    &ctx.site_scope,
                    "openapi",
                    &ctx.client_addr,
                    uri,
                    &detail,
                );
                self.send_403(session, "requisição fora do contrato OpenAPI")
                    .await
            }
        }
    }

    async fn apply_openapi_body(
        &self,
        session: &mut Session,
        ctx: &FerroadaCtx,
        body: &[u8],
    ) -> Result<bool> {
        let Some(matched) = ctx.openapi_match.as_ref() else {
            return Ok(false);
        };
        match matched.validate_body(ctx.request_content_type.as_deref(), body) {
            BodyVerdict::Allow => Ok(false),
            BodyVerdict::Deny { detail } => {
                metrics::record_block_in(
                    &ctx.site_scope,
                    "openapi",
                    &ctx.client_addr,
                    &ctx.request_uri,
                    &detail,
                );
                self.send_403(session, "requisição fora do contrato OpenAPI")
                    .await
            }
        }
    }

    async fn apply_l1(
        &self,
        session: &mut Session,
        ctx: &FerroadaCtx,
        method: &str,
        uri: &str,
        body: &[u8],
        body_is_decoded: bool,
    ) -> Result<bool> {
        // bypass-explicit (websocket, etc.) already skipped L0 body; L1 is
        // not a way around that protocol action.
        if ctx.skip_body_waf || !self.waf_engine.is_coraza() {
            return Ok(false);
        }
        let Some(backend) = ctx.backend.as_ref() else {
            return Ok(false);
        };
        let l1 = backend.l1_for(uri, ctx.request_content_type.as_deref());
        if l1.skip {
            return Ok(false);
        }
        let inspect_uri = waf_l1::strip_query_params(uri, &l1.exclude_parameters);
        let inspect_body = waf_l1::strip_excluded_body(
            body,
            ctx.request_content_type.as_deref(),
            &l1.exclude_parameters,
        );
        let headers = l1_header_pairs(session, &inspect_body, body_is_decoded);
        let verdict = self
            .waf_engine
            .inspect(&InspectRequest {
                method,
                uri: &inspect_uri,
                protocol: http_version_token(session.req_header().version),
                headers: &headers,
                body: &inspect_body,
                client_ip: &ctx.client_addr,
                policy: l1.settings,
                exclude_parameters: &l1.exclude_parameters,
            })
            .await;
        match verdict {
            L1Verdict::Skipped => Ok(false),
            L1Verdict::Allow { rule_ids, score } => {
                if l1.settings.shadow && !rule_ids.is_empty() {
                    let detail = waf_engine::l1_detail(&rule_ids, "", score);
                    metrics::record_l1_shadow(&ctx.site_scope, &ctx.client_addr, uri, &detail);
                }
                Ok(false)
            }
            L1Verdict::Block {
                rule_ids,
                message,
                score,
            } => {
                let detail = waf_engine::l1_detail(&rule_ids, &message, score);
                if l1.settings.shadow {
                    metrics::record_l1_shadow(&ctx.site_scope, &ctx.client_addr, uri, &detail);
                    return Ok(false);
                }
                metrics::record_block_in(&ctx.site_scope, "waf_l1", &ctx.client_addr, uri, &detail);
                if let Some(identity) = ctx.risk_identity.as_ref() {
                    behavioral::record_waf_block(identity);
                }
                self.send_403(session, &detail).await
            }
            L1Verdict::Unavailable => {
                waf_engine::record_unavailable(&ctx.site_scope, &ctx.client_addr, uri, "TimedOut");
                let outcome = InspectionOutcome::TimedOut;
                match ctx.inspection_policy.disposition(outcome) {
                    InspectionDisposition::Deny => {
                        record_inspection_outcome(
                            outcome,
                            &ctx.client_addr,
                            uri,
                            true,
                            &ctx.site_scope,
                        );
                        if let Some(identity) = ctx.risk_identity.as_ref() {
                            behavioral::record_waf_block(identity);
                        }
                        self.send_403(session, incomplete_inspection_reason(outcome))
                            .await
                    }
                    InspectionDisposition::Monitor => {
                        record_inspection_outcome(
                            outcome,
                            &ctx.client_addr,
                            uri,
                            false,
                            &ctx.site_scope,
                        );
                        Ok(false)
                    }
                    InspectionDisposition::Allow => Ok(false),
                }
            }
        }
    }

    async fn send_413(
        &self,
        session: &mut Session,
        uri: &str,
        client_addr: &str,
        max_body: usize,
        site_scope: &str,
    ) -> Result<bool> {
        metrics::record_block_in(
            site_scope,
            "size_limit",
            client_addr,
            uri,
            &format!("Body size > max {max_body}"),
        );
        let body = "413 Corpo da requisição muito grande\n";
        let mut header = ResponseHeader::build(413, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_body_timeout(&self, session: &mut Session, ctx: &FerroadaCtx) -> Result<bool> {
        let outcome = on_body_read_timeout(&ctx.client_addr, &ctx.request_uri, &ctx.site_scope);
        self.send_408(session, outcome.denied_status()).await
    }

    async fn send_408(&self, session: &mut Session, status: u16) -> Result<bool> {
        let body = format!("{status} Tempo esgotado ao ler a requisição\n");
        let mut header = ResponseHeader::build(status, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_401(&self, session: &mut Session, reason: &str) -> Result<bool> {
        let body = format!("401 Não autorizado: {reason}\n");
        let mut header = ResponseHeader::build(401, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("WWW-Authenticate", "Bearer")?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_403(&self, session: &mut Session, reason: &str) -> Result<bool> {
        let body = format!("403 Proibido: {reason}\n");
        let mut header = ResponseHeader::build(403, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_431(&self, session: &mut Session) -> Result<bool> {
        let body = "431 Headers da requisição muito grandes\n";
        let mut header = ResponseHeader::build(431, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_502(&self, session: &mut Session) -> Result<bool> {
        let body = "502 Resposta bloqueada pelo DLP\n";
        let mut header = ResponseHeader::build(502, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn send_503(&self, session: &mut Session) -> Result<bool> {
        let body = "503 Serviço temporariamente sobrecarregado\n";
        let mut header = ResponseHeader::build(503, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Retry-After", "1")?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_headers_drop_content_encoding_after_inflate() {
        let headers = vec![
            ("host".to_string(), "api.example".to_string()),
            ("content-encoding".to_string(), "gzip".to_string()),
            ("content-length".to_string(), "40".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let adjusted = adjust_l1_headers(headers, 12, true);
        assert!(
            !adjusted
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding")),
            "{adjusted:?}"
        );
        let length = adjusted
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.as_str());
        assert_eq!(length, Some("12"));
        assert!(adjusted.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == "application/json"
        }));
        let untouched = adjust_l1_headers(
            vec![("content-encoding".to_string(), "gzip".to_string())],
            12,
            false,
        );
        assert_eq!(untouched.len(), 1);
    }

    #[test]
    fn body_timeout_records_timed_out_and_is_408() {
        let outcome = on_body_read_timeout("192.0.2.9", "/slow", "timeout.example");
        assert_eq!(outcome, InspectionOutcome::TimedOut);
        assert_eq!(outcome.denied_status(), 408);
        assert_ne!(outcome.denied_status(), 403);
        let snapshot = metrics::snapshot_json();
        assert!(snapshot.contains("inspection_timeout"), "{snapshot}");
        assert!(snapshot.contains("TimedOut"), "{snapshot}");
        let prometheus = metrics::snapshot_prometheus();
        assert!(prometheus.contains("ferroada_waf_inspection_total{status=\"timed_out\"}"));
    }

    #[test]
    fn garbage_json_fail_closed_reason_names_parse_error() {
        assert_eq!(
            incomplete_inspection_reason(InspectionOutcome::ParseError),
            "JSON inválido (ParseError)"
        );
        assert_eq!(InspectionOutcome::ParseError.denied_status(), 403);
        record_inspection_outcome(
            InspectionOutcome::ParseError,
            "192.0.2.10",
            "/api/payment",
            true,
            "api.example",
        );
        let snapshot = metrics::snapshot_json();
        assert!(snapshot.contains("\"event_type\": \"inspection_parse_error\""));
        assert!(snapshot.contains("ParseError"));
        assert!(snapshot.contains("\"inspection_parse_error\":"));
        let prometheus = metrics::snapshot_prometheus();
        assert!(prometheus.contains("ferroada_waf_inspection_total{status=\"parse_error\"}"));
        assert!(prometheus.contains("ferroada_blocks_total{type=\"inspection_parse_error\"}"));
    }

    #[test]
    fn raw_framing_headers_preserve_cl_te_ambiguity() {
        let raw = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(raw_framing_header_counts(raw), (1, 1));

        let duplicate_te = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(raw_framing_header_counts(duplicate_te), (0, 2));
    }

    #[test]
    fn request_budget_reserves_local_replay_and_inflate_buffers() {
        assert_eq!(request_inspection_reservation(Some(32), 64, None), Some(64));
        assert_eq!(request_inspection_reservation(None, 64, None), Some(128));
        assert_eq!(
            request_inspection_reservation(Some(32), 64, Some("gzip")),
            Some(64 + waf::max_inflate_buffer_bytes())
        );
    }

    #[test]
    fn decode_chunked_reads_two_chunks() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw).unwrap(), b"hello world");
        assert!(decode_chunked(b"5\r\nhel").is_none());
    }

    #[test]
    fn spool_reservation_is_one_copy_plus_inflate_not_replay_double() {
        assert_eq!(spool_inspection_reservation(Some(32), 64, None), Some(32));
        assert_eq!(spool_inspection_reservation(None, 64, None), Some(64));
        assert_eq!(
            spool_inspection_reservation(Some(32), 64, Some("gzip")),
            Some(32 + waf::inflate_buffer_bytes(64))
        );
    }

    #[test]
    fn concurrency_limit_sheds_load_and_recovers_after_release() {
        let state = Arc::new(ConcurrencyState {
            current: AtomicUsize::new(0),
            max: 1,
        });
        let guard = state.acquire().expect("first request is admitted");
        assert!(state.acquire().is_none());
        drop(guard);
        assert!(state.acquire().is_some());
    }

    #[test]
    fn byte_budget_never_exceeds_limit_and_recovers_after_release() {
        let budget = ByteBudget {
            current: AtomicUsize::new(0),
            max: 10,
        };
        assert!(budget.reserve(7));
        assert!(!budget.reserve(4));
        budget.release(7);
        assert!(budget.reserve(10));
    }

    #[test]
    fn bounded_body_buffer_preserves_chunks_and_rejects_overflow() {
        let mut buffer = BoundedBodyBuffer::new(5);
        assert!(buffer.push(b"ab"));
        assert!(buffer.push(b"cde"));
        assert!(!buffer.push(b"f"));
        assert_eq!(buffer.as_slice(), b"abcde");
    }

    #[test]
    fn connection_named_hop_by_hop_headers_are_removed() {
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("Host", "example.test").unwrap();
        request
            .insert_header("Connection", "close, X-Evil")
            .unwrap();
        request.insert_header("X-Evil", "injected").unwrap();
        request.insert_header("X-Keep", "yes").unwrap();

        strip_hop_by_hop_headers(&mut request);

        assert!(!request.headers.contains_key("Connection"));
        assert!(!request.headers.contains_key("X-Evil"));
        assert_eq!(
            request.headers.get("X-Keep").and_then(|v| v.to_str().ok()),
            Some("yes")
        );
        assert_eq!(
            request.headers.get("Host").and_then(|v| v.to_str().ok()),
            Some("example.test")
        );
    }

    #[test]
    fn client_controlled_forwarding_headers_are_removed() {
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("Forwarded", "for=127.0.0.1;proto=https")
            .unwrap();
        request
            .insert_header("X-Forwarded-Host", "admin.internal")
            .unwrap();
        request.insert_header("X-Forwarded-Ssl", "on").unwrap();

        strip_untrusted_forwarding_headers(&mut request);

        assert!(!request.headers.contains_key("Forwarded"));
        assert!(!request.headers.contains_key("X-Forwarded-Host"));
        assert!(!request.headers.contains_key("X-Forwarded-Ssl"));
    }

    #[test]
    fn origin_secret_unset_strips_client_header() {
        let cfg = parse_origin_secret(None, None).unwrap();
        assert!(cfg.value.is_none());
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("X-Ferroada-Origin", "forged")
            .unwrap();
        apply_origin_secret(&mut request, &cfg);
        assert!(!request.headers.contains_key("X-Ferroada-Origin"));
        assert!(parse_origin_secret(Some("X-Ferroada-Origin"), Some(""))
            .unwrap()
            .value
            .is_none());
    }

    #[test]
    fn origin_secret_defaults_header_name_and_replaces_client_value() {
        let cfg = parse_origin_secret(None, Some("s3cret")).unwrap();
        assert_eq!(cfg.header, "X-Ferroada-Origin");
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("X-Ferroada-Origin", "forged")
            .unwrap();
        apply_origin_secret(&mut request, &cfg);
        assert_eq!(
            request
                .headers
                .get("X-Ferroada-Origin")
                .and_then(|value| value.to_str().ok()),
            Some("s3cret")
        );
    }

    #[test]
    fn origin_secret_rejects_control_chars_in_header_name() {
        assert!(parse_origin_secret(Some("X-Evil\r\nX-Other"), Some("s")).is_err());
        assert!(parse_origin_secret(Some("X-Bad:Name"), Some("s")).is_err());
        assert!(parse_origin_secret(Some("Host"), Some("s")).is_err());
        assert!(parse_origin_secret(Some("X-Forwarded-For"), Some("s")).is_err());
        assert!(parse_origin_secret(None, Some("bad\r\nvalue")).is_err());
    }
}
