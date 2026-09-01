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
use crate::client_ip::{RiskIdentity, TrustedProxies};
use crate::config::Config;
use crate::dlp;
use crate::headers;
use crate::metrics;
use crate::rate_limit::RateLimiter;
use crate::shield::{self, ShieldVerdict};
use crate::waf::{self, WafVerdict};

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
    let reserves_inflated_body = content_encoding.is_some_and(|encoding| {
        matches!(
            encoding.trim().to_ascii_lowercase().as_str(),
            "gzip" | "x-gzip" | "deflate"
        )
    });
    if reserves_inflated_body {
        bytes = bytes.checked_add(waf::max_inflate_buffer_bytes())?;
    }
    Some(bytes)
}

pub struct FerroadaProxy {
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
    pub trusted_proxies: TrustedProxies,
    concurrency: Arc<ConcurrencyState>,
    dlp_budget: Arc<ByteBudget>,
    request_budget: Arc<ByteBudget>,
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
    ) -> Self {
        Self {
            config,
            rate_limiter,
            trusted_proxies,
            concurrency: Arc::new(ConcurrencyState::from_env()),
            dlp_budget: Arc::new(ByteBudget::from_env(
                "DLP_MAX_IN_FLIGHT_BYTES",
                64 * 1024 * 1024,
            )),
            request_budget: Arc::new(ByteBudget::from_env(
                "WAF_MAX_IN_FLIGHT_BYTES",
                64 * 1024 * 1024,
            )),
        }
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
    pub inspect_request_body: bool,
    pub request_https: bool,
    pub backend: Option<crate::config::Backend>,
    pub risk_identity: Option<RiskIdentity>,
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
            inspect_request_body: false,
            request_https: false,
            backend: None,
            risk_identity: None,
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
        let peer_is_trusted = socket_ip
            .map(|ip| self.trusted_proxies.is_trusted(ip))
            .unwrap_or(false);
        let forwarded_for = session
            .req_header()
            .headers
            .get("X-Forwarded-For")
            .and_then(|value| value.to_str().ok());
        let client_addr = self
            .trusted_proxies
            .resolve(socket_ip, forwarded_for)
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
                metrics::record_block(
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
            metrics::record_block(
                "https_redirect",
                &client_addr,
                &uri,
                "redirecionamento HTTP→HTTPS",
            );
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
        ctx.risk_identity = parse_ip(&client_addr)
            .map(|ip| RiskIdentity::new(&site, ip, &uri, session_id, api_key));

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
            shield::check_smuggling(has_cl, cl_count, te_count, te, &uri, &client_addr),
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
            shield::check_user_agent(ua, &uri, &client_addr),
            ShieldVerdict::BlockBadBot
        ) {
            return self
                .send_403(session, "Bloqueado: identificação de cliente suspeita")
                .await;
        }

        // Method restriction check
        let method = session.req_header().method.as_str().to_string();
        if matches!(
            shield::check_method(&method, &uri, &client_addr),
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
            shield::check_uri_length(&uri, &client_addr),
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

        // Body size check (via Content-Length header)
        let content_length = session
            .req_header()
            .headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        if let Some(cl) = content_length {
            if matches!(
                shield::check_body_size(cl, &uri, &client_addr),
                ShieldVerdict::BlockBodySize
            ) {
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
                return Ok(true);
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

        // WAF inspection on URI + headers
        let header_values: Vec<String> = session
            .req_header()
            .headers
            .values()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        let waf_profile = ctx.backend.as_ref().expect("backend resolved").waf_profile;
        match waf::inspect_request_with_profile(&uri, &header_values, &client_addr, waf_profile) {
            WafVerdict::Allow => {}
            WafVerdict::Block(reason) => {
                if let Some(identity) = ctx.risk_identity.as_ref() {
                    behavioral::record_waf_block(identity);
                }
                return self.send_403(session, &reason).await;
            }
        }

        // Read and approve the complete body before Pingora opens the upstream.
        // Pingora's retry buffer replays the approved bytes afterwards.
        if !session.as_mut().is_body_empty() {
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
            session.set_read_timeout(Some(*BODY_READ_TIMEOUT));

            let reservation = request_inspection_reservation(
                content_length,
                shield::max_body_size(),
                ctx.request_content_encoding.as_deref(),
            )
            .unwrap_or(usize::MAX);
            if !ctx.reserve_request(reservation) {
                metrics::record_block(
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

            session.as_downstream_mut().enable_retry_buffering();
            let deadline = Instant::now() + *BODY_READ_TIMEOUT;
            loop {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return self.send_408(session).await;
                };
                let next = tokio::time::timeout(
                    remaining,
                    session.as_downstream_mut().read_request_body(),
                )
                .await;
                let chunk = match next {
                    Ok(result) => result?,
                    Err(_) => return self.send_408(session).await,
                };
                let Some(chunk) = chunk else {
                    break;
                };

                if !ctx.request_body.push(&chunk) {
                    return self
                        .send_413(session, &ctx.request_uri, &ctx.client_addr)
                        .await;
                }
            }

            if ctx.request_body.is_empty() {
                let request = session.as_downstream_mut().req_header_mut();
                request.remove_header("Transfer-Encoding");
                request.insert_header("Content-Length", "0")?;
            } else {
                let replay_matches = session
                    .as_downstream()
                    .get_retry_buffer()
                    .is_some_and(|buffer| buffer.as_ref() == ctx.request_body.as_slice());
                if !replay_matches {
                    metrics::record_block(
                        "request_buffer_limit",
                        &ctx.client_addr,
                        &ctx.request_uri,
                        "Pingora request replay buffer was incomplete",
                    );
                    return self.send_503(session).await;
                }
            }

            let inspect_body = waf::inflate_for_inspect(
                ctx.request_body.as_slice(),
                ctx.request_content_encoding.as_deref(),
            );
            let inspection = waf::inspect_body(
                &inspect_body.bytes,
                &ctx.request_uri,
                &ctx.client_addr,
                ctx.request_content_type.as_deref(),
            );
            let inspection_status = inspect_body.status.combine(inspection.status);
            metrics::record_waf_inspection(inspection_status.as_str());
            match inspection.verdict {
                WafVerdict::Allow => {
                    let require_complete = ctx
                        .backend
                        .as_ref()
                        .map(|backend| backend.requires_complete_waf_inspection(&ctx.request_uri))
                        .unwrap_or(false);
                    if require_complete && !inspection_status.is_complete() {
                        metrics::record_block(
                            "waf_incomplete",
                            &ctx.client_addr,
                            &ctx.request_uri,
                            inspection_status.as_str(),
                        );
                        if let Some(identity) = ctx.risk_identity.as_ref() {
                            behavioral::record_waf_block(identity);
                        }
                        return self
                            .send_403(session, "Inspeção WAF completa obrigatória nesta rota")
                            .await;
                    }
                    if !inspection_status.is_complete() {
                        tracing::warn!(
                            client = %ctx.client_addr,
                            uri = %ctx.request_uri,
                            inspection_status = inspection_status.as_str(),
                            "Request body was not completely inspected"
                        );
                    }
                }
                WafVerdict::Block(reason) => {
                    if let Some(identity) = ctx.risk_identity.as_ref() {
                        behavioral::record_waf_block(identity);
                    }
                    return self.send_403(session, &reason).await;
                }
            }

            // Keep the global reservation until the request finishes: Pingora now
            // owns the replay copy even though our inspection copy can be dropped.
            ctx.inspect_request_body = !ctx.request_body.is_empty();
            let _ = ctx.request_body.take();
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
        if ctx.inspect_request_body {
            debug_assert!(end_of_stream, "pre-buffered bodies must be replayed at EOS");
            debug_assert!(body.is_some(), "approved body replay must contain bytes");
        }
        Ok(())
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
        let backend = ctx.backend.as_ref().expect("backend must be resolved");
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
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Behavioral scoring: track upstream response codes
        let status = upstream_response.status.as_u16();
        if matches!(status, 401 | 403 | 404) {
            if let Some(identity) = ctx.risk_identity.as_ref() {
                behavioral::record_response(identity, status);
            }
        }

        // Capture content-type for DLP (before modifying headers)
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

        // Strip headers that leak server/framework info
        headers::strip_server_headers(upstream_response);

        // Inject security hardening headers
        headers::apply_security_headers(upstream_response);

        Ok(())
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
                // Too large — flush what we have and skip DLP for the rest
                ctx.skip_dlp = true;
                let mut flushed = ctx.body_buffer.take();
                ctx.release_dlp();
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
            let result = dlp::sanitize_encoded_body(
                &buffered,
                ct,
                ctx.response_content_encoding.as_deref(),
                *MAX_RESPONSE_BUFFER,
            );
            ctx.release_dlp();
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
    ] {
        request.remove_header(header);
    }
}

impl FerroadaProxy {
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

    async fn send_413(&self, session: &mut Session, uri: &str, client_addr: &str) -> Result<bool> {
        metrics::record_block(
            "size_limit",
            client_addr,
            uri,
            &format!("Body size > max {}", shield::max_body_size()),
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

    async fn send_408(&self, session: &mut Session) -> Result<bool> {
        let body = "408 Tempo esgotado ao ler a requisição\n";
        let mut header = ResponseHeader::build(408, None)?;
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
}
