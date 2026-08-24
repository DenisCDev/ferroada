use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::{Error, ErrorType};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
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

use crate::behavioral::{self, BehavioralVerdict};
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

pub struct FerroadaProxy {
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
}

/// Max response body to buffer for DLP inspection (50MB).
/// Responses larger than this are passed through without DLP.
const MAX_RESPONSE_BUFFER: usize = 50 * 1024 * 1024;

pub struct FerroadaCtx {
    pub body_buffer: Vec<u8>,
    pub request_body: Vec<u8>,
    pub request_uri: String,
    pub client_addr: String,
    pub content_type: Option<String>,
    pub request_content_type: Option<String>,
    pub request_content_encoding: Option<String>,
    pub skip_dlp: bool,
    pub inspect_request_body: bool,
    pub backend: Option<crate::config::Backend>,
}

#[async_trait]
impl ProxyHttp for FerroadaProxy {
    type CTX = FerroadaCtx;

    fn new_ctx(&self) -> Self::CTX {
        FerroadaCtx {
            body_buffer: Vec::new(),
            request_body: Vec::new(),
            request_uri: String::new(),
            client_addr: String::new(),
            content_type: None,
            request_content_type: None,
            request_content_encoding: None,
            skip_dlp: false,
            inspect_request_body: false,
            backend: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        metrics::increment_requests();

        let uri = session
            .req_header()
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let client_addr = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Store in ctx for body filter
        ctx.request_uri = uri.clone();
        ctx.client_addr = client_addr.clone();

        // Behavioral scoring — check threat score before any processing
        if let Some(ip) = parse_ip(&client_addr) {
            let ua = session.req_header().headers.get("User-Agent")
                .and_then(|v| v.to_str().ok());
            match behavioral::check_and_record(ip, &uri, ua, &client_addr) {
                BehavioralVerdict::Block => {
                    return self.send_403(session, "Temporarily blocked: suspicious activity").await;
                }
                BehavioralVerdict::Throttle => {
                    return self.send_429(session, "Too many suspicious requests", 30).await;
                }
                BehavioralVerdict::Allow => {}
            }
        }

        // HTTPS enforcement: redirect HTTP → HTTPS when FORCE_HTTPS=true and TLS is configured
        let force_https = std::env::var("FORCE_HTTPS")
            .map(|v| v == "true")
            .unwrap_or(false);

        if force_https {
            // Detect plain HTTP via X-Forwarded-Proto or scheme.
            // On Pingora, requests arriving on the TLS listener have ssl_digest set.
            let digest = session.digest();
            let is_plain_http = digest
                .as_ref()
                .map(|d| d.ssl_digest.is_none())
                .unwrap_or(true);
            if is_plain_http {
                let host = session
                    .req_header()
                    .headers
                    .get("Host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("localhost");
                let location = format!("https://{}{}", host, uri);
                let body = "301 Moved Permanently\n";
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
                metrics::record_block("https_redirect", &client_addr, &uri, "HTTP→HTTPS redirect");
                return Ok(true);
            }
        }

        // Host header validation (DNS rebinding protection)
        let host_val = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref hv) = host_val {
            match shield::check_host(hv, &uri, &client_addr) {
                ShieldVerdict::BlockHost => {
                    let body = "421 Misdirected Request\n";
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
                _ => {}
            }
        }

        // Multi-site routing: resolve backend by Host header
        let host_for_resolve = host_val.as_deref().unwrap_or("");
        match self.config.resolve(host_for_resolve) {
            Some(backend) => {
                ctx.backend = Some(backend.clone());
            }
            None => {
                // No matching site and no default backend → 421
                let body = "421 Misdirected Request\n";
                let mut header = ResponseHeader::build(421, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;
                metrics::record_block("host", &client_addr, &uri, &format!("No site for host: {}", host_for_resolve));
                return Ok(true);
            }
        }

        // HTTP Request Smuggling detection
        let has_cl = session.req_header().headers.get("Content-Length").is_some();
        let cl_count = session.req_header().headers.get_all("Content-Length").iter().count();
        let te = session.req_header().headers.get("Transfer-Encoding")
            .and_then(|v| v.to_str().ok());
        match shield::check_smuggling(has_cl, cl_count, te, &uri, &client_addr) {
            ShieldVerdict::BlockSmuggling => {
                return self.send_400(session, "Bad Request: HTTP request smuggling detected").await;
            }
            _ => {}
        }

        // Bad Bot User-Agent check
        let ua = session.req_header().headers.get("User-Agent")
            .and_then(|v| v.to_str().ok()).unwrap_or("");
        match shield::check_user_agent(ua, &uri, &client_addr) {
            ShieldVerdict::BlockBadBot => {
                return self.send_403(session, "Blocked: suspicious user-agent").await;
            }
            _ => {}
        }

        // Method restriction check
        let method = session.req_header().method.as_str().to_string();
        match shield::check_method(&method, &uri, &client_addr) {
            ShieldVerdict::BlockMethod => {
                let body = "405 Method Not Allowed\n";
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
            _ => {}
        }

        // URI length check
        match shield::check_uri_length(&uri, &client_addr) {
            ShieldVerdict::BlockUriLength => {
                let body = "414 URI Too Long\n";
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
            _ => {}
        }

        // Body size check (via Content-Length header)
        if let Some(cl) = session
            .req_header()
            .headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
        {
            match shield::check_body_size(cl, &uri, &client_addr) {
                ShieldVerdict::BlockBodySize => {
                    let body = "413 Payload Too Large\n";
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
                _ => {}
            }
        }

        // Rate limiting check (before WAF to save CPU on floods)
        let ip = parse_ip(&client_addr);

        if let Some(ip) = ip {
            if !self.rate_limiter.check(ip, &uri) {
                let body = "429 Too Many Requests\n";
                let mut header = ResponseHeader::build(429, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                header.insert_header(
                    "Retry-After",
                    self.rate_limiter.window_secs().to_string(),
                )?;
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

        match waf::inspect_request(&uri, &header_values, &client_addr) {
            WafVerdict::Allow => {}
            WafVerdict::Block(reason) => {
                if let Some(ip) = parse_ip(&client_addr) {
                    behavioral::record_waf_block(ip);
                }
                return self.send_403(session, &reason).await;
            }
        }

        // Body inspection happens in request_body_filter so every Pingora chunk
        // is seen. Stealing the body here would leave the upstream with nothing:
        // Session has no write_request_body in pingora 0.8.
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            ctx.inspect_request_body = true;
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
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if !ctx.inspect_request_body {
            return Ok(());
        }

        if let Some(chunk) = body.take() {
            if shield::body_would_exceed(ctx.request_body.len(), chunk.len()) {
                self.send_413(session, &ctx.request_uri, &ctx.client_addr)
                    .await?;
                return Error::e_explain(
                    ErrorType::HTTPStatus(413),
                    "request body exceeded MAX_BODY_SIZE",
                );
            }
            ctx.request_body.extend_from_slice(&chunk);
        }

        if !end_of_stream {
            // Pingora 0.8 treats None as EOS (`end_of_body || data.is_none()`).
            // Some(empty) keeps the upstream stream open while we buffer.
            *body = hold_body_until_complete();
            return Ok(());
        }

        let inspect_bytes = waf::inflate_for_inspect(
            &ctx.request_body,
            ctx.request_content_encoding.as_deref(),
        );
        match waf::inspect_body(
            &inspect_bytes,
            &ctx.request_uri,
            &ctx.client_addr,
            ctx.request_content_type.as_deref(),
        ) {
            WafVerdict::Allow => {
                *body = assembled_body_to_upstream(std::mem::take(&mut ctx.request_body));
                Ok(())
            }
            WafVerdict::Block(reason) => {
                if let Some(ip) = parse_ip(&ctx.client_addr) {
                    behavioral::record_waf_block(ip);
                }
                self.send_403(session, &reason).await?;
                Error::e_explain(ErrorType::HTTPStatus(403), reason)
            }
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

    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        error: &Error,
    ) -> bool {
        matches!(error.etype(), ErrorType::HTTPStatus(403 | 413))
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let backend = ctx.backend.as_ref().expect("backend must be resolved in request_filter");
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
        upstream_request
            .insert_header("Host", &backend.host)
            .unwrap();
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
            if let Some(ip) = parse_ip(&ctx.client_addr) {
                behavioral::record_response(ip, status);
            }
        }

        // Capture content-type for DLP (before modifying headers)
        ctx.content_type = upstream_response
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        upstream_response.remove_header("Content-Length");
        upstream_response
            .insert_header("Transfer-Encoding", "chunked")
            .unwrap();

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
            if ctx.body_buffer.len() + b.len() > MAX_RESPONSE_BUFFER {
                // Too large — flush what we have and skip DLP for the rest
                ctx.skip_dlp = true;
                let mut flushed = std::mem::take(&mut ctx.body_buffer);
                flushed.extend_from_slice(&b);
                *body = Some(Bytes::from(flushed));
                return Ok(None);
            }
            ctx.body_buffer.extend_from_slice(&b);
        }

        if end_of_stream {
            let ct = ctx.content_type.as_deref();
            let sanitized = dlp::sanitize_body(&ctx.body_buffer, ct);
            *body = Some(sanitized);
        }

        Ok(None)
    }
}

/// Pingora 0.8: `None` in `request_body_filter` is end-of-body even when
/// `end_of_stream` is false. Yield an empty Some to pause the upstream write.
fn hold_body_until_complete() -> Option<Bytes> {
    Some(Bytes::new())
}

fn assembled_body_to_upstream(assembled: Vec<u8>) -> Option<Bytes> {
    Some(Bytes::from(assembled))
}

impl FerroadaProxy {
    async fn send_429(&self, session: &mut Session, reason: &str, retry_after: u64) -> Result<bool> {
        let body = format!("429 Too Many Requests: {reason}\n");
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
        let body = format!("400 Bad Request: {reason}\n");
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
        let body = "413 Payload Too Large\n";
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

    async fn send_403(&self, session: &mut Session, reason: &str) -> Result<bool> {
        let body = format!("403 Forbidden: {reason}\n");
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_is_empty_some_not_none() {
        let held = hold_body_until_complete();
        assert!(
            held.is_some(),
            "None is EOS in pingora 0.8; holding must be Some"
        );
        assert!(
            held.unwrap().is_empty(),
            "the hold chunk must not leak buffered bytes early"
        );
    }

    #[test]
    fn eos_forwards_the_assembled_original() {
        let out = assembled_body_to_upstream(b"{\"q\":\"1 UNION SELECT\"}".to_vec());
        assert_eq!(out.unwrap().as_ref(), b"{\"q\":\"1 UNION SELECT\"}");
    }
}
