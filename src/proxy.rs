use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tracing::info;

use std::net::IpAddr;

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
    pub request_uri: String,
    pub client_addr: String,
    pub content_type: Option<String>,
    pub skip_dlp: bool,
    pub backend: Option<crate::config::Backend>,
}

#[async_trait]
impl ProxyHttp for FerroadaProxy {
    type CTX = FerroadaCtx;

    fn new_ctx(&self) -> Self::CTX {
        FerroadaCtx {
            body_buffer: Vec::new(),
            request_uri: String::new(),
            client_addr: String::new(),
            content_type: None,
            skip_dlp: false,
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

        // WAF inspection on request body (POST/PUT/PATCH)
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            let req_content_type = session.req_header().headers.get("Content-Type")
                .and_then(|v| v.to_str().ok());
            // Read buffered body if available
            if let Some(body) = session.read_request_body().await? {
                match waf::inspect_body(&body, &uri, &client_addr, req_content_type) {
                    WafVerdict::Allow => {
                        // Body was consumed; write it back for upstream
                        session.write_request_body(Some(body), true).await?;
                    }
                    WafVerdict::Block(reason) => {
                        if let Some(ip) = parse_ip(&client_addr) {
                            behavioral::record_waf_block(ip);
                        }
                        return self.send_403(session, &reason).await;
                    }
                }
            }
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let backend = ctx.backend.as_ref().expect("backend must be resolved in request_filter");
        info!(addr = %backend.addr, tls = backend.tls, host = %backend.host, "Connecting to upstream");
        let peer = HttpPeer::new(backend.addr, backend.tls, backend.host.clone());
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
