use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::dlp;
use crate::headers;
use crate::metrics;
use crate::rate_limit::RateLimiter;
use crate::shield::{self, ShieldVerdict};
use crate::waf::{self, WafVerdict};

pub struct FerroadaProxy {
    pub addr: SocketAddr,
    pub host: String,
    pub tls: bool,
    pub rate_limiter: Arc<RateLimiter>,
}

pub struct FerroadaCtx {
    pub body_buffer: Vec<u8>,
    pub request_uri: String,
    pub client_addr: String,
}

#[async_trait]
impl ProxyHttp for FerroadaProxy {
    type CTX = FerroadaCtx;

    fn new_ctx(&self) -> Self::CTX {
        FerroadaCtx {
            body_buffer: Vec::new(),
            request_uri: String::new(),
            client_addr: String::new(),
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
                    .unwrap_or(&self.host);
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
        if let Some(host_val) = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
        {
            match shield::check_host(host_val, &uri, &client_addr) {
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
        let ip = client_addr
            .parse::<std::net::SocketAddr>()
            .map(|s| s.ip())
            .or_else(|_| client_addr.parse::<std::net::IpAddr>())
            .ok();

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
                return self.send_403(session, &reason).await;
            }
        }

        // WAF inspection on request body (POST/PUT/PATCH)
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            // Read buffered body if available
            if let Some(body) = session.read_request_body().await? {
                match waf::inspect_body(&body, &uri, &client_addr) {
                    WafVerdict::Allow => {
                        // Body was consumed; write it back for upstream
                        session.write_request_body(Some(body), true).await?;
                    }
                    WafVerdict::Block(reason) => {
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
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        info!(addr = %self.addr, tls = self.tls, "Connecting to upstream");
        let peer = HttpPeer::new(self.addr, self.tls, self.host.clone());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", &self.host)
            .unwrap();
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
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
        if let Some(b) = body.take() {
            ctx.body_buffer.extend_from_slice(&b);
        }

        if end_of_stream {
            let sanitized = dlp::sanitize_body(&ctx.body_buffer);
            *body = Some(sanitized);
        }

        Ok(None)
    }
}

impl FerroadaProxy {
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
