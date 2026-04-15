mod dashboard;
mod dlp;
mod metrics;
mod proxy;
mod rate_limit;
mod waf;

use dashboard::DashboardService;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use proxy::FerroadaProxy;
use rate_limit::RateLimiter;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    // Load .env file (ignore if missing)
    let _ = dotenvy::dotenv();

    // Initialize tracing with RUST_LOG env filter
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let target_url = std::env::var("TARGET_URL").expect("TARGET_URL environment variable required");
    info!(target = %target_url, "Ferroada starting");

    // Parse TARGET_URL
    let url = url_parse(&target_url);

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::from_env());

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // --- Proxy service ---
    let proxy = FerroadaProxy {
        addr: url.addr,
        host: url.host.clone(),
        tls: url.tls,
        rate_limiter,
    };

    let mut svc = http_proxy_service(&server.configuration, proxy);
    svc.add_tcp("0.0.0.0:3000");

    // Optional TLS listener
    if let (Ok(cert_path), Ok(key_path)) = (
        std::env::var("TLS_CERT_PATH"),
        std::env::var("TLS_KEY_PATH"),
    ) {
        let tls_settings =
            TlsSettings::intermediate(&cert_path, &key_path).expect("Failed to load TLS certs");
        svc.add_tls("0.0.0.0:3443", tls_settings);
        info!(listen = "0.0.0.0:3443", "HTTPS listener ready");
    }

    server.add_service(svc);
    info!(listen = "0.0.0.0:3000", upstream = %target_url, "Ferroada proxy ready");

    // --- Dashboard service ---
    let dashboard_port = std::env::var("DASHBOARD_PORT").unwrap_or_else(|_| "9000".to_string());
    let dashboard_addr = format!("0.0.0.0:{dashboard_port}");

    let mut dashboard_svc = http_proxy_service(&server.configuration, DashboardService);
    dashboard_svc.add_tcp(&dashboard_addr);

    server.add_service(dashboard_svc);
    info!(listen = %dashboard_addr, "Dashboard ready");

    server.run_forever();
}

struct ParsedUrl {
    addr: SocketAddr,
    host: String,
    tls: bool,
}

fn url_parse(url: &str) -> ParsedUrl {
    let tls = url.starts_with("https://");
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .expect("TARGET_URL must start with http:// or https://");

    // Strip path
    let authority = without_scheme.split('/').next().unwrap();

    let default_port: u16 = if tls { 443 } else { 80 };
    let (host, port) = if let Some(idx) = authority.rfind(':') {
        let h = &authority[..idx];
        let p = authority[idx + 1..]
            .parse::<u16>()
            .unwrap_or(default_port);
        (h.to_string(), p)
    } else {
        (authority.to_string(), default_port)
    };

    let addr_str = format!("{host}:{port}");
    let addr = addr_str
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("Cannot resolve {addr_str}: {e}"))
        .next()
        .unwrap_or_else(|| panic!("No addresses found for {addr_str}"));

    info!(%host, %port, %tls, "Parsed upstream target");

    ParsedUrl { addr, host, tls }
}
