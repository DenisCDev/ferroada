mod config;
mod dashboard;
mod dlp;
mod headers;
mod metrics;
mod proxy;
mod rate_limit;
mod shield;
mod waf;

use config::Config;
use dashboard::DashboardService;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use proxy::FerroadaProxy;
use rate_limit::RateLimiter;
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

    info!("Ferroada starting");

    // Load config: ferroada.toml (multi-site) or TARGET_URL (single-site)
    let config = Arc::new(Config::load());

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::from_env());

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // --- Proxy service ---
    let proxy = FerroadaProxy {
        config: Arc::clone(&config),
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
    info!(listen = "0.0.0.0:3000", "Ferroada proxy ready");

    // --- Dashboard service ---
    let dashboard_port = std::env::var("DASHBOARD_PORT").unwrap_or_else(|_| "9000".to_string());
    let dashboard_addr = format!("0.0.0.0:{dashboard_port}");

    let mut dashboard_svc = http_proxy_service(&server.configuration, DashboardService);
    dashboard_svc.add_tcp(&dashboard_addr);

    server.add_service(dashboard_svc);
    info!(listen = %dashboard_addr, "Dashboard ready");

    server.run_forever();
}
