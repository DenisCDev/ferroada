use ferroada::client_ip::TrustedProxies;
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::dashboard::{production_enabled, validate_exposure, DashboardService};
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use ferroada::waf;
use pingora::prelude::*;
use pingora::proxy::{http_proxy, http_proxy_service};
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::listening::Service;
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
    waf::validate_config();

    // Load config: ferroada.toml (multi-site) or TARGET_URL (single-site)
    let config = Arc::new(Config::load());

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::from_env());
    let trusted_proxies = TrustedProxies::from_env().expect("TRUSTED_PROXIES inválido");
    if trusted_proxies.is_empty() {
        info!("Nenhum proxy confiável configurado; headers de IP encaminhado serão ignorados");
    }

    let server_conf = ServerConf {
        max_retries: total_upstream_attempts(std::env::var("MAX_UPSTREAM_RETRIES").ok().as_deref()),
        grace_period_seconds: Some(env_u64("GRACE_PERIOD_SECS", 5)),
        graceful_shutdown_timeout_seconds: Some(env_u64("GRACEFUL_SHUTDOWN_TIMEOUT_SECS", 30)),
        threads: std::env::var("PROXY_THREADS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1)
            })
            .min(64),
        ..Default::default()
    };
    let opt = Opt::parse_args();
    let mut server = Server::new_with_opt_and_conf(Some(opt), server_conf);
    server.bootstrap();

    // --- Proxy service ---
    let proxy = FerroadaProxy::new(Arc::clone(&config), rate_limiter, trusted_proxies);

    let proxy_app = http_proxy(&server.configuration, proxy);
    let connection_filter = ConnectionRateFilter::from_env();
    let mut svc = Service::new(
        "Ferroada proxy".to_string(),
        connection_filter.wrap(proxy_app),
    );
    svc.set_connection_filter(Arc::new(connection_filter));
    svc.add_tcp("0.0.0.0:3000");

    // Optional TLS listener
    if let (Ok(cert_path), Ok(key_path)) = (
        std::env::var("TLS_CERT_PATH"),
        std::env::var("TLS_KEY_PATH"),
    ) {
        svc.add_tls("0.0.0.0:3443", &cert_path, &key_path)
            .expect("Failed to load TLS certs");
        info!(listen = "0.0.0.0:3443", "HTTPS listener ready");
    }

    server.add_service(svc);
    info!(listen = "0.0.0.0:3000", "Ferroada proxy ready");

    // --- Dashboard service ---
    let dashboard_port = std::env::var("DASHBOARD_PORT").unwrap_or_else(|_| "9000".to_string());
    let dashboard_bind =
        std::env::var("DASHBOARD_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let dashboard_ip = dashboard_bind
        .parse::<std::net::IpAddr>()
        .expect("DASHBOARD_BIND deve ser um endereço IP válido");
    let dashboard_token = std::env::var("DASHBOARD_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty());
    validate_exposure(
        dashboard_ip,
        dashboard_token.as_deref(),
        production_enabled(),
    )
    .expect("Dashboard inseguro");
    let dashboard_addr = std::net::SocketAddr::new(
        dashboard_ip,
        dashboard_port
            .parse()
            .expect("DASHBOARD_PORT deve ser uma porta válida"),
    );

    let mut dashboard_svc = http_proxy_service(
        &server.configuration,
        DashboardService::new(dashboard_token, config.backend_addresses()),
    );
    dashboard_svc.add_tcp(&dashboard_addr.to_string());

    server.add_service(dashboard_svc);
    info!(listen = %dashboard_addr, "Dashboard ready");

    server.run_forever();
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn total_upstream_attempts(configured_retries: Option<&str>) -> usize {
    configured_retries
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(3)
        .saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::total_upstream_attempts;

    #[test]
    fn zero_extra_retries_still_performs_one_upstream_attempt() {
        assert_eq!(total_upstream_attempts(None), 1);
        assert_eq!(total_upstream_attempts(Some("0")), 1);
        assert_eq!(total_upstream_attempts(Some("2")), 3);
        assert_eq!(total_upstream_attempts(Some("999")), 4);
    }
}
