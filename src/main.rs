use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::dashboard::{production_enabled, validate_exposure, DashboardService};
use ferroada::proxy::FerroadaProxy;
use ferroada::proxy_protocol;
use ferroada::rate_limit::RateLimiter;
use ferroada::waf;
use pingora::listeners::ConnectionFilter;
use pingora::prelude::*;
use pingora::proxy::{http_proxy, http_proxy_service};
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::listening::Service;
use pingora::tls::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("init") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            if let Err(error) = ferroada::init::run(&args) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return;
        }
        Some("cidrs") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            if let Err(error) = ferroada::cidrs::run(&args) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return;
        }
        Some("healthcheck") => {
            let extra: Vec<String> = std::env::args().skip(2).collect();
            if extra.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!(
                    "ferroada healthcheck — GET em DASHBOARD_BIND:DASHBOARD_PORT/healthz; sai 0 se 200, 1 se o dashboard não responde (limite 2s)."
                );
                return;
            }
            if !extra.is_empty() {
                eprintln!("ferroada healthcheck não aceita argumentos");
                std::process::exit(1);
            }
            let _ = dotenvy::dotenv();
            if let Err(error) = ferroada::healthcheck::probe_from_env() {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return;
        }
        _ => {}
    }

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
    let client_ip =
        ClientIpConfig::from_env().expect("CLIENT_IP_ORDER / FORWARDED_HEADER inválido");
    let proxy_protocol = proxy_protocol::enabled();
    if proxy_protocol {
        info!("PROXY protocol v2 obrigatório neste listener; prefixo inválido recusa a conexão");
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
    let proxy = FerroadaProxy::new(
        Arc::clone(&config),
        rate_limiter,
        trusted_proxies,
        client_ip,
        proxy_protocol,
    );

    let proxy_app = http_proxy(&server.configuration, proxy.clone());
    let connection_filter = ConnectionRateFilter::from_env();
    let mut svc = Service::new(
        "Ferroada proxy".to_string(),
        connection_filter.wrap(proxy_app, proxy_protocol, None),
    );
    let proxy_listen = ferroada::listen::from_env("PROXY_LISTEN", ferroada::listen::DEFAULT_PROXY)
        .unwrap_or_else(|error| panic!("{error}"));
    svc.add_tcp(&proxy_listen);

    let tls_paths = match (
        std::env::var("TLS_CERT_PATH"),
        std::env::var("TLS_KEY_PATH"),
    ) {
        (Ok(cert_path), Ok(key_path)) => Some((cert_path, key_path)),
        _ => None,
    };
    if let Some((cert_path, key_path)) = tls_paths {
        let tls_listen = ferroada::listen::from_env("TLS_LISTEN", ferroada::listen::DEFAULT_TLS)
            .unwrap_or_else(|error| panic!("{error}"));
        if proxy_protocol {
            // Pingora 0.8.1 handshakes before process_new. PreTlsProcess = our
            // parser on add_tcp, then handshake, so PROXY v2 is consumed first.
            let acceptor =
                tls_acceptor(&cert_path, &key_path).unwrap_or_else(|error| panic!("{error}"));
            let tls_app = http_proxy(&server.configuration, proxy);
            let mut tls_svc = Service::new(
                "Ferroada proxy tls".to_string(),
                connection_filter.wrap(tls_app, proxy_protocol, Some(acceptor)),
            );
            let filter: Arc<dyn ConnectionFilter> = Arc::new(connection_filter);
            svc.set_connection_filter(Arc::clone(&filter));
            tls_svc.set_connection_filter(filter);
            tls_svc.add_tcp(&tls_listen);
            server.add_service(tls_svc);
            info!(listen = %tls_listen, "HTTPS listener ready (PROXY v2 antes do handshake)");
        } else {
            svc.set_connection_filter(Arc::new(connection_filter));
            svc.add_tls(&tls_listen, &cert_path, &key_path)
                .expect("Failed to load TLS certs");
            info!(listen = %tls_listen, "HTTPS listener ready");
        }
    } else {
        svc.set_connection_filter(Arc::new(connection_filter));
    }

    server.add_service(svc);
    info!(listen = %proxy_listen, "Ferroada proxy ready");

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

fn tls_acceptor(cert_path: &str, key_path: &str) -> Result<SslAcceptor, String> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|error| format!("falha a criar o aceitador TLS: {error}"))?;
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|error| format!("falha a ler a chave TLS {key_path}: {error}"))?;
    builder
        .set_certificate_chain_file(cert_path)
        .map_err(|error| format!("falha a ler o certificado TLS {cert_path}: {error}"))?;
    Ok(builder.build())
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
