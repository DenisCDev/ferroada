//! Optional OTLP export (PR 20 / Fase 8). Ring buffer and dashboard JSON stay local.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::metrics;
use ferroada::otel;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use pingora::apps::HttpServerOptions;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static LIVE: Mutex<()> = Mutex::new(());

fn live_lock() -> std::sync::MutexGuard<'static, ()> {
    LIVE.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct Stub {
    addr: SocketAddr,
}

fn spawn_ok_stub() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    Stub { addr }
}

struct Collector {
    addr: SocketAddr,
    accepts: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn spawn_collector() -> Collector {
    spawn_collector_status(200)
}

fn spawn_collector_status(status: u16) -> Collector {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicU64::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let accept_count = Arc::clone(&accepts);
    let recorded = Arc::clone(&requests);
    std::thread::spawn(move || {
        let reply =
            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            accept_count.fetch_add(1, Ordering::Relaxed);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let raw = read_http_message(&mut stream);
            recorded.lock().unwrap().push(raw);
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    Collector {
        addr,
        accepts,
        requests,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let header_text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let content_length = header_text
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    let mut filled = 0;
    while filled < content_length {
        match stream.read(&mut body[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    body.truncate(filled);
    buf.extend_from_slice(&body);
    buf
}

fn free_bind() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_proxy(listen: SocketAddr, toml: &str) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    let config = Config::from_toml(toml);
    std::thread::spawn(move || {
        let proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            false,
        );
        let server_conf = ServerConf {
            threads: 1,
            max_retries: 4,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), server_conf);
        server.bootstrap();
        let mut app = http_proxy(&server.configuration, proxy);
        let mut h2c = HttpServerOptions::default();
        h2c.h2c = true;
        app.server_options = Some(h2c);
        let filter = ConnectionRateFilter::from_env();
        let mut svc = Service::new("test otlp proxy".to_string(), filter.wrap(app, false, None));
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn send(addr: SocketAddr, req: &str) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream.write_all(req.as_bytes()).ok()?;
    let _ = stream.flush();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Some(buf)
}

fn get_req(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

fn get_req_with_secrets(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer super-secret-token\r\nCookie: session=abc\r\nConnection: close\r\n\r\n"
    )
}

fn wait_listen(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("proxy did not listen");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn send_until_http(addr: SocketAddr, req: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(body) = send(addr, req) {
            if body.starts_with(b"HTTP/1.1 ") {
                return body;
            }
        }
        if Instant::now() >= deadline {
            panic!("proxy did not answer");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn status(buf: &[u8]) -> u16 {
    let text = std::str::from_utf8(buf).unwrap_or("");
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn site_toml(host: &str, origin: SocketAddr) -> String {
    format!("[[sites]]\nhosts = [\"{host}\"]\nbackend = \"http://{origin}\"\n")
}

fn disable_otlp() {
    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    std::env::remove_var("FERROADA_OTLP_ENDPOINT");
    std::env::remove_var("OTEL_EXPORTER_OTLP_TIMEOUT");
    std::env::remove_var("FERROADA_OTLP_METRICS_INTERVAL_MS");
    otel::boot();
}

struct OtlpGuard;

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        disable_otlp();
    }
}

fn enable_otlp(addr: SocketAddr) -> OtlpGuard {
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", format!("http://{addr}"));
    std::env::set_var("OTEL_EXPORTER_OTLP_TIMEOUT", "400");
    std::env::set_var("FERROADA_OTLP_METRICS_INTERVAL_MS", "80");
    otel::boot();
    OtlpGuard
}

fn joined(requests: &[Vec<u8>]) -> String {
    requests
        .iter()
        .map(|raw| String::from_utf8_lossy(raw).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn wait_until_captured(
    collector: &Collector,
    timeout: Duration,
    ready: impl Fn(&[Vec<u8>]) -> bool,
) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let requests = collector.requests.lock().unwrap();
            if ready(&requests) {
                return requests.clone();
            }
        }
        if Instant::now() >= deadline {
            let requests = collector.requests.lock().unwrap();
            panic!(
                "collector did not receive expected OTLP: {:?}",
                requests
                    .iter()
                    .map(|raw| String::from_utf8_lossy(raw)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string())
                    .collect::<Vec<_>>()
            );
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

#[test]
fn without_endpoint_get_succeeds_and_never_dials_otlp() {
    let _lock = live_lock();
    disable_otlp();
    let collector = spawn_collector();
    let stub = spawn_ok_stub();
    let listen = free_bind();
    let host = "otlp.off.test";
    spawn_proxy(listen, &site_toml(host, stub.addr));
    let response = send_until_http(listen, &get_req(host, "/"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        collector.accepts.load(Ordering::Relaxed),
        0,
        "no OTLP socket attempt when endpoint is unset"
    );
    let json = metrics::snapshot_json();
    assert!(json.contains("\"recent_events\""));
    assert!(!json.contains("otel_export_failed"));
}

#[test]
fn mock_collector_receives_metric_and_span_without_authorization() {
    let _lock = live_lock();
    let collector = spawn_collector();
    let _otlp = enable_otlp(collector.addr);
    let stub = spawn_ok_stub();
    let listen = free_bind();
    let host = "otlp.on.test";
    spawn_proxy(listen, &site_toml(host, stub.addr));
    wait_listen(listen);

    let allowed = send_until_http(
        listen,
        &get_req_with_secrets(host, "/clean?token=sekrit&cpf=39053344705"),
    );
    assert_eq!(
        status(&allowed),
        200,
        "{}",
        String::from_utf8_lossy(&allowed)
    );

    let denied =
        send(listen, &get_req_with_secrets(host, "/search?q=1+OR+1=1")).unwrap_or_default();
    assert_eq!(status(&denied), 403, "{}", String::from_utf8_lossy(&denied));

    let captured = wait_until_captured(&collector, Duration::from_secs(4), |requests| {
        let blob = joined(requests);
        blob.contains("POST /v1/metrics ")
            && blob.contains("POST /v1/traces ")
            && blob.contains("/clean")
            && blob.contains("/search")
            && (blob.contains("\"stringValue\":\"deny\"")
                || blob.contains("\"stringValue\": \"deny\""))
    });
    let blob = joined(&captured);
    assert!(
        captured
            .iter()
            .any(|raw| { String::from_utf8_lossy(raw).contains("POST /v1/traces ") }),
        "missing traces POST: {blob}"
    );
    assert!(
        captured
            .iter()
            .any(|raw| { String::from_utf8_lossy(raw).contains("POST /v1/metrics ") }),
        "missing metrics POST: {blob}"
    );
    let lower = blob.to_ascii_lowercase();
    assert!(
        !lower.contains("authorization"),
        "OTLP request must not carry Authorization: {blob}"
    );
    assert!(!blob.contains("super-secret-token"), "{blob}");
    assert!(!blob.contains("session=abc"), "{blob}");
    assert!(!blob.contains("39053344705"), "{blob}");
    assert!(!blob.contains("token=sekrit"), "{blob}");
    assert!(
        blob.contains("resourceSpans") || blob.contains("resourceMetrics"),
        "{blob}"
    );
    assert!(blob.contains("ferroada_requests_total"), "{blob}");
    assert!(blob.contains("inspection_outcome"), "{blob}");
    assert!(blob.contains("/clean"), "{blob}");
    assert!(blob.contains("/search"), "{blob}");
    assert!(
        blob.contains("\"stringValue\":\"deny\"") || blob.contains("\"stringValue\": \"deny\""),
        "denied request must export decision=deny: {blob}"
    );
    let traces = captured
        .iter()
        .filter(|raw| String::from_utf8_lossy(raw).contains("POST /v1/traces "))
        .map(|raw| String::from_utf8_lossy(raw).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        traces.contains("sqli"),
        "denied SQLi must export event_type on the span: {traces}"
    );
    assert!(
        blob.contains("\"stringValue\":\"allow\"") || blob.contains("\"stringValue\": \"allow\""),
        "clean GET must export decision=allow: {blob}"
    );

    let json = metrics::snapshot_json();
    let value: serde_json::Value = serde_json::from_str(&json).expect("dashboard JSON");
    assert!(value.get("recent_events").is_some());
    assert!(value.get("requests_total").is_some());
    assert!(value.get("otel_export_failed").is_none());
}

#[test]
fn collector_down_keeps_serving_and_counts_export_failure() {
    let _lock = live_lock();
    let down = unused_addr();
    let _otlp = enable_otlp(down);
    let before = metrics::otel_export_failed();
    let stub = spawn_ok_stub();
    let listen = free_bind();
    let host = "otlp.down.test";
    spawn_proxy(listen, &site_toml(host, stub.addr));
    let response = send_until_http(listen, &get_req(host, "/"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while metrics::otel_export_failed() <= before {
        if Instant::now() >= deadline {
            panic!(
                "otel_export_failed did not rise (before={before}, now={})",
                metrics::otel_export_failed()
            );
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(metrics::snapshot_prometheus().contains("ferroada_otel_export_failed_total"));
    let json = metrics::snapshot_json();
    assert!(!json.contains("otel_export_failed"));
}

#[test]
fn collector_http_error_counts_export_failure() {
    let _lock = live_lock();
    let collector = spawn_collector_status(503);
    let _otlp = enable_otlp(collector.addr);
    let before = metrics::otel_export_failed();
    let stub = spawn_ok_stub();
    let listen = free_bind();
    let host = "otlp.http503.test";
    spawn_proxy(listen, &site_toml(host, stub.addr));
    let response = send_until_http(listen, &get_req(host, "/"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while metrics::otel_export_failed() <= before {
        if Instant::now() >= deadline {
            panic!(
                "HTTP 503 collector must count as export failure (before={before}, now={})",
                metrics::otel_export_failed()
            );
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}
