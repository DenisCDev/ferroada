//! L1 Coraza sidecar (PR 11). L0 stays on; sidecar down + fail-closed is 403.

#![cfg(unix)]

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::metrics;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use ferroada::waf_engine::WafEngine;
use pingora::apps::HttpServerOptions;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LIVE: Mutex<()> = Mutex::new(());

fn live_lock() -> std::sync::MutexGuard<'static, ()> {
    LIVE.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct Stub {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
    addr: SocketAddr,
}

fn spawn_stub() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&hits);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf);
            recorded.lock().unwrap().push(buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    Stub { hits, addr }
}

fn free_bind() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn fail_closed_config(origin: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["waf.test"]
backend = "http://{origin}"
require_complete_waf_inspection = ["/api/payment"]
"#
    ))
}

fn open_config(origin: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["waf.test"]
backend = "http://{origin}"
"#
    ))
}

fn spawn_proxy(listen: SocketAddr, config: Config, engine: WafEngine) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    std::thread::spawn(move || {
        let proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            false,
        )
        .with_waf_engine(engine);
        let server_conf = ServerConf {
            threads: 1,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), server_conf);
        server.bootstrap();
        let mut app = http_proxy(&server.configuration, proxy);
        let mut h2c = HttpServerOptions::default();
        h2c.h2c = true;
        app.server_options = Some(h2c);
        let filter = ConnectionRateFilter::from_env();
        let mut svc = Service::new("test l1 proxy".to_string(), filter.wrap(app, false, None));
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn send(addr: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream.write_all(payload).ok()?;
    let _ = stream.flush();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Some(buf)
}

fn send_until_http(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(body) = send(addr, payload) {
            if body.starts_with(b"HTTP/1.1 ") {
                return body;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("proxy did not answer");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: waf.test\r\nUser-Agent: ferroada-l1-test\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn temp_sock() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fa-l1-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn serve_sidecar(socket: std::path::PathBuf, body: &'static [u8]) {
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let mut buf = vec![0u8; 16 * 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = &buf[..n];
            if request.starts_with(b"GET /readyz") {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                continue;
            }
            let _ = stream.write_all(body);
        }
    });
    std::thread::sleep(Duration::from_millis(40));
}

#[test]
fn sidecar_down_on_fail_closed_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let socket = temp_sock();
    let _ = std::fs::remove_file(&socket);
    let engine = WafEngine::coraza(&socket, Duration::from_millis(80));
    spawn_proxy(listen, fail_closed_config(stub.addr), engine);

    let response = send_until_http(listen, &get("/api/payment"));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "sidecar down + fail_closed must be 403, got {}",
        String::from_utf8_lossy(&response[..response.len().min(240)])
    );
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "fail-closed must not reach the origin"
    );
    let snapshot = metrics::snapshot_json();
    assert!(snapshot.contains("waf_engine_unavailable"), "{snapshot}");
    let prometheus = metrics::snapshot_prometheus();
    assert!(prometheus.contains("ferroada_waf_engine_unavailable_total"));
}

#[test]
fn sidecar_down_on_open_route_is_not_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let socket = temp_sock();
    let _ = std::fs::remove_file(&socket);
    let engine = WafEngine::coraza(&socket, Duration::from_millis(80));
    spawn_proxy(listen, open_config(stub.addr), engine);

    let response = send_until_http(listen, &get("/health"));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "open route fail-open-explicit must forward, got {}",
        String::from_utf8_lossy(&response[..response.len().min(240)])
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stub.hits.lock().unwrap().len(), 1);
}

#[test]
fn sidecar_deny_puts_rule_id_in_event_detail() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let socket = temp_sock();
    let json = r#"{"action":"deny","rule_ids":[942100],"msg":"SQL Injection Attack"}"#;
    let deny = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    let deny = Box::leak(deny.into_boxed_str());
    serve_sidecar(socket.clone(), deny.as_bytes());
    let engine = WafEngine::coraza(&socket, Duration::from_millis(500));
    spawn_proxy(listen, fail_closed_config(stub.addr), engine);

    let response = send_until_http(listen, &get("/api/payment?q=1%27%20OR%201%3D1"));
    let _ = std::fs::remove_file(&socket);
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "L1 deny must be 403, got {}",
        String::from_utf8_lossy(&response[..response.len().min(240)])
    );
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("942100"), "rule id in 403 body: {text}");
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let snapshot = metrics::snapshot_json();
    assert!(snapshot.contains("942100"), "{snapshot}");
    assert!(
        snapshot.contains("waf_l1") || snapshot.contains("CRS"),
        "{snapshot}"
    );
}

#[test]
fn native_engine_does_not_need_sidecar() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, fail_closed_config(stub.addr), WafEngine::native());
    let response = send_until_http(listen, &get("/api/payment"));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "L0-only fail_closed GET must pass, got {}",
        String::from_utf8_lossy(&response[..response.len().min(240)])
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stub.hits.lock().unwrap().len(), 1);
}
