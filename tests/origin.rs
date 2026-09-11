//! Load balancing, health checks and circuit breaker (PR 19 / Fase 7).

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::metrics;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use pingora::apps::HttpServerOptions;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LIVE: Mutex<()> = Mutex::new(());

fn live_lock() -> std::sync::MutexGuard<'static, ()> {
    LIVE.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HitKind {
    Health,
    Get,
    Post,
    Other,
}

struct Stub {
    hits: Arc<Mutex<Vec<HitKind>>>,
    addr: SocketAddr,
}

fn classify(buf: &[u8]) -> HitKind {
    let text = String::from_utf8_lossy(buf);
    let line = text.lines().next().unwrap_or("");
    if line.contains(" /health/ready") {
        HitKind::Health
    } else if line.starts_with("POST ") {
        HitKind::Post
    } else if line.starts_with("GET ") {
        HitKind::Get
    } else {
        HitKind::Other
    }
}

fn read_http_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
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
    buf
}

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn spawn_stub(reset_app: bool) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&hits);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let buf = read_http_head(&mut stream);
            let kind = classify(&buf);
            recorded.lock().unwrap().push(kind);
            if !reset_app || kind == HitKind::Health {
                let _ = stream.write_all(OK_RESPONSE);
            }
        }
    });
    Stub { hits, addr }
}

fn spawn_ok_stub() -> Stub {
    spawn_stub(false)
}

fn spawn_reset_stub() -> Stub {
    spawn_stub(true)
}

fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn free_bind() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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
        let mut svc = Service::new(
            "test origin proxy".to_string(),
            filter.wrap(app, false, None),
        );
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn send(addr: SocketAddr, _host: &str, req: &str) -> Option<Vec<u8>> {
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

fn post_req(host: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nping"
    )
}

fn wait_listen(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("proxy did not listen");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn send_until_http(addr: SocketAddr, host: &str, req: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(body) = send(addr, host, req) {
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

fn status(buf: &[u8]) -> u16 {
    let text = std::str::from_utf8(buf).unwrap_or("");
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn app_hits(stub: &Stub, kind: HitKind) -> usize {
    stub.hits
        .lock()
        .unwrap()
        .iter()
        .filter(|hit| **hit == kind)
        .count()
}

fn two_backends(host: &str, a: SocketAddr, b: SocketAddr) -> String {
    format!("[[sites]]\nhosts = [\"{host}\"]\nbackend = [\"http://{a}\", \"http://{b}\"]\n")
}

#[test]
fn single_backend_string_still_returns_200() {
    let _lock = live_lock();
    let stub = spawn_ok_stub();
    let listen = free_bind();
    let host = "one.origin.test";
    spawn_proxy(
        listen,
        &format!(
            "[[sites]]\nhosts = [\"{host}\"]\nbackend = \"http://{}\"\n",
            stub.addr
        ),
    );
    let response = send_until_http(listen, host, &get_req(host, "/"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn two_origins_one_down_on_health_goes_to_the_live_one() {
    let _lock = live_lock();
    let live = spawn_ok_stub();
    let down = unused_addr();
    let listen = free_bind();
    let host = "pair.origin.test";
    spawn_proxy(listen, &two_backends(host, down, live.addr));
    let response = send_until_http(listen, host, &get_req(host, "/"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while app_hits(&live, HitKind::Get) == 0 {
        if std::time::Instant::now() >= deadline {
            panic!("live origin saw no GET");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn both_origins_down_returns_503_after_waf() {
    let _lock = live_lock();
    let down_a = unused_addr();
    let down_b = unused_addr();
    let listen = free_bind();
    let host = "dead.origin.test";
    spawn_proxy(listen, &two_backends(host, down_a, down_b));
    let clean = send_until_http(listen, host, &get_req(host, "/"));
    assert_eq!(status(&clean), 503, "{}", String::from_utf8_lossy(&clean));
    let json = metrics::snapshot_json();
    assert!(
        json.contains("\"event_type\": \"503\""),
        "expected 503 event, got {json}"
    );

    let blocked = send(listen, host, &get_req(host, "/search?q=1+OR+1=1")).unwrap_or_default();
    assert_eq!(
        status(&blocked),
        403,
        "WAF must still evaluate: {}",
        String::from_utf8_lossy(&blocked)
    );
}

#[test]
fn get_retries_once_when_first_origin_resets() {
    let _lock = live_lock();
    let reset = spawn_reset_stub();
    let live = spawn_ok_stub();
    let listen = free_bind();
    let host = "retry.origin.test";
    spawn_proxy(listen, &two_backends(host, reset.addr, live.addr));
    wait_listen(listen);
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let reset_before = app_hits(&reset, HitKind::Get);
        let live_before = app_hits(&live, HitKind::Get);
        let response = send(listen, host, &get_req(host, "/")).unwrap_or_default();
        let reset_after = app_hits(&reset, HitKind::Get);
        let live_after = app_hits(&live, HitKind::Get);
        if reset_after > reset_before {
            assert_eq!(
                status(&response),
                200,
                "{}",
                String::from_utf8_lossy(&response)
            );
            assert!(
                live_after > live_before,
                "the same GET must be retried onto the live origin"
            );
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "GET never hit the resetting origin; reset={} live={}",
                reset_after, live_after
            );
        }
    }
}

#[test]
fn post_does_not_retry() {
    let _lock = live_lock();
    let reset = spawn_reset_stub();
    let live = spawn_ok_stub();
    let listen = free_bind();
    let host = "post.origin.test";
    spawn_proxy(listen, &two_backends(host, reset.addr, live.addr));
    wait_listen(listen);
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let reset_before = app_hits(&reset, HitKind::Post);
        let live_before = app_hits(&live, HitKind::Post);
        let _ = send(listen, host, &post_req(host));
        let reset_after = app_hits(&reset, HitKind::Post);
        let live_after = app_hits(&live, HitKind::Post);
        if reset_after > reset_before {
            assert_eq!(
                live_after, live_before,
                "POST that hit the resetting origin must not be replayed"
            );
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "POST never hit the resetting origin; reset={} live={}",
                reset_after, live_after
            );
        }
    }
}
