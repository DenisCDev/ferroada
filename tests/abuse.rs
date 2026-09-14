//! Abuse engine: stuffing quotas follow fingerprint, not IP. Opt-in per site.

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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LIVE: Mutex<()> = Mutex::new(());

fn live_lock() -> std::sync::MutexGuard<'static, ()> {
    LIVE.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct Stub {
    hits: Arc<AtomicU64>,
    addr: SocketAddr,
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
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
    let header_text = String::from_utf8_lossy(&buf);
    let mut content_length = 0usize;
    for line in header_text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0).min(65_536);
            break;
        }
    }
    let mut got = 0usize;
    while got < content_length {
        let mut chunk = vec![0u8; content_length - got];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                got += n;
            }
            Err(_) => break,
        }
    }
    buf
}

fn spawn_stub() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&hits);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let req = read_http_request(&mut stream);
            let text = String::from_utf8_lossy(&req);
            let line = text.lines().next().unwrap_or("");
            let is_login = line.contains("POST /login");
            let is_users = line.contains("GET /users/") || line.contains("GET /accounts/");
            if is_login || is_users {
                count.fetch_add(1, Ordering::Relaxed);
            }
            let (status, reason, body) = if is_login {
                (401, "Unauthorized", "no")
            } else if is_users {
                (404, "Not Found", "missing")
            } else {
                (200, "OK", "ok")
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
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

fn spawn_proxy(listen: SocketAddr, config: Config) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    std::thread::spawn(move || {
        let proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("127.0.0.1/32").unwrap(),
            ClientIpConfig::default(),
            false,
        );
        let server_conf = ServerConf {
            threads: 1,
            max_retries: 1,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), server_conf);
        server.bootstrap();
        let mut app = http_proxy(&server.configuration, proxy);
        let mut h2c = HttpServerOptions::default();
        h2c.h2c = true;
        app.server_options = Some(h2c);
        let filter = ConnectionRateFilter::from_env();
        let mut svc = Service::new("test abuse proxy".to_string(), filter.wrap(app, false, None));
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
            if body.starts_with(b"HTTP/1.1 ") || body.starts_with(b"HTTP/1.0 ") {
                return body;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("proxy did not answer");
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn status_of(response: &[u8]) -> u16 {
    response
        .split(|&b| b == b' ')
        .nth(1)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn login_post(addr: SocketAddr, host: &str, xff: &str, extra_header: Option<&str>) -> Vec<u8> {
    let extra = extra_header.unwrap_or("");
    let payload = format!(
        "POST /login HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nX-Forwarded-For: {xff}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\nConnection: close\r\n{extra}\r\npassword=x"
    );
    send_until_http(addr, payload.as_bytes())
}

fn site_toml(host: &str, origin: SocketAddr, abuse: &str) -> String {
    format!(
        "[[sites]]\nhosts = [\"{host}\"]\nbackend = \"http://{origin}\"\n{abuse}"
    )
}

#[test]
fn stuffing_same_fingerprint_different_ips_trips_after_ten() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let host = "abuse.test";
    let config = Config::from_toml(&site_toml(
        host,
        stub.addr,
        "abuse = { stuffing_max = 10, challenge = \"none\" }\n",
    ));
    spawn_proxy(listen, config);
    let _ = send_until_http(
        listen,
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-abuse-test\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    stub.hits.store(0, Ordering::Relaxed);
    for i in 0..10 {
        let ip = format!("198.51.100.{i}");
        let res = login_post(listen, host, &ip, None);
        assert_eq!(status_of(&res), 401, "{}", String::from_utf8_lossy(&res));
    }
    assert_eq!(stub.hits.load(Ordering::Relaxed), 10);
    for i in 10..20 {
        let ip = format!("198.51.100.{i}");
        let res = login_post(listen, host, &ip, None);
        assert_eq!(status_of(&res), 403, "{}", String::from_utf8_lossy(&res));
        let body = String::from_utf8_lossy(&res);
        assert!(body.contains("stuffing"), "{body}");
        assert!(!body.to_ascii_lowercase().contains("password"));
    }
    assert_eq!(stub.hits.load(Ordering::Relaxed), 10);
}

#[test]
fn stuffing_distinct_fingerprints_do_not_share_quota() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let host = "abuse-fp.test";
    let config = Config::from_toml(&site_toml(
        host,
        stub.addr,
        "abuse = { stuffing_max = 10, challenge = \"none\" }\n",
    ));
    spawn_proxy(listen, config);
    let _ = send_until_http(
        listen,
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-abuse-test\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    stub.hits.store(0, Ordering::Relaxed);
    for i in 0..20 {
        let ip = format!("203.0.113.{i}");
        let extra = format!("X-Trace-{i}: 1\r\n");
        let res = login_post(listen, host, &ip, Some(&extra));
        assert_eq!(status_of(&res), 401, "i={i} {}", String::from_utf8_lossy(&res));
    }
    assert_eq!(stub.hits.load(Ordering::Relaxed), 20);
}

#[test]
fn site_without_abuse_block_forwards_all_failed_logins() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let host = "clean.test";
    let config = Config::from_toml(&site_toml(host, stub.addr, ""));
    spawn_proxy(listen, config);
    let _ = send_until_http(
        listen,
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-abuse-test\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    stub.hits.store(0, Ordering::Relaxed);
    for i in 0..20 {
        let ip = format!("192.0.2.{i}");
        let res = login_post(listen, host, &ip, None);
        assert_eq!(status_of(&res), 401, "{}", String::from_utf8_lossy(&res));
    }
    assert_eq!(stub.hits.load(Ordering::Relaxed), 20);
}

#[test]
fn browser_over_threshold_gets_pow_without_password_in_event() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let host = "pow.test";
    let config = Config::from_toml(&site_toml(
        host,
        stub.addr,
        "abuse = { stuffing_max = 10, challenge = \"pow\", challenge_score = 40 }\n",
    ));
    spawn_proxy(listen, config);
    let _ = send_until_http(
        listen,
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-abuse-test\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    for i in 0..10 {
        let ip = format!("198.51.100.{i}");
        let res = login_post(listen, host, &ip, None);
        assert_eq!(status_of(&res), 401);
    }
    let get = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nX-Forwarded-For: 198.51.100.99\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let res = send_until_http(listen, get.as_bytes());
    assert_eq!(status_of(&res), 403, "{}", String::from_utf8_lossy(&res));
    let body = String::from_utf8_lossy(&res);
    assert!(body.contains("text/html"), "{body}");
    assert!(body.contains("SHA-256") || body.contains("crypto.subtle"), "{body}");
    assert!(!body.to_ascii_lowercase().contains("password"));
    let snapshot = metrics::snapshot_json();
    assert!(snapshot.contains("\"abuse\"") || snapshot.contains("stuffing"), "{snapshot}");
    assert!(!snapshot.to_ascii_lowercase().contains("password=x"));
}

#[test]
fn json_api_does_not_get_html_challenge() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let host = "api-json.test";
    let config = Config::from_toml(&site_toml(
        host,
        stub.addr,
        "abuse = { stuffing_max = 10, challenge = \"pow\", challenge_score = 40 }\n",
    ));
    spawn_proxy(listen, config);
    let _ = send_until_http(
        listen,
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-abuse-test\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    for i in 0..10 {
        let ip = format!("198.51.100.{i}");
        let _ = login_post(listen, host, &ip, None);
    }
    let get = format!(
        "GET /api HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nX-Forwarded-For: 198.51.100.0\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let res = send_until_http(listen, get.as_bytes());
    let body = String::from_utf8_lossy(&res);
    assert!(
        !body.contains("<!DOCTYPE html"),
        "API/JSON must not receive PoW HTML: {body}"
    );
}

#[test]
fn process_starts_without_mmdb_and_asn_is_none() {
    let id = ferroada::client_ip::RiskIdentity::new(
        "x",
        "127.0.0.1".parse().unwrap(),
        "/",
        None,
        None,
    );
    assert!(id.asn.is_none());
    let file = ferroada::config::Config::from_toml(
        "[[sites]]\nhosts = [\"mmdb.test\"]\nbackend = \"http://127.0.0.1:9\"\nabuse = { stuffing_max = 10 }\n",
    );
    assert!(file.resolve("mmdb.test").unwrap().abuse.as_ref().unwrap().mmdb.is_none());
}
