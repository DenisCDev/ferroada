//! Spool-before-origin (PR 8). Inspection window matches the wire ceiling.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use ferroada::spool;
use flate2::write::GzEncoder;
use flate2::Compression;
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
        listener.set_nonblocking(false).ok();
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let Some(buf) = read_full_request(&mut stream) else {
                continue;
            };
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

fn spawn_proxy(listen: SocketAddr, config: Config) {
    // Process-global behavioral score would 429 later tests (no User-Agent is +8
    // per request; WAF 403 is +20). This suite asserts spool/WAF outcomes, not the scorer.
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    std::thread::spawn(move || {
        spool::boot(&config).expect("spool boot");
        let proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            false,
        );
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
        let mut svc = Service::new(
            "test spool proxy".to_string(),
            filter.wrap(app, false, None),
        );
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn spool_config(origin: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["spool.test"]
backend = "http://{origin}"

[[sites.routes]]
prefix = "/api/payment"
inspection.require_complete = true
inspection.on_truncated = "deny"
inspection.on_parse_error = "deny"
inspection.max_decoded_body = "256KiB"
"#
    ))
}

fn temp_spool_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferroada-spool-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn read_full_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end = None;
    let mut content_length = None;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                content_length = parse_content_length(&buf[..pos + 4]);
            }
        }
        if let (Some(end), Some(cl)) = (header_end, content_length) {
            if buf.len() >= end + cl {
                buf.truncate(end + cl);
                return Some(buf);
            }
        }
        if buf.len() > 3 * 1024 * 1024 {
            break;
        }
    }
    None
}

fn send(addr: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
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
            if body.starts_with(b"HTTP/1.1") {
                return body;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("proxy não respondeu HTTP em {addr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn post(path: &str, body: &[u8], extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: spool.test\r\nUser-Agent: ferroada-spool-test\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn body_len(hit: &[u8]) -> usize {
    let pos = hit
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    hit.len() - (pos + 4)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn setup(origin: SocketAddr) -> (SocketAddr, std::path::PathBuf) {
    let dir = temp_spool_dir();
    std::env::set_var("SPOOL_DIR", &dir);
    let listen = free_bind();
    spawn_proxy(listen, spool_config(origin));
    (listen, dir)
}

#[test]
fn sqli_in_last_kib_is_blocked_by_match_not_truncation() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let (listen, dir) = setup(stub.addr);

    let mut body = vec![b'a'; 200 * 1024];
    let payload = b" UNION SELECT password FROM users";
    let start = body.len() - 1024;
    body[start..start + payload.len()].copy_from_slice(payload);
    let req = post("/api/payment", &body, &[("Content-Type", "text/plain")]);
    let response = send_until_http(listen, &req);
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "expected 403, got {}",
        String::from_utf8_lossy(&response[..response.len().min(200)])
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.to_ascii_lowercase().contains("sql"),
        "403 must be the SQLi match, not Truncated: {text}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "blocked spool request must not reach the origin"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clean_200kib_body_reaches_origin_in_full() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let (listen, dir) = setup(stub.addr);

    let body = vec![b'a'; 200 * 1024];
    let req = post("/api/payment", &body, &[("Content-Type", "text/plain")]);
    let response = send_until_http(listen, &req);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&response[..response.len().min(200)])
    );
    std::thread::sleep(Duration::from_millis(300));
    let hits = stub.hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "origin should see exactly one request");
    assert_eq!(body_len(&hits[0]), 200 * 1024);
    drop(hits);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zip_bomb_is_truncated_and_denied_on_require_complete() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let (listen, dir) = setup(stub.addr);

    let payload = gzip(&vec![0u8; 1024 * 1024]);
    let req = post(
        "/api/payment",
        &payload,
        &[("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
    );
    let response = send_until_http(listen, &req);
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "zip bomb Truncated + deny must be 403, got {}",
        String::from_utf8_lossy(&response[..response.len().min(240)])
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_route_still_413_at_64kib() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let (listen, dir) = setup(stub.addr);

    let body = vec![b'x'; 65_537];
    let req = post("/health", &body, &[("Content-Type", "text/plain")]);
    let response = send_until_http(listen, &req);
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "open route must stay at 64 KiB, got {}",
        String::from_utf8_lossy(&response[..response.len().min(200)])
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spool_max_bytes_is_503_and_file_is_gone() {
    let _guard = live_lock();
    std::env::set_var("SPOOL_MAX_BYTES", "1024");
    let stub = spawn_stub();
    let (listen, dir) = setup(stub.addr);

    let body = vec![b'a'; 2048];
    let req = post("/api/payment", &body, &[("Content-Type", "text/plain")]);
    let response = send_until_http(listen, &req);
    std::env::remove_var("SPOOL_MAX_BYTES");
    assert!(
        response.starts_with(b"HTTP/1.1 503"),
        "expected 503 on spool budget, got {}",
        String::from_utf8_lossy(&response[..response.len().min(200)])
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(
        leftovers.is_empty(),
        "spool file must vanish on Drop, found {leftovers:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn leftover_spool_star_is_wiped_on_boot_when_spool_is_on() {
    let _guard = live_lock();
    let dir = temp_spool_dir();
    let leftover = dir.join("spool-oom");
    std::fs::write(&leftover, b"pii").unwrap();
    std::env::set_var("SPOOL_DIR", &dir);
    let config = spool_config("127.0.0.1:9".parse().unwrap());
    spool::boot(&config).unwrap();
    assert!(!leftover.exists(), "leftover spool-* must go on boot");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn process_without_knob_does_not_create_default_spool_dir() {
    let missing = std::env::temp_dir().join(format!(
        "ferroada-no-spool-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let config = Config::from_target_url("http://127.0.0.1:9");
    assert!(!config.has_spool_routes());
    spool::boot(&config).unwrap();
    assert!(
        !missing.exists(),
        "boot without max_decoded_body must not mkdir"
    );
}
