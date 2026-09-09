//! PR 10: DLP_ACTION + origin secret. Monitor leaves CPF intact; block overflow is 502.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::dlp::DlpAction;
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

struct Stub {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
    addr: SocketAddr,
}

fn spawn_stub(response: &'static [u8]) -> Stub {
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
            let Some(buf) = read_request_head(&mut stream) else {
                continue;
            };
            recorded.lock().unwrap().push(buf);
            let _ = stream.write_all(response);
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

fn spawn_proxy(
    listen: SocketAddr,
    config: Config,
    action: DlpAction,
    secret: Option<(String, String)>,
) {
    std::env::set_var("DLP_MAX_RESPONSE_BYTES", "1024");
    std::thread::spawn(move || {
        let mut proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            false,
        )
        .with_dlp_action(action);
        if let Some((header, value)) = secret {
            proxy = proxy.with_origin_secret(header, value);
        }
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
        let mut svc = Service::new("test dlp proxy".to_string(), filter.wrap(app, false, None));
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn dlp_config(origin: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["dlp.test"]
backend = "http://{origin}"
"#
    ))
}

fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Some(buf);
        }
        if buf.len() > 64 * 1024 {
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

fn get() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: dlp.test\r\nConnection: close\r\n\r\n".to_vec()
}

fn get_with_forged_origin() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: dlp.test\r\nX-Ferroada-Origin: forged\r\nConnection: close\r\n\r\n"
        .to_vec()
}

fn setup(
    response: &'static [u8],
    action: DlpAction,
    secret: Option<(String, String)>,
) -> (SocketAddr, Stub) {
    let stub = spawn_stub(response);
    let listen = free_bind();
    spawn_proxy(listen, dlp_config(stub.addr), action, secret);
    (listen, stub)
}

#[test]
fn monitor_leaves_cpf_intact_and_counts_detection() {
    let _guard = live_lock();
    const BODY: &[u8] = b"CPF 123.456.789-00";
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\nCPF 123.456.789-00";
    assert_eq!(BODY.len(), 18);
    let (listen, _stub) = setup(response, DlpAction::Monitor, None);
    let out = send_until_http(listen, &get());
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    assert!(
        out.windows(BODY.len()).any(|window| window == BODY),
        "monitor must leave CPF intact: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.windows(14).any(|window| window == b"***.***.***-**"),
        "monitor must not redact: {}",
        String::from_utf8_lossy(&out)
    );
    let snap = ferroada::metrics::snapshot_json();
    assert!(
        snap.contains("Detected") && snap.contains("CPFs"),
        "monitor must count detection: {snap}"
    );
}

#[test]
fn block_overflow_is_502_not_partial_body() {
    let _guard = live_lock();
    const MARKER: &[u8] = b"PARTIAL-SECRET-BODY";
    // Content-Length above DLP_MAX_RESPONSE_BYTES default (1 MiB) trips block in
    // response_filter before any origin body is written downstream.
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\nPARTIAL-SECRET-BODY";
    let (listen, _stub) = setup(response, DlpAction::Block, None);
    let out = send_until_http(listen, &get());
    assert!(
        out.starts_with(b"HTTP/1.1 502"),
        "expected 502, got {}",
        String::from_utf8_lossy(&out[..out.len().min(240)])
    );
    assert!(
        !out.windows(MARKER.len()).any(|window| window == MARKER),
        "block overflow must not flush origin body: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn block_delayed_chunked_overflow_is_502_not_partial_body() {
    let _guard = live_lock();
    const MARKER: &[u8] = b"PARTIAL-SECRET-BODY";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        listener.set_nonblocking(false).ok();
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let _ = read_request_head(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(600));
            let mut chunk = Vec::from(MARKER);
            chunk.resize(2000, b'x');
            let _ = stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes());
            let _ = stream.write_all(&chunk);
            let _ = stream.write_all(b"\r\n0\r\n\r\n");
        }
    });
    let listen = free_bind();
    spawn_proxy(listen, dlp_config(origin), DlpAction::Block, None);
    let out = send_until_http(listen, &get());
    assert!(
        out.starts_with(b"HTTP/1.1 502"),
        "expected 502, got {}",
        String::from_utf8_lossy(&out[..out.len().min(240)])
    );
    assert!(
        !out.windows(MARKER.len()).any(|window| window == MARKER),
        "block overflow must not flush origin body: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn origin_secret_header_is_injected_on_upstream() {
    let _guard = live_lock();
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let (listen, stub) = setup(
        response,
        DlpAction::Monitor,
        Some((
            "X-Ferroada-Origin".to_string(),
            "origin-lock-token".to_string(),
        )),
    );
    let out = send_until_http(listen, &get_with_forged_origin());
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    std::thread::sleep(Duration::from_millis(200));
    let hits = stub.hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "origin should see the request");
    let head = String::from_utf8_lossy(&hits[0]).to_ascii_lowercase();
    assert!(
        head.contains("x-ferroada-origin: origin-lock-token"),
        "missing origin secret on upstream: {head}"
    );
    assert!(
        !head.contains("x-ferroada-origin: forged"),
        "client-forged origin secret must be replaced: {head}"
    );
}

#[test]
fn empty_origin_secret_strips_client_forged_header() {
    let _guard = live_lock();
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let (listen, stub) = setup(response, DlpAction::Monitor, None);
    let out = send_until_http(listen, &get_with_forged_origin());
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    std::thread::sleep(Duration::from_millis(200));
    let hits = stub.hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "origin should see the request");
    let head = String::from_utf8_lossy(&hits[0]).to_ascii_lowercase();
    assert!(
        !head.contains("x-ferroada-origin"),
        "empty ORIGIN_SECRET must strip client header, got: {head}"
    );
}
