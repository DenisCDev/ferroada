//! PR 15: field-aware DLP, check digits, block commit-point, brotli budget.

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

fn spawn_proxy(listen: SocketAddr, config: Config, action: DlpAction) {
    std::env::set_var("DLP_MAX_RESPONSE_BYTES", "1024");
    std::thread::spawn(move || {
        let proxy = FerroadaProxy::new(
            Arc::new(config),
            Arc::new(RateLimiter::new(10_000, 60, 50_000)),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            false,
        )
        .with_dlp_action(action);
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
        let mut svc = Service::new("test dlp fields".to_string(), filter.wrap(app, false, None));
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn field_config(origin: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["fields.test"]
backend = "http://{origin}"

[[sites.dlp.fields]]
path = "$.user.cpf"
detector = "cpf"

[[sites.dlp.fields]]
path = "$.card"
detector = "card"

[[sites]]
hosts = ["blob.test"]
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

fn get(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

fn brotli_compress(body: &[u8]) -> Vec<u8> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    encoder.write_all(body).unwrap();
    encoder.flush().unwrap();
    encoder.into_inner()
}

fn http_response(content_type: &str, extra: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for (name, value) in extra {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

#[test]
fn json_field_redact_masks_cpf_and_origin_saw_the_request() {
    let _guard = live_lock();
    const BODY: &[u8] = br#"{"user":{"cpf":"390.533.447-05"}}"#;
    let response = http_response("application/json", &[], BODY);
    let leaked: &'static [u8] = Box::leak(response.into_boxed_slice());
    let stub = spawn_stub(leaked);
    let listen = free_bind();
    spawn_proxy(listen, field_config(stub.addr), DlpAction::Redact);
    let out = send_until_http(listen, &get("fields.test"));
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("***.***.***-**"),
        "redact must mask the CPF field: {text}"
    );
    assert!(
        !text.contains("390.533.447-05"),
        "redact must not leak the CPF: {text}"
    );
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "origin stub must see the original request"
    );
}

#[test]
fn invalid_cpf_is_not_masked() {
    let _guard = live_lock();
    const BODY: &[u8] = br#"{"user":{"cpf":"123.456.789-00"}}"#;
    let response = http_response("application/json", &[], BODY);
    let leaked: &'static [u8] = Box::leak(response.into_boxed_slice());
    let stub = spawn_stub(leaked);
    let listen = free_bind();
    spawn_proxy(listen, field_config(stub.addr), DlpAction::Redact);
    let out = send_until_http(listen, &get("fields.test"));
    assert!(out.starts_with(b"HTTP/1.1 200"));
    assert!(
        out.windows(BODY.len()).any(|window| window == BODY),
        "invalid CPF must stay intact: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.windows(14).any(|window| window == b"***.***.***-**"),
        "invalid CPF must not be masked: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn luhn_card_in_block_is_502_with_zero_origin_bytes_on_client() {
    let _guard = live_lock();
    const CARD: &[u8] = b"4111111111111111";
    const BODY: &[u8] = b"4111111111111111";
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
            std::thread::sleep(Duration::from_millis(400));
            let _ = stream.write_all(format!("{:x}\r\n", BODY.len()).as_bytes());
            let _ = stream.write_all(BODY);
            let _ = stream.write_all(b"\r\n0\r\n\r\n");
        }
    });
    let listen = free_bind();
    spawn_proxy(listen, field_config(origin), DlpAction::Block);
    let out = send_until_http(listen, &get("fields.test"));
    assert!(
        out.starts_with(b"HTTP/1.1 502"),
        "expected 502, got {}",
        String::from_utf8_lossy(&out[..out.len().min(240)])
    );
    assert!(
        !out.windows(CARD.len()).any(|window| window == CARD),
        "block must not flush the card to the client: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.windows(b"HTTP/1.1 200".len())
            .any(|window| window == b"HTTP/1.1 200"),
        "block must not flush a partial 200: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn brotli_without_budget_is_observable_skip_not_silent_redact() {
    let _guard = live_lock();
    let mut plain = Vec::from(b"CPF 390.533.447-05 ".as_slice());
    plain.resize(2048, b'x');
    let compressed = brotli_compress(&plain);
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    response.extend_from_slice(&compressed);
    let leaked: &'static [u8] = Box::leak(response.into_boxed_slice());
    let stub = spawn_stub(leaked);
    let listen = free_bind();
    spawn_proxy(listen, field_config(stub.addr), DlpAction::Redact);
    let out = send_until_http(listen, &get("fields.test"));
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    assert!(
        !out.windows(14).any(|window| window == b"***.***.***-**"),
        "over-budget brotli must not silently redact: {}",
        String::from_utf8_lossy(&out)
    );
    let snap = ferroada::metrics::snapshot_json();
    assert!(
        snap.contains("dlp_skip")
            && snap.contains("could not be inspected within the configured limit"),
        "over-budget brotli must be an observable skip: {snap}"
    );
}

#[test]
fn site_without_field_paths_keeps_blob_dlp() {
    let _guard = live_lock();
    const BODY: &[u8] = b"CPF 390.533.447-05";
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\nCPF 390.533.447-05";
    let stub = spawn_stub(response);
    let listen = free_bind();
    spawn_proxy(listen, field_config(stub.addr), DlpAction::Redact);
    let out = send_until_http(listen, &get("blob.test"));
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "expected 200, got {}",
        String::from_utf8_lossy(&out[..out.len().min(200)])
    );
    assert!(
        out.windows(14).any(|window| window == b"***.***.***-**"),
        "blob DLP must still mask a valid CPF: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.windows(BODY.len()).any(|window| window == BODY),
        "blob DLP must not leave the CPF intact: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn signed_response_is_not_transformed() {
    let _guard = live_lock();
    const BODY: &[u8] = br#"{"user":{"cpf":"390.533.447-05"}}"#;
    let response = http_response("application/json", &[("Signature", "sig1")], BODY);
    let leaked: &'static [u8] = Box::leak(response.into_boxed_slice());
    let stub = spawn_stub(leaked);
    let listen = free_bind();
    spawn_proxy(listen, field_config(stub.addr), DlpAction::Redact);
    let out = send_until_http(listen, &get("fields.test"));
    assert!(out.starts_with(b"HTTP/1.1 200"));
    assert!(
        out.windows(BODY.len()).any(|window| window == BODY),
        "signed response must stay intact: {}",
        String::from_utf8_lossy(&out)
    );
}
