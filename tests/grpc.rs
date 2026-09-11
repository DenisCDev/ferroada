//! gRPC method allowlist (PR 17). Opt-in; no grpc block = protocol matrix.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::grpc;
use ferroada::metrics;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use ferroada::spool;
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00\x00\x00\x00\x00");
        }
    });
    Stub { hits, addr }
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
        if let Some(end) = header_end {
            let need = content_length.unwrap_or(0);
            if buf.len() >= end + need {
                buf.truncate(end + need);
                return Some(buf);
            }
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    None
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn free_bind() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn write_descriptor(dir: &std::path::Path) -> String {
    let path = dir.join("api.pb");
    std::fs::write(&path, grpc::test_hello_descriptor_bytes()).unwrap();
    path.to_string_lossy().replace('\\', "/")
}

fn grpc_config(origin: SocketAddr, dir: &std::path::Path) -> Config {
    let descriptor = write_descriptor(dir);
    Config::from_toml_in(
        &format!(
            r#"
[[sites]]
hosts = ["grpc.test"]
backend = "http://{origin}"
require_complete_waf_inspection = ["/pkg.Service/", "/grpc.reflection.v1.ServerReflection/"]
grpc = {{ descriptor = "{descriptor}", allow = ["pkg.Service/Allowed"], max_message_bytes = "16", reflection = false }}

[[sites.routes]]
prefix = "/pkg.Service/"
inspection.require_complete = true
inspection.on_parse_error = "deny"
inspection.max_decoded_body = "64KiB"

[[sites.routes]]
prefix = "/grpc.reflection.v1.ServerReflection/"
inspection.require_complete = true
inspection.on_parse_error = "deny"
inspection.max_decoded_body = "64KiB"

[[sites]]
hosts = ["plain.test"]
backend = "http://{origin}"

[[sites.routes]]
prefix = "/pkg.Service/"
inspection.require_complete = true
inspection.max_decoded_body = "64KiB"
"#
        ),
        dir,
    )
}

fn bypass_config(origin: SocketAddr, dir: &std::path::Path) -> Config {
    Config::from_toml_in(
        &format!(
            r#"
[protocols]
grpc = "bypass-explicit"

[[sites]]
hosts = ["plain.test"]
backend = "http://{origin}"

[[sites.routes]]
prefix = "/pkg.Service/"
inspection.require_complete = true
inspection.max_decoded_body = "64KiB"
"#
        ),
        dir,
    )
}

fn temp_spool_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferroada-grpc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn_proxy(listen: SocketAddr, config: Config) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    let dir = temp_spool_dir();
    std::env::set_var("SPOOL_DIR", &dir);
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
        let mut svc = Service::new("test grpc proxy".to_string(), filter.wrap(app, false, None));
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

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn hello_req(name: &str) -> Vec<u8> {
    let mut msg = vec![0x0A, name.len() as u8];
    msg.extend_from_slice(name.as_bytes());
    grpc_frame(&msg)
}

fn post_grpc(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-grpc-test\r\nConnection: close\r\nContent-Type: application/grpc\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn post_grpc_proto(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    post_grpc_proto_with_timeout(host, path, body, None)
}

fn post_grpc_proto_with_timeout(
    host: &str,
    path: &str,
    body: &[u8],
    timeout: Option<&str>,
) -> Vec<u8> {
    let timeout_line = match timeout {
        Some(value) => format!("grpc-timeout: {value}\r\n"),
        None => String::new(),
    };
    let mut out = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-grpc-test\r\nConnection: close, grpc-timeout\r\n{timeout_line}Content-Type: application/grpc+proto\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn events_for(uri: &str) -> Vec<serde_json::Value> {
    let snapshot: serde_json::Value =
        serde_json::from_str(&metrics::snapshot_json()).expect("metrics JSON");
    snapshot["recent_events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event["uri"].as_str() == Some(uri))
        .collect()
}

fn status_line(response: &[u8]) -> &str {
    let end = response
        .iter()
        .position(|b| *b == b'\r')
        .unwrap_or(response.len());
    std::str::from_utf8(&response[..end]).unwrap_or("")
}

#[test]
fn allowed_method_with_descriptor_is_200_stub_1() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let response = send_until_http(
        listen,
        &post_grpc_proto("grpc.test", "/pkg.Service/Allowed", &hello_req("ok")),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "allowed method must pass, got {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );
    std::thread::sleep(Duration::from_millis(80));
    let hits = stub.hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "allowed method must reach the origin once");
    let upstream = String::from_utf8_lossy(&hits[0]);
    assert!(
        upstream.to_ascii_lowercase().contains("grpc-timeout: 10s"),
        "missing timeout must be injected after hop-by-hop strip, got {upstream}"
    );
}

#[test]
fn client_timeout_survives_connection_hop_by_hop() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let response = send_until_http(
        listen,
        &post_grpc_proto_with_timeout(
            "grpc.test",
            "/pkg.Service/Allowed",
            &hello_req("ok"),
            Some("1S"),
        ),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "valid client timeout must pass, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    let hits = stub.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    let upstream = String::from_utf8_lossy(&hits[0]);
    assert!(
        upstream.to_ascii_lowercase().contains("grpc-timeout: 1s"),
        "client timeout must be restamped after Connection strip, got {upstream}"
    );
}

#[test]
fn unknown_method_is_403_stub_0() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let response = send_until_http(
        listen,
        &post_grpc("grpc.test", "/pkg.Service/Unknown", &hello_req("ok")),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "unknown method must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "deny must not hit origin"
    );
    let events = events_for("/pkg.Service/Unknown");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("grpc")
                && event["detail"].as_str() == Some("pkg.Service/Unknown")
                && !event["detail"].as_str().unwrap_or("").contains('\x0a')
        }),
        "expected grpc event with service/method and no payload, got {events:?}"
    );
}

#[test]
fn message_over_max_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let body = vec![0, 0, 0, 0, 17];
    let response = send_until_http(
        listen,
        &post_grpc("grpc.test", "/pkg.Service/Allowed", &body),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "oversized message must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/pkg.Service/Allowed");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("grpc")
                && event["detail"].as_str() == Some("pkg.Service/Allowed")
        }),
        "expected grpc size event with service/method, got {events:?}"
    );
}

#[test]
fn server_reflection_info_with_reflection_off_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
    let response = send_until_http(listen, &post_grpc("grpc.test", path, &grpc_frame(&[])));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "reflection must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for(path);
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("grpc")
                && event["detail"].as_str()
                    == Some("grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
        }),
        "expected reflection event, got {events:?}"
    );
}

#[test]
fn garbage_protobuf_on_fail_closed_is_403_parse_error() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let body = vec![0, 0, 0, 0, 1, 0xFF];
    let response = send_until_http(
        listen,
        &post_grpc("grpc.test", "/pkg.Service/Allowed", &body),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "invalid protobuf fail-closed must be 403, got {}",
        status_line(&response)
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("ParseError"),
        "response must name ParseError, got {text}"
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
}

#[test]
fn site_without_grpc_block_follows_protocol_matrix_deny() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, grpc_config(stub.addr, &dir));

    let response = send_until_http(
        listen,
        &post_grpc("plain.test", "/pkg.Service/MatrixDeny", &hello_req("ok")),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "site without grpc block must keep matrix deny, got {}",
        status_line(&response)
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("gRPC não é suportado"),
        "matrix deny reason, got {text}"
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/pkg.Service/MatrixDeny");
    assert!(
        events
            .iter()
            .any(|event| event["event_type"].as_str() == Some("protocol_deny")),
        "expected protocol_deny, not grpc inspect, got {events:?}"
    );
    assert!(
        events
            .iter()
            .all(|event| event["event_type"].as_str() != Some("grpc")),
        "site without block must not emit grpc allowlist events, got {events:?}"
    );
}

#[test]
fn site_without_grpc_block_and_matrix_bypass_does_not_inspect() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    let dir = temp_spool_dir();
    spawn_proxy(listen, bypass_config(stub.addr, &dir));

    let response = send_until_http(
        listen,
        &post_grpc("plain.test", "/pkg.Service/Unknown", &hello_req("ok")),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "bypass matrix must not start inspecting methods, got {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "bypass without grpc block must reach the origin"
    );
}
