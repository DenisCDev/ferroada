//! GraphQL AST limits (PR 16). Opt-in; no graphql block = Level 1.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
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

fn gql_config(origin: SocketAddr) -> Config {
    // Spool is only so POST 200 can replay the body to the stub (same as
    // tests/spool.rs). GraphQL itself runs in request_filter on the buffered
    // body; the 403 cases do not need origin.
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["gql.test"]
backend = "http://{origin}"
require_complete_waf_inspection = ["/gql"]
graphql = {{ max_depth = 3, max_operations = 5, introspection = false }}

[[sites.routes]]
prefix = "/gql"
inspection.require_complete = true
inspection.on_parse_error = "deny"
inspection.max_decoded_body = "64KiB"

[[sites]]
hosts = ["plain.test"]
backend = "http://{origin}"

[[sites.routes]]
prefix = "/gql"
inspection.require_complete = true
inspection.max_decoded_body = "64KiB"
"#
    ))
}

fn temp_spool_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferroada-gql-{}-{}",
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
        let mut svc = Service::new(
            "test graphql proxy".to_string(),
            filter.wrap(app, false, None),
        );
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

fn post_json(host: &str, path: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-graphql-test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
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
fn shallow_query_within_ceiling_is_200_stub_1() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let body = r#"{"query":"{ user { id } }"}"#;
    let response = send_until_http(listen, &post_json("gql.test", "/gql/ok", body));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "shallow query must pass, got {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "shallow query must reach the origin once"
    );
}

#[test]
fn depth_over_max_is_403_stub_0_event_depth() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let body = r#"{"query":"{ a { b { c { d } } } }"}"#;
    let response = send_until_http(listen, &post_json("gql.test", "/gql/deep", body));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "deep query must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "deny must not hit origin"
    );
    let events = events_for("/gql/deep");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("graphql")
                && event["detail"].as_str() == Some("depth")
                && !event["detail"].as_str().unwrap_or("").contains("{ a { b")
        }),
        "expected graphql depth event without the query, got {events:?}"
    );
}

#[test]
fn schema_with_introspection_off_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let body = r#"{"query":"{ __schema { types { name } } }"}"#;
    let response = send_until_http(listen, &post_json("gql.test", "/gql/schema", body));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "__schema must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/gql/schema");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("graphql")
                && event["detail"].as_str() == Some("introspection")
        }),
        "expected introspection event, got {events:?}"
    );
}

#[test]
fn batch_of_20_with_max_operations_5_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let item = r#"{"query":"{ user { id } }"}"#;
    let body = format!("[{}]", vec![item; 20].join(","));
    let response = send_until_http(listen, &post_json("gql.test", "/gql/batch", &body));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "batch of 20 must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/gql/batch");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("graphql")
                && event["detail"].as_str() == Some("operations")
        }),
        "expected operations event, got {events:?}"
    );
}

#[test]
fn invalid_query_on_fail_closed_is_403_parse_error() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let body = r#"{"query":"not graphql"}"#;
    let response = send_until_http(listen, &post_json("gql.test", "/gql/parse", body));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "invalid query fail-closed must be 403, got {}",
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
fn site_without_graphql_block_does_not_403_on_depth() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, gql_config(stub.addr));

    let body = r#"{"query":"{ a { b { c { d } } } }"}"#;
    let response = send_until_http(listen, &post_json("plain.test", "/gql/plain", body));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "site without graphql must stay Level 1, got {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "site without graphql must reach the origin"
    );
}
