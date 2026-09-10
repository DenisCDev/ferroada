//! OpenAPI request validation (PR 13). Spec is compiled at load; no spec = Level 1.

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
use std::path::PathBuf;
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
            let mut buf = vec![0u8; 8192];
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

fn spec_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openapi-pets.yaml")
        .to_string_lossy()
        .replace('\\', "/")
}

fn spec_config(origin: SocketAddr, unknown: &str) -> Config {
    let spec = spec_path();
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["pets.test"]
backend = "http://{origin}"
openapi = {{ spec = "{spec}", unknown_endpoint = "{unknown}" }}

[[sites]]
hosts = ["plain.test"]
backend = "http://{origin}"
"#
    ))
}

fn require_complete_config(origin: SocketAddr) -> Config {
    let spec = spec_path();
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["pets.test"]
backend = "http://{origin}"
require_complete_waf_inspection = ["/"]
openapi = "{spec}"
"#
    ))
}

fn spawn_proxy(listen: SocketAddr, config: Config) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
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
            "test openapi proxy".to_string(),
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

fn request(host: &str, method: &str, path: &str, extra: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-openapi-test\r\nConnection: close\r\n"
    )
    .into_bytes();
    req.extend_from_slice(extra);
    if extra.is_empty() {
        req.extend_from_slice(b"\r\n");
    }
    req
}

fn post_json(host: &str, path: &str, body: &str) -> Vec<u8> {
    request(
        host,
        "POST",
        path,
        &format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
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
fn get_known_pet_is_200() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let response = send_until_http(listen, &request("pets.test", "GET", "/pets/1", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "GET /pets/1 must pass, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "known GET must reach the origin"
    );
}

#[test]
fn unknown_endpoint_deny_is_403_with_event_and_zero_stub() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let response = send_until_http(listen, &request("pets.test", "GET", "/nao-existe", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "unknown endpoint + deny must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "deny must not reach the origin"
    );
    let events = events_for("/nao-existe");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("openapi")
                && event["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("unknown_endpoint"))
        }),
        "expected openapi unknown_endpoint event, got {events:?}"
    );
}

#[test]
fn post_body_outside_schema_is_403_zero_stub() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let body = r#"{"name":"secret-value-xyz","is_admin":true}"#;
    let response = send_until_http(listen, &post_json("pets.test", "/pets", body));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "extra field must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/pets");
    assert!(
        events.iter().any(|event| {
            let detail = event["detail"].as_str().unwrap_or("");
            event["event_type"].as_str() == Some("openapi")
                && detail.contains("/is_admin")
                && detail.contains("additionalProperties")
                && !detail.contains("secret-value-xyz")
        }),
        "event must name the field and must not dump the body, got {events:?}"
    );
}

#[test]
fn post_unlisted_xml_content_type_is_403() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let xml = "<pet/>";
    let payload = request(
        "pets.test",
        "POST",
        "/pets",
        &format!(
            "Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{xml}",
            xml.len()
        )
        .into_bytes(),
    );
    let response = send_until_http(listen, &payload);
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "xml content-type must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/pets");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("openapi")
                && event["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("unknown_content_type"))
        }),
        "expected unknown_content_type event, got {events:?}"
    );
}

#[test]
fn site_without_spec_does_not_403_unknown_endpoint() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let response = send_until_http(listen, &request("plain.test", "GET", "/nao-existe", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "site without spec must stay Level 1, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "site without spec must reach the origin"
    );
}

#[test]
fn require_complete_defaults_unknown_endpoint_to_deny() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, require_complete_config(stub.addr));

    let response = send_until_http(listen, &request("pets.test", "GET", "/nao-existe", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "require_complete default must deny unknown endpoint, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
}

#[test]
fn unknown_endpoint_observe_reaches_origin_and_records_event() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "observe"));

    let response = send_until_http(listen, &request("pets.test", "GET", "/nao-existe", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "observe must not 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(!stub.hits.lock().unwrap().is_empty());
    let events = events_for("/nao-existe");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("openapi_observe")
                && event["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("unknown_endpoint"))
        }),
        "observe must still emit an event, got {events:?}"
    );
}

#[test]
fn openapi_body_still_denies_when_protocol_skips_waf_body() {
    let _guard = live_lock();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, spec_config(stub.addr, "deny"));

    let body = r#"{"name":"rex","is_admin":true}"#;
    let payload = request(
        "pets.test",
        "POST",
        "/pets",
        &format!(
            "Content-Type: application/json\r\nContent-Encoding: zstd\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let response = send_until_http(listen, &payload);
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "OpenAPI body must still deny when WAF body is skipped, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "schema deny must not reach the origin even if protocol skips WAF body"
    );
}
