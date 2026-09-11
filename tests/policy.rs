//! Signed policy snapshots and last-known-good (PR 18). No control plane.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::connection::ConnectionRateFilter;
use ferroada::metrics;
use ferroada::policy::PolicyStore;
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferroada-policy-it-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn site_toml(host: &str, origin: SocketAddr) -> String {
    format!("[[sites]]\nhosts = [\"{host}\"]\nbackend = \"http://{origin}\"\n")
}

fn spawn_proxy(listen: SocketAddr, store: Arc<PolicyStore>) {
    std::env::set_var("BEHAVIORAL_ENABLED", "false");
    std::thread::spawn(move || {
        let proxy = FerroadaProxy::from_policy(
            store,
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
            "test policy proxy".to_string(),
            filter.wrap(app, false, None),
        );
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn send(addr: SocketAddr, host: &str) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let _ = stream.flush();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Some(buf)
}

fn send_until_http(addr: SocketAddr, host: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(body) = send(addr, host) {
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

fn snapshot_has_event(event_type: &str, needle: &str) -> bool {
    let json = metrics::snapshot_json();
    json.contains(&format!("\"event_type\": \"{event_type}\"")) && json.contains(needle)
}

#[test]
fn valid_toml_on_boot_proxies_the_request() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let dir = temp_dir();
    let path = dir.join("ferroada.toml");
    std::fs::write(&path, site_toml("boot.policy.test", stub.addr)).unwrap();
    let store = Arc::new(PolicyStore::from_toml_path(path).expect("boot"));
    let listen = free_bind();
    spawn_proxy(listen, Arc::clone(&store));
    let response = send_until_http(listen, "boot.policy.test");
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while stub.hits.lock().unwrap().is_empty() {
        if std::time::Instant::now() >= deadline {
            panic!("stub saw no request");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn broken_toml_reload_keeps_200_and_records_rejection() {
    let _lock = live_lock();
    let stub = spawn_stub();
    let dir = temp_dir();
    let path = dir.join("ferroada.toml");
    std::fs::write(&path, site_toml("keep.policy.test", stub.addr)).unwrap();
    let store = Arc::new(PolicyStore::from_toml_path(path.clone()).expect("boot"));
    let before = store.snapshot().policy_version;
    let listen = free_bind();
    spawn_proxy(listen, Arc::clone(&store));
    assert_eq!(status(&send_until_http(listen, "keep.policy.test")), 200);

    std::fs::write(&path, "[[[ not toml").unwrap();
    let err = store.try_reload().expect_err("broken toml");
    assert!(
        err.contains("TOML") || err.contains("Invalid") || err.contains("inválid"),
        "{err}"
    );
    assert_eq!(store.snapshot().policy_version, before);
    assert_eq!(status(&send_until_http(listen, "keep.policy.test")), 200);
    assert!(
        snapshot_has_event("policy_reload_rejected", &before),
        "{}",
        metrics::snapshot_json()
    );
}

#[test]
fn valid_reload_swaps_host_routing() {
    let _lock = live_lock();
    std::env::remove_var("FERROADA_POLICY_PUBKEY");
    std::env::remove_var("FERROADA_POLICY_SIG");
    let stub = spawn_stub();
    let dir = temp_dir();
    let path = dir.join("ferroada.toml");
    std::fs::write(&path, site_toml("old.policy.test", stub.addr)).unwrap();
    let store = Arc::new(PolicyStore::from_toml_path(path.clone()).expect("boot"));
    let before = store.snapshot().policy_version;
    let listen = free_bind();
    spawn_proxy(listen, Arc::clone(&store));
    assert_eq!(status(&send_until_http(listen, "old.policy.test")), 200);

    std::fs::write(&path, site_toml("new.policy.test", stub.addr)).unwrap();
    let outcome = store.try_reload().expect("valid reload");
    assert_ne!(outcome.version, before);
    assert_eq!(status(&send_until_http(listen, "old.policy.test")), 421);
    assert_eq!(status(&send_until_http(listen, "new.policy.test")), 200);
    assert!(
        snapshot_has_event("policy_reload", &outcome.version),
        "{}",
        metrics::snapshot_json()
    );
}

#[test]
fn unsigned_toml_still_boots_without_pubkey() {
    let _lock = live_lock();
    std::env::remove_var("FERROADA_POLICY_PUBKEY");
    std::env::remove_var("FERROADA_POLICY_SIG");
    let stub = spawn_stub();
    let dir = temp_dir();
    let path = dir.join("ferroada.toml");
    std::fs::write(&path, site_toml("loose.policy.test", stub.addr)).unwrap();
    let store = PolicyStore::from_toml_path(path).expect("unsigned toml must boot");
    assert!(!store.snapshot().signed);
    let listen = free_bind();
    spawn_proxy(listen, Arc::new(store));
    assert_eq!(status(&send_until_http(listen, "loose.policy.test")), 200);
}
