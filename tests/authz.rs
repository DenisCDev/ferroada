//! Opt-in Unix-socket authorization callback (Level 3).
//!
//! JWT bindings already check claim == path/body. This asks the app whether
//! that principal may perform the action on the resource.

#![cfg(unix)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
use ferroada::metrics;
use ferroada::proxy::FerroadaProxy;
use ferroada::rate_limit::RateLimiter;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use pingora::apps::HttpServerOptions;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LIVE: Mutex<()> = Mutex::new(());
static JTI: AtomicU64 = AtomicU64::new(0);

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

struct TcpProbe {
    hits: Arc<AtomicU64>,
    addr: SocketAddr,
}

fn spawn_tcp_probe() -> TcpProbe {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            counted.fetch_add(1, Ordering::Relaxed);
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf);
        }
    });
    TcpProbe { hits, addr }
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
            "test authz proxy".to_string(),
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

fn status_line(response: &[u8]) -> &str {
    let end = response
        .iter()
        .position(|b| *b == b'\r')
        .unwrap_or(response.len());
    std::str::from_utf8(&response[..end]).unwrap_or("")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

const RSA_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZhGurAmmIhGSL
rlIbD9WrliuGtwhC+5daDHHne8Z40q2RrVappuJAhRlX2dHNWXb7DCcLjspAY6cT
fN0m5RyKDQMPlPPW2jJo4iY7yWkGX8O11c4x0ntglS8ABA65qnY2r19OyMvQA5SW
gEaDRlxUX3opgnMEqVTJWFcEsvaG7FR3ugjih2ymzBXESG2DwsFmPqIc2Q0iO7hD
R/k80QNBL1FBrYcstI2TlI0l2KE3kHpzyjio3LADa/O0Qw/dCSY8+U1OMGSoJkCs
X8vTWPVnpFUdAKbbl5VW/32RpiachNnJXh96/0JQp93Ep2XP3Om+HDDwKg68sMAz
l/u53YBjAgMBAAECggEAP0UGIsqxt+PolHDZwfF6vGb9tV3F9+U88Y3je+XVXIJn
qnxoFS+EW9b/JOfOwfU3RiwyA19sF7F6cFurwZX3dyX5tvhKrqfq0rMx0r4lnMzn
Gg/uFTaMRrf1UOpbL0YDxnHss8mpxidTm9tuNDhRYSygam8q/CbVnM3dv0AKvnwQ
wsVeIh8F4qjZOqjwjai7hlsagb8eM40+o26l+Ae3dvtJmv5xcxTr4uBC/75golKv
usYWPwxKYj5SRJwY6S5WWIFXikXqXt+pYzvyFHAejHdZjJtTjtbQrQEjjglUAPjf
cVxcYIZ1eH7sMp0LsmDmKyLAZ7v+F3uQmM9QVacmEQKBgQDHaWoT7swSZ1dn1Dqr
bHCzlJb1zqzP3Pu+qxRkb6pF+4wPJ9+vXViRkUeZmIMYyDptGDQ6TDcKzUvTtn6q
hyipO5xBqLHC2i00wrgJzuCo1wseLcdm2F+pKt9Zr1VM4qExgK0bcIn1pco6guLY
60VVpVubAMa2uzjwnr0pT4GqHwKBgQDFFO0+o3/Ur/PMjmQg/3FbpEmWKCG8/UKv
EoMRtvAc9Hru8Du1Gy34GyGoPXWtu8q5urCKjJ6Uhm9k1JdmI3E4rhym16hA0YlH
omf/ILZe1TN1fU8fpzjC3nvX/gVi8gJwGKiyVRRvRZ5MofUX9Y1Rcn/8+Zn+0rAg
0rV3xycpPQKBgG+9zkdlJM2bQwtXjZjJp026Ee2j5oqEFj19uGufdxbIIm/LtDic
YikP88NKBww4ByVizsFsO9u9tqPoO4prOom6cZEJarL5dyN9iYtVdeamugArPvWO
gexVrdqfuXjf9du7c0VRBr20LWIkPeG31J5tjquI/9EdkIalLPKdLteZAoGARlT9
hYkbqW9RdgKqwQvoDGhIyolv4N4Q2iGlHMFIV0z4QiUBadRVR2GHVV75jBKkejuh
nRAp159SSY2EqjKjyTJ5jyEPLnKYpzPSIT4vVxCG2LrrbcRjgUecsqw4h+MN86sZ
KOsr67nQkFCMAwzibdqKymDZEBNoP45yrFgqJZECgYEAuNd8JonT0MdYWMlrPF9+
sO0jbKx3IuXAR6Msde0ZseBTrnU1spFl8UuwEWOJhrwP2IjwodrN6nCTIT5nW3QI
9WdU26aRY5S8kvUsdraajGE3Bybm9eNNTrLZzlqSv84wQkT/OMt+HM1JmZ9F8ZeI
PjD2b1xN7IuKIjC0duBcuTw=
-----END PRIVATE KEY-----
";

fn seed_rand() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut buf = [0u8; 64];
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(31).wrapping_add(0x5A);
        }
        unsafe {
            openssl_sys::RAND_add(buf.as_ptr().cast(), buf.len() as i32, 64.0);
        }
    });
}

fn rsa() -> Rsa<openssl::pkey::Private> {
    seed_rand();
    Rsa::private_key_from_pem(RSA_PEM).unwrap()
}

fn sign_rs256(rsa: &Rsa<openssl::pkey::Private>, kid: &str, claims: &Value) -> String {
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": kid});
    let header_b64 = b64(&serde_json::to_vec(&header).unwrap());
    let payload_b64 = b64(&serde_json::to_vec(claims).unwrap());
    let signing = format!("{header_b64}.{payload_b64}");
    let pkey = PKey::from_rsa(rsa.clone()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    signer.update(signing.as_bytes()).unwrap();
    let sig = signer.sign_to_vec().unwrap();
    format!("{signing}.{}", b64(&sig))
}

fn rsa_jwk(rsa: &Rsa<openssl::pkey::Private>, kid: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64(&rsa.n().to_vec()),
        "e": b64(&rsa.e().to_vec()),
    })
}

fn claims(sub: &str, now: u64) -> Value {
    json!({
        "iss": "https://issuer.test",
        "aud": "api.test",
        "sub": sub,
        "exp": now + 600,
        "nbf": now - 5,
        "iat": now - 5,
        "jti": format!("jti-{}-{}", sub, JTI.fetch_add(1, Ordering::Relaxed)),
        "tenant_id": "tenant-a",
    })
}

struct JwksServer {
    addr: SocketAddr,
}

fn spawn_jwks(initial: &[u8]) -> JwksServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(Mutex::new(initial.to_vec()));
    let shared = Arc::clone(&body);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let mut buf = vec![0u8; 2048];
            let _ = stream.read(&mut buf);
            let payload = shared.lock().unwrap().clone();
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&payload);
        }
    });
    JwksServer { addr }
}

fn bearer_get(host: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-authz-test\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn events_for(uri: &str) -> Vec<Value> {
    let snapshot: Value = serde_json::from_str(&metrics::snapshot_json()).expect("metrics JSON");
    snapshot["recent_events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event["uri"].as_str() == Some(uri))
        .collect()
}

fn assert_no_token_leak(events: &[Value], token: &str) {
    for event in events {
        let dumped = event.to_string();
        assert!(
            !dumped.contains(token),
            "event must not contain the token: {event}"
        );
        assert!(
            !dumped.contains("eyJ"),
            "event must not contain JWT payload: {event}"
        );
    }
}

fn temp_sock() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fa-authz-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

struct AuthzSidecar {
    hits: Arc<Mutex<Vec<Vec<u8>>>>,
    path: std::path::PathBuf,
}

fn allow_body() -> &'static [u8] {
    let json = r#"{"allow":true}"#;
    let body = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    Box::leak(body.into_boxed_str()).as_bytes()
}

fn deny_body() -> &'static [u8] {
    let json = r#"{"allow":false}"#;
    let body = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    Box::leak(body.into_boxed_str()).as_bytes()
}

fn serve_authz(path: std::path::PathBuf, response: &'static [u8]) -> AuthzSidecar {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&hits);
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let mut buf = vec![0u8; 16 * 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            recorded.lock().unwrap().push(buf[..n].to_vec());
            let _ = stream.write_all(response);
        }
    });
    std::thread::sleep(Duration::from_millis(40));
    AuthzSidecar { hits, path }
}

fn hang_authz(path: std::path::PathBuf) {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(stream) = incoming else {
                continue;
            };
            std::thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
    });
    std::thread::sleep(Duration::from_millis(40));
}

fn authz_config(
    origin: SocketAddr,
    jwks: SocketAddr,
    socket: &std::path::Path,
    fail_mode: &str,
) -> Config {
    let sock = socket.display().to_string();
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["api.test"]
backend = "http://{origin}"
jwt = {{ jwks = "http://{jwks}/jwks.json", issuer = "https://issuer.test", audience = "api.test", paths = ["/accounts/{{account_id}}"] }}

[[sites.routes]]
prefix = "/accounts/"
authorization = {{ socket = "unix://{sock}", action = "transfer:create", resource = "path.account_id", fail_mode = "{fail_mode}" }}
"#
    ))
}

fn jwt_only_config(origin: SocketAddr, jwks: SocketAddr) -> Config {
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["api.test"]
backend = "http://{origin}"
jwt = {{ jwks = "http://{jwks}/jwks.json", issuer = "https://issuer.test", audience = "api.test", paths = ["/accounts/{{account_id}}"] }}
"#
    ))
}

fn boot(key: &Rsa<openssl::pkey::Private>) -> (JwksServer, Stub, SocketAddr) {
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    (jwks_srv, stub, listen)
}

#[test]
fn socket_allow_is_200_stub_1() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    let sidecar = serve_authz(sock.clone(), allow_body());
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sidecar.path, "closed"),
    );

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let response = send_until_http(listen, &bearer_get("api.test", "/accounts/allow-1", &token));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "socket allow must be 200, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "allow must reach origin"
    );
    let hits = sidecar.hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "authz socket must be called once");
    let wire = String::from_utf8_lossy(&hits[0]);
    assert!(
        wire.starts_with("POST /authorize"),
        "expected POST /authorize, got {wire}"
    );
    assert!(wire.contains(r#""principal":"user-1""#), "{wire}");
    assert!(wire.contains(r#""action":"transfer:create""#), "{wire}");
    assert!(wire.contains(r#""resource":"allow-1""#), "{wire}");
    assert!(wire.contains(r#""tenant":"tenant-a""#), "{wire}");
    assert!(
        !wire.contains("eyJ"),
        "socket request must not carry the JWT"
    );
    assert!(
        !wire.to_ascii_lowercase().contains("authorization: bearer"),
        "socket request must not forward the bearer token"
    );
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn socket_deny_is_403_stub_0_event_authz() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    let sidecar = serve_authz(sock.clone(), deny_body());
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sidecar.path, "closed"),
    );

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let path = "/accounts/deny-1";
    let response = send_until_http(listen, &bearer_get("api.test", path, &token));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "socket deny must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "deny must not reach origin"
    );
    let events = events_for(path);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"].as_str() == Some("authz")),
        "expected authz event, got {events:?}"
    );
    assert_no_token_leak(&events, &token);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn socket_down_closed_is_403_authz_unavailable() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    let _ = std::fs::remove_file(&sock);
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sock, "closed"),
    );

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let path = "/accounts/down-closed";
    let response = send_until_http(listen, &bearer_get("api.test", path, &token));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "socket down + closed must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for(path);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"].as_str() == Some("authz_unavailable")),
        "expected authz_unavailable event, got {events:?}"
    );
    assert_no_token_leak(&events, &token);
}

#[test]
fn socket_down_open_is_200_metric_authz_unavailable() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    let _ = std::fs::remove_file(&sock);
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sock, "open"),
    );

    let before = metrics::authz_unavailable();
    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let response = send_until_http(
        listen,
        &bearer_get("api.test", "/accounts/down-open", &token),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "socket down + open must pass, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "fail_mode=open must reach the origin"
    );
    assert!(
        metrics::authz_unavailable() > before,
        "authz_unavailable metric must rise"
    );
}

#[test]
fn route_without_authorization_does_not_talk_to_socket() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    let sidecar = serve_authz(sock.clone(), allow_body());
    spawn_proxy(listen, jwt_only_config(stub.addr, jwks_srv.addr));

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let response = send_until_http(listen, &bearer_get("api.test", "/health", &token));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "route without authorization must stay as today, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "request must reach the origin"
    );
    assert_eq!(
        sidecar.hits.lock().unwrap().len(),
        0,
        "route without authorization must not talk to the socket"
    );
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn get_does_not_open_tcp_to_a_remote_pdp() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let pdp = spawn_tcp_probe();
    let sock = temp_sock();
    let sidecar = serve_authz(sock.clone(), allow_body());
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sidecar.path, "closed"),
    );

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let response = send_until_http(
        listen,
        &bearer_get("api.test", "/accounts/tcp-check", &token),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "unix authz allow must be 200, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        pdp.hits.load(Ordering::Relaxed),
        0,
        "GET must not open TCP to a remote PDP at {}",
        pdp.addr
    );
    assert_eq!(sidecar.hits.lock().unwrap().len(), 1);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn hanging_socket_closed_is_403_timeout() {
    let _guard = live_lock();
    let key = rsa();
    let (jwks_srv, stub, listen) = boot(&key);
    let sock = temp_sock();
    hang_authz(sock.clone());
    spawn_proxy(
        listen,
        authz_config(stub.addr, jwks_srv.addr, &sock, "closed"),
    );

    let token = sign_rs256(&key, "k1", &claims("user-1", unix_now()));
    let path = "/accounts/hang-1";
    let response = send_until_http(listen, &bearer_get("api.test", path, &token));
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "hanging socket + closed must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for(path);
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("authz_unavailable")
                && event["detail"].as_str() == Some("timeout")
        }),
        "expected timeout authz_unavailable, got {events:?}"
    );
    let _ = std::fs::remove_file(&sock);
}
