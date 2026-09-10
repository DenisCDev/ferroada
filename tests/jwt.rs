//! JWT/JWKS identity and declarative bindings (PR 14).

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
        let mut svc = Service::new("test jwt proxy".to_string(), filter.wrap(app, false, None));
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

const RSA_ALT_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCTe9DIhpxjfGo5
nXQ4BbjCVOHB8jFPPDYTRqCYwswPxxOBT50gHT0HcfKBHoFPATCcMP8X/sa3f8Ui
jfdo35nXK5ZgLCjeuys/fUfhecdrErBgg86OlR5aWxjOFAwJPIZV/MhRkgBdZJgV
YRR6HIIpOmn391T3DB2+IxOd7ZX9M1OQNCEanyxjqRMCA1y9gZ9YoLXbfF+CKvwR
11IzZygj93htEcy35XOYXH6COoy/7WK6nJBE3jjojC6IYEVHfwVxBbAfwyZCN/PI
v9DQ93CWmDh1HIn5jDcl8Sct2BxpWrV5imJ3bJbWNSHSl3whDl00d5ExnXbCtIiu
pFCnkRJjAgMBAAECggEARYxYy4c3Dm8oRJ0sphKEqxeOEoCcoinZskNXDlKmGjad
yxf5F6DSG8WvPxZckh4Uh0NPuEgL+5KEKyRZbJotGNvUIOwSJd6LqXfxwrFDyglZ
JVpiuLg3RRK6YsvvVRe2nawD5vt7so7ybPqHxoHVG44RVL7M0WdkSzqNUKcuWOT4
6URXT2fJXOAO8EgGPY01rH0jrUxbQkKGr6MTpqE1lwhwDWbv3dIxlicgTvOlqZ04
baJVRuzPnITqLKyl7hRgmxw+hdJgOaOEOtoJdEd1C3cOEeabH/vvsuiywsGO3162
f5Vw/KSL5VMSlk9O8ECYCp3rxMQZMK4gFf8bmxFfAQKBgQDLeaP15p7n/vYC+8TK
NTvHjTG1lIZKYnTzKf+PmTJC80yYUzFOZpHryOu+DZrgwb7HBikyof6tOHKqfPOj
28jaWVYUw3jVPv2azasrCIhNLRrDpwfBDfZ/32iT4zRid7Qa1tfp6zVO5ahOGc0l
hPXfRgzzprJYw962gKOc+KwjgQKBgQC5jg7gO1Kjw3VpEZOUw5p7OsgBYBFwKYMd
612Ami7UeNuF/JyRIaNSVFnLZbjfkEDdVfrZwNeOU9vuTuDAT95N4yMSqp6TR7N4
Iby/1w4esO8Zy4yUcq/4Aw+/VtSE2P6RLGKY3nl2GJnQ87Yf6NRCOxJim8a+sjov
as05Oj0X4wKBgQCcKkjPwue1EPbJhWgc9cxitJgxT8PdtUEjG9m74Y002zyvMDKI
hKp796IPJKv40lpUsALQjIpFcix3cx0fZuD5zFUH7JqBuC22MSGtDohmCzcecMS/
w7Kro9DEqD2dUVgWvUvLia1JV3PcNWtA35JBgacRHaCGBhaZpZNtN2IOgQKBgQCM
JvWrfoNb+H2NX95F5jyfyXVaPJLPUjub9LQKN+sZRzQgjv4/TNYMkHPGgs3R5yZn
R9MSeGsYMNUUufVerLTvxZkvNzpRaj3vhiQIDsq2edQPesRzN/Eb9kwFrPMWaMRX
KNxMNPYvMkO0JPCyR21TnUS0wI6saPgz6oqaKBgPGwKBgQCQMEVlhT6IJCso1UBU
JNe70HI1jw5rRMzi8rNlF60f3dMPgnuH0CXoED6Saxn84izH2D/40jZdJJplGiS7
gLXUvK7l2Iq0KMadB/yQv1I3EXTmJIThdy5CzHmqpONobOJGw1pQ59j+Ng4WvmPj
60oL0SLgWhT23ksCjyyWnWf6Og==
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

fn rsa_alt() -> Rsa<openssl::pkey::Private> {
    seed_rand();
    Rsa::private_key_from_pem(RSA_ALT_PEM).unwrap()
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

fn claims(sub: &str, now: u64, extra: &[(&str, Value)]) -> Value {
    let mut value = json!({
        "iss": "https://issuer.test",
        "aud": "api.test",
        "sub": sub,
        "exp": now + 600,
        "nbf": now - 5,
        "iat": now - 5,
        "jti": format!("jti-{sub}-{now}-{}", extra.len()),
        "tenant_id": "tenant-a",
    });
    for (key, item) in extra {
        value[key] = item.clone();
    }
    value
}

struct JwksServer {
    body: Arc<Mutex<Vec<u8>>>,
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
    JwksServer { body, addr }
}

fn jwt_config(origin: SocketAddr, jwks: SocketAddr, with_bindings: bool) -> Config {
    let bindings = if with_bindings {
        r#", paths = ["/accounts/{account_id}"], bindings = ["jwt.sub == path.account_id", "jwt.tenant_id == body.tenant_id"]"#
    } else {
        ""
    };
    Config::from_toml(&format!(
        r#"
[[sites]]
hosts = ["api.test"]
backend = "http://{origin}"
jwt = {{ jwks = "http://{jwks}/jwks.json", issuer = "https://issuer.test", audience = "api.test"{bindings} }}

[[sites]]
hosts = ["plain.test"]
backend = "http://{origin}"
"#
    ))
}

fn request(host: &str, method: &str, path: &str, extra: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ferroada-jwt-test\r\nConnection: close\r\n"
    )
    .into_bytes();
    req.extend_from_slice(extra);
    if extra.is_empty() {
        req.extend_from_slice(b"\r\n");
    }
    req
}

fn bearer_get(host: &str, path: &str, token: &str) -> Vec<u8> {
    request(
        host,
        "GET",
        path,
        &format!("Authorization: Bearer {token}\r\n\r\n").into_bytes(),
    )
}

fn bearer_post(host: &str, path: &str, token: &str, body: &str) -> Vec<u8> {
    request(
        host,
        "POST",
        path,
        &format!(
            "Authorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
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
        let detail = event["detail"].as_str().unwrap_or("");
        assert!(
            !detail.contains(token),
            "event must not contain the token: {event}"
        );
        assert!(
            !detail.contains("eyJ"),
            "event must not contain JWT payload: {event}"
        );
    }
}

#[test]
fn valid_jwt_and_binding_is_200() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, true));

    let now = unix_now();
    let token = sign_rs256(&key, "k1", &claims("user-1", now, &[]));
    let response = send_until_http(
        listen,
        &bearer_get("api.test", "/accounts/user-1", &token),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "valid jwt + binding must pass, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "valid request must reach the origin"
    );
}

#[test]
fn alg_none_is_401_zero_stub() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, false));

    let now = unix_now();
    let header = b64(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
    let payload = b64(&serde_json::to_vec(&claims("user-1", now, &[])).unwrap());
    let token = format!("{header}.{payload}.");
    let response = send_until_http(listen, &bearer_get("api.test", "/none-alg", &token));
    assert!(
        response.starts_with(b"HTTP/1.1 401"),
        "alg none must be 401, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/none-alg");
    assert!(
        events.iter().any(|event| {
            event["event_type"].as_str() == Some("jwt")
                && event["detail"].as_str() == Some("alg")
        }),
        "expected jwt alg event, got {events:?}"
    );
    assert_no_token_leak(&events, &token);
}

#[test]
fn wrong_iss_is_401_zero_stub() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, false));

    let now = unix_now();
    let token = sign_rs256(
        &key,
        "k1",
        &claims("user-1", now, &[("iss", json!("https://evil.test"))]),
    );
    let response = send_until_http(listen, &bearer_get("api.test", "/wrong-iss", &token));
    assert!(
        response.starts_with(b"HTTP/1.1 401"),
        "wrong iss must be 401, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
}

#[test]
fn expired_exp_is_401_zero_stub() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, false));

    let now = unix_now();
    let token = sign_rs256(
        &key,
        "k1",
        &claims("user-1", now, &[("exp", json!(now - 120))]),
    );
    let response = send_until_http(listen, &bearer_get("api.test", "/expired", &token));
    assert!(
        response.starts_with(b"HTTP/1.1 401"),
        "expired exp must be 401, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
}

#[test]
fn sub_not_equal_path_account_id_is_403_zero_stub() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, true));

    let now = unix_now();
    let token = sign_rs256(&key, "k1", &claims("user-1", now, &[]));
    let response = send_until_http(
        listen,
        &bearer_get("api.test", "/accounts/other-user", &token),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "sub ≠ path.account_id must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
    let events = events_for("/accounts/other-user");
    assert!(
        events
            .iter()
            .any(|event| event["event_type"].as_str() == Some("jwt_binding")),
        "expected jwt_binding event, got {events:?}"
    );
    assert_no_token_leak(&events, &token);
}

#[test]
fn jwks_rotation_new_kid_passes_after_refresh() {
    let _guard = live_lock();
    let key1 = rsa();
    let key2 = rsa_alt();
    let jwks1 = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key1, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks1);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, false));

    let now = unix_now();
    let t1 = sign_rs256(&key1, "k1", &claims("user-1", now, &[]));
    let first = send_until_http(listen, &bearer_get("api.test", "/rotate", &t1));
    assert!(
        first.starts_with(b"HTTP/1.1 200"),
        "kid1 must pass, got {}",
        status_line(&first)
    );

    *jwks_srv.body.lock().unwrap() =
        serde_json::to_vec(&json!({"keys": [rsa_jwk(&key2, "k2")]})).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let t2 = sign_rs256(&key2, "k2", &claims("user-2", now, &[]));
    let second = send_until_http(listen, &bearer_get("api.test", "/rotate", &t2));
    assert!(
        second.starts_with(b"HTTP/1.1 200"),
        "kid2 must pass after JWKS refresh, got {}",
        status_line(&second)
    );
}

#[test]
fn site_without_jwt_is_200_without_authorization() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, false));

    let response = send_until_http(listen, &request("plain.test", "GET", "/", &[]));
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "site without jwt must stay Level 1, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        !stub.hits.lock().unwrap().is_empty(),
        "site without jwt must reach the origin"
    );
}

#[test]
fn body_tenant_mismatch_is_403_zero_stub() {
    let _guard = live_lock();
    let key = rsa();
    let jwks = serde_json::to_vec(&json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap();
    let jwks_srv = spawn_jwks(&jwks);
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, jwt_config(stub.addr, jwks_srv.addr, true));

    let now = unix_now();
    let token = sign_rs256(&key, "k1", &claims("user-1", now, &[]));
    let response = send_until_http(
        listen,
        &bearer_post(
            "api.test",
            "/accounts/user-1",
            &token,
            r#"{"tenant_id":"other"}"#,
        ),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "tenant binding mismatch must be 403, got {}",
        status_line(&response)
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(stub.hits.lock().unwrap().len(), 0);
}
