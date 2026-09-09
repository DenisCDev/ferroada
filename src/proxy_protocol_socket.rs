//! Socket-level PROXY v2 tests (no TLS). Mandatory PR 6 exit.

#![cfg(test)]

use crate::client_ip::{ClientIpConfig, TrustedProxies};
use crate::config::Config;
use crate::connection::ConnectionRateFilter;
use crate::proxy::FerroadaProxy;
use crate::proxy_protocol::{encode_v2, encode_v2_local};
use crate::rate_limit::RateLimiter;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LIVE: Mutex<()> = Mutex::new(());

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
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            recorded.lock().unwrap().push(buf[..n].to_vec());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    Stub { hits, addr }
}

fn free_bind() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_proxy(listen: SocketAddr, origin: SocketAddr) {
    std::thread::spawn(move || {
        let config = Arc::new(Config::from_target_url(&format!("http://{origin}")));
        let proxy = FerroadaProxy::new(
            config,
            Arc::new(RateLimiter::from_env()),
            TrustedProxies::parse("").unwrap(),
            ClientIpConfig::default(),
            true,
        );
        let server_conf = ServerConf {
            threads: 1,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), server_conf);
        server.bootstrap();
        let app = http_proxy(&server.configuration, proxy);
        let filter = ConnectionRateFilter::for_test(1);
        let mut svc = Service::new("test proxy".to_string(), filter.wrap(app, true, None));
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
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

fn http_get(xff: Option<&str>) -> Vec<u8> {
    let mut req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n".to_vec();
    if let Some(xff) = xff {
        req.extend_from_slice(format!("X-Forwarded-For: {xff}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req
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

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let needle = format!("{name}:");
    for line in text.split("\r\n") {
        if line.len() >= needle.len() && line[..needle.len()].eq_ignore_ascii_case(&needle) {
            return Some(line[needle.len()..].trim().to_string());
        }
    }
    None
}

#[test]
fn proxy_v2_get_uses_header_identity_and_raw_get_is_refused() {
    let _guard = LIVE.lock().unwrap();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, stub.addr);

    let src: SocketAddr = "203.0.113.88:54321".parse().unwrap();
    let dst: SocketAddr = "10.0.0.1:3000".parse().unwrap();
    let mut good = encode_v2(src, dst).unwrap();
    good.extend_from_slice(&http_get(Some("198.51.100.4")));
    let response = send_until_http(listen, &good);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "resposta inesperada: {}",
        String::from_utf8_lossy(&response)
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if stub.hits.lock().unwrap().len() == 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("stub não viu o GET após PROXY v2");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let first = stub.hits.lock().unwrap()[0].clone();
    let real_ip = header_value(&first, "X-Real-IP").expect("X-Real-IP ausente no stub");
    assert!(
        real_ip.starts_with("203.0.113.88"),
        "identidade deveria ser o IP do PROXY v2, veio {real_ip}"
    );
    let xff = header_value(&first, "X-Forwarded-For").unwrap_or_default();
    assert!(
        xff.starts_with("203.0.113.88"),
        "XFF spoof do cliente não pode vencer o PROXY v2: {xff}"
    );

    let raw = send(listen, &http_get(None));
    if let Some(body) = raw {
        assert!(
            body.is_empty() || !body.starts_with(b"HTTP/1.1 200"),
            "GET cru com a flag on não pode virar HTTP: {}",
            String::from_utf8_lossy(&body)
        );
    }

    let mut invalid = encode_v2_local();
    invalid[12] = 0x2F;
    invalid.extend_from_slice(&http_get(None));
    let _ = send(listen, &invalid);

    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        1,
        "GET cru / v2 inválido não podem gerar request no stub"
    );
}
