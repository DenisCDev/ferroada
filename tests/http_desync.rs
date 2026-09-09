//! Socket-level HTTP desync tests (PR 7). Smuggling must never reach the origin.

use ferroada::client_ip::{ClientIpConfig, TrustedProxies};
use ferroada::config::Config;
use ferroada::connection::ConnectionRateFilter;
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
            let Some(buf) = read_until_headers(&mut stream) else {
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_proxy(listen: SocketAddr, origin: SocketAddr) {
    std::thread::spawn(move || {
        let config = Arc::new(Config::from_target_url(&format!("http://{origin}")));
        let proxy = FerroadaProxy::new(
            config,
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
            "test desync proxy".to_string(),
            filter.wrap(app, false, None),
        );
        svc.set_connection_filter(Arc::new(filter));
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
}

fn read_until_headers(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            break;
        }
    }
    (!buf.is_empty()).then_some(buf)
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

fn assert_smuggling_rejected(response: &[u8], stub: &Stub) {
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "smuggling deve ser 400, veio: {}",
        String::from_utf8_lossy(response)
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "smuggling não pode gerar request no stub: {}",
        stub.hits
            .lock()
            .unwrap()
            .iter()
            .map(|hit| String::from_utf8_lossy(hit).into_owned())
            .collect::<Vec<_>>()
            .join(" | ")
    );
}

fn header_present(raw: &[u8], name: &str) -> bool {
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let needle = format!("{name}:");
    text.split("\r\n").any(|line| {
        line.len() >= needle.len() && line[..needle.len()].eq_ignore_ascii_case(&needle)
    })
}

#[test]
fn cl_te_never_reaches_origin() {
    let _guard = LIVE.lock().unwrap();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, stub.addr);

    let payload = b"POST / HTTP/1.1\r\n\
Host: 127.0.0.1\r\n\
Content-Length: 4\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\
\r\n\
0\r\n\
\r\n";
    let response = send_until_http(listen, payload);
    assert_smuggling_rejected(&response, &stub);
}

#[test]
fn duplicate_te_never_reaches_origin() {
    let _guard = LIVE.lock().unwrap();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, stub.addr);

    let payload = b"POST / HTTP/1.1\r\n\
Host: 127.0.0.1\r\n\
Transfer-Encoding: chunked\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\
\r\n\
0\r\n\
\r\n";
    let response = send_until_http(listen, payload);
    assert_smuggling_rejected(&response, &stub);
}

#[test]
fn connection_x_evil_is_stripped_before_origin() {
    let _guard = LIVE.lock().unwrap();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, stub.addr);

    let payload = b"GET / HTTP/1.1\r\n\
Host: 127.0.0.1\r\n\
Connection: close, X-Evil\r\n\
X-Evil: injected\r\n\
\r\n";
    let response = send_until_http(listen, payload);
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
            panic!("stub não viu o GET com Connection: X-Evil");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let forwarded = stub.hits.lock().unwrap()[0].clone();
    assert!(
        header_present(&forwarded, "X-Real-IP") || header_present(&forwarded, "Host"),
        "stub tem de ter visto os headers completos, veio: {}",
        String::from_utf8_lossy(&forwarded)
    );
    assert!(
        !header_present(&forwarded, "X-Evil"),
        "X-Evil listado em Connection deve ser removido, stub viu: {}",
        String::from_utf8_lossy(&forwarded)
    );
    assert!(
        !header_present(&forwarded, "Connection")
            || !String::from_utf8_lossy(&forwarded)
                .to_ascii_lowercase()
                .contains("x-evil"),
        "Connection não pode reencaminhar X-Evil: {}",
        String::from_utf8_lossy(&forwarded)
    );
}

fn send_h2_host_authority_split(addr: SocketAddr) -> Option<u16> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let tcp =
            tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                .await
                .ok()?
                .ok()?;
        let (mut sender, conn) = h2::client::handshake(tcp).await.ok()?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://evil.example/")
            .header("host", "victim.example")
            .body(())
            .ok()?;
        let (response, _) = sender.send_request(request, true).ok()?;
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .ok()?
            .ok()?;
        driver.abort();
        Some(response.status().as_u16())
    })
}

#[test]
fn host_authority_split_never_reaches_origin() {
    let _guard = LIVE.lock().unwrap();
    let stub = spawn_stub();
    let listen = free_bind();
    spawn_proxy(listen, stub.addr);

    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = send_h2_host_authority_split(listen) {
            break status;
        }
        if std::time::Instant::now() > deadline {
            panic!("proxy não respondeu HTTP/2 em {listen}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        status, 400,
        "Host vs :authority divergentes deve ser 400, veio {status}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        stub.hits.lock().unwrap().len(),
        0,
        "split Host/:authority não pode gerar request no stub"
    );
}
