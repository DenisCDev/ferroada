//! Dashboard admin auth: token, session/CSRF, RBAC, query credentials. GET / is not a UI.

use ferroada::dashboard::{AdminAudit, AdminAuth, DashboardService, Role};
use ferroada::policy::PolicyStore;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static LIVE: Mutex<()> = Mutex::new(());

fn live_lock() -> std::sync::MutexGuard<'static, ()> {
    LIVE.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn free_bind() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn wait_ready(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("dashboard did not start on {addr}");
}

fn spawn_dashboard(listen: SocketAddr, service: DashboardService) {
    std::thread::spawn(move || {
        let server_conf = ServerConf {
            threads: 1,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), server_conf);
        server.bootstrap();
        let mut svc = http_proxy_service(&server.configuration, service);
        svc.add_tcp(&listen.to_string());
        server.add_service(svc);
        server.run_forever();
    });
    wait_ready(listen);
}

struct Http {
    status: u16,
    headers: String,
    body: String,
}

fn request(addr: SocketAddr, raw: &str) -> Http {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        if buf.len() > 256 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .unwrap_or((text.as_ref(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Http {
        status,
        headers: head.to_string(),
        body: body.to_string(),
    }
}

fn cookie_from(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie:") {
            let _ = rest;
            let value = line.split_once(':')?.1.trim().split(';').next()?.trim();
            return Some(value.to_string());
        }
    }
    None
}

fn host(addr: SocketAddr) -> String {
    format!("{}:{}", addr.ip(), addr.port())
}

#[test]
fn root_is_not_html_metrics_need_auth() {
    let _lock = live_lock();
    let addr = free_bind();
    spawn_dashboard(addr, DashboardService::new(Some("segredo".into()), vec![]));
    let page = request(
        addr,
        &format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("API do proxy"));
    assert!(!page.body.contains("<html"));
    assert!(!page.body.contains("Token do dashboard"));
    let metrics = request(
        addr,
        &format!(
            "GET /api/metrics HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(metrics.status, 401);
    let health = request(
        addr,
        &format!(
            "GET /healthz HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(health.status, 200);
}

#[test]
fn token_in_query_is_rejected() {
    let _lock = live_lock();
    let addr = free_bind();
    spawn_dashboard(addr, DashboardService::new(Some("segredo".into()), vec![]));
    let res = request(
        addr,
        &format!(
            "POST /api/login?token=segredo HTTP/1.0\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(res.status, 400, "{}", res.body);
    assert!(res.body.contains("query string"));
}

#[test]
fn login_form_sets_httponly_cookie_and_metrics() {
    let _lock = live_lock();
    let addr = free_bind();
    spawn_dashboard(addr, DashboardService::new(Some("segredo".into()), vec![]));
    let body = "token=segredo";
    let res = request(
        addr,
        &format!(
            "POST /api/login HTTP/1.0\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            host(addr),
            body.len()
        ),
    );
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains("\"role\":\"operator\""));
    assert!(res.body.contains("\"csrf\""));
    assert!(res.headers.to_ascii_lowercase().contains("httponly"));
    assert!(res.headers.to_ascii_lowercase().contains("samesite=strict"));
    assert!(!res.headers.to_ascii_lowercase().contains("secure"));
    let cookie = cookie_from(&res.headers).expect("Set-Cookie");
    let metrics = request(
        addr,
        &format!(
            "GET /api/metrics HTTP/1.0\r\nHost: {}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(metrics.status, 200, "{}", metrics.body);
    assert!(
        metrics.body.contains("\"role\": \"operator\"")
            || metrics.body.contains("\"role\":\"operator\""),
        "{}",
        metrics.body
    );
}

#[test]
fn loopback_bearer_still_reads_metrics() {
    let _lock = live_lock();
    let addr = free_bind();
    spawn_dashboard(addr, DashboardService::new(Some("segredo".into()), vec![]));
    let res = request(
        addr,
        &format!(
            "GET /api/metrics HTTP/1.0\r\nHost: {}\r\nAuthorization: Bearer segredo\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(res.status, 200, "{}", res.body);
}

#[test]
fn viewer_reload_is_403_operator_session_needs_csrf() {
    let _lock = live_lock();
    let addr = free_bind();
    let auth = AdminAuth::with_token(Some("segredo".into()));
    let viewer = auth.issue(Role::Viewer, None).unwrap();
    let operator = auth.issue(Role::Operator, None).unwrap();
    let policy = Arc::new(PolicyStore::pinned(Arc::new(
        ferroada::config::Config::from_target_url("http://127.0.0.1:1"),
    )));
    spawn_dashboard(
        addr,
        DashboardService::with_policy(policy).with_admin(auth, AdminAudit::disabled(), false),
    );
    let viewer_cookie = format!("ferroada_admin={}", viewer.id);
    let body = format!("csrf={}", viewer.csrf);
    let forbidden = request(
        addr,
        &format!(
            "POST /api/reload HTTP/1.0\r\nHost: {}\r\nCookie: {viewer_cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            host(addr),
            body.len()
        ),
    );
    assert_eq!(forbidden.status, 403, "{}", forbidden.body);

    let operator_cookie = format!("ferroada_admin={}", operator.id);
    let missing = request(
        addr,
        &format!(
            "POST /api/reload HTTP/1.0\r\nHost: {}\r\nCookie: {operator_cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(missing.status, 403, "{}", missing.body);
    assert!(missing.body.to_ascii_lowercase().contains("csrf"));

    let csrf_body = format!("csrf={}", operator.csrf);
    let reload = request(
        addr,
        &format!(
            "POST /api/reload HTTP/1.0\r\nHost: {}\r\nCookie: {operator_cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{csrf_body}",
            host(addr),
            csrf_body.len()
        ),
    );
    assert_eq!(reload.status, 409, "{}", reload.body);
    assert!(reload.body.contains("política anterior"));

    let bearer_reload = request(
        addr,
        &format!(
            "POST /api/reload HTTP/1.0\r\nHost: {}\r\nAuthorization: Bearer segredo\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            host(addr)
        ),
    );
    assert_eq!(bearer_reload.status, 409, "{}", bearer_reload.body);
    assert!(!bearer_reload.body.to_ascii_lowercase().contains("csrf"));
}

#[test]
fn audit_log_records_login_without_token() {
    let _lock = live_lock();
    let addr = free_bind();
    let log = std::env::temp_dir().join(format!(
        "ferroada-dash-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let audit = AdminAudit::open(&log).unwrap();
    let auth = AdminAuth::with_token(Some("segredo-super-secreto".into()));
    spawn_dashboard(
        addr,
        DashboardService::new(None, vec![]).with_admin(auth, audit, false),
    );
    let body = "token=segredo-super-secreto";
    let res = request(
        addr,
        &format!(
            "POST /api/login HTTP/1.0\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            host(addr),
            body.len()
        ),
    );
    assert_eq!(res.status, 200, "{}", res.body);
    let bad = request(
        addr,
        &format!(
            "POST /api/login HTTP/1.0\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\ntoken=errado",
            host(addr)
        ),
    );
    assert_eq!(bad.status, 401);
    let recorded = std::fs::read_to_string(&log).unwrap();
    assert!(recorded.contains("\"action\":\"login\""));
    assert!(recorded.contains("\"action\":\"auth_failure\""));
    assert!(!recorded.contains("segredo-super-secreto"));
    let _ = std::fs::remove_file(&log);
}
