//! L1 WAF client: optional Coraza sidecar over a Unix socket.
//!
//! L0 regex in `waf.rs` stays always-on. This module never links Coraza;
//! a crash or hang in CRS cannot take down the data plane.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

use crate::metrics;
use crate::waf_l1::L1Settings;

/// CRS 4.25 on a cold or fat request does not fit in 20 ms. That default
/// plus fail-closed would 403 clean traffic at start. 500 ms is the floor.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_SOCKET: &str = "/run/coraza/waf.sock";
const BOOT_WAIT: Duration = Duration::from_secs(15);
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WafEngineKind {
    Native,
    Coraza,
}

#[derive(Clone, Debug)]
pub struct WafEngine {
    kind: WafEngineKind,
    socket: PathBuf,
    timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum L1Verdict {
    Skipped,
    Allow {
        rule_ids: Vec<u32>,
        score: u32,
    },
    Block {
        rule_ids: Vec<u32>,
        message: String,
        score: u32,
    },
    Unavailable,
}

pub struct InspectRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub protocol: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub client_ip: &'a str,
    pub policy: L1Settings,
    pub exclude_parameters: &'a [String],
}

#[derive(Serialize)]
struct InspectWire<'a> {
    method: &'a str,
    uri: &'a str,
    protocol: &'a str,
    headers: &'a [(String, String)],
    body_b64: String,
    client_ip: &'a str,
    policy: InspectWirePolicy<'a>,
}

#[derive(Serialize)]
struct InspectWirePolicy<'a> {
    blocking_paranoia: u8,
    executing_paranoia: u8,
    anomaly_score_threshold: u32,
    exclude_parameters: &'a [String],
}

#[derive(Deserialize)]
struct InspectWireResponse {
    action: String,
    #[serde(default)]
    rule_ids: Vec<u32>,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    score: u32,
}

impl WafEngine {
    pub fn native() -> Self {
        Self {
            kind: WafEngineKind::Native,
            socket: PathBuf::from(DEFAULT_SOCKET),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn from_env() -> Self {
        let kind = parse_engine(std::env::var("WAF_ENGINE").ok().as_deref());
        let timeout = parse_timeout(std::env::var("WAF_SIDECAR_TIMEOUT_MS").ok().as_deref());
        let socket = std::env::var("WAF_SIDECAR_SOCKET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
        if kind == WafEngineKind::Coraza && socket.as_os_str().is_empty() {
            panic!("WAF_ENGINE=coraza exige WAF_SIDECAR_SOCKET");
        }
        Self {
            kind,
            socket,
            timeout,
        }
    }

    /// Ready-probe the sidecar before the process claims Coraza is on.
    pub fn boot(&self) {
        if self.kind != WafEngineKind::Coraza {
            return;
        }
        #[cfg(not(unix))]
        panic!(
            "WAF_ENGINE=coraza exige Unix socket; este sistema operacional não oferece ({})",
            self.socket.display()
        );
        #[cfg(unix)]
        {
            let deadline = std::time::Instant::now() + BOOT_WAIT;
            loop {
                if probe_ready(&self.socket, self.timeout) {
                    info!(
                        socket = %self.socket.display(),
                        timeout_ms = self.timeout.as_millis() as u64,
                        "WAF L1 Coraza sidecar ready"
                    );
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    panic!(
                        "WAF_ENGINE=coraza: sidecar não respondeu em {} em {:?}",
                        self.socket.display(),
                        BOOT_WAIT
                    );
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    pub fn kind(&self) -> WafEngineKind {
        self.kind
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn is_coraza(&self) -> bool {
        self.kind == WafEngineKind::Coraza
    }

    pub async fn inspect(&self, request: &InspectRequest<'_>) -> L1Verdict {
        if self.kind != WafEngineKind::Coraza {
            return L1Verdict::Skipped;
        }
        match inspect_socket(&self.socket, self.timeout, request).await {
            Ok(verdict) => verdict,
            Err(error) => {
                warn!(
                    socket = %self.socket.display(),
                    error = %error,
                    "WAF L1 sidecar unavailable"
                );
                L1Verdict::Unavailable
            }
        }
    }

    /// Point at a sidecar without the boot probe. Tests and custom wiring.
    pub fn coraza(socket: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            kind: WafEngineKind::Coraza,
            socket: socket.into(),
            timeout,
        }
    }
}

pub fn l1_detail(rule_ids: &[u32], message: &str, score: u32) -> String {
    let ids = if rule_ids.is_empty() {
        "unknown".to_string()
    } else {
        rule_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    if message.is_empty() {
        format!("CRS {ids} score={score}")
    } else {
        format!("CRS {ids} score={score}: {message}")
    }
}

pub fn record_unavailable(site_scope: &str, client_ip: &str, uri: &str, detail: &str) {
    metrics::record_waf_engine_unavailable(site_scope, client_ip, uri, detail);
}

fn parse_engine(raw: Option<&str>) -> WafEngineKind {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => WafEngineKind::Native,
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "native" => WafEngineKind::Native,
            "coraza" => WafEngineKind::Coraza,
            other => panic!("WAF_ENGINE inválido: {other}; use native ou coraza"),
        },
    }
}

fn parse_timeout(raw: Option<&str>) -> Duration {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => DEFAULT_TIMEOUT,
        Some(value) => {
            let ms: u64 = value
                .parse()
                .unwrap_or_else(|_| panic!("WAF_SIDECAR_TIMEOUT_MS inválido: {value}"));
            if ms == 0 || ms > 30_000 {
                panic!("WAF_SIDECAR_TIMEOUT_MS deve estar entre 1 e 30000, não {ms}");
            }
            Duration::from_millis(ms)
        }
    }
}

#[derive(Debug)]
struct EngineError(String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn encode_inspect_json(request: &InspectRequest<'_>) -> Result<Vec<u8>, EngineError> {
    let wire = InspectWire {
        method: request.method,
        uri: request.uri,
        protocol: request.protocol,
        headers: request.headers,
        body_b64: b64_encode(request.body),
        client_ip: request.client_ip,
        policy: InspectWirePolicy {
            blocking_paranoia: request.policy.blocking_paranoia,
            executing_paranoia: request.policy.executing_paranoia,
            anomaly_score_threshold: request.policy.anomaly_score_threshold,
            exclude_parameters: request.exclude_parameters,
        },
    };
    serde_json::to_vec(&wire).map_err(|error| EngineError(error.to_string()))
}

fn encode_http_post(path: &str, json: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST {path} HTTP/1.1\r\nHost: coraza\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        json.len()
    )
    .into_bytes();
    out.extend_from_slice(json);
    out
}

fn encode_http_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: coraza\r\nConnection: close\r\n\r\n").into_bytes()
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn try_parse_http(raw: &[u8]) -> Option<Result<HttpResponse, EngineError>> {
    let header_end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head =
        std::str::from_utf8(&raw[..header_end]).map_err(|error| EngineError(error.to_string()));
    let head = match head {
        Ok(head) => head,
        Err(error) => return Some(Err(error)),
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut tokens = status_line.split_whitespace();
    let _version = tokens.next();
    let Some(status_token) = tokens.next() else {
        return Some(Err(EngineError("resposta HTTP sem status".into())));
    };
    let Ok(status) = status_token.parse::<u16>() else {
        return Some(Err(EngineError(format!(
            "status HTTP inválido: {status_token}"
        ))));
    };
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            match value.trim().parse::<usize>() {
                Ok(len) => content_length = Some(len),
                Err(_) => {
                    return Some(Err(EngineError(
                        "Content-Length inválido na resposta do sidecar".into(),
                    )))
                }
            }
        }
    }
    let rest = &raw[header_end + 4..];
    if let Some(len) = content_length {
        if rest.len() < len {
            return None;
        }
        Some(Ok(HttpResponse {
            status,
            body: rest[..len].to_vec(),
        }))
    } else {
        Some(Ok(HttpResponse {
            status,
            body: rest.to_vec(),
        }))
    }
}

fn parse_inspect_body(status: u16, body: &[u8]) -> Result<L1Verdict, EngineError> {
    if status != 200 {
        return Err(EngineError(format!("sidecar HTTP {status}")));
    }
    let parsed: InspectWireResponse = serde_json::from_slice(body)
        .map_err(|error| EngineError(format!("JSON do sidecar: {error}")))?;
    match parsed.action.to_ascii_lowercase().as_str() {
        "allow" => Ok(L1Verdict::Allow {
            rule_ids: parsed.rule_ids,
            score: parsed.score,
        }),
        "deny" => Ok(L1Verdict::Block {
            rule_ids: parsed.rule_ids,
            message: parsed.msg,
            score: parsed.score,
        }),
        other => Err(EngineError(format!("ação L1 desconhecida: {other}"))),
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(unix)]
fn probe_ready(socket: &Path, timeout: Duration) -> bool {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    if stream.write_all(&encode_http_get("/readyz")).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_RESPONSE {
                    return false;
                }
                if let Some(Ok(response)) = try_parse_http(&buf) {
                    return response.status == 200;
                }
            }
            Err(_) => return false,
        }
    }
    matches!(try_parse_http(&buf), Some(Ok(response)) if response.status == 200)
}

#[cfg(unix)]
async fn inspect_socket(
    socket: &Path,
    timeout: Duration,
    request: &InspectRequest<'_>,
) -> Result<L1Verdict, EngineError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let json = encode_inspect_json(request)?;
    let payload = encode_http_post("/inspect", &json);
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|error| EngineError(error.to_string()))?;
        stream
            .write_all(&payload)
            .await
            .map_err(|error| EngineError(error.to_string()))?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|error| EngineError(error.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_RESPONSE {
                return Err(EngineError("resposta do sidecar excede o teto".into()));
            }
            match try_parse_http(&buf) {
                Some(Ok(response)) => return parse_inspect_body(response.status, &response.body),
                Some(Err(error)) => return Err(error),
                None => {}
            }
        }
        match try_parse_http(&buf) {
            Some(Ok(response)) => parse_inspect_body(response.status, &response.body),
            Some(Err(error)) => Err(error),
            None => Err(EngineError("resposta HTTP incompleta do sidecar".into())),
        }
    })
    .await
    .map_err(|_| EngineError("timeout".into()))?
}

#[cfg(not(unix))]
async fn inspect_socket(
    _socket: &Path,
    _timeout: Duration,
    _request: &InspectRequest<'_>,
) -> Result<L1Verdict, EngineError> {
    Err(EngineError(
        "WAF L1 exige Unix socket neste sistema operacional".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InspectionDisposition, InspectionPolicy};
    use crate::waf::InspectionOutcome;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn restore(key: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn default_engine_is_native_with_500ms_timeout() {
        let _guard = env_guard();
        let engine = std::env::var_os("WAF_ENGINE");
        let timeout = std::env::var_os("WAF_SIDECAR_TIMEOUT_MS");
        let socket = std::env::var_os("WAF_SIDECAR_SOCKET");
        std::env::remove_var("WAF_ENGINE");
        std::env::remove_var("WAF_SIDECAR_TIMEOUT_MS");
        std::env::remove_var("WAF_SIDECAR_SOCKET");
        let parsed = WafEngine::from_env();
        restore("WAF_ENGINE", engine);
        restore("WAF_SIDECAR_TIMEOUT_MS", timeout);
        restore("WAF_SIDECAR_SOCKET", socket);
        assert_eq!(parsed.kind(), WafEngineKind::Native);
        assert_eq!(parsed.timeout(), Duration::from_millis(500));
        assert_ne!(parsed.timeout(), Duration::from_millis(20));
    }

    #[test]
    fn native_inspect_is_skipped() {
        let engine = WafEngine::native();
        let headers = Vec::new();
        let request = InspectRequest {
            method: "GET",
            uri: "/",
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            client_ip: "192.0.2.1",
            policy: L1Settings::default_crs(),
            exclude_parameters: &[],
        };
        let verdict = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(engine.inspect(&request));
        assert_eq!(verdict, L1Verdict::Skipped);
    }

    #[test]
    fn ferroada_manifest_does_not_depend_on_coraza() {
        let manifest: toml::Value = include_str!("../Cargo.toml").parse().expect("Cargo.toml");
        for section in ["dependencies", "dev-dependencies"] {
            let Some(table) = manifest.get(section).and_then(|value| value.as_table()) else {
                continue;
            };
            for name in table.keys() {
                assert!(
                    !name.to_ascii_lowercase().contains("coraza"),
                    "{section} lista {name}"
                );
            }
        }
        if let Some(members) = manifest
            .get("workspace")
            .and_then(|value| value.get("members"))
            .and_then(|value| value.as_array())
        {
            for member in members {
                let name = member.as_str().unwrap_or("");
                assert!(
                    !name.to_ascii_lowercase().contains("coraza"),
                    "workspace member {name}"
                );
            }
        }
    }

    #[test]
    fn inspect_json_roundtrip_deny_carries_rule_ids() {
        let headers = vec![("host".to_string(), "api.example".to_string())];
        let request = InspectRequest {
            method: "GET",
            uri: "/search?q=1'+OR+1=1",
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            client_ip: "192.0.2.8",
            policy: L1Settings {
                blocking_paranoia: 1,
                executing_paranoia: 4,
                shadow: true,
                anomaly_score_threshold: 5,
                exclude: false,
            },
            exclude_parameters: &[],
        };
        let json = encode_inspect_json(&request).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["method"], "GET");
        assert_eq!(value["uri"], "/search?q=1'+OR+1=1");
        assert_eq!(value["body_b64"], "");
        assert_eq!(value["policy"]["blocking_paranoia"], 1);
        assert_eq!(value["policy"]["executing_paranoia"], 4);
        assert_ne!(
            value["policy"]["executing_paranoia"],
            value["policy"]["blocking_paranoia"]
        );
        assert_eq!(value["policy"]["anomaly_score_threshold"], 5);

        let deny = parse_inspect_body(
            200,
            br#"{"action":"deny","rule_ids":[942100,942110],"msg":"SQLi","score":15}"#,
        )
        .unwrap();
        match deny {
            L1Verdict::Block {
                rule_ids,
                message,
                score,
            } => {
                assert_eq!(rule_ids, vec![942100, 942110]);
                assert_eq!(message, "SQLi");
                assert_eq!(score, 15);
                let detail = l1_detail(&rule_ids, &message, score);
                assert!(detail.contains("942100"), "{detail}");
                assert!(detail.contains("942110"), "{detail}");
                assert!(detail.contains("score=15"), "{detail}");
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn sidecar_http_error_is_unavailable_not_allow() {
        let err = parse_inspect_body(500, b"nope").unwrap_err();
        assert!(err.0.contains("500"), "{err}");
    }

    #[test]
    fn timed_out_fail_closed_is_deny_open_is_monitor() {
        assert_eq!(
            InspectionPolicy::fail_closed().disposition(InspectionOutcome::TimedOut),
            InspectionDisposition::Deny
        );
        assert_eq!(
            InspectionPolicy::open().disposition(InspectionOutcome::TimedOut),
            InspectionDisposition::Monitor
        );
    }

    #[test]
    fn b64_encodes_rfc4648() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    fn temp_sock() -> PathBuf {
        std::env::temp_dir().join(format!(
            "fa-waf-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn serve(socket: PathBuf, handler: impl Fn(&[u8]) -> Vec<u8> + Send + 'static) {
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else {
                    continue;
                };
                let mut buf = vec![0u8; 16 * 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let response = handler(&buf[..n]);
                let _ = stream.write_all(&response);
            }
        });
        std::thread::sleep(Duration::from_millis(30));
    }

    fn http_json(status: u16, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn missing_socket_is_unavailable() {
        let engine = WafEngine::coraza("/tmp/ferroada-missing-waf.sock", DEFAULT_TIMEOUT);
        let headers: Vec<(String, String)> = Vec::new();
        let request = InspectRequest {
            method: "GET",
            uri: "/",
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            client_ip: "192.0.2.1",
            policy: L1Settings::default_crs(),
            exclude_parameters: &[],
        };
        let verdict = runtime().block_on(engine.inspect(&request));
        assert_eq!(verdict, L1Verdict::Unavailable);
    }

    #[test]
    fn sidecar_timeout_is_unavailable() {
        let socket = temp_sock();
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(_stream) = incoming else {
                    continue;
                };
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        std::thread::sleep(Duration::from_millis(30));
        let engine = WafEngine::coraza(&socket, Duration::from_millis(50));
        let headers: Vec<(String, String)> = Vec::new();
        let request = InspectRequest {
            method: "GET",
            uri: "/",
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            client_ip: "192.0.2.1",
            policy: L1Settings::default_crs(),
            exclude_parameters: &[],
        };
        let verdict = runtime().block_on(engine.inspect(&request));
        let _ = std::fs::remove_file(&socket);
        assert_eq!(verdict, L1Verdict::Unavailable);
    }

    #[test]
    fn sidecar_deny_returns_rule_ids() {
        let socket = temp_sock();
        let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        serve(socket.clone(), move |req| {
            recorded.lock().unwrap().extend_from_slice(req);
            http_json(
                200,
                r#"{"action":"deny","rule_ids":[942100],"msg":"SQL Injection Attack"}"#,
            )
        });
        let engine = WafEngine::coraza(&socket, DEFAULT_TIMEOUT);
        let headers = vec![("host".to_string(), "api.example".to_string())];
        let request = InspectRequest {
            method: "GET",
            uri: "/search?q=1'+OR+1=1",
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            client_ip: "192.0.2.9",
            policy: L1Settings::default_crs(),
            exclude_parameters: &[],
        };
        let verdict = runtime().block_on(engine.inspect(&request));
        let _ = std::fs::remove_file(&socket);
        match verdict {
            L1Verdict::Block {
                rule_ids,
                message,
                score: _,
            } => {
                assert_eq!(rule_ids, vec![942100]);
                assert!(message.to_ascii_lowercase().contains("sql"), "{message}");
            }
            other => panic!("expected block, got {other:?}"),
        }
        let seen = seen.lock().unwrap();
        let sent = String::from_utf8_lossy(&seen);
        assert!(sent.contains("/inspect"), "{sent}");
        assert!(sent.contains("/search"), "{sent}");
    }

    #[test]
    fn ready_probe_accepts_200() {
        let socket = temp_sock();
        serve(socket.clone(), |_| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
        });
        assert!(probe_ready(&socket, DEFAULT_TIMEOUT));
        let _ = std::fs::remove_file(&socket);
    }
}
