//! Opt-in authorization callback over a Unix socket (Level 3).
//!
//! Ferroada does not invent object ownership. A route with an `authorization`
//! block POSTs `{principal, action, resource, tenant?}` to the application's
//! decision service. No block = no call. Never HTTP/TCP to a remote PDP.

#[cfg(unix)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

use crate::jwt::JwtPolicy;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(50);
pub const MAX_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(unix)]
const MAX_RESPONSE: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    Closed,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceSelector {
    Path(String),
    Body(String),
}

#[derive(Clone, Debug)]
pub struct AuthzPolicy {
    socket: PathBuf,
    action: String,
    resource: ResourceSelector,
    fail_mode: FailMode,
    timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthzVerdict {
    Allow,
    Deny,
    Unavailable { detail: &'static str },
}

pub struct AuthzRequest<'a> {
    pub principal: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub tenant: Option<&'a str>,
}

#[cfg(unix)]
#[derive(Serialize)]
struct AuthzWire<'a> {
    principal: &'a str,
    action: &'a str,
    resource: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<&'a str>,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct AuthzWireResponse {
    allow: bool,
}

impl AuthzPolicy {
    pub fn parse(
        socket: &str,
        action: &str,
        resource: &str,
        fail_mode: &str,
        timeout_ms: Option<u64>,
    ) -> Result<Self, String> {
        let socket = parse_unix_socket(socket)?;
        let action = action.trim();
        if action.is_empty() {
            return Err("authorization.action não pode ser vazio".into());
        }
        let resource = parse_resource(resource)?;
        let fail_mode = parse_fail_mode(fail_mode)?;
        let timeout = parse_timeout(timeout_ms)?;
        Ok(Self {
            socket,
            action: action.to_string(),
            resource,
            fail_mode,
            timeout,
        })
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn fail_mode(&self) -> FailMode {
        self.fail_mode
    }

    pub fn resource(&self) -> &ResourceSelector {
        &self.resource
    }

    pub fn needs_body(&self) -> bool {
        matches!(self.resource, ResourceSelector::Body(_))
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn extract_resource(
        &self,
        path: &str,
        body: &[u8],
        jwt: Option<&JwtPolicy>,
        extra: &BTreeMap<String, String>,
    ) -> Option<String> {
        match &self.resource {
            ResourceSelector::Path(name) => {
                let params = match jwt {
                    Some(policy) => policy.path_params(path, extra),
                    None => extra.clone(),
                };
                params.get(name).cloned()
            }
            ResourceSelector::Body(pointer) => {
                if body.iter().all(u8::is_ascii_whitespace) {
                    return None;
                }
                let json: Value = serde_json::from_slice(body).ok()?;
                json_field(&json, pointer)
            }
        }
    }

    pub async fn decide(&self, request: &AuthzRequest<'_>) -> AuthzVerdict {
        match query_socket(&self.socket, self.timeout, request).await {
            Ok(verdict) => verdict,
            Err(error) => {
                warn!(
                    socket = %self.socket.display(),
                    error = %error.0,
                    "authorization service unavailable"
                );
                AuthzVerdict::Unavailable { detail: error.1 }
            }
        }
    }
}

pub fn parse_unix_socket(raw: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("authorization.socket não pode ser vazio".into());
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("tcp://")
        || lower.starts_with("grpc://")
    {
        return Err("authorization.socket não pode ser HTTP/TCP; só unix:// no hot path".into());
    }
    let Some(path) = raw.strip_prefix("unix://") else {
        return Err(format!(
            "authorization.socket deve ser unix://..., não {raw:?}"
        ));
    };
    let path = path.trim();
    if path.is_empty() {
        return Err("authorization.socket unix:// sem path".into());
    }
    if !path.starts_with('/') {
        return Err(format!(
            "authorization.socket unix:// exige path absoluto, não {path:?}"
        ));
    }
    Ok(PathBuf::from(path))
}

fn parse_resource(raw: &str) -> Result<ResourceSelector, String> {
    let trimmed = raw.trim();
    if let Some(name) = trimmed.strip_prefix("path.") {
        let name = name.trim();
        if name.is_empty() || name.contains('.') {
            return Err(format!("authorization.resource path inválido: {trimmed}"));
        }
        return Ok(ResourceSelector::Path(name.to_string()));
    }
    if let Some(name) = trimmed.strip_prefix("body.") {
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("authorization.resource body inválido: {trimmed}"));
        }
        return Ok(ResourceSelector::Body(name.to_string()));
    }
    Err(format!(
        "authorization.resource deve ser path.<param> ou body.<campo>, não {trimmed:?}"
    ))
}

fn parse_fail_mode(raw: &str) -> Result<FailMode, String> {
    match raw.trim() {
        "closed" => Ok(FailMode::Closed),
        "open" => Ok(FailMode::Open),
        other => Err(format!(
            "authorization.fail_mode deve ser closed ou open, não {other:?}"
        )),
    }
}

fn parse_timeout(timeout_ms: Option<u64>) -> Result<Duration, String> {
    match timeout_ms {
        None => Ok(DEFAULT_TIMEOUT),
        Some(0) => Err("authorization.timeout_ms deve ser entre 1 e 200".into()),
        Some(ms) if ms > MAX_TIMEOUT.as_millis() as u64 => Err(format!(
            "authorization.timeout_ms teto é {} ms, não {ms}",
            MAX_TIMEOUT.as_millis()
        )),
        Some(ms) => Ok(Duration::from_millis(ms)),
    }
}

fn json_field(root: &Value, dotted: &str) -> Option<String> {
    let mut current = root;
    for part in dotted.split('.') {
        current = current.get(part)?;
    }
    match current {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

struct SocketError(String, &'static str);

#[cfg(unix)]
fn encode_http_post(json: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST /authorize HTTP/1.1\r\nHost: authz\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        json.len()
    )
    .into_bytes();
    out.extend_from_slice(json);
    out
}

#[cfg(unix)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

#[cfg(unix)]
fn try_parse_http(raw: &[u8]) -> Option<Result<HttpResponse, SocketError>> {
    let header_end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = match std::str::from_utf8(&raw[..header_end]) {
        Ok(head) => head,
        Err(_) => {
            return Some(Err(SocketError(
                "resposta do authz não é UTF-8".into(),
                "protocol",
            )))
        }
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut tokens = status_line.split_whitespace();
    let _version = tokens.next();
    let Some(status_token) = tokens.next() else {
        return Some(Err(SocketError(
            "resposta HTTP sem status".into(),
            "protocol",
        )));
    };
    let Ok(status) = status_token.parse::<u16>() else {
        return Some(Err(SocketError(
            format!("status HTTP inválido: {status_token}"),
            "protocol",
        )));
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
                    return Some(Err(SocketError(
                        "Content-Length inválido na resposta do authz".into(),
                        "protocol",
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

#[cfg(unix)]
fn parse_allow_body(status: u16, body: &[u8]) -> Result<AuthzVerdict, SocketError> {
    if status != 200 {
        return Err(SocketError(format!("authz HTTP {status}"), "protocol"));
    }
    let parsed: AuthzWireResponse = serde_json::from_slice(body)
        .map_err(|error| SocketError(format!("JSON do authz: {error}"), "protocol"))?;
    if parsed.allow {
        Ok(AuthzVerdict::Allow)
    } else {
        Ok(AuthzVerdict::Deny)
    }
}

#[cfg(unix)]
async fn query_socket(
    socket: &Path,
    timeout: Duration,
    request: &AuthzRequest<'_>,
) -> Result<AuthzVerdict, SocketError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let wire = AuthzWire {
        principal: request.principal,
        action: request.action,
        resource: request.resource,
        tenant: request.tenant,
    };
    let json =
        serde_json::to_vec(&wire).map_err(|error| SocketError(error.to_string(), "protocol"))?;
    let payload = encode_http_post(&json);
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|error| SocketError(error.to_string(), "connect"))?;
        stream
            .write_all(&payload)
            .await
            .map_err(|error| SocketError(error.to_string(), "connect"))?;
        let _ = stream.shutdown().await;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|error| SocketError(error.to_string(), "timeout"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_RESPONSE {
                return Err(SocketError(
                    "resposta do authz excede o teto".into(),
                    "protocol",
                ));
            }
            match try_parse_http(&buf) {
                Some(Ok(response)) => return parse_allow_body(response.status, &response.body),
                Some(Err(error)) => return Err(error),
                None => {}
            }
        }
        match try_parse_http(&buf) {
            Some(Ok(response)) => parse_allow_body(response.status, &response.body),
            Some(Err(error)) => Err(error),
            None => Err(SocketError(
                "resposta HTTP incompleta do authz".into(),
                "protocol",
            )),
        }
    })
    .await
    .map_err(|_| SocketError("timeout".into(), "timeout"))?
}

#[cfg(not(unix))]
async fn query_socket(
    _socket: &Path,
    _timeout: Duration,
    _request: &AuthzRequest<'_>,
) -> Result<AuthzVerdict, SocketError> {
    Err(SocketError(
        "authorization exige Unix socket neste sistema operacional".into(),
        "connect",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_socket_is_accepted() {
        let path = parse_unix_socket("unix:///run/authz.sock").unwrap();
        assert_eq!(path, PathBuf::from("/run/authz.sock"));
    }

    #[test]
    fn http_socket_is_rejected() {
        let error = parse_unix_socket("http://127.0.0.1:8080/authorize").unwrap_err();
        assert!(error.contains("HTTP"), "{error}");
        let error = parse_unix_socket("https://pdp.example/v1").unwrap_err();
        assert!(error.contains("HTTP"), "{error}");
        let error = parse_unix_socket("tcp://10.0.0.1:9090").unwrap_err();
        assert!(
            error.contains("HTTP/TCP") || error.contains("unix://"),
            "{error}"
        );
        let error = parse_unix_socket("grpc://127.0.0.1:50051").unwrap_err();
        assert!(
            error.contains("HTTP/TCP") || error.contains("unix://"),
            "{error}"
        );
    }

    #[test]
    fn timeout_is_capped_at_200ms() {
        assert_eq!(parse_timeout(None).unwrap(), DEFAULT_TIMEOUT);
        assert_eq!(parse_timeout(Some(50)).unwrap(), Duration::from_millis(50));
        assert_eq!(
            parse_timeout(Some(200)).unwrap(),
            Duration::from_millis(200)
        );
        assert!(parse_timeout(Some(0)).is_err());
        assert!(parse_timeout(Some(201)).unwrap_err().contains("200"));
    }

    #[test]
    fn resource_and_fail_mode_parse() {
        assert!(matches!(
            parse_resource("path.account_id").unwrap(),
            ResourceSelector::Path(name) if name == "account_id"
        ));
        assert!(matches!(
            parse_resource("body.tenant_id").unwrap(),
            ResourceSelector::Body(name) if name == "tenant_id"
        ));
        assert!(parse_resource("account_id").is_err());
        assert_eq!(parse_fail_mode("closed").unwrap(), FailMode::Closed);
        assert_eq!(parse_fail_mode("open").unwrap(), FailMode::Open);
        assert!(parse_fail_mode("fail_open").is_err());
    }

    #[test]
    fn missing_resource_is_not_extracted() {
        let policy = AuthzPolicy::parse(
            "unix:///run/authz.sock",
            "transfer:create",
            "path.account_id",
            "open",
            None,
        )
        .unwrap();
        assert!(policy
            .extract_resource("/accounts/x/y", &[], None, &BTreeMap::new())
            .is_none());
        let mut extra = BTreeMap::new();
        extra.insert("account_id".into(), "a1".into());
        assert_eq!(
            policy
                .extract_resource("/ignored", &[], None, &extra)
                .as_deref(),
            Some("a1")
        );
    }

    #[test]
    fn body_resource_reads_json_and_rejects_empty() {
        let policy = AuthzPolicy::parse(
            "unix:///run/authz.sock",
            "transfer:create",
            "body.account_id",
            "open",
            None,
        )
        .unwrap();
        assert_eq!(
            policy
                .extract_resource("/", br#"{"account_id":"a1"}"#, None, &BTreeMap::new())
                .as_deref(),
            Some("a1")
        );
        assert!(policy
            .extract_resource("/", b"{}", None, &BTreeMap::new())
            .is_none());
        assert!(policy
            .extract_resource("/", b"", None, &BTreeMap::new())
            .is_none());
    }

    #[test]
    fn policy_parse_wires_the_block() {
        let policy = AuthzPolicy::parse(
            "unix:///run/authz.sock",
            "transfer:create",
            "path.account_id",
            "closed",
            None,
        )
        .unwrap();
        assert_eq!(policy.action(), "transfer:create");
        assert_eq!(policy.fail_mode(), FailMode::Closed);
        assert!(!policy.needs_body());
        assert_eq!(policy.timeout(), DEFAULT_TIMEOUT);
    }
}
