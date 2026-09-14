//! Dashboard session, CSRF, RBAC, rate limit and mTLS identity.
//! OIDC lives in `dashboard_oidc.rs` (submodule) to keep the HTTP surface here.

use async_trait::async_trait;
use dashmap::DashMap;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::nid::Nid;
use pingora::tls::ssl::{SslFiletype, SslVerifyMode};
use pingora::tls::x509::X509Name;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "dashboard_oidc.rs"]
mod oidc;

pub use oidc::OidcConfig;

const COOKIE_NAME: &str = "ferroada_admin";
const DEFAULT_TTL_SECS: u64 = 900;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 8 * 3600;
const DEFAULT_RATE_MAX: u64 = 60;
const DEFAULT_RATE_WINDOW: u64 = 60;
const DEFAULT_RATE_IPS: usize = 10_000;
const MAX_SESSIONS: usize = 4096;
const OIDC_PENDING_TTL: Duration = Duration::from_secs(600);
const TOKEN_MAX: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
        }
    }

    pub fn can_reload(self) -> bool {
        matches!(self, Self::Operator)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Token,
    Session,
    Oidc,
    Mtls,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Session => "session",
            Self::Oidc => "oidc",
            Self::Mtls => "mtls",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Authn {
    pub role: Role,
    pub method: AuthMethod,
    pub csrf: Option<String>,
    pub subject: Option<String>,
}

struct SessionRecord {
    role: Role,
    csrf: String,
    expires: Instant,
    subject: Option<String>,
}

struct PendingRecord {
    pending: oidc::PendingOidc,
    expires: Instant,
}

struct MtlsRoles {
    operators: HashSet<String>,
    viewers: HashSet<String>,
}

impl MtlsRoles {
    fn role(&self, cn: &str) -> Option<Role> {
        if self.operators.contains(cn) {
            return Some(Role::Operator);
        }
        if self.viewers.contains(cn) {
            return Some(Role::Viewer);
        }
        if self.operators.is_empty() && self.viewers.is_empty() {
            return Some(Role::Viewer);
        }
        None
    }
}

struct ApiRate {
    hits: DashMap<IpAddr, Vec<Instant>>,
    max: u64,
    window: Duration,
    max_ips: usize,
    checks: AtomicU64,
}

impl ApiRate {
    fn new(max: u64, window_secs: u64, max_ips: usize) -> Self {
        Self {
            hits: DashMap::new(),
            max: max.max(1),
            window: Duration::from_secs(window_secs.max(1)),
            max_ips: max_ips.max(1),
            checks: AtomicU64::new(0),
        }
    }

    fn from_env() -> Self {
        let max = env_u64("DASHBOARD_API_RATE_MAX", DEFAULT_RATE_MAX).clamp(1, 10_000);
        let window = env_u64("DASHBOARD_API_RATE_WINDOW", DEFAULT_RATE_WINDOW).clamp(1, 3600);
        Self::new(max, window, DEFAULT_RATE_IPS)
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let n = self.checks.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(256) {
            let cutoff = Instant::now() - self.window;
            self.hits.retain(|_, times| {
                times.retain(|t| *t > cutoff);
                !times.is_empty()
            });
        }
        if self.hits.len() >= self.max_ips && !self.hits.contains_key(&ip) {
            return false;
        }
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut entry = self.hits.entry(ip).or_default();
        entry.retain(|t| *t > cutoff);
        if entry.len() as u64 >= self.max {
            return false;
        }
        entry.push(now);
        true
    }
}

pub struct DashboardTls {
    pub cert_path: String,
    pub key_path: String,
    pub client_ca: Option<String>,
    pub require_client_cert: bool,
}

impl DashboardTls {
    pub fn into_settings(self) -> Result<TlsSettings, String> {
        let callbacks = Box::new(DashboardClientAuth);
        let mut settings = TlsSettings::with_callbacks(callbacks)
            .map_err(|error| format!("TLS do dashboard: {error}"))?;
        settings
            .set_certificate_chain_file(&self.cert_path)
            .map_err(|error| {
                format!(
                    "DASHBOARD_TLS_CERT_PATH inválido ({}): {error}",
                    self.cert_path
                )
            })?;
        settings
            .set_private_key_file(&self.key_path, SslFiletype::PEM)
            .map_err(|error| {
                format!(
                    "DASHBOARD_TLS_KEY_PATH inválido ({}): {error}",
                    self.key_path
                )
            })?;
        if let Some(ca) = &self.client_ca {
            let mut mode = SslVerifyMode::PEER;
            if self.require_client_cert {
                mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
            }
            settings.set_verify(mode);
            settings
                .set_ca_file(ca)
                .map_err(|error| format!("DASHBOARD_MTLS_CA inválido ({ca}): {error}"))?;
            let names = X509Name::load_client_ca_file(ca)
                .map_err(|error| format!("DASHBOARD_MTLS_CA (lista de CAs): {error}"))?;
            settings.set_client_ca_list(names);
        }
        Ok(settings)
    }
}

struct DashboardClientAuth;

#[derive(Debug)]
pub struct ClientCertIdentity {
    pub common_name: Option<String>,
}

#[async_trait]
impl TlsAccept for DashboardClientAuth {
    async fn handshake_complete_callback(
        &self,
        tls_ref: &TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let common_name = tls_ref.peer_certificate().and_then(|cert| {
            let cn = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next()?;
            Some(cn.data().as_utf8().ok()?.to_string())
        });
        Some(Arc::new(ClientCertIdentity { common_name }))
    }
}

pub struct AdminAuth {
    token: Option<Arc<str>>,
    oidc: Option<Arc<OidcConfig>>,
    mtls: Option<MtlsRoles>,
    sessions: DashMap<String, SessionRecord>,
    pending: DashMap<String, PendingRecord>,
    rate: ApiRate,
    ttl: Duration,
    /// Token Bearer is enough off-loopback only when OIDC/mTLS are unset.
    allow_token_off_loopback: bool,
}

pub struct DashboardAuthSetup {
    pub auth: Arc<AdminAuth>,
    pub tls: Option<DashboardTls>,
}

impl AdminAuth {
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            token: None,
            oidc: None,
            mtls: None,
            sessions: DashMap::new(),
            pending: DashMap::new(),
            rate: ApiRate::new(DEFAULT_RATE_MAX, DEFAULT_RATE_WINDOW, DEFAULT_RATE_IPS),
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            allow_token_off_loopback: true,
        })
    }

    pub fn with_token(token: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            token: nonempty_token(token),
            oidc: None,
            mtls: None,
            sessions: DashMap::new(),
            pending: DashMap::new(),
            rate: ApiRate::new(DEFAULT_RATE_MAX, DEFAULT_RATE_WINDOW, DEFAULT_RATE_IPS),
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            allow_token_off_loopback: true,
        })
    }

    pub fn from_env(token: Option<String>) -> Result<DashboardAuthSetup, String> {
        let oidc = OidcConfig::from_env()?.map(Arc::new);
        let client_ca = env_nonempty("DASHBOARD_MTLS_CA");
        if let Some(path) = &client_ca {
            if !Path::new(path).is_file() {
                return Err(format!("DASHBOARD_MTLS_CA não é um ficheiro: {path}"));
            }
        }
        let mtls = client_ca.as_ref().map(|_| MtlsRoles {
            operators: env_set("DASHBOARD_MTLS_OPERATORS"),
            viewers: env_set("DASHBOARD_MTLS_VIEWERS"),
        });
        let tls_cert = env_nonempty("DASHBOARD_TLS_CERT_PATH");
        let tls_key = env_nonempty("DASHBOARD_TLS_KEY_PATH");
        match (&client_ca, &tls_cert, &tls_key) {
            (Some(_), None, _) | (Some(_), _, None) => {
                return Err(
                    "DASHBOARD_MTLS_CA exige DASHBOARD_TLS_CERT_PATH e DASHBOARD_TLS_KEY_PATH"
                        .into(),
                );
            }
            (_, Some(_), None) | (_, None, Some(_)) => {
                return Err(
                    "DASHBOARD_TLS_CERT_PATH e DASHBOARD_TLS_KEY_PATH precisam ser declarados juntos"
                        .into(),
                );
            }
            _ => {}
        }
        // Verify a presented client cert, but never fail the handshake if it is
        // missing: the HTML token form must stay reachable, and a loopback
        // Bearer token must still work even when the process is bound on
        // 0.0.0.0. Non-loopback token-only is rejected in authenticate().
        let tls = match (tls_cert, tls_key) {
            (Some(cert_path), Some(key_path)) => Some(DashboardTls {
                cert_path,
                key_path,
                client_ca: client_ca.clone(),
                require_client_cert: false,
            }),
            _ => None,
        };
        let ttl_secs = env_u64("DASHBOARD_SESSION_TTL_SECS", DEFAULT_TTL_SECS)
            .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let strong = oidc.is_some() || mtls.is_some();
        let auth = Arc::new(Self {
            token: nonempty_token(token),
            oidc,
            mtls,
            sessions: DashMap::new(),
            pending: DashMap::new(),
            rate: ApiRate::from_env(),
            ttl: Duration::from_secs(ttl_secs),
            allow_token_off_loopback: !strong,
        });
        Ok(DashboardAuthSetup { auth, tls })
    }

    pub fn strong(&self) -> bool {
        self.oidc.is_some() || self.mtls.is_some()
    }

    pub fn oidc_enabled(&self) -> bool {
        self.oidc.is_some()
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn api_allowed(&self, path: &str, ip: Option<IpAddr>) -> bool {
        if !path.starts_with("/api") {
            return true;
        }
        self.rate.allow(ip.unwrap_or(IpAddr::from([0, 0, 0, 0])))
    }

    pub fn authenticate(
        &self,
        cookie_header: Option<&str>,
        authorization: Option<&str>,
        client_cn: Option<&str>,
        peer_loopback: bool,
    ) -> Option<Authn> {
        if let Some(authn) = self.session_from_cookie(cookie_header) {
            return Some(authn);
        }
        if let (Some(cn), Some(mtls)) = (client_cn, &self.mtls) {
            if let Some(role) = mtls.role(cn) {
                return Some(Authn {
                    role,
                    method: AuthMethod::Mtls,
                    csrf: None,
                    subject: Some(cn.to_string()),
                });
            }
        }
        if let Some(role) = self.token_role(authorization, peer_loopback) {
            return Some(Authn {
                role,
                method: AuthMethod::Token,
                csrf: None,
                subject: None,
            });
        }
        None
    }

    pub fn token_presented_and_wrong(&self, authorization: Option<&str>) -> bool {
        let Some(expected) = self.token.as_deref() else {
            return false;
        };
        match bearer(authorization) {
            Some(provided) => !constant_time_eq(provided.as_bytes(), expected.as_bytes()),
            None => false,
        }
    }

    pub fn login_with_token(
        &self,
        form_token: &str,
        peer_loopback: bool,
    ) -> Result<IssuedSession, &'static str> {
        let Some(expected) = self.token.as_deref() else {
            return Err("no_token");
        };
        if form_token.len() > TOKEN_MAX
            || !constant_time_eq(form_token.as_bytes(), expected.as_bytes())
        {
            return Err("bad_token");
        }
        if !peer_loopback && !self.allow_token_off_loopback {
            return Err("token_off_loopback");
        }
        self.issue(Role::Operator, None).map_err(|_| "unavailable")
    }

    pub fn issue(
        &self,
        role: Role,
        subject: Option<String>,
    ) -> Result<IssuedSession, &'static str> {
        self.sweep_sessions();
        if self.sessions.len() >= MAX_SESSIONS {
            return Err("unavailable");
        }
        let id = hex_encode(&random_bytes(32).map_err(|_| "unavailable")?);
        let csrf = hex_encode(&random_bytes(32).map_err(|_| "unavailable")?);
        self.sessions.insert(
            id.clone(),
            SessionRecord {
                role,
                csrf: csrf.clone(),
                expires: Instant::now() + self.ttl,
                subject: subject.clone(),
            },
        );
        Ok(IssuedSession {
            id,
            csrf,
            role,
            subject,
        })
    }

    pub fn csrf_ok(&self, authn: &Authn, provided: Option<&str>) -> bool {
        // Bearer with a configured token is not cookie-authenticated, so CSRF
        // does not apply. mTLS and sessions are auto-sent by the browser.
        if authn.method == AuthMethod::Token && self.token.is_some() {
            return true;
        }
        let (Some(expected), Some(got)) = (authn.csrf.as_deref(), provided) else {
            return false;
        };
        constant_time_eq(got.as_bytes(), expected.as_bytes())
    }

    pub fn oidc(&self) -> Option<&OidcConfig> {
        self.oidc.as_deref()
    }

    pub fn begin_oidc(&self) -> Result<(String, String), &'static str> {
        let oidc = self.oidc.as_ref().ok_or("no_oidc")?;
        self.sweep_pending();
        if self.pending.len() >= MAX_SESSIONS {
            return Err("unavailable");
        }
        let (pending, state, url) = oidc.start_pkce().map_err(|_| "unavailable")?;
        self.pending.insert(
            state.clone(),
            PendingRecord {
                pending,
                expires: Instant::now() + OIDC_PENDING_TTL,
            },
        );
        Ok((url, state))
    }

    pub fn take_pending(&self, state: &str) -> Option<oidc::PendingOidc> {
        self.sweep_pending();
        let (_, record) = self.pending.remove(state)?;
        if record.expires <= Instant::now() {
            return None;
        }
        Some(record.pending)
    }

    pub fn complete_oidc(
        &self,
        code: &str,
        pending: &oidc::PendingOidc,
    ) -> Result<IssuedSession, &'static str> {
        let oidc = self.oidc.as_ref().ok_or("no_oidc")?;
        let identity = oidc.exchange(code, pending).map_err(|_| "oidc_exchange")?;
        self.issue(identity.role, Some(identity.subject))
    }

    fn session_from_cookie(&self, header: Option<&str>) -> Option<Authn> {
        let id = cookie_value(header, COOKIE_NAME)?;
        let mut expired = false;
        let authn = {
            let record = self.sessions.get(id)?;
            if record.expires <= Instant::now() {
                expired = true;
                None
            } else {
                Some(Authn {
                    role: record.role,
                    method: AuthMethod::Session,
                    csrf: Some(record.csrf.clone()),
                    subject: record.subject.clone(),
                })
            }
        };
        if expired {
            self.sessions.remove(id);
            return None;
        }
        authn
    }

    fn token_role(&self, authorization: Option<&str>, peer_loopback: bool) -> Option<Role> {
        match self.token.as_deref() {
            Some(expected) => {
                if !(peer_loopback || self.allow_token_off_loopback) {
                    return None;
                }
                let provided = bearer(authorization)?;
                constant_time_eq(provided.as_bytes(), expected.as_bytes()).then_some(Role::Operator)
            }
            // No token and no OIDC/mTLS: metrics stay public (compat), but
            // never as operator — reload must not be open.
            None if self.allow_token_off_loopback => Some(Role::Viewer),
            None => None,
        }
    }

    fn sweep_sessions(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, record| record.expires > now);
    }

    fn sweep_pending(&self) {
        let now = Instant::now();
        self.pending.retain(|_, record| record.expires > now);
    }
}

#[derive(Debug)]
pub struct IssuedSession {
    pub id: String,
    pub csrf: String,
    pub role: Role,
    pub subject: Option<String>,
}

impl IssuedSession {
    pub fn cookie(&self, ttl: Duration, secure: bool) -> String {
        session_cookie(&self.id, ttl, secure)
    }
}

pub fn production_enabled() -> bool {
    std::env::var("FERROADA_PRODUCTION")
        .map(|value| value == "true")
        .unwrap_or(false)
}

pub fn validate_exposure(
    bind: IpAddr,
    token: Option<&str>,
    production: bool,
    strong_auth: bool,
) -> Result<(), &'static str> {
    let has_token = token
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    if has_token {
        return Ok(());
    }
    if production {
        return Err("DASHBOARD_TOKEN é obrigatório quando FERROADA_PRODUCTION=true");
    }
    if !bind.is_loopback() && !strong_auth {
        return Err("DASHBOARD_TOKEN é obrigatório quando DASHBOARD_BIND não é loopback");
    }
    Ok(())
}

pub fn session_cookie(id: &str, ttl: Duration, secure: bool) -> String {
    let mut cookie = format!(
        "{COOKIE_NAME}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        ttl.as_secs()
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn credentials_in_query(path: &str, query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    let callback = path == "/oidc/callback";
    query.split('&').any(|pair| {
        let key = pair
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match key.as_str() {
            "token" | "access_token" | "id_token" | "client_secret" | "code_verifier"
            | "refresh_token" => true,
            "code" if !callback => true,
            _ => false,
        }
    })
}

pub fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == name {
            return Some(form_decode(value));
        }
    }
    None
}

pub fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            if pair == name {
                return Some(String::new());
            }
            continue;
        };
        if key == name {
            return Some(form_decode(value));
        }
    }
    None
}

pub fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    let header = header?;
    for part in header.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key.trim() == name {
            return Some(value.trim());
        }
    }
    None
}

fn bearer(authorization: Option<&str>) -> Option<&str> {
    let value = authorization.map(str::trim).filter(|v| !v.is_empty())?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() || token.len() > TOKEN_MAX {
        return None;
    }
    Some(token)
}

fn form_decode(raw: &str) -> String {
    let plus = raw.replace('+', " ");
    let bytes = plus.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap_or(plus)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn env_set(name: &str) -> HashSet<String> {
    match env_nonempty(name) {
        Some(raw) => raw
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect(),
        None => HashSet::new(),
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn nonempty_token(token: Option<String>) -> Option<Arc<str>> {
    token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Arc::from)
}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    openssl::rand::rand_bytes(&mut buf).map_err(|error| format!("rand: {error}"))?;
    Ok(buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn constant_time_eq(provided: &[u8], expected: &[u8]) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    provided
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
impl AdminAuth {
    fn for_test(token: Option<&str>, ttl: Duration, allow_token_off_loopback: bool) -> Arc<Self> {
        Arc::new(Self {
            token: nonempty_token(token.map(str::to_string)),
            oidc: None,
            mtls: None,
            sessions: DashMap::new(),
            pending: DashMap::new(),
            rate: ApiRate::new(5, 60, 100),
            ttl,
            allow_token_off_loopback,
        })
    }

    fn with_mtls(self: &Arc<Self>, operators: &[&str], viewers: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            token: self.token.clone(),
            oidc: self.oidc.clone(),
            mtls: Some(MtlsRoles {
                operators: operators.iter().map(|s| (*s).to_string()).collect(),
                viewers: viewers.iter().map(|s| (*s).to_string()).collect(),
            }),
            sessions: DashMap::new(),
            pending: DashMap::new(),
            rate: ApiRate::new(5, 60, 100),
            ttl: self.ttl,
            allow_token_off_loopback: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn cookie_flags_include_httponly_samesite_and_secure_iff_tls() {
        let plain = session_cookie("abc", Duration::from_secs(900), false);
        assert!(plain.contains("HttpOnly"));
        assert!(plain.contains("SameSite=Strict"));
        assert!(plain.contains("Max-Age=900"));
        assert!(!plain.contains("Secure"));
        let tls = session_cookie("abc", Duration::from_secs(900), true);
        assert!(tls.contains("Secure"));
        assert!(tls.contains("HttpOnly"));
    }

    #[test]
    fn credentials_rejected_in_query_except_oidc_callback_code() {
        assert!(credentials_in_query("/api/login", Some("token=secret")));
        assert!(credentials_in_query("/api/metrics", Some("access_token=x")));
        assert!(credentials_in_query("/oidc/login", Some("code=abc")));
        assert!(!credentials_in_query(
            "/oidc/callback",
            Some("code=abc&state=s")
        ));
        assert!(credentials_in_query(
            "/oidc/callback",
            Some("code=abc&client_secret=x")
        ));
        assert!(!credentials_in_query("/api/metrics", None));
    }

    #[test]
    fn form_token_stays_in_body_parser() {
        assert_eq!(
            form_field("token=abc%20def&csrf=1", "token").as_deref(),
            Some("abc def")
        );
        assert_eq!(form_field("csrf=zzz", "token"), None);
    }

    #[test]
    fn loopback_token_issues_operator_session() {
        let auth = AdminAuth::for_test(Some("segredo"), Duration::from_secs(900), false);
        let issued = auth.login_with_token("segredo", true).unwrap();
        assert_eq!(issued.role, Role::Operator);
        let header = format!("{COOKIE_NAME}={}", issued.id);
        let authn = auth.authenticate(Some(&header), None, None, true).unwrap();
        assert_eq!(authn.method, AuthMethod::Session);
        assert_eq!(authn.role, Role::Operator);
        assert!(auth.csrf_ok(&authn, Some(&issued.csrf)));
        assert!(!auth.csrf_ok(&authn, Some("nope")));
        assert!(!auth.csrf_ok(&authn, None));
    }

    #[test]
    fn token_off_loopback_denied_when_strong_auth() {
        let auth = AdminAuth::for_test(Some("segredo"), Duration::from_secs(900), false);
        assert_eq!(
            auth.login_with_token("segredo", false).unwrap_err(),
            "token_off_loopback"
        );
        assert!(auth
            .authenticate(None, Some("Bearer segredo"), None, false)
            .is_none());
        assert!(auth
            .authenticate(None, Some("Bearer segredo"), None, true)
            .is_some());
    }

    #[test]
    fn token_off_loopback_allowed_without_strong_auth() {
        let auth = AdminAuth::for_test(Some("segredo"), Duration::from_secs(900), true);
        assert!(auth
            .authenticate(None, Some("Bearer segredo"), None, false)
            .is_some());
    }

    #[test]
    fn viewer_cannot_reload_operator_can() {
        assert!(!Role::Viewer.can_reload());
        assert!(Role::Operator.can_reload());
    }

    #[test]
    fn mtls_cn_maps_roles_and_unknown_is_none_when_lists_set() {
        let base = AdminAuth::for_test(None, Duration::from_secs(900), false);
        let auth = base.with_mtls(&["ops"], &["read"]);
        let operator = auth.authenticate(None, None, Some("ops"), false).unwrap();
        assert_eq!(operator.role, Role::Operator);
        assert_eq!(operator.method, AuthMethod::Mtls);
        let viewer = auth.authenticate(None, None, Some("read"), false).unwrap();
        assert_eq!(viewer.role, Role::Viewer);
        assert!(auth
            .authenticate(None, None, Some("stranger"), false)
            .is_none());
    }

    #[test]
    fn session_expires() {
        let auth = AdminAuth::for_test(Some("segredo"), Duration::from_millis(1), true);
        let issued = auth.login_with_token("segredo", true).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let header = format!("{COOKIE_NAME}={}", issued.id);
        assert!(auth.authenticate(Some(&header), None, None, true).is_none());
    }

    #[test]
    fn api_rate_limit_trips() {
        let auth = AdminAuth::for_test(None, Duration::from_secs(900), true);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        for _ in 0..5 {
            assert!(auth.api_allowed("/api/metrics", Some(ip)));
        }
        assert!(!auth.api_allowed("/api/metrics", Some(ip)));
        assert!(auth.api_allowed("/healthz", Some(ip)));
    }

    #[test]
    fn production_still_requires_token_even_with_strong_auth() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(validate_exposure(loopback, None, true, true).is_err());
        assert_eq!(validate_exposure(loopback, Some("t"), true, true), Ok(()));
    }

    #[test]
    fn non_loopback_accepts_strong_auth_without_token() {
        let external: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(validate_exposure(external, None, false, false).is_err());
        assert_eq!(validate_exposure(external, None, false, true), Ok(()));
        assert_eq!(validate_exposure(external, Some("t"), false, false), Ok(()));
    }

    #[test]
    fn bearer_post_skips_csrf_session_does_not() {
        let auth = AdminAuth::for_test(Some("segredo"), Duration::from_secs(900), true);
        let token = auth
            .authenticate(None, Some("Bearer segredo"), None, true)
            .unwrap();
        assert!(auth.csrf_ok(&token, None));
        let issued = auth.login_with_token("segredo", true).unwrap();
        let header = format!("{COOKIE_NAME}={}", issued.id);
        let session = auth.authenticate(Some(&header), None, None, true).unwrap();
        assert!(!auth.csrf_ok(&session, None));
        assert!(auth.csrf_ok(&session, Some(&issued.csrf)));
    }

    #[test]
    fn no_token_without_strong_auth_is_viewer_not_operator() {
        let auth = AdminAuth::for_test(None, Duration::from_secs(900), true);
        let authn = auth.authenticate(None, None, None, true).unwrap();
        assert_eq!(authn.role, Role::Viewer);
        assert!(!authn.role.can_reload());
        assert!(!auth.csrf_ok(&authn, None));
    }

    #[test]
    fn strong_auth_without_token_is_unauthenticated() {
        let auth = AdminAuth::for_test(None, Duration::from_secs(900), false);
        assert!(auth.authenticate(None, None, None, true).is_none());
        assert!(auth.authenticate(None, None, None, false).is_none());
    }

    #[test]
    fn mtls_post_requires_csrf() {
        let base = AdminAuth::for_test(None, Duration::from_secs(900), false);
        let auth = base.with_mtls(&["ops"], &["read"]);
        let operator = auth.authenticate(None, None, Some("ops"), false).unwrap();
        assert_eq!(operator.role, Role::Operator);
        assert!(!auth.csrf_ok(&operator, None));
    }
}
