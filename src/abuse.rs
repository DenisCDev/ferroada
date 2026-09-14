//! Application abuse engine (Fase 6, first slice).
//!
//! Opt-in per site (`abuse = { ... }` in TOML). No block → the site behaves as
//! before. No ML. UA signatures remain a weak score signal, not the quota.
//!
//! `tls_fingerprint` is a ClientHello hash (see `tls_fingerprint.rs`), not JA4.
//! `http_fingerprint` is the ordered list of header **names**, never values.

use crate::client_ip::RiskIdentity;
use crate::metrics;
use crate::shield;
use dashmap::DashMap;
use http::HeaderMap;
use openssl::rand::rand_bytes;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_STUFFING: u32 = 10;
const DEFAULT_ENUMERATION: u32 = 20;
const DEFAULT_SIGNUP: u32 = 5;
const DEFAULT_RECOVER: u32 = 5;
const DEFAULT_WINDOW_SECS: u64 = 600;
const DEFAULT_CHALLENGE_SCORE: u32 = 40;
const IP_ROTATE_NETWORKS: usize = 3;
const MAX_KEYS: usize = 50_000;
const SWEEP_EVERY: u64 = 256;
const MMDB_MAX_BYTES: usize = 64 * 1024 * 1024;
const POW_BITS: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbuseReason {
    Stuffing,
    Enumeration,
    Signup,
    Recover,
    UaWeak,
    IpRotate,
}

impl AbuseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stuffing => "stuffing",
            Self::Enumeration => "enumeration",
            Self::Signup => "signup",
            Self::Recover => "recover",
            Self::UaWeak => "ua_weak",
            Self::IpRotate => "ip_rotate",
        }
    }

    fn points(self) -> u32 {
        match self {
            Self::Stuffing => 40,
            Self::Enumeration => 30,
            Self::Signup => 25,
            Self::Recover => 25,
            Self::UaWeak => 5,
            Self::IpRotate => 15,
        }
    }
}

pub fn format_reasons(reasons: &[AbuseReason]) -> String {
    reasons
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeKind {
    None,
    Pow,
    External,
}

impl ChallengeKind {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "none" => Ok(Self::None),
            "pow" => Ok(Self::Pow),
            "external" => Ok(Self::External),
            other => Err(format!(
                "abuse.challenge inválido ({other:?}); use none, pow ou external"
            )),
        }
    }
}

#[derive(Clone)]
pub struct AsnDb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl AsnDb {
    fn load(path: &Path) -> Result<Option<Self>, String> {
        if !path.is_file() {
            tracing::warn!(
                path = %path.display(),
                "abuse.mmdb ausente; asn fica vazio e o processo segue"
            );
            return Ok(None);
        }
        let bytes = std::fs::read(path).map_err(|error| {
            format!("abuse.mmdb não pôde ser lido ({}): {error}", path.display())
        })?;
        if bytes.len() > MMDB_MAX_BYTES {
            return Err(format!(
                "abuse.mmdb excede {MMDB_MAX_BYTES} bytes ({})",
                path.display()
            ));
        }
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|error| format!("abuse.mmdb inválido ({}): {error}", path.display()))?;
        Ok(Some(Self {
            reader: Arc::new(reader),
        }))
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<u32> {
        let result = self.reader.lookup(ip).ok()?;
        let asn = result.decode::<maxminddb::geoip2::Asn>().ok()??;
        asn.autonomous_system_number
    }
}

#[derive(Clone)]
pub struct AbusePolicy {
    pub stuffing_max: u32,
    pub enumeration_max: u32,
    pub signup_max: u32,
    pub recover_max: u32,
    pub window: Duration,
    pub challenge: ChallengeKind,
    pub challenge_url: Option<String>,
    pub challenge_score: u32,
    pub mmdb: Option<AsnDb>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AbuseFile {
    #[serde(default)]
    pub mmdb: Option<String>,
    #[serde(default)]
    pub stuffing_max: Option<u32>,
    #[serde(default)]
    pub enumeration_max: Option<u32>,
    #[serde(default)]
    pub signup_max: Option<u32>,
    #[serde(default)]
    pub recover_max: Option<u32>,
    #[serde(default)]
    pub window_secs: Option<u64>,
    #[serde(default)]
    pub challenge: Option<String>,
    #[serde(default)]
    pub challenge_url: Option<String>,
    #[serde(default)]
    pub challenge_score: Option<u32>,
}

impl AbuseFile {
    pub fn into_policy(self, base_dir: &Path, site: Option<&str>) -> Result<AbusePolicy, String> {
        let challenge = match self.challenge.as_deref() {
            Some(raw) => ChallengeKind::parse(raw)?,
            None => ChallengeKind::None,
        };
        if challenge == ChallengeKind::External
            && self
                .challenge_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .is_none()
        {
            return Err("abuse.challenge = external exige challenge_url".into());
        }
        let mmdb = match self
            .mmdb
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            Some(raw) => {
                let path = Path::new(raw);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    base_dir.join(path)
                };
                AsnDb::load(&path)
                    .map_err(|error| format!("{error} ({})", site.unwrap_or("site")))?
            }
            None => None,
        };
        Ok(AbusePolicy {
            stuffing_max: self.stuffing_max.unwrap_or(DEFAULT_STUFFING).max(1),
            enumeration_max: self.enumeration_max.unwrap_or(DEFAULT_ENUMERATION).max(1),
            signup_max: self.signup_max.unwrap_or(DEFAULT_SIGNUP).max(1),
            recover_max: self.recover_max.unwrap_or(DEFAULT_RECOVER).max(1),
            window: Duration::from_secs(self.window_secs.unwrap_or(DEFAULT_WINDOW_SECS).max(1)),
            challenge,
            challenge_url: self.challenge_url,
            challenge_score: self.challenge_score.unwrap_or(DEFAULT_CHALLENGE_SCORE),
            mmdb,
        })
    }

    pub fn mmdb_path(&self, base_dir: &Path) -> Option<PathBuf> {
        let raw = self.mmdb.as_deref()?.trim();
        if raw.is_empty() {
            return None;
        }
        let path = Path::new(raw);
        Some(if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum QuotaKind {
    Stuffing,
    Enumeration,
    Signup,
    Recover,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum QuotaDim {
    Fingerprint(u64),
    Session(u64),
    JwtSub(u64),
    Network(IpAddr),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct QuotaKey {
    site: String,
    kind: QuotaKind,
    dim: QuotaDim,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RotateKey {
    site: String,
    fingerprint: u64,
}

pub struct AbuseEngine {
    counters: DashMap<QuotaKey, Vec<Instant>>,
    rotations: DashMap<RotateKey, HashSet<IpAddr>>,
    hits: AtomicU64,
}

#[derive(Debug)]
pub enum AbuseVerdict {
    Allow,
    Block {
        reasons: Vec<AbuseReason>,
        challenge: bool,
    },
}

pub struct AbuseRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub ua: Option<&'a str>,
    pub accept: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub has_jwt: bool,
}

impl AbuseEngine {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            rotations: DashMap::new(),
            hits: AtomicU64::new(0),
        }
    }

    pub fn inspect(
        &self,
        policy: &AbusePolicy,
        identity: &RiskIdentity,
        request: AbuseRequest<'_>,
    ) -> AbuseVerdict {
        self.maybe_sweep(policy.window);
        self.note_rotation(identity);
        let path = request.path.split('?').next().unwrap_or(request.path);
        let mut reasons = Vec::new();
        if self.over(
            identity,
            QuotaKind::Stuffing,
            policy.stuffing_max,
            policy.window,
        ) {
            reasons.push(AbuseReason::Stuffing);
        }
        if self.over(
            identity,
            QuotaKind::Enumeration,
            policy.enumeration_max,
            policy.window,
        ) {
            reasons.push(AbuseReason::Enumeration);
        }
        if self.over(
            identity,
            QuotaKind::Signup,
            policy.signup_max,
            policy.window,
        ) {
            reasons.push(AbuseReason::Signup);
        } else if is_signup_path(request.method, path) {
            self.hit(identity, QuotaKind::Signup);
        }
        if self.over(
            identity,
            QuotaKind::Recover,
            policy.recover_max,
            policy.window,
        ) {
            reasons.push(AbuseReason::Recover);
        } else if is_recover_path(request.method, path) {
            self.hit(identity, QuotaKind::Recover);
        }
        if request.ua.is_some_and(shield::ua_is_weak) {
            reasons.push(AbuseReason::UaWeak);
        }
        if self.rotated(identity) {
            reasons.push(AbuseReason::IpRotate);
        }
        let score: u32 = reasons.iter().map(|reason| reason.points()).sum();
        let path_block = (reasons.contains(&AbuseReason::Stuffing)
            && is_stuffing_path(request.method, path))
            || (reasons.contains(&AbuseReason::Enumeration) && is_enumeration_path(path))
            || (reasons.contains(&AbuseReason::Signup) && is_signup_path(request.method, path))
            || (reasons.contains(&AbuseReason::Recover) && is_recover_path(request.method, path));
        let over_score = score >= policy.challenge_score && policy.challenge_score > 0;
        if !path_block && !over_score {
            return AbuseVerdict::Allow;
        }
        if path_block {
            let challenge = wants_html_challenge(
                policy.challenge,
                request.accept,
                request.content_type,
                request.has_jwt,
            );
            return AbuseVerdict::Block { reasons, challenge };
        }
        if skip_html_challenge(request.accept, request.content_type, request.has_jwt)
            || !request
                .accept
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("text/html")
            || policy.challenge == ChallengeKind::None
        {
            return AbuseVerdict::Allow;
        }
        AbuseVerdict::Block {
            reasons,
            challenge: true,
        }
    }

    pub fn record_origin_status(
        &self,
        identity: &RiskIdentity,
        method: &str,
        path: &str,
        status: u16,
    ) {
        let path = path.split('?').next().unwrap_or(path);
        if status == 401 && is_stuffing_path(method, path) {
            self.hit(identity, QuotaKind::Stuffing);
        }
        if status == 404 && is_enumeration_path(path) {
            self.hit(identity, QuotaKind::Enumeration);
        }
    }

    fn hit(&self, identity: &RiskIdentity, kind: QuotaKind) {
        for dim in identity_dims(identity) {
            let key = QuotaKey {
                site: identity.site.clone(),
                kind: kind.clone(),
                dim,
            };
            self.counters.entry(key).or_default().push(Instant::now());
        }
    }

    fn over(&self, identity: &RiskIdentity, kind: QuotaKind, max: u32, window: Duration) -> bool {
        let now = Instant::now();
        for dim in identity_dims(identity) {
            let key = QuotaKey {
                site: identity.site.clone(),
                kind: kind.clone(),
                dim,
            };
            if let Some(mut entry) = self.counters.get_mut(&key) {
                entry.retain(|at| now.duration_since(*at) < window);
                if entry.len() as u32 >= max {
                    return true;
                }
            }
        }
        false
    }

    fn note_rotation(&self, identity: &RiskIdentity) {
        let Some(fingerprint) = identity.preferred_fingerprint() else {
            return;
        };
        let key = RotateKey {
            site: identity.site.clone(),
            fingerprint,
        };
        let mut networks = self.rotations.entry(key).or_default();
        if networks.len() < 32 {
            networks.insert(identity.network);
        }
    }

    fn rotated(&self, identity: &RiskIdentity) -> bool {
        let Some(fingerprint) = identity.preferred_fingerprint() else {
            return false;
        };
        self.rotations
            .get(&RotateKey {
                site: identity.site.clone(),
                fingerprint,
            })
            .map(|networks| networks.len() >= IP_ROTATE_NETWORKS)
            .unwrap_or(false)
    }

    fn maybe_sweep(&self, window: Duration) {
        let n = self.hits.fetch_add(1, Ordering::Relaxed);
        if !n.is_multiple_of(SWEEP_EVERY) {
            return;
        }
        let now = Instant::now();
        self.counters.retain(|_, times| {
            times.retain(|at| now.duration_since(*at) < window);
            !times.is_empty()
        });
        if self.counters.len() > MAX_KEYS {
            self.counters.clear();
        }
        if self.rotations.len() > MAX_KEYS {
            self.rotations.clear();
        }
    }
}

impl Default for AbuseEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn identity_dims(identity: &RiskIdentity) -> Vec<QuotaDim> {
    let mut dims = Vec::new();
    if let Some(fp) = identity.tls_fingerprint {
        dims.push(QuotaDim::Fingerprint(fp));
    }
    if let Some(fp) = identity.http_fingerprint {
        if identity.tls_fingerprint != Some(fp) {
            dims.push(QuotaDim::Fingerprint(fp));
        }
    }
    if let Some(hash) = identity.session_hash {
        dims.push(QuotaDim::Session(hash));
    }
    if let Some(hash) = identity.jwt_sub_hash {
        dims.push(QuotaDim::JwtSub(hash));
    }
    dims.push(QuotaDim::Network(identity.network));
    dims
}

pub fn http_fingerprint(headers: &HeaderMap) -> u64 {
    let mut hasher = DefaultHasher::new();
    for (name, _) in headers.iter() {
        name.as_str().to_ascii_lowercase().hash(&mut hasher);
        hasher.write_u8(0);
    }
    hasher.finish()
}

pub fn is_stuffing_path(method: &str, path: &str) -> bool {
    if !method.eq_ignore_ascii_case("POST") {
        return false;
    }
    matches!(path, "/login" | "/auth/token" | "/auth/login" | "/session")
        || path.starts_with("/login/")
}

pub fn is_enumeration_path(path: &str) -> bool {
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    match (parts.next(), parts.next(), parts.next()) {
        (Some("users") | Some("accounts"), Some(id), None) => !id.is_empty(),
        _ => false,
    }
}

pub fn is_signup_path(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        && matches!(path, "/signup" | "/register" | "/auth/register")
}

pub fn is_recover_path(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        && matches!(
            path,
            "/recover-password" | "/forgot-password" | "/password/reset" | "/auth/recover"
        )
}

pub fn skip_html_challenge(
    accept: Option<&str>,
    content_type: Option<&str>,
    has_jwt: bool,
) -> bool {
    if has_jwt {
        return true;
    }
    if content_type.is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"))
    {
        return true;
    }
    let accept = accept.unwrap_or("").to_ascii_lowercase();
    accept.contains("application/json") && !accept.contains("text/html")
}

fn wants_html_challenge(
    kind: ChallengeKind,
    accept: Option<&str>,
    content_type: Option<&str>,
    has_jwt: bool,
) -> bool {
    if kind == ChallengeKind::None {
        return false;
    }
    if skip_html_challenge(accept, content_type, has_jwt) {
        return false;
    }
    accept
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("text/html")
}

pub struct ChallengeBody {
    pub content_type: &'static str,
    pub body: String,
}

pub fn render_challenge(policy: &AbusePolicy, reasons: &[AbuseReason]) -> ChallengeBody {
    let detail = format_reasons(reasons);
    match policy.challenge {
        ChallengeKind::Pow => ChallengeBody {
            content_type: "text/html; charset=utf-8",
            body: pow_html(),
        },
        ChallengeKind::External => {
            let url = policy
                .challenge_url
                .as_deref()
                .unwrap_or("https://invalid.invalid/");
            ChallengeBody {
                content_type: "text/html; charset=utf-8",
                body: external_html(url),
            }
        }
        ChallengeKind::None => ChallengeBody {
            content_type: "text/plain; charset=utf-8",
            body: format!("403 Proibido: abuso ({detail})\n"),
        },
    }
}

pub fn plain_block_body(reasons: &[AbuseReason]) -> String {
    format!("403 Proibido: abuso ({})\n", format_reasons(reasons))
}

fn pow_html() -> String {
    let nonce = random_nonce();
    format!(
        r#"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verificação</title>
</head>
<body>
<p>Confirme que não é automação. Isto pode levar alguns segundos.</p>
<noscript><p>Ative o JavaScript ou recarregue daqui a alguns minutos.</p></noscript>
<script>
const nonce = {nonce:?};
const bits = {POW_BITS};
const status = document.createElement('p');
document.body.appendChild(status);
async function solve() {{
  if (!window.crypto || !crypto.subtle) {{
    status.textContent = 'Este navegador não consegue concluir a verificação. Recarregue daqui a alguns minutos.';
    return;
  }}
  const enc = new TextEncoder();
  try {{
    for (let n = 0; n < 50000000; n++) {{
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(nonce + ':' + n));
      const view = new DataView(buf);
      if ((view.getUint32(0) >>> (32 - bits)) === 0) {{
        status.textContent = 'Verificação local concluída. Recarregue a página. Se o acesso continuar bloqueado, aguarde alguns minutos.';
        return;
      }}
    }}
    status.textContent = 'Não foi possível concluir a verificação. Recarregue a página.';
  }} catch (err) {{
    status.textContent = 'A verificação falhou. Recarregue daqui a alguns minutos.';
  }}
}}
solve();
</script>
</body>
</html>
"#
    )
}

fn external_html(url: &str) -> String {
    let escaped = url
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(
        r#"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verificação</title>
</head>
<body>
<p>Complete a verificação e volte a esta página.</p>
<p><a href="{escaped}">Abrir verificação</a></p>
</body>
</html>
"#
    )
}

fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    if rand_bytes(&mut buf).is_err() {
        return "ferroada".into();
    }
    buf.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn record_block(site: &str, ip: &str, uri: &str, reasons: &[AbuseReason], challenge: bool) {
    let mut detail = format_reasons(reasons);
    if challenge {
        if !detail.is_empty() {
            detail.push(',');
        }
        detail.push_str("challenge");
    }
    metrics::record_block_in(site, "abuse", ip, uri, &detail);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn identity(ip: u8, fp: u64) -> RiskIdentity {
        let mut id = RiskIdentity::new(
            "api.example.com",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, ip)),
            "/login",
            None,
            None,
        );
        id.set_fingerprints(None, Some(fp));
        id
    }

    fn policy(challenge: ChallengeKind) -> AbusePolicy {
        AbusePolicy {
            stuffing_max: 10,
            enumeration_max: 20,
            signup_max: 5,
            recover_max: 5,
            window: Duration::from_secs(600),
            challenge,
            challenge_url: None,
            challenge_score: 40,
            mmdb: None,
        }
    }

    fn req<'a>(
        method: &'a str,
        path: &'a str,
        accept: Option<&'a str>,
        content_type: Option<&'a str>,
        has_jwt: bool,
    ) -> AbuseRequest<'a> {
        AbuseRequest {
            method,
            path,
            ua: Some("Mozilla/5.0"),
            accept,
            content_type,
            has_jwt,
        }
    }

    #[test]
    fn stuffing_follows_fingerprint_across_ips() {
        let engine = AbuseEngine::new();
        let policy = policy(ChallengeKind::None);
        for ip in 1..=10 {
            let id = identity(ip, 42);
            engine.record_origin_status(&id, "POST", "/login", 401);
        }
        match engine.inspect(
            &policy,
            &identity(99, 42),
            req("POST", "/login", None, None, false),
        ) {
            AbuseVerdict::Block { reasons, challenge } => {
                assert!(reasons.contains(&AbuseReason::Stuffing));
                assert!(!challenge);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stuffing_does_not_fire_for_distinct_fingerprints() {
        let engine = AbuseEngine::new();
        let policy = policy(ChallengeKind::None);
        for ip in 1..=20 {
            let id = identity(ip, u64::from(ip));
            engine.record_origin_status(&id, "POST", "/login", 401);
            match engine.inspect(&policy, &id, req("POST", "/login", None, None, false)) {
                AbuseVerdict::Allow => {}
                other => panic!("fp {ip}: {other:?}"),
            }
        }
    }

    #[test]
    fn stuffing_score_challenges_browser_get_but_skips_jwt() {
        let engine = AbuseEngine::new();
        let policy = policy(ChallengeKind::Pow);
        for ip in 1..=10 {
            engine.record_origin_status(&identity(ip, 7), "POST", "/login", 401);
        }
        match engine.inspect(
            &policy,
            &identity(99, 7),
            req("GET", "/", Some("text/html"), None, false),
        ) {
            AbuseVerdict::Block { reasons, challenge } => {
                assert!(reasons.contains(&AbuseReason::Stuffing));
                assert!(challenge);
            }
            other => panic!("{other:?}"),
        }
        match engine.inspect(
            &policy,
            &identity(99, 7),
            req("GET", "/api", Some("text/html"), None, true),
        ) {
            AbuseVerdict::Allow => {}
            other => panic!("jwt must skip HTML challenge: {other:?}"),
        }
        match engine.inspect(
            &policy,
            &identity(99, 7),
            req(
                "GET",
                "/api",
                Some("application/json"),
                Some("application/json"),
                false,
            ),
        ) {
            AbuseVerdict::Allow => {}
            other => panic!("JSON API must skip HTML challenge: {other:?}"),
        }
    }

    #[test]
    fn jwt_skips_html_challenge() {
        assert!(skip_html_challenge(Some("text/html"), None, true));
        assert!(skip_html_challenge(Some("application/json"), None, false));
        assert!(!skip_html_challenge(
            Some("text/html,application/xhtml+xml"),
            None,
            false
        ));
    }

    #[test]
    fn http_fingerprint_ignores_values() {
        let mut a = HeaderMap::new();
        a.insert("user-agent", "one".parse().unwrap());
        a.insert("accept", "text/html".parse().unwrap());
        let mut b = HeaderMap::new();
        b.insert("User-Agent", "two".parse().unwrap());
        b.insert("Accept", "*/*".parse().unwrap());
        assert_eq!(http_fingerprint(&a), http_fingerprint(&b));
        b.insert("x-trace", "1".parse().unwrap());
        assert_ne!(http_fingerprint(&a), http_fingerprint(&b));
    }

    #[test]
    fn enumeration_and_signup_paths() {
        assert!(is_enumeration_path("/users/42"));
        assert!(is_enumeration_path("/accounts/abc"));
        assert!(!is_enumeration_path("/users/"));
        assert!(!is_enumeration_path("/users/42/extra"));
        assert!(is_signup_path("POST", "/register"));
        assert!(!is_signup_path("GET", "/register"));
        assert!(is_recover_path("POST", "/forgot-password"));
    }

    #[test]
    fn pow_html_has_no_password_and_lists_no_secret() {
        let policy = policy(ChallengeKind::Pow);
        let body = render_challenge(&policy, &[AbuseReason::Stuffing]);
        assert!(body.body.contains("lang=\"pt-BR\""));
        assert!(body.body.contains("SHA-256"));
        assert!(body.body.contains("<noscript>"));
        assert!(body.body.contains("Recarregue"));
        assert!(!body.body.to_ascii_lowercase().contains("password"));
        assert!(!body.body.to_ascii_lowercase().contains("senha"));
        assert_eq!(body.content_type, "text/html; charset=utf-8");
        let external = AbusePolicy {
            challenge: ChallengeKind::External,
            challenge_url: Some("https://verify.example/start".into()),
            ..policy
        };
        let ext = render_challenge(&external, &[AbuseReason::Stuffing]);
        assert!(ext.body.contains("href=\"https://verify.example/start\""));
        assert!(ext.body.contains("lang=\"pt-BR\""));
        assert_eq!(ext.content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn asn_absent_without_mmdb() {
        let policy = AbuseFile::default()
            .into_policy(Path::new("."), None)
            .unwrap();
        assert!(policy.mmdb.is_none());
    }

    #[test]
    fn missing_mmdb_file_leaves_asn_none() {
        let file = AbuseFile {
            mmdb: Some("./no-such-ferroada-asn.mmdb".into()),
            stuffing_max: Some(10),
            ..AbuseFile::default()
        };
        let policy = file.into_policy(Path::new("."), None).unwrap();
        assert!(policy.mmdb.is_none());
    }

    #[test]
    fn signup_cap_allows_five_then_blocks() {
        let engine = AbuseEngine::new();
        let policy = policy(ChallengeKind::None);
        for n in 1..=5 {
            match engine.inspect(
                &policy,
                &identity(n, 9),
                req("POST", "/register", None, None, false),
            ) {
                AbuseVerdict::Allow => {}
                other => panic!("signup {n} should reach origin: {other:?}"),
            }
        }
        match engine.inspect(
            &policy,
            &identity(99, 9),
            req("POST", "/register", None, None, false),
        ) {
            AbuseVerdict::Block { reasons, .. } => {
                assert!(reasons.contains(&AbuseReason::Signup));
            }
            other => panic!("{other:?}"),
        }
    }
}
