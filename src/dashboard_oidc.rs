//! Dashboard OIDC authorization code + PKCE. Codes and verifiers never go in logs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use openssl::sign::Verifier;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{env_nonempty, env_set, random_bytes, Role};

const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_MAX_BODY: usize = 64 * 1024;
const HTTP_MAX_REDIRECTS: u8 = 3;
const RSA_MIN_BITS: i32 = 2048;
const LEEWAY_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub scopes: String,
    pub role_claim: String,
    pub operators: HashSet<String>,
    pub viewers: HashSet<String>,
}

#[derive(Clone, Debug)]
pub struct PendingOidc {
    pub verifier: String,
    pub nonce: String,
}

pub struct OidcIdentity {
    pub subject: String,
    pub role: Role,
}

impl OidcConfig {
    pub fn from_env() -> Result<Option<Self>, String> {
        let keys = [
            "DASHBOARD_OIDC_ISSUER",
            "DASHBOARD_OIDC_CLIENT_ID",
            "DASHBOARD_OIDC_CLIENT_SECRET",
            "DASHBOARD_OIDC_REDIRECT_URI",
            "DASHBOARD_OIDC_AUTHORIZATION_ENDPOINT",
            "DASHBOARD_OIDC_TOKEN_ENDPOINT",
            "DASHBOARD_OIDC_JWKS_URI",
            "DASHBOARD_OIDC_SCOPES",
            "DASHBOARD_OIDC_ROLE_CLAIM",
            "DASHBOARD_OIDC_OPERATORS",
            "DASHBOARD_OIDC_VIEWERS",
        ];
        let any = keys.iter().any(|name| env_nonempty(name).is_some());
        if !any {
            return Ok(None);
        }
        let issuer = env_nonempty("DASHBOARD_OIDC_ISSUER")
            .ok_or("DASHBOARD_OIDC_ISSUER é obrigatório quando OIDC está ligado")?;
        let client_id = env_nonempty("DASHBOARD_OIDC_CLIENT_ID")
            .ok_or("DASHBOARD_OIDC_CLIENT_ID é obrigatório quando OIDC está ligado")?;
        let redirect_uri = env_nonempty("DASHBOARD_OIDC_REDIRECT_URI")
            .ok_or("DASHBOARD_OIDC_REDIRECT_URI é obrigatório quando OIDC está ligado")?;
        let issuer = trim_slash(&issuer);
        if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            return Err("DASHBOARD_OIDC_ISSUER deve ser um URL http(s)".into());
        }
        if issuer.contains('@') {
            return Err("DASHBOARD_OIDC_ISSUER não pode ter userinfo".into());
        }
        if !redirect_uri.starts_with("https://") && !redirect_uri.starts_with("http://") {
            return Err("DASHBOARD_OIDC_REDIRECT_URI deve ser um URL http(s)".into());
        }
        let authorization_endpoint = env_nonempty("DASHBOARD_OIDC_AUTHORIZATION_ENDPOINT");
        let token_endpoint = env_nonempty("DASHBOARD_OIDC_TOKEN_ENDPOINT");
        let jwks_uri = env_nonempty("DASHBOARD_OIDC_JWKS_URI");
        let (authorization_endpoint, token_endpoint, jwks_uri) = match (
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
        ) {
            (Some(a), Some(t), Some(j)) => (a, t, j),
            (None, None, None) => discover(&issuer)?,
            _ => {
                return Err(
                        "DASHBOARD_OIDC_* endpoints: preencha os três (authorization, token, jwks) ou nenhum para descoberta"
                            .into(),
                    );
            }
        };
        let scopes = env_nonempty("DASHBOARD_OIDC_SCOPES").unwrap_or_else(|| "openid".into());
        let role_claim =
            env_nonempty("DASHBOARD_OIDC_ROLE_CLAIM").unwrap_or_else(|| "ferroada_role".into());
        let operators = match env_nonempty("DASHBOARD_OIDC_OPERATORS") {
            Some(_) => env_set("DASHBOARD_OIDC_OPERATORS"),
            None => HashSet::from(["operator".into()]),
        };
        let viewers = match env_nonempty("DASHBOARD_OIDC_VIEWERS") {
            Some(_) => env_set("DASHBOARD_OIDC_VIEWERS"),
            None => HashSet::from(["viewer".into()]),
        };
        Ok(Some(Self {
            issuer,
            client_id,
            client_secret: env_nonempty("DASHBOARD_OIDC_CLIENT_SECRET"),
            redirect_uri,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            scopes,
            role_claim,
            operators,
            viewers,
        }))
    }

    pub fn authorize_url(&self, state: &str, nonce: &str, challenge: &str) -> String {
        let mut url = self.authorization_endpoint.clone();
        let join = if url.contains('?') { '&' } else { '?' };
        url.push(join);
        url.push_str("response_type=code");
        url.push_str("&client_id=");
        url.push_str(&form_encode(&self.client_id));
        url.push_str("&redirect_uri=");
        url.push_str(&form_encode(&self.redirect_uri));
        url.push_str("&scope=");
        url.push_str(&form_encode(&self.scopes));
        url.push_str("&state=");
        url.push_str(&form_encode(state));
        url.push_str("&nonce=");
        url.push_str(&form_encode(nonce));
        url.push_str("&code_challenge=");
        url.push_str(&form_encode(challenge));
        url.push_str("&code_challenge_method=S256");
        url
    }

    pub fn start_pkce(&self) -> Result<(PendingOidc, String, String), String> {
        let (verifier, challenge) = generate_pkce()?;
        let state = hex_encode(&random_bytes(32)?);
        let nonce = hex_encode(&random_bytes(32)?);
        let pending = PendingOidc { verifier, nonce };
        let url = self.authorize_url(&state, &pending.nonce, &challenge);
        Ok((pending, state, url))
    }

    pub fn exchange(&self, code: &str, pending: &PendingOidc) -> Result<OidcIdentity, String> {
        if code.is_empty() || code.len() > 4096 {
            return Err("oidc_code".into());
        }
        let mut form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            form_encode(code),
            form_encode(&self.redirect_uri),
            form_encode(&self.client_id),
            form_encode(&pending.verifier)
        );
        if let Some(secret) = &self.client_secret {
            form.push_str("&client_secret=");
            form.push_str(&form_encode(secret));
        }
        let body = http_post(&self.token_endpoint, &form, Instant::now() + HTTP_TIMEOUT)?;
        let token: TokenResponse =
            serde_json::from_str(&body).map_err(|_| "oidc_token".to_string())?;
        let id_token = token.id_token.ok_or_else(|| "oidc_id_token".to_string())?;
        let claims = verify_id_token(
            &id_token,
            self,
            &pending.nonce,
            Instant::now() + HTTP_TIMEOUT,
        )?;
        let role = map_role(&claims, &self.role_claim, &self.operators, &self.viewers)
            .ok_or_else(|| "oidc_role".to_string())?;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "oidc_sub".to_string())?
            .to_string();
        Ok(OidcIdentity { subject, role })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

fn discover(issuer: &str) -> Result<(String, String, String), String> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let body = http_get(&url, Instant::now() + HTTP_TIMEOUT, 0)?;
    let doc: Discovery =
        serde_json::from_str(&body).map_err(|error| format!("OIDC discovery JSON: {error}"))?;
    if trim_slash(&doc.issuer) != issuer {
        return Err("OIDC discovery issuer não coincide".into());
    }
    if let Some(methods) = &doc.code_challenge_methods_supported {
        if !methods.iter().any(|m| m == "S256") {
            return Err("OIDC IdP não anuncia PKCE S256".into());
        }
    }
    Ok((doc.authorization_endpoint, doc.token_endpoint, doc.jwks_uri))
}

pub fn generate_pkce() -> Result<(String, String), String> {
    let raw = random_bytes(32)?;
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let digest = sha256(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    Ok((verifier, challenge))
}

pub fn map_role(
    claims: &Value,
    claim: &str,
    operators: &HashSet<String>,
    viewers: &HashSet<String>,
) -> Option<Role> {
    let values = claim_values(claims, claim);
    if values.iter().any(|value| operators.contains(value)) {
        return Some(Role::Operator);
    }
    if values.iter().any(|value| viewers.contains(value)) {
        return Some(Role::Viewer);
    }
    None
}

fn claim_values(payload: &Value, claim: &str) -> Vec<String> {
    match payload.get(claim) {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    nonce: &str,
    deadline: Instant,
) -> Result<Value, String> {
    let (header_json, payload_json, signing_input, signature) = split_jwt(token)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_json).map_err(|_| "oidc_jwt".to_string())?;
    if header.crit.as_ref().is_some_and(|crit| !crit.is_empty()) {
        return Err("oidc_crit".into());
    }
    let alg = header.alg.as_str();
    if alg != "RS256" && alg != "ES256" {
        return Err("oidc_alg".into());
    }
    let kid = header
        .kid
        .as_deref()
        .map(str::trim)
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| "oidc_kid".to_string())?;
    let jwks_body = http_get(&config.jwks_uri, deadline, 0)?;
    let keys = parse_jwks(&jwks_body)?;
    let key = keys.get(kid).ok_or_else(|| "oidc_kid".to_string())?;
    match (alg, &key.material) {
        ("RS256", KeyMaterial::Rsa { n, e }) => {
            verify_rsa(n, e, signing_input.as_bytes(), &signature)?
        }
        ("ES256", KeyMaterial::Ec { x, y }) => {
            verify_es256(x, y, signing_input.as_bytes(), &signature)?
        }
        _ => return Err("oidc_alg".into()),
    }
    let payload: Value =
        serde_json::from_slice(&payload_json).map_err(|_| "oidc_jwt".to_string())?;
    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| "oidc_iss".to_string())?;
    if trim_slash(iss) != config.issuer {
        return Err("oidc_iss".into());
    }
    if !aud_matches(payload.get("aud"), &config.client_id) {
        return Err("oidc_aud".into());
    }
    let now = unix_now();
    let exp = unix_claim(&payload, "exp").ok_or_else(|| "oidc_exp".to_string())?;
    if exp + LEEWAY_SECS < now {
        return Err("oidc_exp".into());
    }
    if let Some(nbf) = unix_claim(&payload, "nbf") {
        if nbf > now.saturating_add(LEEWAY_SECS) {
            return Err("oidc_nbf".into());
        }
    }
    if let Some(iat) = unix_claim(&payload, "iat") {
        if iat > now.saturating_add(LEEWAY_SECS) {
            return Err("oidc_iat".into());
        }
    }
    let got_nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| "oidc_nonce".to_string())?;
    if got_nonce != nonce {
        return Err("oidc_nonce".into());
    }
    Ok(payload)
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
}

enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { x: Vec<u8>, y: Vec<u8> },
}

struct CachedJwk {
    material: KeyMaterial,
}

fn parse_jwks(body: &str) -> Result<HashMap<String, CachedJwk>, String> {
    #[derive(Deserialize)]
    struct Doc {
        keys: Vec<Jwk>,
    }
    #[derive(Deserialize)]
    struct Jwk {
        kty: String,
        #[serde(default)]
        kid: Option<String>,
        #[serde(default, rename = "use")]
        use_: Option<String>,
        #[serde(default)]
        n: Option<String>,
        #[serde(default)]
        e: Option<String>,
        #[serde(default)]
        crv: Option<String>,
        #[serde(default)]
        x: Option<String>,
        #[serde(default)]
        y: Option<String>,
    }
    let doc: Doc = serde_json::from_str(body).map_err(|_| "oidc_jwks".to_string())?;
    if doc.keys.len() > 32 {
        return Err("oidc_jwks".into());
    }
    let mut out = HashMap::new();
    for jwk in doc.keys {
        if jwk.use_.as_deref() == Some("enc") {
            continue;
        }
        let Some(kid) = jwk
            .kid
            .as_deref()
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
        else {
            continue;
        };
        let material = match jwk.kty.as_str() {
            "RSA" => {
                let Ok(n) = b64url_decode(jwk.n.as_deref().unwrap_or("")) else {
                    continue;
                };
                let Ok(e) = b64url_decode(jwk.e.as_deref().unwrap_or("")) else {
                    continue;
                };
                if n.is_empty() || e.is_empty() {
                    continue;
                }
                KeyMaterial::Rsa { n, e }
            }
            "EC" => {
                if jwk.crv.as_deref() != Some("P-256") {
                    continue;
                }
                let Ok(x) = b64url_decode(jwk.x.as_deref().unwrap_or("")) else {
                    continue;
                };
                let Ok(y) = b64url_decode(jwk.y.as_deref().unwrap_or("")) else {
                    continue;
                };
                KeyMaterial::Ec { x, y }
            }
            _ => continue,
        };
        out.insert(kid.to_string(), CachedJwk { material });
    }
    if out.is_empty() {
        return Err("oidc_jwks".into());
    }
    Ok(out)
}

type JwtParts = (Vec<u8>, Vec<u8>, String, Vec<u8>);

fn split_jwt(token: &str) -> Result<JwtParts, String> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or_else(|| "oidc_jwt".to_string())?;
    let payload = parts.next().ok_or_else(|| "oidc_jwt".to_string())?;
    let signature = parts.next().unwrap_or("");
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return Err("oidc_jwt".into());
    }
    Ok((
        b64url_decode(header).map_err(|_| "oidc_jwt".to_string())?,
        b64url_decode(payload).map_err(|_| "oidc_jwt".to_string())?,
        format!("{header}.{payload}"),
        if signature.is_empty() {
            Vec::new()
        } else {
            b64url_decode(signature).map_err(|_| "oidc_jwt".to_string())?
        },
    ))
}

fn verify_rsa(n: &[u8], e: &[u8], input: &[u8], signature: &[u8]) -> Result<(), String> {
    let n = BigNum::from_slice(n).map_err(|_| "oidc_sig".to_string())?;
    if n.num_bits() < RSA_MIN_BITS {
        return Err("oidc_sig".into());
    }
    let e = BigNum::from_slice(e).map_err(|_| "oidc_sig".to_string())?;
    let rsa = Rsa::from_public_components(n, e).map_err(|_| "oidc_sig".to_string())?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| "oidc_sig".to_string())?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| "oidc_sig".to_string())?;
    verifier.update(input).map_err(|_| "oidc_sig".to_string())?;
    match verifier.verify(signature) {
        Ok(true) => Ok(()),
        _ => Err("oidc_sig".into()),
    }
}

fn verify_es256(x: &[u8], y: &[u8], input: &[u8], signature: &[u8]) -> Result<(), String> {
    if signature.len() != 64 {
        return Err("oidc_sig".into());
    }
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| "oidc_sig".to_string())?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|_| "oidc_sig".to_string())?;
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&left_pad(x, 32).ok_or_else(|| "oidc_sig".to_string())?);
    uncompressed.extend_from_slice(&left_pad(y, 32).ok_or_else(|| "oidc_sig".to_string())?);
    let point =
        EcPoint::from_bytes(&group, &uncompressed, &mut ctx).map_err(|_| "oidc_sig".to_string())?;
    let ec = EcKey::from_public_key(&group, &point).map_err(|_| "oidc_sig".to_string())?;
    let pkey = PKey::from_ec_key(ec).map_err(|_| "oidc_sig".to_string())?;
    let der = ecdsa_raw_to_der(signature).ok_or_else(|| "oidc_sig".to_string())?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| "oidc_sig".to_string())?;
    verifier.update(input).map_err(|_| "oidc_sig".to_string())?;
    match verifier.verify(&der) {
        Ok(true) => Ok(()),
        _ => Err("oidc_sig".into()),
    }
}

fn ecdsa_raw_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    let r = BigNum::from_slice(&raw[..32]).ok()?;
    let s = BigNum::from_slice(&raw[32..]).ok()?;
    let sig = EcdsaSig::from_private_components(r, s).ok()?;
    sig.to_der().ok()
}

fn left_pad(bytes: &[u8], size: usize) -> Option<Vec<u8>> {
    if bytes.len() > size {
        return None;
    }
    let mut out = vec![0u8; size];
    out[size - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

fn aud_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(expected)),
        _ => false,
    }
}

fn unix_claim(payload: &Value, name: &str) -> Option<u64> {
    payload.get(name).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(input.as_bytes()).map_err(|_| ())
}

pub fn form_encode(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn trim_slash(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

struct ParsedUrl {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Result<ParsedUrl, String> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("OIDC URL inválido".into());
    };
    if rest.contains('@') {
        return Err("OIDC URL com userinfo recusado".into());
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(host) = authority.strip_prefix('[') {
        let end = host
            .find(']')
            .ok_or_else(|| "OIDC URL IPv6 inválido".to_string())?;
        let host_name = &host[..end];
        let port = host[end + 1..]
            .strip_prefix(':')
            .map(|port| {
                port.parse::<u16>()
                    .map_err(|_| "OIDC URL porta inválida".to_string())
            })
            .transpose()?
            .unwrap_or(if tls { 443 } else { 80 });
        (host_name.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| "OIDC URL porta inválida".to_string())?;
        (host.to_string(), port)
    } else {
        (authority.to_string(), if tls { 443 } else { 80 })
    };
    if host.is_empty() {
        return Err("OIDC URL sem host".into());
    }
    Ok(ParsedUrl {
        tls,
        host,
        port,
        path,
    })
}

enum BodyStream {
    Plain(TcpStream),
    Tls(openssl::ssl::SslStream<TcpStream>),
}

impl Read for BodyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for BodyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn connect(url: &str, deadline: Instant) -> Result<(ParsedUrl, BodyStream), String> {
    let parsed = parse_http_url(url)?;
    let timeout = remaining(deadline)?;
    let addr = resolve_host(&parsed.host, parsed.port, timeout)?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|error| format!("OIDC connect: {error}"))?;
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("OIDC: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("OIDC: {error}"))?;
    let stream = if parsed.tls {
        let connector = tls_connector()?;
        let tls = connector
            .connect(&parsed.host, stream)
            .map_err(|error| format!("OIDC tls: {error}"))?;
        BodyStream::Tls(tls)
    } else {
        BodyStream::Plain(stream)
    };
    Ok((parsed, stream))
}

fn host_header(parsed: &ParsedUrl) -> String {
    if parsed.port == if parsed.tls { 443 } else { 80 } {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    }
}

fn http_get(url: &str, deadline: Instant, redirects: u8) -> Result<String, String> {
    if redirects > HTTP_MAX_REDIRECTS {
        return Err("OIDC: demasiados redireccionamentos".into());
    }
    let (parsed, mut stream) = connect(url, deadline)?;
    let host = host_header(&parsed);
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ferroada-oidc\r\nConnection: close\r\n\r\n",
        parsed.path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("OIDC escrita: {error}"))?;
    if let BodyStream::Plain(plain) = &stream {
        let _ = plain.shutdown(Shutdown::Write);
    }
    let (status, location, body) = read_http(&mut stream)?;
    if (300..400).contains(&status) {
        let location = location.ok_or_else(|| format!("OIDC {status} sem Location"))?;
        let next = if location.starts_with("http://") || location.starts_with("https://") {
            location
        } else if let Some(rest) = location.strip_prefix('/') {
            let scheme = if parsed.tls { "https" } else { "http" };
            format!("{scheme}://{host}/{rest}")
        } else {
            return Err("OIDC Location inválido".into());
        };
        return http_get(&next, deadline, redirects + 1);
    }
    if status != 200 {
        return Err(format!("OIDC HTTP {status}"));
    }
    Ok(body)
}

fn http_post(url: &str, form: &str, deadline: Instant) -> Result<String, String> {
    let (parsed, mut stream) = connect(url, deadline)?;
    let host = host_header(&parsed);
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ferroada-oidc\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        parsed.path,
        host,
        form.len(),
        form
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("OIDC escrita: {error}"))?;
    if let BodyStream::Plain(plain) = &stream {
        let _ = plain.shutdown(Shutdown::Write);
    }
    let (status, _, body) = read_http(&mut stream)?;
    if status != 200 {
        return Err("oidc_token".into());
    }
    Ok(body)
}

fn read_http(stream: &mut BodyStream) -> Result<(u16, Option<String>, String), String> {
    let raw = read_limited(stream, HTTP_MAX_BODY + 4096)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| "OIDC: resposta HTTP incompleta".to_string())?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "OIDC: resposta HTTP vazia".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "OIDC: status HTTP malformado".to_string())?;
    let mut location = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("location") {
                location = Some(value.trim().to_string());
            }
        }
    }
    if body.len() > HTTP_MAX_BODY {
        return Err("OIDC: resposta excede o teto".into());
    }
    Ok((status, location, body.to_string()))
}

fn resolve_host(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr, String> {
    let host_owned = host.to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host_owned.as_str(), port)
            .to_socket_addrs()
            .map(|mut addrs| addrs.next())
            .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => Err(format!("OIDC DNS vazio: {host}")),
        Ok(Err(error)) => Err(format!("OIDC DNS {host}: {error}")),
        Err(_) => Err("OIDC: tempo esgotado".into()),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err("OIDC: tempo esgotado".into())
    } else {
        Ok(left)
    }
}

fn read_limited(stream: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Err("OIDC: tempo esgotado".into());
            }
            Err(error) => return Err(format!("OIDC leitura: {error}")),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

fn tls_connector() -> Result<openssl::ssl::SslConnector, String> {
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
        .map_err(|error| format!("OIDC tls: {error}"))?;
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            builder
                .set_ca_file(&path)
                .map_err(|error| format!("OIDC tls CA: {error}"))?;
            return Ok(builder.build());
        }
    }
    let probe = openssl_probe::probe();
    if let Some(file) = probe.cert_file.filter(|path| path.is_file()) {
        builder
            .set_ca_file(&file)
            .map_err(|error| format!("OIDC tls CA: {error}"))?;
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::sign_rs256;
    use openssl::rsa::Rsa;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn seed_rand() {
        let mut buf = [0u8; 32];
        let _ = openssl::rand::rand_bytes(&mut buf);
    }

    #[test]
    fn pkce_challenge_is_s256_and_stays_out_of_authorize_url() {
        seed_rand();
        let (verifier, challenge) = generate_pkce().unwrap();
        assert!(verifier.len() >= 43);
        let expected = URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        let config = OidcConfig {
            issuer: "http://issuer.test".into(),
            client_id: "client".into(),
            client_secret: Some("super-secret".into()),
            redirect_uri: "http://127.0.0.1:9000/oidc/callback".into(),
            authorization_endpoint: "http://issuer.test/authorize".into(),
            token_endpoint: "http://issuer.test/token".into(),
            jwks_uri: "http://issuer.test/jwks".into(),
            scopes: "openid".into(),
            role_claim: "ferroada_role".into(),
            operators: HashSet::from(["operator".into()]),
            viewers: HashSet::from(["viewer".into()]),
        };
        let url = config.authorize_url("st", "nn", &challenge);
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&form_encode(&challenge)));
        assert!(!url.contains(&verifier));
        assert!(!url.contains("super-secret"));
        assert!(!url.contains("client_secret"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn role_claim_maps_operator_over_viewer() {
        let operators = HashSet::from(["operator".into(), "admin".into()]);
        let viewers = HashSet::from(["viewer".into()]);
        assert_eq!(
            map_role(
                &json!({"ferroada_role": "operator"}),
                "ferroada_role",
                &operators,
                &viewers
            ),
            Some(Role::Operator)
        );
        assert_eq!(
            map_role(
                &json!({"ferroada_role": ["viewer", "operator"]}),
                "ferroada_role",
                &operators,
                &viewers
            ),
            Some(Role::Operator)
        );
        assert_eq!(
            map_role(
                &json!({"ferroada_role": "viewer"}),
                "ferroada_role",
                &operators,
                &viewers
            ),
            Some(Role::Viewer)
        );
        assert_eq!(
            map_role(
                &json!({"ferroada_role": "guest"}),
                "ferroada_role",
                &operators,
                &viewers
            ),
            None
        );
    }

    #[test]
    fn id_token_rejects_wrong_nonce_and_accepts_matching_rs256() {
        seed_rand();
        let rsa = Rsa::generate(2048).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let n = URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
        let jwks = json!({"keys":[{"kty":"RSA","kid":"k1","n":n,"e":e}]}).to_string();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&hits);
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else {
                    continue;
                };
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf);
                recorded.lock().unwrap().push(buf);
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{jwks}",
                    jwks.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let now = unix_now();
        let claims = json!({
            "iss": "http://issuer.test",
            "aud": "client",
            "sub": "user-1",
            "exp": now + 120,
            "iat": now,
            "nonce": "expected-nonce",
            "ferroada_role": "operator"
        });
        let token = sign_rs256(&rsa, "k1", &claims);
        let config = OidcConfig {
            issuer: "http://issuer.test".into(),
            client_id: "client".into(),
            client_secret: None,
            redirect_uri: "http://127.0.0.1:9000/oidc/callback".into(),
            authorization_endpoint: "http://issuer.test/authorize".into(),
            token_endpoint: "http://issuer.test/token".into(),
            jwks_uri: format!("http://{addr}/jwks"),
            scopes: "openid".into(),
            role_claim: "ferroada_role".into(),
            operators: HashSet::from(["operator".into()]),
            viewers: HashSet::from(["viewer".into()]),
        };
        let payload = verify_id_token(
            &token,
            &config,
            "expected-nonce",
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(payload["sub"], "user-1");
        let err = verify_id_token(
            &token,
            &config,
            "other-nonce",
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(err, "oidc_nonce");
    }
}
