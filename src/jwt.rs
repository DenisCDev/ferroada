//! JWT/JWKS identity (PR 14). Opt-in per site. No token or payload in logs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dashmap::DashMap;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

const DEFAULT_LEEWAY_SECS: u64 = 60;
const JWKS_TIMEOUT: Duration = Duration::from_secs(2);
const JWKS_TTL: Duration = Duration::from_secs(300);
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(1);
const JWKS_MAX_BODY: usize = 64 * 1024;
const JWKS_MAX_KEYS: usize = 32;
const JWKS_MAX_REDIRECTS: u8 = 3;
const TOKEN_MAX_BYTES: usize = 8 * 1024;
const MAX_JTI: usize = 50_000;
const RSA_MIN_BITS: i32 = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Rs256,
    Es256,
    Hs256,
    Hs384,
    Hs512,
}

impl Algorithm {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            "HS256" => Ok(Self::Hs256),
            "HS384" => Ok(Self::Hs384),
            "HS512" => Ok(Self::Hs512),
            "none" | "None" | "NONE" => {
                Err("alg none é recusado; não entra na allowlist".into())
            }
            other if other.to_ascii_uppercase().starts_with("HS") => Err(format!(
                "alg {other} exige listagem explícita (HS256/HS384/HS512)"
            )),
            other => Err(format!(
                "alg {other:?} não suportado; use RS256, ES256 ou HS256/384/512"
            )),
        }
    }

    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }

    fn is_hmac(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }

    fn digest(self) -> MessageDigest {
        match self {
            Self::Rs256 | Self::Es256 | Self::Hs256 => MessageDigest::sha256(),
            Self::Hs384 => MessageDigest::sha384(),
            Self::Hs512 => MessageDigest::sha512(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BindSource {
    Path(String),
    Body(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    claim: String,
    source: BindSource,
}

#[derive(Clone, Debug)]
struct PathTemplate {
    segments: Vec<PathSeg>,
}

#[derive(Clone, Debug)]
enum PathSeg {
    Literal(String),
    Param(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtFailure {
    Unauthorized(&'static str),
    Forbidden(&'static str),
}

impl JwtFailure {
    pub fn status(self) -> u16 {
        match self {
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Unauthorized(reason) | Self::Forbidden(reason) => reason,
        }
    }

    pub fn event_type(self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "jwt",
            Self::Forbidden(_) => "jwt_binding",
        }
    }
}

#[derive(Clone, Debug)]
pub struct JwtPrincipal {
    pub sub: String,
    pub tenant: Option<String>,
    claims: BTreeMap<String, String>,
}

impl JwtPrincipal {
    fn claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).map(String::as_str)
    }
}

struct JwtInner {
    issuer: String,
    audience: String,
    algorithms: HashSet<Algorithm>,
    bindings: Vec<Binding>,
    paths: Vec<PathTemplate>,
    hmac_secret: Option<Vec<u8>>,
    jwks: JwksCache,
    jti: DashMap<u64, u64>,
    leeway: u64,
}

#[derive(Clone)]
pub struct JwtPolicy {
    inner: std::sync::Arc<JwtInner>,
}

pub struct JwtSpec<'a> {
    pub jwks: &'a str,
    pub issuer: &'a str,
    pub audience: &'a str,
    pub algorithms: &'a [String],
    pub bindings: &'a [String],
    pub paths: &'a [String],
    pub hmac_secret_env: Option<&'a str>,
}

impl JwtPolicy {
    pub fn load(spec: JwtSpec<'_>, base_dir: &Path, site: Option<&str>) -> Result<Self, String> {
        let issuer = spec.issuer.trim();
        let audience = spec.audience.trim();
        if issuer.is_empty() {
            return Err("jwt.issuer (iss) é obrigatório".into());
        }
        if audience.is_empty() {
            return Err("jwt.audience (aud) é obrigatório".into());
        }
        let algorithms = parse_algorithms(spec.algorithms)?;
        let hmac_secret = if algorithms.iter().any(|alg| alg.is_hmac()) {
            let name = spec
                .hmac_secret_env
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    "HS* na allowlist exige hmac_secret_env apontando para o segredo".to_string()
                })?;
            let value = std::env::var(name).map_err(|_| {
                format!("hmac_secret_env {name} não está definido no ambiente")
            })?;
            if value.is_empty() {
                return Err(format!("hmac_secret_env {name} está vazio"));
            }
            Some(value.into_bytes())
        } else if spec.hmac_secret_env.is_some() {
            return Err("hmac_secret_env só é válido com HS256/HS384/HS512 na allowlist".into());
        } else {
            None
        };
        let parsed_bindings = parse_bindings(spec.bindings)?;
        let path_templates = parse_path_templates(spec.paths)?;
        let source = JwksSource::parse(spec.jwks, base_dir)?;
        let mut cache = JwksCache::new(source, JWKS_TIMEOUT, JWKS_TTL, JWKS_MIN_REFRESH);
        cache
            .refresh()
            .map_err(|error| {
                format!(
                    "JWKS inicial falhou para {} ({}): {error}",
                    site.unwrap_or("site"),
                    spec.jwks
                )
            })?;
        Ok(Self {
            inner: std::sync::Arc::new(JwtInner {
                issuer: issuer.to_string(),
                audience: audience.to_string(),
                algorithms,
                bindings: parsed_bindings,
                paths: path_templates,
                hmac_secret,
                jwks: cache,
                jti: DashMap::new(),
                leeway: DEFAULT_LEEWAY_SECS,
            }),
        })
    }

    pub fn has_body_bindings(&self) -> bool {
        self.inner
            .bindings
            .iter()
            .any(|binding| matches!(binding.source, BindSource::Body(_)))
    }

    pub fn authenticate(
        &self,
        authorization: Option<&str>,
        now: u64,
    ) -> Result<JwtPrincipal, JwtFailure> {
        let token = bearer(authorization)?;
        let (header_json, payload_json, signing_input, signature) = split_token(token)?;
        let header: JwtHeader = serde_json::from_slice(&header_json).map_err(|_| {
            JwtFailure::Unauthorized("malformed")
        })?;
        if let Some(crit) = header.crit.as_ref() {
            if !crit.is_empty() {
                return Err(JwtFailure::Unauthorized("crit"));
            }
        }
        if let Some(typ) = header.typ.as_deref() {
            if !typ.eq_ignore_ascii_case("JWT") && !typ.eq_ignore_ascii_case("at+jwt") {
                return Err(JwtFailure::Unauthorized("typ"));
            }
        }
        let alg = match Algorithm::parse(header.alg.as_str()) {
            Ok(alg) if self.inner.algorithms.contains(&alg) => alg,
            Ok(_) | Err(_) => return Err(JwtFailure::Unauthorized("alg")),
        };
        let kid = header
            .kid
            .as_deref()
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
            .ok_or(JwtFailure::Unauthorized("kid"))?;
        let payload: Value = serde_json::from_slice(&payload_json)
            .map_err(|_| JwtFailure::Unauthorized("malformed"))?;
        verify_signature(self, alg, kid, signing_input, &signature)?;
        let claims = validate_claims(&payload, &self.inner.issuer, &self.inner.audience, now, self.inner.leeway)?;
        remember_jti(
            &self.inner.jti,
            &claims.jti,
            claims.exp.saturating_add(self.inner.leeway),
            now,
        )?;
        Ok(JwtPrincipal {
            sub: claims.sub,
            tenant: claims.tenant,
            claims: claims.rest,
        })
    }

    pub fn bind_path(
        &self,
        principal: &JwtPrincipal,
        path: &str,
        extra: &BTreeMap<String, String>,
    ) -> Result<(), JwtFailure> {
        let params = path_params(&self.inner.paths, path, extra);
        for binding in &self.inner.bindings {
            let BindSource::Path(name) = &binding.source else {
                continue;
            };
            let left = principal
                .claim(&binding.claim)
                .ok_or(JwtFailure::Forbidden("binding"))?;
            let right = params
                .get(name.as_str())
                .map(String::as_str)
                .ok_or(JwtFailure::Forbidden("binding"))?;
            if left != right {
                return Err(JwtFailure::Forbidden("binding"));
            }
        }
        Ok(())
    }

    pub fn bind_body(&self, principal: &JwtPrincipal, body: &[u8]) -> Result<(), JwtFailure> {
        let needed: Vec<&Binding> = self
            .inner
            .bindings
            .iter()
            .filter(|binding| matches!(binding.source, BindSource::Body(_)))
            .collect();
        if needed.is_empty() {
            return Ok(());
        }
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let json: Value = serde_json::from_slice(body).map_err(|_| JwtFailure::Forbidden("binding"))?;
        for binding in needed {
            let BindSource::Body(pointer) = &binding.source else {
                continue;
            };
            let left = principal
                .claim(&binding.claim)
                .ok_or(JwtFailure::Forbidden("binding"))?;
            let right = json_field(&json, pointer).ok_or(JwtFailure::Forbidden("binding"))?;
            if left != right {
                return Err(JwtFailure::Forbidden("binding"));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
}

struct ValidatedClaims {
    sub: String,
    tenant: Option<String>,
    jti: String,
    exp: u64,
    rest: BTreeMap<String, String>,
}

fn parse_algorithms(raw: &[String]) -> Result<HashSet<Algorithm>, String> {
    if raw.is_empty() {
        return Ok(HashSet::from([Algorithm::Rs256, Algorithm::Es256]));
    }
    let mut out = HashSet::new();
    for item in raw {
        out.insert(Algorithm::parse(item)?);
    }
    if out.is_empty() {
        return Err("jwt.algorithms vazio".into());
    }
    Ok(out)
}

fn parse_bindings(raw: &[String]) -> Result<Vec<Binding>, String> {
    raw.iter()
        .map(|item| parse_binding(item))
        .collect()
}

fn parse_binding(raw: &str) -> Result<Binding, String> {
    let trimmed = raw.trim();
    let Some((left, right)) = trimmed.split_once("==") else {
        return Err(format!("binding JWT inválido (falta ==): {trimmed}"));
    };
    let left = left.trim();
    let right = right.trim();
    let claim = left
        .strip_prefix("jwt.")
        .ok_or_else(|| format!("lado esquerdo do binding deve ser jwt.<claim>: {trimmed}"))?
        .trim();
    if claim.is_empty() || claim.contains('.') {
        return Err(format!("claim JWT inválida no binding: {trimmed}"));
    }
    let source = if let Some(name) = right.strip_prefix("path.") {
        let name = name.trim();
        if name.is_empty() || name.contains('.') {
            return Err(format!("path binding inválido: {trimmed}"));
        }
        BindSource::Path(name.to_string())
    } else if let Some(name) = right.strip_prefix("body.") {
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("body binding inválido: {trimmed}"));
        }
        BindSource::Body(name.to_string())
    } else {
        return Err(format!(
            "lado direito do binding deve ser path.<param> ou body.<campo>: {trimmed}"
        ));
    };
    Ok(Binding {
        claim: claim.to_string(),
        source,
    })
}

fn parse_path_templates(raw: &[String]) -> Result<Vec<PathTemplate>, String> {
    raw.iter()
        .map(|item| parse_path_template(item))
        .collect()
}

fn parse_path_template(raw: &str) -> Result<PathTemplate, String> {
    let path = raw.trim();
    if !path.starts_with('/') {
        return Err(format!("jwt.paths deve ser um path absoluto: {path}"));
    }
    let mut segments = Vec::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        if let Some(name) = part.strip_prefix('{').and_then(|part| part.strip_suffix('}')) {
            if name.is_empty() || name.contains('{') {
                return Err(format!("parâmetro de path inválido em {path}"));
            }
            segments.push(PathSeg::Param(name.to_string()));
        } else {
            segments.push(PathSeg::Literal(part.to_string()));
        }
    }
    Ok(PathTemplate { segments })
}

fn path_params(
    templates: &[PathTemplate],
    path: &str,
    extra: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let path = path.split('?').next().unwrap_or(path);
    let path = crate::config::canonical_route_path(path).unwrap_or_else(|| path.to_string());
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let mut params = extra.clone();
    for template in templates {
        if template.segments.len() != parts.len() {
            continue;
        }
        let mut found = BTreeMap::new();
        let mut ok = true;
        for (seg, part) in template.segments.iter().zip(&parts) {
            match seg {
                PathSeg::Literal(literal) => {
                    if literal != part {
                        ok = false;
                        break;
                    }
                }
                PathSeg::Param(name) => {
                    found.insert(name.clone(), percent_decode_once(part));
                }
            }
        }
        if ok {
            for (key, value) in found {
                params.entry(key).or_insert(value);
            }
            break;
        }
    }
    params
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn json_field(root: &Value, dotted: &str) -> Option<String> {
    let mut current = root;
    for part in dotted.split('.') {
        current = current.get(part)?;
    }
    value_as_string(current)
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn bearer(authorization: Option<&str>) -> Result<&str, JwtFailure> {
    let Some(value) = authorization.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(JwtFailure::Unauthorized("missing"));
    };
    let Some((scheme, rest)) = value.split_once(' ') else {
        return Err(JwtFailure::Unauthorized("missing"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(JwtFailure::Unauthorized("missing"));
    }
    let token = rest.trim();
    if token.is_empty() || token.len() > TOKEN_MAX_BYTES {
        return Err(JwtFailure::Unauthorized("malformed"));
    }
    Ok(token)
}

type TokenParts = (Vec<u8>, Vec<u8>, String, Vec<u8>);

fn split_token(token: &str) -> Result<TokenParts, JwtFailure> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or(JwtFailure::Unauthorized("malformed"))?;
    let payload = parts.next().ok_or(JwtFailure::Unauthorized("malformed"))?;
    let signature = parts.next().unwrap_or("");
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return Err(JwtFailure::Unauthorized("malformed"));
    }
    let header_json = b64url_decode(header).map_err(|_| JwtFailure::Unauthorized("malformed"))?;
    let payload_json = b64url_decode(payload).map_err(|_| JwtFailure::Unauthorized("malformed"))?;
    let signature = if signature.is_empty() {
        Vec::new()
    } else {
        b64url_decode(signature).map_err(|_| JwtFailure::Unauthorized("malformed"))?
    };
    Ok((
        header_json,
        payload_json,
        format!("{header}.{payload}"),
        signature,
    ))
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(input.as_bytes()).map_err(|_| ())
}

#[cfg(test)]
fn b64url_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn verify_signature(
    policy: &JwtPolicy,
    alg: Algorithm,
    kid: &str,
    signing_input: String,
    signature: &[u8],
) -> Result<(), JwtFailure> {
    if alg.is_hmac() {
        let secret = policy
            .inner
            .hmac_secret
            .as_deref()
            .ok_or(JwtFailure::Unauthorized("alg"))?;
        return verify_hmac(alg, secret, signing_input.as_bytes(), signature);
    }
    let key = policy
        .inner
        .jwks
        .key(kid)
        .ok_or(JwtFailure::Unauthorized("kid"))?;
    if let Some(key_alg) = key.alg {
        if key_alg != alg {
            return Err(JwtFailure::Unauthorized("alg"));
        }
    }
    match (alg, &key.material) {
        (Algorithm::Rs256, KeyMaterial::Rsa { n, e }) => {
            verify_rsa(n, e, signing_input.as_bytes(), signature)
        }
        (Algorithm::Es256, KeyMaterial::Ec { x, y }) => {
            verify_es256(x, y, signing_input.as_bytes(), signature)
        }
        _ => Err(JwtFailure::Unauthorized("alg")),
    }
}

fn verify_hmac(
    alg: Algorithm,
    secret: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<(), JwtFailure> {
    let pkey = PKey::hmac(secret).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let mut signer =
        Signer::new(alg.digest(), &pkey).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    signer
        .update(input)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let mac = signer
        .sign_to_vec()
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    if mac.len() == signature.len() && openssl::memcmp::eq(&mac, signature) {
        Ok(())
    } else {
        Err(JwtFailure::Unauthorized("sig"))
    }
}

fn verify_rsa(n: &[u8], e: &[u8], input: &[u8], signature: &[u8]) -> Result<(), JwtFailure> {
    let n = BigNum::from_slice(n).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    if n.num_bits() < RSA_MIN_BITS {
        return Err(JwtFailure::Unauthorized("sig"));
    }
    let e = BigNum::from_slice(e).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let rsa =
        Rsa::from_public_components(n, e).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    verifier
        .update(input)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    match verifier.verify(signature) {
        Ok(true) => Ok(()),
        _ => Err(JwtFailure::Unauthorized("sig")),
    }
}

fn verify_es256(x: &[u8], y: &[u8], input: &[u8], signature: &[u8]) -> Result<(), JwtFailure> {
    if signature.len() != 64 {
        return Err(JwtFailure::Unauthorized("sig"));
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let mut ctx =
        openssl::bn::BigNumContext::new().map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&left_pad(x, 32).ok_or(JwtFailure::Unauthorized("sig"))?);
    uncompressed.extend_from_slice(&left_pad(y, 32).ok_or(JwtFailure::Unauthorized("sig"))?);
    let point = EcPoint::from_bytes(&group, &uncompressed, &mut ctx)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let ec =
        EcKey::from_public_key(&group, &point).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let pkey = PKey::from_ec_key(ec).map_err(|_| JwtFailure::Unauthorized("sig"))?;
    let der = ecdsa_raw_to_der(signature).ok_or(JwtFailure::Unauthorized("sig"))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    verifier
        .update(input)
        .map_err(|_| JwtFailure::Unauthorized("sig"))?;
    match verifier.verify(&der) {
        Ok(true) => Ok(()),
        _ => Err(JwtFailure::Unauthorized("sig")),
    }
}

fn ecdsa_raw_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    let r = BigNum::from_slice(&raw[..32]).ok()?;
    let s = BigNum::from_slice(&raw[32..]).ok()?;
    let sig = EcdsaSig::from_private_components(r, s).ok()?;
    sig.to_der().ok()
}

#[cfg(test)]
fn ecdsa_der_to_raw(der: &[u8]) -> Option<Vec<u8>> {
    let sig = EcdsaSig::from_der(der).ok()?;
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&left_pad(&sig.r().to_vec(), 32)?);
    raw.extend_from_slice(&left_pad(&sig.s().to_vec(), 32)?);
    Some(raw)
}

fn left_pad(bytes: &[u8], size: usize) -> Option<Vec<u8>> {
    if bytes.len() > size {
        return None;
    }
    let mut out = vec![0u8; size];
    out[size - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

fn validate_claims(
    payload: &Value,
    issuer: &str,
    audience: &str,
    now: u64,
    leeway: u64,
) -> Result<ValidatedClaims, JwtFailure> {
    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(JwtFailure::Unauthorized("iss"))?;
    if iss != issuer {
        return Err(JwtFailure::Unauthorized("iss"));
    }
    if !aud_matches(payload.get("aud"), audience) {
        return Err(JwtFailure::Unauthorized("aud"));
    }
    let exp = unix_claim(payload, "exp").ok_or(JwtFailure::Unauthorized("exp"))?;
    if exp + leeway < now {
        return Err(JwtFailure::Unauthorized("exp"));
    }
    let nbf = unix_claim(payload, "nbf").ok_or(JwtFailure::Unauthorized("nbf"))?;
    if nbf > now.saturating_add(leeway) {
        return Err(JwtFailure::Unauthorized("nbf"));
    }
    let iat = unix_claim(payload, "iat").ok_or(JwtFailure::Unauthorized("iat"))?;
    if iat > now.saturating_add(leeway) {
        return Err(JwtFailure::Unauthorized("iat"));
    }
    let jti = payload
        .get("jti")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|jti| !jti.is_empty())
        .ok_or(JwtFailure::Unauthorized("jti"))?
        .to_string();
    let sub = payload
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|sub| !sub.is_empty())
        .ok_or(JwtFailure::Unauthorized("sub"))?
        .to_string();
    let mut rest = BTreeMap::new();
    if let Some(object) = payload.as_object() {
        for (key, value) in object {
            if let Some(text) = value_as_string(value) {
                rest.insert(key.clone(), text);
            }
        }
    }
    let tenant = rest
        .get("tenant_id")
        .cloned()
        .or_else(|| rest.get("tenant").cloned())
        .or_else(|| rest.get("tid").cloned());
    Ok(ValidatedClaims {
        sub,
        tenant,
        jti,
        exp,
        rest,
    })
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
            .or_else(|| value.as_f64().and_then(|n| (n >= 0.0).then_some(n as u64)))
    })
}

fn remember_jti(
    cache: &DashMap<u64, u64>,
    jti: &str,
    exp: u64,
    now: u64,
) -> Result<(), JwtFailure> {
    let key = hash_str(jti);
    if cache.len() >= MAX_JTI {
        cache.retain(|_, until| *until >= now);
        if cache.len() >= MAX_JTI {
            let mut seen = 0u32;
            cache.retain(|_, _| {
                seen += 1;
                seen.is_multiple_of(10)
            });
        }
    }
    match cache.entry(key) {
        dashmap::mapref::entry::Entry::Occupied(entry) if *entry.get() >= now => {
            Err(JwtFailure::Unauthorized("jti"))
        }
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            entry.insert(exp);
            Ok(())
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(exp);
            Ok(())
        }
    }
}

fn hash_str(value: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

enum JwksSource {
    File(PathBuf),
    Url(String),
}

impl JwksSource {
    fn parse(raw: &str, base_dir: &Path) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("jwt.jwks é obrigatório".into());
        }
        if raw.starts_with("https://") || raw.starts_with("http://") {
            return Ok(Self::Url(raw.to_string()));
        }
        let path = Path::new(raw);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        };
        Ok(Self::File(path))
    }

    fn fetch(&self, timeout: Duration) -> Result<String, String> {
        match self {
            Self::File(path) => {
                let bytes = std::fs::read(path)
                    .map_err(|error| format!("não leu JWKS {}: {error}", path.display()))?;
                if bytes.len() > JWKS_MAX_BODY {
                    return Err(format!("JWKS {} excede {JWKS_MAX_BODY} bytes", path.display()));
                }
                String::from_utf8(bytes).map_err(|_| "JWKS não é UTF-8".into())
            }
            Self::Url(url) => http_get(url, Instant::now() + timeout, 0),
        }
    }
}

#[derive(Clone)]
struct CachedJwk {
    alg: Option<Algorithm>,
    material: KeyMaterial,
}

#[derive(Clone)]
enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { x: Vec<u8>, y: Vec<u8> },
}

struct JwksState {
    keys: HashMap<String, CachedJwk>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

struct JwksCache {
    source: JwksSource,
    timeout: Duration,
    ttl: Duration,
    min_refresh: Duration,
    state: Mutex<JwksState>,
    fetch: Mutex<()>,
}

impl JwksCache {
    fn new(source: JwksSource, timeout: Duration, ttl: Duration, min_refresh: Duration) -> Self {
        Self {
            source,
            timeout,
            ttl,
            min_refresh,
            state: Mutex::new(JwksState {
                keys: HashMap::new(),
                fetched_at: None,
                last_attempt: None,
            }),
            fetch: Mutex::new(()),
        }
    }

    fn refresh(&mut self) -> Result<(), String> {
        let body = self.source.fetch(self.timeout)?;
        let keys = parse_jwks(&body)?;
        if keys.is_empty() {
            return Err("JWKS sem chaves utilizáveis".into());
        }
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.keys = keys;
        let now = Instant::now();
        state.fetched_at = Some(now);
        state.last_attempt = Some(now);
        Ok(())
    }

    fn key(&self, kid: &str) -> Option<CachedJwk> {
        let now = Instant::now();
        {
            let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            if let Some(cached) = fresh_key(&state, kid, now, self.ttl) {
                return Some(cached);
            }
            let known = state.keys.contains_key(kid);
            let stale = state
                .fetched_at
                .map(|at| now.saturating_duration_since(at) >= self.ttl)
                .unwrap_or(true);
            let recent = state
                .last_attempt
                .is_some_and(|at| now.saturating_duration_since(at) < self.min_refresh);
            if !stale && (known || recent) {
                return state.keys.get(kid).cloned();
            }
        }
        let _fetch = self.fetch.lock().unwrap_or_else(|poison| poison.into_inner());
        {
            let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            if let Some(cached) = fresh_key(&state, kid, Instant::now(), self.ttl) {
                return Some(cached);
            }
        }
        {
            let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            state.last_attempt = Some(Instant::now());
        }
        let fetched = self.source.fetch(self.timeout);
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        match fetched {
            Ok(body) => match parse_jwks(&body) {
                Ok(keys) if !keys.is_empty() => {
                    state.keys = keys;
                    state.fetched_at = Some(Instant::now());
                }
                Ok(_) => {
                    warn!("JWKS vazio na rotação; last-known-good mantido");
                }
                Err(_) => {
                    warn!("JWKS inválido na rotação; last-known-good mantido");
                }
            },
            Err(_) => {
                warn!("JWKS fetch falhou; last-known-good mantido");
            }
        }
        state.keys.get(kid).cloned()
    }
}

fn fresh_key(state: &JwksState, kid: &str, now: Instant, ttl: Duration) -> Option<CachedJwk> {
    let fetched_at = state.fetched_at?;
    if now.saturating_duration_since(fetched_at) >= ttl {
        return None;
    }
    state.keys.get(kid).cloned()
}

fn parse_jwks(body: &str) -> Result<HashMap<String, CachedJwk>, String> {
    let doc: JwksDoc =
        serde_json::from_str(body).map_err(|error| format!("JWKS JSON inválido: {error}"))?;
    if doc.keys.len() > JWKS_MAX_KEYS {
        return Err(format!("JWKS tem mais de {JWKS_MAX_KEYS} chaves"));
    }
    let mut out = HashMap::new();
    for jwk in doc.keys {
        if jwk.use_.as_deref() == Some("enc") {
            continue;
        }
        let Some(kid) = jwk.kid.as_deref().map(str::trim).filter(|kid| !kid.is_empty()) else {
            continue;
        };
        let alg = match jwk.alg.as_deref() {
            Some(raw) => match Algorithm::parse(raw) {
                Ok(alg) => Some(alg),
                Err(_) => continue,
            },
            None => None,
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
        out.insert(kid.to_string(), CachedJwk { alg, material });
    }
    Ok(out)
}

#[derive(Deserialize)]
struct JwksDoc {
    keys: Vec<JwkDoc>,
}

#[derive(Deserialize)]
struct JwkDoc {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
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
        return Err(format!("JWKS URL inválida: {url}"));
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let authority = authority.split('@').next_back().unwrap_or(authority);
    let (host, port) = if let Some(host) = authority.strip_prefix('[') {
        let end = host
            .find(']')
            .ok_or_else(|| format!("JWKS URL IPv6 inválida: {url}"))?;
        let host_name = &host[..end];
        let port = host[end + 1..]
            .strip_prefix(':')
            .map(|port| {
                port.parse::<u16>()
                    .map_err(|_| format!("JWKS URL porta inválida: {url}"))
            })
            .transpose()?
            .unwrap_or(if tls { 443 } else { 80 });
        (host_name.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("JWKS URL porta inválida: {url}"))?;
        (host.to_string(), port)
    } else {
        (authority.to_string(), if tls { 443 } else { 80 })
    };
    if host.is_empty() {
        return Err(format!("JWKS URL sem host: {url}"));
    }
    Ok(ParsedUrl {
        tls,
        host,
        port,
        path,
    })
}

fn http_get(url: &str, deadline: Instant, redirects: u8) -> Result<String, String> {
    if redirects > JWKS_MAX_REDIRECTS {
        return Err("JWKS: demasiados redireccionamentos".into());
    }
    let parsed = parse_http_url(url)?;
    let timeout = remaining(deadline)?;
    let addr = resolve_host(&parsed.host, parsed.port, timeout)?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|error| format!("JWKS connect {url}: {error}"))?;
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("JWKS: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("JWKS: {error}"))?;
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
    let mut stream = if parsed.tls {
        let connector = tls_connector()?;
        let tls = connector
            .connect(&parsed.host, stream)
            .map_err(|error| format!("JWKS tls {url}: {error}"))?;
        BodyStream::Tls(tls)
    } else {
        BodyStream::Plain(stream)
    };
    let host = if parsed.port == if parsed.tls { 443 } else { 80 } {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ferroada-jwks\r\nConnection: close\r\n\r\n",
        parsed.path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("JWKS escrita {url}: {error}"))?;
    if let BodyStream::Plain(plain) = &stream {
        let _ = plain.shutdown(Shutdown::Write);
    }
    let raw = read_limited(&mut stream, JWKS_MAX_BODY + 4096)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| "JWKS: resposta HTTP incompleta".to_string())?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "JWKS: resposta HTTP vazia".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "JWKS: status HTTP malformado".to_string())?;
    let mut location = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("location") {
                location = Some(value.trim().to_string());
            }
        }
    }
    if (300..400).contains(&status) {
        let location = location.ok_or_else(|| format!("JWKS {url} {status} sem Location"))?;
        let next = if location.starts_with("http://") || location.starts_with("https://") {
            location
        } else if let Some(rest) = location.strip_prefix('/') {
            let scheme = if parsed.tls { "https" } else { "http" };
            format!("{scheme}://{host}/{rest}")
        } else {
            return Err("JWKS Location inválido".into());
        };
        return http_get(&next, deadline, redirects + 1);
    }
    if status != 200 {
        return Err(format!("JWKS {url} devolveu HTTP {status}"));
    }
    if body.len() > JWKS_MAX_BODY {
        return Err("JWKS excede o teto de 64 KiB".into());
    }
    Ok(body.to_string())
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
        Ok(Ok(None)) => Err(format!("JWKS DNS vazio: {host}")),
        Ok(Err(error)) => Err(format!("JWKS DNS {host}: {error}")),
        Err(_) => Err("JWKS: tempo esgotado".into()),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err("JWKS: tempo esgotado".into())
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
                return Err("JWKS: tempo esgotado".into());
            }
            Err(error) => return Err(format!("JWKS leitura: {error}")),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

fn tls_connector() -> Result<openssl::ssl::SslConnector, String> {
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
        .map_err(|error| format!("JWKS tls: {error}"))?;
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            builder
                .set_ca_file(&path)
                .map_err(|error| format!("JWKS tls CA: {error}"))?;
            return Ok(builder.build());
        }
    }
    let probe = openssl_probe::probe();
    if let Some(file) = probe.cert_file.filter(|path| path.is_file()) {
        builder
            .set_ca_file(&file)
            .map_err(|error| format!("JWKS tls CA: {error}"))?;
    }
    Ok(builder.build())
}

#[cfg(test)]
fn seed_rand() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut buf = [0u8; 64];
        let pid = std::process::id().to_le_bytes();
        buf[..4].copy_from_slice(&pid);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos().to_le_bytes())
            .unwrap_or_default();
        buf[4..20].copy_from_slice(&nanos);
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte ^= (index as u8).wrapping_mul(31).wrapping_add(0x5A);
        }
        unsafe {
            openssl_sys::RAND_add(buf.as_ptr().cast(), buf.len() as i32, 64.0);
        }
    });
}

#[cfg(test)]
pub(crate) fn sign_rs256(
    rsa: &Rsa<openssl::pkey::Private>,
    kid: &str,
    claims: &Value,
) -> String {
    seed_rand();
    sign_with(Algorithm::Rs256, kid, claims, |input| {
        let pkey = PKey::from_rsa(rsa.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(input.as_bytes()).unwrap();
        signer.sign_to_vec().unwrap()
    })
}

#[cfg(test)]
fn sign_es256(ec: &EcKey<openssl::pkey::Private>, kid: &str, claims: &Value) -> String {
    seed_rand();
    sign_with(Algorithm::Es256, kid, claims, |input| {
        let pkey = PKey::from_ec_key(ec.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(input.as_bytes()).unwrap();
        let der = signer.sign_to_vec().unwrap();
        ecdsa_der_to_raw(&der).expect("der to raw")
    })
}

#[cfg(test)]
fn sign_hs256(secret: &[u8], kid: &str, claims: &Value) -> String {
    sign_with(Algorithm::Hs256, kid, claims, |input| {
        let pkey = PKey::hmac(secret).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(input.as_bytes()).unwrap();
        signer.sign_to_vec().unwrap()
    })
}

#[cfg(test)]
fn sign_with(alg: Algorithm, kid: &str, claims: &Value, sign: impl FnOnce(&str) -> Vec<u8>) -> String {
    let header = serde_json::json!({"alg": alg.as_str(), "typ": "JWT", "kid": kid});
    let header_b64 = b64url_encode(&serde_json::to_vec(&header).unwrap());
    let payload_b64 = b64url_encode(&serde_json::to_vec(claims).unwrap());
    let signing = format!("{header_b64}.{payload_b64}");
    let sig = sign(&signing);
    format!("{signing}.{}", b64url_encode(&sig))
}

#[cfg(test)]
fn rsa_jwk(rsa: &Rsa<openssl::pkey::Private>, kid: &str) -> Value {
    serde_json::json!({
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_encode(&rsa.n().to_vec()),
        "e": b64url_encode(&rsa.e().to_vec()),
    })
}

#[cfg(test)]
fn default_claims(sub: &str, now: u64) -> Value {
    serde_json::json!({
        "iss": "https://issuer.test",
        "aud": "api.test",
        "sub": sub,
        "exp": now + 600,
        "nbf": now - 5,
        "iat": now - 5,
        "jti": format!("jti-{sub}-{now}"),
        "tenant_id": "tenant-a",
    })
}

#[cfg(test)]
fn policy_from_jwks(jwks: &Value, extra: &[(&str, &str)]) -> JwtPolicy {
    let dir = std::env::temp_dir().join(format!(
        "ferroada-jwt-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("jwks.json");
    std::fs::write(&path, serde_json::to_vec(jwks).unwrap()).unwrap();
    let mut algorithms = Vec::new();
    let mut bindings = Vec::new();
    let mut paths = Vec::new();
    let mut hmac_env = None;
    for (key, value) in extra {
        match *key {
            "algorithms" => algorithms = value.split(',').map(|s| s.to_string()).collect(),
            "bindings" => bindings = value.split(';').map(|s| s.to_string()).collect(),
            "paths" => paths = value.split(';').map(|s| s.to_string()).collect(),
            "hmac_secret_env" => hmac_env = Some(*value),
            _ => {}
        }
    }
    let jwks_path = path.to_string_lossy().into_owned();
    JwtPolicy::load(
        JwtSpec {
            jwks: &jwks_path,
            issuer: "https://issuer.test",
            audience: "api.test",
            algorithms: &algorithms,
            bindings: &bindings,
            paths: &paths,
            hmac_secret_env: hmac_env,
        },
        &dir,
        Some("api.test"),
    )
    .expect("load jwt policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::Private;

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

    const EC_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOX+olXGOH0MkN6rDalPb/eHi4eVpD4i40PZ5tIxW+4loAoGCCqGSM49
AwEHoUQDQgAExY+8CoF2luSHSBdhCMfbX7pWTmqRHYRYM/l4G9LSq6P24RmtiBve
n5LKC4fKIpFKBXjMNiu/w68QS62SvhQ0gA==
-----END EC PRIVATE KEY-----
";

    fn rsa() -> Rsa<Private> {
        seed_rand();
        Rsa::private_key_from_pem(RSA_PEM).unwrap()
    }

    fn rsa_alt() -> Rsa<Private> {
        seed_rand();
        Rsa::private_key_from_pem(RSA_ALT_PEM).unwrap()
    }

    #[test]
    fn valid_rs256_token_authenticates() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        let principal = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .expect("valid jwt");
        assert_eq!(principal.sub, "user-1");
        assert_eq!(principal.tenant.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn alg_none_is_unauthorized() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let claims = default_claims("user-1", now);
        let header = b64url_encode(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
        let payload = b64url_encode(&serde_json::to_vec(&claims).unwrap());
        let token = format!("{header}.{payload}.");
        let err = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("alg"));
        assert_eq!(err.status(), 401);
    }

    #[test]
    fn wrong_iss_is_unauthorized() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let mut claims = default_claims("user-1", now);
        claims["iss"] = Value::String("https://other".into());
        let token = sign_rs256(&key, "k1", &claims);
        let err = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("iss"));
    }

    #[test]
    fn expired_exp_is_unauthorized() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let mut claims = default_claims("user-1", now);
        claims["exp"] = serde_json::json!(now - 120);
        let token = sign_rs256(&key, "k1", &claims);
        let err = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("exp"));
    }

    #[test]
    fn hs256_rejected_without_explicit_allowlist() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let token = sign_hs256(b"supersecret", "k1", &default_claims("user-1", now));
        let err = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("alg"));
    }

    #[test]
    fn none_in_toml_is_load_error() {
        let dir = std::env::temp_dir();
        let none = vec!["none".to_string()];
        let empty: Vec<String> = Vec::new();
        let Err(err) = JwtPolicy::load(
            JwtSpec {
                jwks: "https://127.0.0.1:1/jwks",
                issuer: "iss",
                audience: "aud",
                algorithms: &none,
                bindings: &empty,
                paths: &empty,
                hmac_secret_env: None,
            },
            &dir,
            None,
        ) else {
            panic!("alg none must fail at load");
        };
        assert!(err.contains("none"), "{err}");
    }

    #[test]
    fn path_binding_mismatch_is_forbidden() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(
            &jwks,
            &[
                ("bindings", "jwt.sub == path.account_id"),
                ("paths", "/accounts/{account_id}"),
            ],
        );
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        let principal = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap();
        let err = policy
            .bind_path(&principal, "/accounts/other", &BTreeMap::new())
            .unwrap_err();
        assert_eq!(err, JwtFailure::Forbidden("binding"));
        assert_eq!(err.status(), 403);
        policy
            .bind_path(&principal, "/accounts/user-1", &BTreeMap::new())
            .unwrap();
    }

    #[test]
    fn body_binding_compares_tenant() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(
            &jwks,
            &[("bindings", "jwt.tenant_id == body.tenant_id")],
        );
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        let principal = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .unwrap();
        policy
            .bind_body(&principal, br#"{"tenant_id":"tenant-a"}"#)
            .unwrap();
        let err = policy
            .bind_body(&principal, br#"{"tenant_id":"other"}"#)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Forbidden("binding"));
    }

    #[test]
    fn jwks_file_rotation_picks_up_new_kid() {
        let key1 = rsa();
        let key2 = rsa_alt();
        let dir = std::env::temp_dir().join(format!(
            "ferroada-jwt-rot-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jwks.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"keys": [rsa_jwk(&key1, "k1")]})).unwrap(),
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let jwks_path = path.to_string_lossy().into_owned();
        let policy = JwtPolicy::load(
            JwtSpec {
                jwks: &jwks_path,
                issuer: "https://issuer.test",
                audience: "api.test",
                algorithms: &empty,
                bindings: &empty,
                paths: &empty,
                hmac_secret_env: None,
            },
            &dir,
            Some("api.test"),
        )
        .unwrap();
        let now = unix_now();
        let t1 = sign_rs256(&key1, "k1", &default_claims("user-1", now));
        policy
            .authenticate(Some(&format!("Bearer {t1}")), now)
            .unwrap();
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"keys": [rsa_jwk(&key2, "k2")]})).unwrap(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let t2 = sign_rs256(&key2, "k2", &default_claims("user-2", now));
        policy
            .authenticate(Some(&format!("Bearer {t2}")), now)
            .expect("new kid after refresh");
    }

    #[test]
    fn jwks_fetch_failure_keeps_last_known_good() {
        let key = rsa();
        let dir = std::env::temp_dir().join(format!(
            "ferroada-jwt-lkg-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jwks.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"keys": [rsa_jwk(&key, "k1")]})).unwrap(),
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let jwks_path = path.to_string_lossy().into_owned();
        let policy = JwtPolicy::load(
            JwtSpec {
                jwks: &jwks_path,
                issuer: "https://issuer.test",
                audience: "api.test",
                algorithms: &empty,
                bindings: &empty,
                paths: &empty,
                hmac_secret_env: None,
            },
            &dir,
            Some("api.test"),
        )
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .expect("last-known-good after fetch fail");
    }

    #[test]
    fn jti_replay_is_unauthorized() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        let header = format!("Bearer {token}");
        policy.authenticate(Some(&header), now).unwrap();
        let err = policy.authenticate(Some(&header), now).unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("jti"));
    }

    #[test]
    fn jti_replay_covers_leeway_after_exp() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [rsa_jwk(&key, "k1")]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let mut claims = default_claims("user-1", now);
        claims["exp"] = serde_json::json!(now);
        claims["jti"] = serde_json::json!("jti-leeway");
        let token = sign_rs256(&key, "k1", &claims);
        let header = format!("Bearer {token}");
        policy.authenticate(Some(&header), now).unwrap();
        let err = policy
            .authenticate(Some(&header), now + 1)
            .unwrap_err();
        assert_eq!(err, JwtFailure::Unauthorized("jti"));
    }

    #[test]
    fn jwks_skips_unknown_alg_and_keeps_rs256() {
        let key = rsa();
        let jwks = serde_json::json!({"keys": [
            rsa_jwk(&key, "k1"),
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": "ed1",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        ]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let token = sign_rs256(&key, "k1", &default_claims("user-1", now));
        policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .expect("RS256 sibling must survive EdDSA in the same JWKS");
    }

    #[test]
    fn es256_roundtrip() {
        let ec = EcKey::private_key_from_pem(EC_PEM).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let bytes = ec
            .public_key()
            .to_bytes(
                ec.group(),
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(bytes[0], 0x04);
        let x = &bytes[1..33];
        let y = &bytes[33..65];
        let jwks = serde_json::json!({"keys": [{
            "kty": "EC",
            "kid": "ec1",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": b64url_encode(x),
            "y": b64url_encode(y),
        }]});
        let policy = policy_from_jwks(&jwks, &[]);
        let now = unix_now();
        let token = sign_es256(&ec, "ec1", &default_claims("user-ec", now));
        let principal = policy
            .authenticate(Some(&format!("Bearer {token}")), now)
            .expect("es256");
        assert_eq!(principal.sub, "user-ec");
    }

    #[test]
    fn authenticate_does_not_embed_token_in_failure_reason() {
        assert_eq!(JwtFailure::Unauthorized("alg").reason(), "alg");
        assert_eq!(JwtFailure::Forbidden("binding").reason(), "binding");
    }
}
