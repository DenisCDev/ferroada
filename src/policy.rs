//! Versioned policy snapshots and last-known-good (PR 18 / Fase 3).
//!
//! Standalone: the TOML/env that booted is compiled to an immutable JSON blob
//! with `policy_version = sha256(blob)`. Reload never installs an empty
//! config — parse or signature failure keeps the in-memory snapshot.
//! `FERROADA_POLICY_PUBKEY` is opt-in Ed25519 over that blob. Cluster, HTTP
//! control plane, GitOps and OIDC stay out.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::config::{self, Config};
use crate::metrics;
use crate::spool::{self, SpoolRuntime};

const SNAPSHOT_FORMAT: u32 = 1;
const DEFAULT_TOML: &str = "ferroada.toml";
const DEFAULT_SIG: &str = "ferroada.policy.sig";
const DEFAULT_PID: &str = "ferroada.pid";
#[cfg(windows)]
const DEFAULT_SENTINEL: &str = "ferroada.reload";
const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

#[derive(Serialize)]
struct PolicyIr<'a> {
    format: u32,
    source: &'a str,
    body: &'a str,
    attachments: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    pub policy_version: String,
    pub blob: Arc<[u8]>,
    pub signed: bool,
}

struct LivePolicy {
    config: Arc<Config>,
    snapshot: PolicySnapshot,
    spool: Arc<SpoolRuntime>,
}

enum PolicyOrigin {
    Toml { path: PathBuf },
    Env,
    Pinned,
}

pub struct PolicyStore {
    inner: RwLock<Arc<LivePolicy>>,
    origin: PolicyOrigin,
}

#[derive(Debug)]
pub struct ReloadOutcome {
    pub version: String,
    pub previous: String,
}

impl PolicyStore {
    /// Boot from `ferroada.toml` or `TARGET_URL`. Fails closed: no snapshot, no process.
    pub fn boot() -> Result<Self, String> {
        let toml_path = PathBuf::from(DEFAULT_TOML);
        if toml_path.is_file() {
            Self::from_toml_path(toml_path)
        } else {
            let live = load_env()?;
            Ok(Self::from_live(live, PolicyOrigin::Env))
        }
    }

    pub fn from_toml_path(path: PathBuf) -> Result<Self, String> {
        let live = load_toml(&path)?;
        Ok(Self::from_live(live, PolicyOrigin::Toml { path }))
    }

    /// Tests that do not reload wrap an already-built Config.
    pub fn pinned(config: Arc<Config>) -> Self {
        let blob = compile_ir("pinned", "", BTreeMap::new()).unwrap_or_else(|_| b"{}".to_vec());
        let spool = Arc::new(SpoolRuntime::from_config(&config));
        let live = LivePolicy {
            config,
            snapshot: PolicySnapshot {
                policy_version: version_of(&blob),
                blob: blob.into(),
                signed: false,
            },
            spool,
        };
        Self {
            inner: RwLock::new(Arc::new(live)),
            origin: PolicyOrigin::Pinned,
        }
    }

    fn from_live(live: LivePolicy, origin: PolicyOrigin) -> Self {
        metrics::set_policy_version(&live.snapshot.policy_version, live.snapshot.signed);
        info!(
            version = %live.snapshot.policy_version,
            signed = live.snapshot.signed,
            "política versionada em memória"
        );
        Self {
            inner: RwLock::new(Arc::new(live)),
            origin,
        }
    }

    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.live().config)
    }

    pub fn snapshot(&self) -> PolicySnapshot {
        self.live().snapshot.clone()
    }

    pub fn spool(&self) -> Arc<SpoolRuntime> {
        Arc::clone(&self.live().spool)
    }

    fn live(&self) -> Arc<LivePolicy> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        Arc::clone(&guard)
    }

    /// Re-read the origin. On any failure the previous snapshot stays.
    pub fn try_reload(&self) -> Result<ReloadOutcome, String> {
        let previous = self.snapshot().policy_version;
        match self.origin.load() {
            Ok(live) => {
                let version = live.snapshot.policy_version.clone();
                let signed = live.snapshot.signed;
                {
                    let mut guard = self
                        .inner
                        .write()
                        .unwrap_or_else(|poison| poison.into_inner());
                    *guard = Arc::new(live);
                }
                metrics::set_policy_version(&version, signed);
                metrics::record_policy_reload(true, &format!("versão {version}"));
                info!(version = %version, "política recarregada");
                Ok(ReloadOutcome { version, previous })
            }
            Err(error) => {
                metrics::record_policy_reload(
                    false,
                    &format!("versão {previous} intacta: {error}"),
                );
                warn!(version = %previous, "reload recusado; last-known-good mantida: {error}");
                Err(error)
            }
        }
    }
}

impl PolicyOrigin {
    fn load(&self) -> Result<LivePolicy, String> {
        match self {
            Self::Toml { path } => load_toml(path),
            Self::Env => load_env(),
            Self::Pinned => Err("política pinned não recarrega".into()),
        }
    }
}

fn load_toml(path: &Path) -> Result<LivePolicy, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("ficheiro de política ausente ({}): {error}", path.display()))?;
    let (blob, version) = compile_toml_blob(&contents, base_dir(path))?;
    let signed = verify_if_configured(&blob)?;
    let config = Config::try_from_toml_in(&contents, base_dir(path))?;
    live_from_config(Arc::new(config), blob, version, signed)
}

fn load_env() -> Result<LivePolicy, String> {
    let target = std::env::var("TARGET_URL")
        .map_err(|_| "TARGET_URL or ferroada.toml required".to_string())?;
    let body = env_policy_body(&target);
    let blob = compile_ir("env", &body, BTreeMap::new())?;
    let version = version_of(&blob);
    let signed = verify_if_configured(&blob)?;
    let config = Config::try_from_target_url(&target)?;
    live_from_config(Arc::new(config), blob, version, signed)
}

fn live_from_config(
    config: Arc<Config>,
    blob: Vec<u8>,
    version: String,
    signed: bool,
) -> Result<LivePolicy, String> {
    spool::boot(&config)?;
    let spool = Arc::new(SpoolRuntime::from_config(&config));
    Ok(LivePolicy {
        config,
        snapshot: PolicySnapshot {
            policy_version: version,
            blob: blob.into(),
            signed,
        },
        spool,
    })
}

fn env_policy_body(target: &str) -> String {
    let mut body = format!("TARGET_URL={target}");
    if let Ok(paths) = std::env::var("WAF_REQUIRE_COMPLETE_PATHS") {
        if !paths.trim().is_empty() {
            body.push('\n');
            body.push_str("WAF_REQUIRE_COMPLETE_PATHS=");
            body.push_str(&paths);
        }
    }
    body
}

fn base_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub fn compile_toml_blob(contents: &str, base_dir: &Path) -> Result<(Vec<u8>, String), String> {
    let mut attachments = BTreeMap::new();
    for (key, file) in config::referenced_policy_files(contents, base_dir)? {
        let bytes = std::fs::read(&file)
            .map_err(|error| format!("anexo {key} ({}): {error}", file.display()))?;
        attachments.insert(key, sha256_hex(&bytes)?);
    }
    let blob = compile_ir("toml", contents, attachments)?;
    let version = version_of(&blob);
    Ok((blob, version))
}

fn compile_ir(
    source: &str,
    body: &str,
    attachments: BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PolicyIr {
        format: SNAPSHOT_FORMAT,
        source,
        body,
        attachments,
    })
    .map_err(|error| format!("falha a serializar snapshot: {error}"))
}

fn version_of(blob: &[u8]) -> String {
    match sha256_hex(blob) {
        Ok(digest) => digest,
        Err(_) => "sha256:0".to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> Result<String, String> {
    let digest =
        hash(MessageDigest::sha256(), bytes).map_err(|error| format!("sha256: {error}"))?;
    Ok(format!("sha256:{}", hex_encode(&digest)))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    if !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn verify_if_configured(blob: &[u8]) -> Result<bool, String> {
    let Ok(raw) = std::env::var("FERROADA_POLICY_PUBKEY") else {
        return Ok(false);
    };
    if raw.trim().is_empty() {
        return Ok(false);
    }
    let pubkey = parse_public_key(&raw)?;
    let signature = read_signature()?;
    if !verify_ed25519(&pubkey, blob, &signature)? {
        return Err("assinatura da política inválida".into());
    }
    Ok(true)
}

fn signature_path() -> PathBuf {
    std::env::var("FERROADA_POLICY_SIG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SIG))
}

fn read_signature() -> Result<Vec<u8>, String> {
    let path = signature_path();
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "FERROADA_POLICY_PUBKEY exige assinatura em {} ({error})",
            path.display()
        )
    })?;
    decode_signature(&bytes)
}

fn decode_signature(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() == ED25519_SIG_LEN {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "assinatura não é Ed25519 (64 bytes) nem texto base64/hex".to_string())?
        .trim();
    if let Some(decoded) = hex_decode(text) {
        if decoded.len() == ED25519_SIG_LEN {
            return Ok(decoded);
        }
    }
    STANDARD
        .decode(text)
        .ok()
        .filter(|decoded| decoded.len() == ED25519_SIG_LEN)
        .ok_or_else(|| "assinatura Ed25519 inválida (espere 64 bytes)".to_string())
}

fn parse_public_key(raw: &str) -> Result<PKey<Public>, String> {
    let pem = raw.trim().replace("\\n", "\n");
    if pem.contains("BEGIN") {
        return PKey::public_key_from_pem(pem.as_bytes())
            .map_err(|error| format!("FERROADA_POLICY_PUBKEY PEM inválida: {error}"));
    }
    let bytes = decode_key_bytes(raw.trim())?;
    if bytes.len() != ED25519_KEY_LEN {
        return Err(format!(
            "FERROADA_POLICY_PUBKEY deve ter {ED25519_KEY_LEN} bytes (Ed25519), veio {}",
            bytes.len()
        ));
    }
    PKey::public_key_from_raw_bytes(&bytes, Id::ED25519)
        .map_err(|error| format!("FERROADA_POLICY_PUBKEY inválida: {error}"))
}

fn decode_key_bytes(text: &str) -> Result<Vec<u8>, String> {
    if let Some(decoded) = hex_decode(text) {
        return Ok(decoded);
    }
    STANDARD
        .decode(text.trim())
        .map_err(|_| "FERROADA_POLICY_PUBKEY deve ser PEM, hex ou base64".to_string())
}

fn parse_private_key(bytes: &[u8]) -> Result<PKey<Private>, String> {
    if let Ok(key) = PKey::private_key_from_pem(bytes) {
        return Ok(key);
    }
    let trimmed = bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if let Ok(text) = std::str::from_utf8(&trimmed) {
        if let Some(raw) = hex_decode(text) {
            if raw.len() == ED25519_KEY_LEN {
                return PKey::private_key_from_raw_bytes(&raw, Id::ED25519)
                    .map_err(|error| format!("chave privada inválida: {error}"));
            }
        }
    }
    Err("chave privada Ed25519 inválida (PEM PKCS8 ou 32 bytes)".into())
}

pub fn sign_ed25519(key: &PKey<Private>, blob: &[u8]) -> Result<Vec<u8>, String> {
    let mut signer = Signer::new_without_digest(key)
        .map_err(|error| format!("não foi possível assinar o snapshot: {error}"))?;
    signer
        .sign_oneshot_to_vec(blob)
        .map_err(|error| format!("assinatura Ed25519 falhou: {error}"))
}

fn verify_ed25519(key: &PKey<Public>, blob: &[u8], signature: &[u8]) -> Result<bool, String> {
    let mut verifier = Verifier::new_without_digest(key)
        .map_err(|error| format!("não foi possível verificar o snapshot: {error}"))?;
    verifier
        .verify_oneshot(signature, blob)
        .map_err(|error| format!("verificação Ed25519 falhou: {error}"))
}

pub fn write_pid_file() {
    let path = pid_file_path(None);
    if let Err(error) = std::fs::write(&path, format!("{}\n", std::process::id())) {
        warn!(
            "não foi possível gravar o pid em {}: {error}",
            path.display()
        );
    }
}

fn pid_file_path(override_path: Option<&str>) -> PathBuf {
    override_path
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("FERROADA_PID_FILE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PID))
}

#[cfg(windows)]
fn sentinel_path(pid_file: Option<&Path>) -> PathBuf {
    if let Some(path) = std::env::var("FERROADA_RELOAD_SENTINEL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    let pid_file = pid_file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| pid_file_path(None));
    pid_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(DEFAULT_SENTINEL)
}

/// SIGHUP (Unix) or a sentinel file (Windows). Never an HTTP control plane.
pub fn spawn_reload_listener(store: Arc<PolicyStore>) {
    let _ = std::thread::Builder::new()
        .name("ferroada-reload".into())
        .spawn(move || {
            if let Err(error) = run_reload_listener(store) {
                warn!("listener de reload parou: {error}");
            }
        });
}

fn run_reload_listener(store: Arc<PolicyStore>) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(reload_listener_loop(store))
}

async fn reload_listener_loop(store: Arc<PolicyStore>) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|error| error.to_string())?;
        loop {
            hangup.recv().await;
            let _ = store.try_reload();
        }
    }
    #[cfg(windows)]
    {
        let path = sentinel_path(None);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if path.is_file() {
                let _ = std::fs::remove_file(&path);
                let _ = store.try_reload();
            }
        }
    }
}

const RELOAD_HELP: &str = "\
ferroada reload — pede ao processo em execução para reler ferroada.toml

Uso:
  ferroada reload [--pid <n>] [--pid-file <path>]

Unix: envia SIGHUP. Windows: escreve ferroada.reload ao lado do pid file
(mesmo sítio que FERROADA_PID_FILE / --pid-file). Lê .env.
Parse ou assinatura inválidos não derrubam o proxy: last-known-good fica.
";

const POLICY_HELP: &str = "\
ferroada policy — snapshot canónico da política (JSON) e assinatura Ed25519 opt-in

Uso:
  ferroada policy compile [--config ferroada.toml] [-o ficheiro]
  ferroada policy sign --key <priv.pem> [--in snapshot.json] [-o ferroada.policy.sig]

Sem FERROADA_POLICY_PUBKEY o TOML solto continua válido. Com a chave, o
processo verifica a assinatura do snapshot no load/reload.
";

pub fn run_reload(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{RELOAD_HELP}");
        return Ok(());
    }
    let mut pid = None;
    let mut pid_file = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pid" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada reload --pid exige um número".to_string())?;
                pid = Some(
                    value
                        .parse::<i32>()
                        .map_err(|_| format!("pid inválido: {value}"))?,
                );
                i += 2;
            }
            "--pid-file" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada reload --pid-file exige um caminho".to_string())?;
                pid_file = Some(value.clone());
                i += 2;
            }
            other => return Err(format!("ferroada reload: argumento desconhecido: {other}")),
        }
    }
    #[cfg(unix)]
    {
        let pid = match pid {
            Some(pid) => pid,
            None => read_pid_file(pid_file.as_deref())?,
        };
        send_sighup(pid)
    }
    #[cfg(windows)]
    {
        let _ = pid;
        let path = sentinel_path(pid_file.as_deref().map(Path::new));
        std::fs::write(&path, b"reload\n").map_err(|error| {
            format!(
                "não foi possível pedir reload ({}): {error}",
                path.display()
            )
        })?;
        Ok(())
    }
}

#[cfg(unix)]
fn read_pid_file(override_path: Option<&str>) -> Result<i32, String> {
    let path = pid_file_path(override_path);
    let text = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "pid file {} ilegível ({error}); passe --pid ou FERROADA_PID_FILE",
            path.display()
        )
    })?;
    text.trim()
        .parse::<i32>()
        .map_err(|_| format!("pid file {} não contém um pid", path.display()))
}

#[cfg(unix)]
fn send_sighup(pid: i32) -> Result<(), String> {
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "SIGHUP para pid {pid} falhou: {}",
            io::Error::last_os_error()
        ))
    }
}

pub fn run_policy(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("--help" | "-h") | None => {
            print!("{POLICY_HELP}");
            Ok(())
        }
        Some("compile") => run_compile(&args[1..]),
        Some("sign") => run_sign(&args[1..]),
        Some(other) => Err(format!(
            "ferroada policy: subcomando desconhecido: {other}\n{POLICY_HELP}"
        )),
    }
}

fn run_compile(args: &[String]) -> Result<(), String> {
    let mut config = PathBuf::from(DEFAULT_TOML);
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print!("{POLICY_HELP}");
                return Ok(());
            }
            "--config" => {
                let value = args.get(i + 1).ok_or_else(|| {
                    "ferroada policy compile --config exige um caminho".to_string()
                })?;
                config = PathBuf::from(value);
                i += 2;
            }
            "-o" | "--out" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada policy compile -o exige um caminho".to_string())?;
                out = Some(PathBuf::from(value));
                i += 2;
            }
            other => {
                return Err(format!(
                    "ferroada policy compile: argumento desconhecido: {other}"
                ))
            }
        }
    }
    let contents = std::fs::read_to_string(&config)
        .map_err(|error| format!("não foi possível ler {} ({error})", config.display()))?;
    let (blob, version) = compile_toml_blob(&contents, base_dir(&config))?;
    info!(version = %version, "snapshot compilado");
    write_output(out.as_deref(), &blob)
}

fn run_sign(args: &[String]) -> Result<(), String> {
    let mut key_path = None;
    let mut input = None;
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print!("{POLICY_HELP}");
                return Ok(());
            }
            "--key" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada policy sign --key exige um caminho".to_string())?;
                key_path = Some(PathBuf::from(value));
                i += 2;
            }
            "--in" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada policy sign --in exige um caminho".to_string())?;
                input = Some(PathBuf::from(value));
                i += 2;
            }
            "-o" | "--out" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "ferroada policy sign -o exige um caminho".to_string())?;
                out = Some(PathBuf::from(value));
                i += 2;
            }
            other => {
                return Err(format!(
                    "ferroada policy sign: argumento desconhecido: {other}"
                ))
            }
        }
    }
    let key_path =
        key_path.ok_or_else(|| "ferroada policy sign exige --key <priv.pem>".to_string())?;
    let pem = std::fs::read(&key_path)
        .map_err(|error| format!("chave {} ilegível: {error}", key_path.display()))?;
    let key = parse_private_key(&pem)?;
    let blob = match input {
        Some(path) => {
            std::fs::read(&path).map_err(|error| format!("{} ilegível: {error}", path.display()))?
        }
        None => read_stdin()?,
    };
    let signature = sign_ed25519(&key, &blob)?;
    match out {
        Some(path) => std::fs::write(&path, &signature)
            .map_err(|error| format!("não foi possível gravar {}: {error}", path.display())),
        None => {
            println!("{}", STANDARD.encode(&signature));
            Ok(())
        }
    }
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<(), String> {
    match path {
        Some(path) => std::fs::write(path, bytes)
            .map_err(|error| format!("não foi possível gravar {}: {error}", path.display())),
        None => {
            io::stdout()
                .write_all(bytes)
                .map_err(|error| format!("stdout: {error}"))?;
            Ok(())
        }
    }
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    io::stdin()
        .read_to_end(&mut buf)
        .map_err(|error| format!("stdin: {error}"))?;
    if buf.is_empty() {
        return Err("ferroada policy sign: snapshot vazio no stdin".into());
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    struct EnvGuard {
        keys: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&str, Option<&str>)]) -> Self {
            let mut keys = Vec::new();
            for (key, value) in pairs {
                keys.push(((*key).to_string(), std::env::var(key).ok()));
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            Self { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.keys.drain(..).rev() {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferroada-policy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn site_toml(host: &str, origin: &str) -> String {
        format!("[[sites]]\nhosts = [\"{host}\"]\nbackend = \"http://{origin}\"\n")
    }

    fn keypair() -> (PKey<Private>, String, String) {
        let key = PKey::generate_ed25519().expect("ed25519");
        let pem = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
        let raw = hex_encode(&key.raw_public_key().unwrap());
        (key, pem, raw)
    }

    #[test]
    fn unsigned_toml_boots_without_pubkey() {
        let _lock = env_lock();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", None),
            ("FERROADA_POLICY_SIG", None),
        ]);
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        std::fs::write(&path, site_toml("boot.test", "127.0.0.1:1")).unwrap();
        let store = PolicyStore::from_toml_path(path).expect("boot");
        assert!(store.snapshot().policy_version.starts_with("sha256:"));
        assert!(!store.snapshot().signed);
        assert!(store.config().resolve("boot.test").is_some());
    }

    #[test]
    fn broken_toml_reload_keeps_last_known_good() {
        let _lock = env_lock();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", None),
            ("FERROADA_POLICY_SIG", None),
        ]);
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        std::fs::write(&path, site_toml("keep.test", "127.0.0.1:1")).unwrap();
        let store = PolicyStore::from_toml_path(path.clone()).expect("boot");
        let before = store.snapshot().policy_version;
        std::fs::write(&path, "isto não é toml [[[").unwrap();
        let err = store.try_reload().expect_err("reload must refuse");
        assert!(
            err.contains("TOML") || err.contains("Invalid") || err.contains("inválid"),
            "{err}"
        );
        assert_eq!(store.snapshot().policy_version, before);
        assert!(store.config().resolve("keep.test").is_some());
    }

    #[test]
    fn missing_file_reload_keeps_in_memory_snapshot() {
        let _lock = env_lock();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", None),
            ("FERROADA_POLICY_SIG", None),
        ]);
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        std::fs::write(&path, site_toml("gone.test", "127.0.0.1:1")).unwrap();
        let store = PolicyStore::from_toml_path(path.clone()).expect("boot");
        let before = store.snapshot().policy_version;
        std::fs::remove_file(&path).unwrap();
        let err = store.try_reload().expect_err("missing file");
        assert!(err.contains("ausente"), "{err}");
        assert_eq!(store.snapshot().policy_version, before);
        assert!(store.config().resolve("gone.test").is_some());
    }

    #[test]
    fn valid_signature_accepts_snapshot() {
        let _lock = env_lock();
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        let sig_path = dir.join("ferroada.policy.sig");
        let toml = site_toml("signed.test", "127.0.0.1:1");
        std::fs::write(&path, &toml).unwrap();
        let (blob, _) = compile_toml_blob(&toml, &dir).unwrap();
        let (key, pem, _) = keypair();
        let signature = sign_ed25519(&key, &blob).unwrap();
        std::fs::write(&sig_path, &signature).unwrap();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", Some(pem.as_str())),
            ("FERROADA_POLICY_SIG", Some(sig_path.to_str().unwrap())),
        ]);
        let store = PolicyStore::from_toml_path(path).expect("signed boot");
        assert!(store.snapshot().signed);
        assert!(store.config().resolve("signed.test").is_some());
    }

    #[test]
    fn wrong_signature_refuses_and_keeps_last_known_good() {
        let _lock = env_lock();
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        let sig_path = dir.join("ferroada.policy.sig");
        let first = site_toml("first.test", "127.0.0.1:1");
        std::fs::write(&path, &first).unwrap();
        let (blob, _) = compile_toml_blob(&first, &dir).unwrap();
        let (key, pem, _) = keypair();
        let signature = sign_ed25519(&key, &blob).unwrap();
        std::fs::write(&sig_path, &signature).unwrap();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", Some(pem.as_str())),
            ("FERROADA_POLICY_SIG", Some(sig_path.to_str().unwrap())),
        ]);
        let store = PolicyStore::from_toml_path(path.clone()).expect("boot");
        let before = store.snapshot().policy_version;

        let second = site_toml("second.test", "127.0.0.1:1");
        std::fs::write(&path, &second).unwrap();
        let mut bad = signature;
        bad[0] ^= 0xff;
        std::fs::write(&sig_path, &bad).unwrap();
        let err = store.try_reload().expect_err("bad signature");
        assert!(err.contains("assinatura"), "{err}");
        assert_eq!(store.snapshot().policy_version, before);
        assert!(store.config().resolve("first.test").is_some());
        assert!(store.config().resolve("second.test").is_none());
    }

    #[test]
    fn hex_pubkey_matches_pem() {
        let (key, _pem, hex) = keypair();
        let blob = b"snapshot-bytes";
        let signature = sign_ed25519(&key, blob).unwrap();
        let parsed = parse_public_key(&hex).unwrap();
        assert!(verify_ed25519(&parsed, blob, &signature).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn sentinel_defaults_next_to_pid_file() {
        let _lock = env_lock();
        let dir = temp_dir();
        let pid = dir.join("ferroada.pid");
        let _env = EnvGuard::set(&[
            ("FERROADA_PID_FILE", Some(pid.to_str().unwrap())),
            ("FERROADA_RELOAD_SENTINEL", None),
        ]);
        assert_eq!(sentinel_path(None), dir.join(DEFAULT_SENTINEL));
        assert_eq!(sentinel_path(Some(&pid)), dir.join(DEFAULT_SENTINEL));
    }

    #[test]
    fn compile_is_deterministic() {
        let dir = temp_dir();
        let toml = site_toml("det.test", "127.0.0.1:9");
        let (a, va) = compile_toml_blob(&toml, &dir).unwrap();
        let (b, vb) = compile_toml_blob(&toml, &dir).unwrap();
        assert_eq!(a, b);
        assert_eq!(va, vb);
    }

    #[test]
    fn pubkey_without_signature_file_refuses_boot() {
        let _lock = env_lock();
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        let sig_path = dir.join("ausente.sig");
        std::fs::write(&path, site_toml("nosig.test", "127.0.0.1:1")).unwrap();
        let (_key, pem, _) = keypair();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", Some(pem.as_str())),
            ("FERROADA_POLICY_SIG", Some(sig_path.to_str().unwrap())),
        ]);
        let err = match PolicyStore::from_toml_path(path) {
            Ok(_) => panic!("pubkey sem assinatura não pode arrancar"),
            Err(err) => err,
        };
        assert!(err.contains("assinatura") || err.contains("exige"), "{err}");
    }

    #[test]
    fn whitespace_pubkey_treats_toml_as_unsigned() {
        let _lock = env_lock();
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        std::fs::write(&path, site_toml("space.test", "127.0.0.1:1")).unwrap();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", Some("   ")),
            ("FERROADA_POLICY_SIG", None),
        ]);
        let store = PolicyStore::from_toml_path(path).expect("whitespace pubkey = unset");
        assert!(!store.snapshot().signed);
        assert!(store.config().resolve("space.test").is_some());
    }

    #[test]
    fn reload_that_needs_spool_without_dir_keeps_last_known_good() {
        let _lock = env_lock();
        let dir = temp_dir();
        let path = dir.join("ferroada.toml");
        std::fs::write(&path, site_toml("nospool.test", "127.0.0.1:1")).unwrap();
        let _env = EnvGuard::set(&[
            ("FERROADA_POLICY_PUBKEY", None),
            ("FERROADA_POLICY_SIG", None),
            ("SPOOL_DIR", None),
        ]);
        let store = PolicyStore::from_toml_path(path.clone()).expect("boot");
        let before = store.snapshot().policy_version;
        std::fs::write(
            &path,
            r#"
[[sites]]
hosts = ["nospool.test"]
backend = "http://127.0.0.1:1"
require_complete_waf_inspection = ["/upload"]

[[sites.routes]]
prefix = "/upload"
inspection.require_complete = true
inspection.max_decoded_body = "256KiB"
"#,
        )
        .unwrap();
        let err = store.try_reload().expect_err("spool dir missing");
        assert!(err.contains("SPOOL_DIR") || err.contains("spool"), "{err}");
        assert_eq!(store.snapshot().policy_version, before);
        assert!(!store.config().has_spool_routes());
    }
}
