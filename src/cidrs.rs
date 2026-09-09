//! `ferroada cidrs update` — operator command. HTTP only lives here.
//! Last-known-good is the file on disk. A failed fetch does not touch it.
//! `--cidrs-from-network` is accepted here and nowhere else (never on `init`).

use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client_ip::TrustedProxies;

const HELP: &str = "\
ferroada cidrs update — descarrega as listas oficiais de CIDR (HTTP com limite de 5s)

Uso:
  ferroada cidrs update [--edge cloudflare|fastly|akamai]
                        [--cidrs-from-network] [--yes]
                        [--dir deploy/cidrs] [--env .env]

  --edge                 um fornecedor; omitido = os três
  --cidrs-from-network   flag deste comando (o init nunca busca rede)
  --yes                  escreve sem perguntar (obrigatório se stdin não for um terminal)
  --dir                  pasta dos snapshots (default: deploy/cidrs)
  --env                  .env cuja linha TRUSTED_PROXIES também é actualizada

O proxy nunca corre isto. Se o HTTP falhar, o ficheiro em disco não é tocado.
";

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 1024 * 1024;
const MAX_REDIRECTS: u8 = 3;
const DEFAULT_DIR: &str = "deploy/cidrs";

const CLOUDFLARE_V4: &str = "https://www.cloudflare.com/ips-v4";
const CLOUDFLARE_V6: &str = "https://www.cloudflare.com/ips-v6";
const FASTLY_JSON: &str = "https://api.fastly.com/public-ip-list";
const AKAMAI_V4: &str = "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt";
const AKAMAI_V6: &str = "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv6_CIDRs.txt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FetchKind {
    Text,
    FastlyJson,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgeName {
    Cloudflare,
    Fastly,
    Akamai,
}

impl EdgeName {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cloudflare" => Ok(Self::Cloudflare),
            "fastly" => Ok(Self::Fastly),
            "akamai" => Ok(Self::Akamai),
            other => Err(format!(
                "--edge desconhecido: {other} (cloudflare|fastly|akamai)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Fastly => "fastly",
            Self::Akamai => "akamai",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare.txt",
            Self::Fastly => "fastly.txt",
            Self::Akamai => "akamai.txt",
        }
    }

    fn kind(self) -> FetchKind {
        match self {
            Self::Fastly => FetchKind::FastlyJson,
            Self::Cloudflare | Self::Akamai => FetchKind::Text,
        }
    }

    fn urls(self) -> &'static [&'static str] {
        match self {
            Self::Cloudflare => &[CLOUDFLARE_V4, CLOUDFLARE_V6],
            Self::Fastly => &[FASTLY_JSON],
            Self::Akamai => &[AKAMAI_V4, AKAMAI_V6],
        }
    }

    fn all() -> [Self; 3] {
        [Self::Cloudflare, Self::Fastly, Self::Akamai]
    }
}

#[derive(Clone, Debug)]
struct EdgeJob {
    edge: EdgeName,
    urls: Vec<String>,
}

#[derive(Debug, Default)]
struct Flags {
    edge: Option<String>,
    cidrs_from_network: bool,
    yes: bool,
    dir: Option<String>,
    env: Option<String>,
}

#[derive(Debug)]
struct CidrDiff {
    added: Vec<String>,
    removed: Vec<String>,
}

impl CidrDiff {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

trait HttpGet {
    fn get(&self, url: &str) -> Result<String, String>;
}

struct NetworkHttp {
    timeout: Duration,
}

impl Default for NetworkHttp {
    fn default() -> Self {
        Self {
            timeout: FETCH_TIMEOUT,
        }
    }
}

impl HttpGet for NetworkHttp {
    fn get(&self, url: &str) -> Result<String, String> {
        http_get(url, Instant::now() + self.timeout, 0)
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h")
        || args.first().map(String::as_str) == Some("--help")
        || args.first().map(String::as_str) == Some("-h")
    {
        print!("{HELP}");
        return Ok(());
    }
    let mut stdout = io::stdout();
    let stdin = io::stdin();
    let mut locked = stdin.lock();
    let is_tty = io::stdin().is_terminal();
    run_with(
        args,
        &NetworkHttp::default(),
        &mut locked,
        &mut stdout,
        is_tty,
        &utc_ymd(SystemTime::now()),
        None,
    )
}

fn run_with(
    args: &[String],
    http: &impl HttpGet,
    stdin: &mut impl BufRead,
    stdout: &mut impl Write,
    is_tty: bool,
    today: &str,
    jobs_override: Option<Vec<EdgeJob>>,
) -> Result<(), String> {
    let flags = parse_args(args)?;
    let dir = PathBuf::from(flags.dir.as_deref().unwrap_or(DEFAULT_DIR));
    if !dir.is_dir() {
        return Err(format!(
            "não achei o diretório de snapshots: {} (passe --dir)",
            dir.display()
        ));
    }
    if let Some(env_path) = flags.env.as_deref() {
        let path = Path::new(env_path);
        if !path.is_file() {
            return Err(format!("não achei o .env: {env_path}"));
        }
    }
    let jobs = match jobs_override {
        Some(jobs) => jobs,
        None => official_jobs(flags.edge.as_deref())?,
    };

    writeln!(
        stdout,
        "A descarregar listas oficiais (HTTP, limite {}s). O init nunca faz isto.{}",
        FETCH_TIMEOUT.as_secs(),
        if flags.cidrs_from_network {
            " [--cidrs-from-network]"
        } else {
            ""
        }
    )
    .map_err(io_err)?;

    let mut prepared: Vec<PreparedEdge> = Vec::new();
    for job in &jobs {
        let fetched = fetch_edge(http, job)?;
        let path = dir.join(job.edge.file_name());
        let old_text = if path.is_file() {
            fs::read_to_string(&path)
                .map_err(|error| format!("não leu {}: {error}", path.display()))?
        } else {
            String::new()
        };
        let old_cidrs = cidrs_from_text(&old_text);
        let diff = diff_cidrs(&old_cidrs, &fetched);
        prepared.push(PreparedEdge {
            edge: job.edge,
            path,
            old_cidrs,
            new_cidrs: fetched,
            diff,
        });
    }

    let any_change = prepared.iter().any(|item| !item.diff.is_empty());
    for item in &prepared {
        write_diff(stdout, item)?;
    }
    if !any_change {
        writeln!(stdout, "Nenhuma alteração nos CIDRs.").map_err(io_err)?;
        return Ok(());
    }

    if !flags.yes {
        if !is_tty {
            return Err(
                "há alterações; passe --yes para escrever (stdin não é um terminal)".into(),
            );
        }
        write!(stdout, "Escrever o snapshot em disco? [s/N] ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let mut line = String::new();
        stdin
            .read_line(&mut line)
            .map_err(|error| format!("leitura do terminal: {error}"))?;
        if !is_yes(line.trim()) {
            writeln!(stdout, "Cancelado. Snapshot no disco intacto.").map_err(io_err)?;
            return Ok(());
        }
    }

    for item in &prepared {
        if item.diff.is_empty() {
            continue;
        }
        let body = render_snapshot(item.edge, today, &item.new_cidrs);
        replace_file(&item.path, &body)?;
        writeln!(
            stdout,
            "Escrito {} ({} CIDRs).",
            item.path.display(),
            item.new_cidrs.len()
        )
        .map_err(io_err)?;
    }

    if let Some(env_path) = flags.env.as_deref() {
        let path = Path::new(env_path);
        let before = fs::read_to_string(path)
            .map_err(|error| format!("não leu {}: {error}", path.display()))?;
        let after = merge_env_trusted(&before, &prepared);
        if after != before {
            replace_file(path, &after)?;
            writeln!(stdout, "Actualizado TRUSTED_PROXIES em {}.", path.display())
                .map_err(io_err)?;
        }
    }

    Ok(())
}

struct PreparedEdge {
    edge: EdgeName,
    path: PathBuf,
    old_cidrs: Vec<String>,
    new_cidrs: Vec<String>,
    diff: CidrDiff,
}

fn official_jobs(edge: Option<&str>) -> Result<Vec<EdgeJob>, String> {
    let selected = match edge {
        None | Some("") => EdgeName::all().to_vec(),
        Some(value) => vec![EdgeName::parse(value)?],
    };
    Ok(selected
        .into_iter()
        .map(|edge| EdgeJob {
            urls: edge.urls().iter().map(|url| (*url).to_string()).collect(),
            edge,
        })
        .collect())
}

fn parse_args(args: &[String]) -> Result<Flags, String> {
    if args.is_empty() {
        return Err("falta o subcomando. Uso: ferroada cidrs update".into());
    }
    match args[0].as_str() {
        "update" => parse_update_flags(&args[1..]),
        other if other.starts_with('-') => Err(format!(
            "falta o subcomando. Uso: ferroada cidrs update. Flag inesperada: {other}"
        )),
        other => Err(format!(
            "subcomando desconhecido: {other}. Uso: ferroada cidrs update"
        )),
    }
}

fn parse_update_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--cidrs-from-network" => {
                flags.cidrs_from_network = true;
                i += 1;
                continue;
            }
            "--yes" | "-y" => {
                flags.yes = true;
                i += 1;
                continue;
            }
            other if other.starts_with("--cidrs-from-network=") => {
                return Err("--cidrs-from-network não leva valor; é uma flag deste comando".into());
            }
            _ => {}
        }
        let (key, inline) = split_flag(arg);
        let mut take =
            |slot: &mut Option<String>, name: &str, inline: Option<&str>| -> Result<(), String> {
                if slot.is_some() {
                    return Err(format!("{name} repetido"));
                }
                let value = match inline {
                    Some(value) => value.to_string(),
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("{name} precisa de um valor"))?
                    }
                };
                *slot = Some(value);
                Ok(())
            };
        match key {
            "--edge" => take(&mut flags.edge, "--edge", inline)?,
            "--dir" => take(&mut flags.dir, "--dir", inline)?,
            "--env" => take(&mut flags.env, "--env", inline)?,
            other if other.starts_with('-') => {
                return Err(format!("flag desconhecida: {other}"));
            }
            other => return Err(format!("argumento inesperado: {other}")),
        }
        i += 1;
    }
    Ok(flags)
}

fn split_flag(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (arg, None),
    }
}

fn fetch_edge(http: &impl HttpGet, job: &EdgeJob) -> Result<Vec<String>, String> {
    let mut all = Vec::new();
    for url in &job.urls {
        let body = http
            .get(url)
            .map_err(|error| format!("{} ({url}): {error}", job.edge.as_str()))?;
        let parsed = match job.edge.kind() {
            FetchKind::Text => parse_text_body(&body)?,
            FetchKind::FastlyJson => parse_fastly_json(&body)?,
        };
        if parsed.is_empty() {
            return Err(format!(
                "{} ({url}): lista vazia — snapshot no disco intacto",
                job.edge.as_str()
            ));
        }
        all.extend(parsed);
    }
    Ok(dedupe_keep_order(all))
}

pub fn cidrs_from_text(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn parse_text_body(body: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    for (index, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        validate_cidr(line).map_err(|error| format!("linha {}: {error}", index + 1))?;
        out.push(line.to_string());
    }
    Ok(out)
}

#[derive(Deserialize)]
struct FastlyPublicIpList {
    addresses: Vec<String>,
    ipv6_addresses: Vec<String>,
}

fn parse_fastly_json(body: &str) -> Result<Vec<String>, String> {
    let parsed: FastlyPublicIpList = serde_json::from_str(body.trim())
        .map_err(|error| format!("JSON Fastly inválido: {error}"))?;
    let mut out = Vec::new();
    for cidr in parsed.addresses.into_iter().chain(parsed.ipv6_addresses) {
        let cidr = cidr.trim().to_string();
        if cidr.is_empty() {
            continue;
        }
        validate_cidr(&cidr)?;
        out.push(cidr);
    }
    Ok(out)
}

fn validate_cidr(value: &str) -> Result<(), String> {
    TrustedProxies::parse(value).map(|_| ())
}

fn diff_cidrs(old: &[String], new: &[String]) -> CidrDiff {
    let old_set: HashSet<&str> = old.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new.iter().map(String::as_str).collect();
    let added = new
        .iter()
        .filter(|cidr| !old_set.contains(cidr.as_str()))
        .cloned()
        .collect();
    let removed = old
        .iter()
        .filter(|cidr| !new_set.contains(cidr.as_str()))
        .cloned()
        .collect();
    CidrDiff { added, removed }
}

fn write_diff(stdout: &mut impl Write, item: &PreparedEdge) -> Result<(), String> {
    if item.diff.is_empty() {
        writeln!(
            stdout,
            "{}: sem alterações ({} CIDRs).",
            item.edge.as_str(),
            item.old_cidrs.len()
        )
        .map_err(io_err)?;
        return Ok(());
    }
    writeln!(
        stdout,
        "{} ({}): {} adicionados, {} removidos",
        item.edge.as_str(),
        item.path.display(),
        item.diff.added.len(),
        item.diff.removed.len()
    )
    .map_err(io_err)?;
    for cidr in &item.diff.added {
        writeln!(stdout, "  + {cidr}").map_err(io_err)?;
    }
    for cidr in &item.diff.removed {
        writeln!(stdout, "  - {cidr}").map_err(io_err)?;
    }
    Ok(())
}

fn render_snapshot(edge: EdgeName, today: &str, cidrs: &[String]) -> String {
    let header = match edge {
        EdgeName::Cloudflare => format!(
            "# Snapshot {today}. Não buscar isto no processo nem no boot.\n\
             # Fonte IPv4: {CLOUDFLARE_V4}\n\
             # Fonte IPv6: {CLOUDFLARE_V6}\n\
             # IPs a partir dos quais a Cloudflare fala com a origem. Firewall + TRUSTED_PROXIES.\n\
             # Formato: um CIDR por linha. Cole no TRUSTED_PROXIES separado por vírgulas.\n"
        ),
        EdgeName::Fastly => format!(
            "# Snapshot {today}. Não buscar isto no processo nem no boot.\n\
             # Fonte: {FASTLY_JSON}\n\
             # IPs públicos Fastly (JSON `addresses` + `ipv6_addresses`).\n\
             # Formato: um CIDR por linha. Cole no TRUSTED_PROXIES separado por vírgulas.\n"
        ),
        EdgeName::Akamai => format!(
            "# Snapshot {today}. Não buscar isto no processo nem no boot.\n\
             # Fonte IPv4: {AKAMAI_V4}\n\
             # Fonte IPv6: {AKAMAI_V6}\n\
             # Supernets públicos Origin IP ACL. Site Shield (Control Center) é por cliente e deve substituir esta lista se existir. Não é o mapa de toda a borda Akamai.\n\
             # Formato: um CIDR por linha. Cole no TRUSTED_PROXIES separado por vírgulas.\n"
        ),
    };
    let mut out = header;
    out.push('\n');
    for cidr in cidrs {
        out.push_str(cidr);
        out.push('\n');
    }
    out
}

fn merge_env_trusted(content: &str, prepared: &[PreparedEdge]) -> String {
    let prefix = "TRUSTED_PROXIES=";
    let current = content
        .lines()
        .find(|line| line.starts_with(prefix))
        .map(|line| line[prefix.len()..].to_string())
        .unwrap_or_default();
    let mut old_set = HashSet::new();
    let mut new_list = Vec::new();
    for item in prepared {
        for cidr in &item.old_cidrs {
            old_set.insert(cidr.clone());
        }
        new_list.extend(item.new_cidrs.iter().cloned());
    }
    let extras: Vec<String> = current
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty() && !old_set.contains(*item))
        .map(str::to_string)
        .collect();
    let merged = dedupe_keep_order(extras.into_iter().chain(new_list).collect());
    set_env_line(content, "TRUSTED_PROXIES", &merged.join(","))
}

fn set_env_line(content: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                found = true;
                format!("{prefix}{value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(format!("{prefix}{value}"));
    }
    let mut out = lines.join("\n");
    if (content.ends_with('\n') || content.is_empty()) && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn replace_file(path: &Path, body: &str) -> Result<(), String> {
    let tmp_name = format!(
        "{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    let tmp = path.with_file_name(tmp_name);
    fs::write(&tmp, body).map_err(|error| format!("não escreveu {}: {error}", tmp.display()))?;
    if let Err(error) = swap_into_place(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn swap_into_place(tmp: &Path, dest: &Path) -> Result<(), String> {
    fs::rename(tmp, dest).map_err(|error| format!("não escreveu {}: {error}", dest.display()))
}

#[cfg(not(unix))]
fn swap_into_place(tmp: &Path, dest: &Path) -> Result<(), String> {
    if !dest.exists() {
        return fs::rename(tmp, dest)
            .map_err(|error| format!("não escreveu {}: {error}", dest.display()));
    }
    let bak_name = format!(
        "{}.bak",
        dest.file_name().unwrap_or_default().to_string_lossy()
    );
    let bak = dest.with_file_name(bak_name);
    fs::rename(dest, &bak).map_err(|error| format!("não escreveu {}: {error}", dest.display()))?;
    match fs::rename(tmp, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&bak);
            Ok(())
        }
        Err(error) => {
            let _ = fs::rename(&bak, dest);
            Err(format!("não escreveu {}: {error}", dest.display()))
        }
    }
}

fn dedupe_keep_order(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.to_ascii_lowercase().as_str(),
        "s" | "sim" | "y" | "yes"
    )
}

fn io_err(error: io::Error) -> String {
    format!("escrita no terminal: {error}")
}

fn utc_ymd(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Howard Hinnant civil_from_days, Unix epoch = 719468 days before 0000-03-01.
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
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
        return Err(format!("URL não é http(s): {url}"));
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((hostport, path)) => (hostport, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() || hostport.starts_with('[') {
        return Err(format!("URL sem host utilizável: {url}"));
    }
    let (host, port) = match hostport.split_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("porta inválida em {url}"))?;
            (host.to_string(), port)
        }
        None => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() || host.contains(' ') {
        return Err(format!("host inválido: {url}"));
    }
    Ok(ParsedUrl {
        tls,
        host,
        port,
        path,
    })
}

fn tls_connector() -> Result<openssl::ssl::SslConnector, String> {
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
        .map_err(|error| format!("tls: {error}"))?;
    let ca = find_ca_bundle()
        .ok_or_else(|| "tls: não achei um bundle de CAs. Defina SSL_CERT_FILE.".to_string())?;
    builder
        .set_ca_file(&ca)
        .map_err(|error| format!("tls CA {}: {error}", ca.display()))?;
    Ok(builder.build())
}

fn find_ca_bundle() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let probe = openssl_probe::probe();
    if let Some(file) = probe.cert_file.filter(|path| path.is_file()) {
        return Some(file);
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    for key in ["ProgramFiles", "ProgramFiles(x86)", "PROGRAMFILES"] {
        if let Ok(root) = std::env::var(key) {
            candidates.push(PathBuf::from(root).join(r"Git\usr\ssl\certs\ca-bundle.crt"));
        }
    }
    candidates.push(PathBuf::from(
        r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    ));
    candidates.push(PathBuf::from("/etc/ssl/certs/ca-certificates.crt"));
    candidates.push(PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"));
    candidates.push(PathBuf::from("/etc/ssl/cert.pem"));
    candidates.into_iter().find(|path| path.is_file())
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "tempo esgotado a descarregar CIDRs".to_string())
}

fn resolve_host(host: &str, port: u16, timeout: Duration) -> Result<std::net::SocketAddr, String> {
    let target = format!("{host}:{port}");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = target
            .to_socket_addrs()
            .map(|mut addrs| addrs.next())
            .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => Err(format!("DNS sem endereço para {host}")),
        Ok(Err(error)) => Err(format!("DNS {host}: {error}")),
        Err(_) => Err(format!("DNS {host}: tempo esgotado")),
    }
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

fn http_get(url: &str, deadline: Instant, redirects: u8) -> Result<String, String> {
    if redirects > MAX_REDIRECTS {
        return Err(format!("demasiados redireccionamentos a partir de {url}"));
    }
    let parsed = parse_http_url(url)?;
    let timeout = remaining(deadline)?;
    let addr = resolve_host(&parsed.host, parsed.port, timeout)?;
    let timeout = remaining(deadline)?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|error| format!("não ligou a {url}: {error}"))?;
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("cidrs: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("cidrs: {error}"))?;

    let mut stream = if parsed.tls {
        let connector = tls_connector()?;
        let tls = connector
            .connect(&parsed.host, stream)
            .map_err(|error| format!("tls {url}: {error}"))?;
        BodyStream::Tls(tls)
    } else {
        BodyStream::Plain(stream)
    };

    let host = host_header(&parsed.host, parsed.port, parsed.tls);
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ferroada-cidrs\r\nConnection: close\r\n\r\n",
        parsed.path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("escrita {url}: {error}"))?;
    if let BodyStream::Plain(plain) = &stream {
        let _ = plain.shutdown(Shutdown::Write);
    }

    let raw = read_limited(&mut stream, MAX_BODY)?;
    let response = parse_response(&raw)?;
    if (300..400).contains(&response.status) {
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| format!("{url} devolveu {} sem Location", response.status))?;
        let next = resolve_redirect(url, location)?;
        return http_get(&next, deadline, redirects + 1);
    }
    if response.status != 200 {
        return Err(format!("{url} devolveu HTTP {}", response.status));
    }
    if response.headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(format!("{url}: resposta chunked não suportada"));
    }
    if let Some((_, value)) = response
        .headers
        .iter()
        .find(|(name, _)| name == "content-length")
    {
        let expected: usize = value
            .parse()
            .map_err(|_| format!("{url}: Content-Length inválido"))?;
        if response.body.len() < expected {
            return Err(format!("{url}: resposta HTTP truncada"));
        }
    }
    Ok(response.body)
}

fn host_header(host: &str, port: u16, tls: bool) -> String {
    let default = if tls { 443 } else { 80 };
    if port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn resolve_redirect(current: &str, location: &str) -> Result<String, String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_string());
    }
    if let Some(rest) = location.strip_prefix('/') {
        let parsed = parse_http_url(current)?;
        let scheme = if parsed.tls { "https" } else { "http" };
        let host = host_header(&parsed.host, parsed.port, parsed.tls);
        return Ok(format!("{scheme}://{host}/{rest}"));
    }
    Err(format!("Location inválido: {location}"))
}

fn read_limited(stream: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0_u8; max];
    let mut filled = 0;
    while filled < max {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Err("tempo esgotado a descarregar CIDRs".into());
            }
            Err(error) => return Err(format!("leitura HTTP falhou: {error}")),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| "resposta HTTP incompleta".to_string())?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "resposta HTTP vazia".to_string())?;
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| "status HTTP malformado".to_string())?;
    if !version.starts_with("HTTP/") {
        return Err("resposta não é HTTP".into());
    }
    let code = parts
        .next()
        .ok_or_else(|| "status HTTP malformado".to_string())?;
    let status: u16 = code
        .parse()
        .map_err(|_| "status HTTP malformado".to_string())?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    struct MapHttp {
        inner: Vec<(String, Result<String, String>)>,
    }

    impl HttpGet for MapHttp {
        fn get(&self, url: &str) -> Result<String, String> {
            self.inner
                .iter()
                .find(|(key, _)| key == url)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| Err(format!("fixture em falta para {url}")))
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "ferroada-cidrs-{}-{}-{}-{label}",
            std::process::id(),
            nanos,
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_snapshot(dir: &Path, name: &str, cidrs: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let mut body = "# Snapshot 2026-09-08. fixture de teste.\n\n".to_string();
        for cidr in cidrs {
            body.push_str(cidr);
            body.push('\n');
        }
        fs::write(&path, &body).unwrap();
        path
    }

    fn job(edge: EdgeName, urls: Vec<String>) -> EdgeJob {
        EdgeJob { edge, urls }
    }

    fn run_test(
        args: &[&str],
        http: &impl HttpGet,
        stdin: &str,
        is_tty: bool,
        jobs: Vec<EdgeJob>,
        _dir: &Path,
    ) -> (Result<(), String>, String) {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut input = Cursor::new(stdin.to_string());
        let mut output = Vec::new();
        let result = run_with(
            &owned,
            http,
            &mut input,
            &mut output,
            is_tty,
            "2026-09-09",
            Some(jobs),
        );
        (result, String::from_utf8_lossy(&output).into_owned())
    }

    fn serve_once(
        status_and_body: &'static [u8],
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(status_and_body);
        });
        (addr, handle)
    }

    #[test]
    fn tls_connector_builds_when_ca_bundle_exists() {
        if find_ca_bundle().is_none() {
            return;
        }
        tls_connector().expect("SslConnector");
    }

    #[test]
    fn utc_ymd_unix_epoch() {
        assert_eq!(utc_ymd(UNIX_EPOCH), "1970-01-01");
        assert_eq!(
            utc_ymd(UNIX_EPOCH + Duration::from_secs(946_684_800)),
            "2000-01-01"
        );
    }

    #[test]
    fn parse_text_skips_comments_and_rejects_garbage() {
        let ok = parse_text_body("# x\n\n173.245.48.0/20\n2400:cb00::/32\n").unwrap();
        assert_eq!(ok, vec!["173.245.48.0/20", "2400:cb00::/32"]);
        let err = parse_text_body("not-a-cidr\n").unwrap_err();
        assert!(err.contains("inválido") || err.contains("IP"), "{err}");
    }

    #[test]
    fn parse_fastly_json_collects_both_families() {
        let body = r#"{"addresses":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}"#;
        let cidrs = parse_fastly_json(body).unwrap();
        assert_eq!(cidrs, vec!["23.235.32.0/20", "2a04:4e40::/32"]);
    }

    #[test]
    fn diff_lists_added_and_removed_in_source_order() {
        let diff = diff_cidrs(
            &["1.0.0.0/8".into(), "2.0.0.0/8".into()],
            &["2.0.0.0/8".into(), "3.0.0.0/8".into()],
        );
        assert_eq!(diff.added, vec!["3.0.0.0/8"]);
        assert_eq!(diff.removed, vec!["1.0.0.0/8"]);
    }

    #[test]
    fn failed_http_leaves_snapshot_untouched() {
        let dir = temp_dir("fail-http");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let jobs = vec![job(
            EdgeName::Cloudflare,
            vec![format!("http://{addr}/ips-v4")],
        )];
        let args = [
            "update",
            "--yes",
            "--dir",
            dir.to_str().unwrap(),
            "--cidrs-from-network",
        ];
        let (result, _) = run_test(&args, &NetworkHttp::default(), "", false, jobs, &dir);
        let err = result.unwrap_err();
        assert!(
            err.contains("não ligou") || err.contains("tempo") || err.contains("HTTP"),
            "{err}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_500_leaves_snapshot_untouched() {
        let dir = temp_dir("http-500");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();
        let (addr, handle) =
            serve_once(b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        let jobs = vec![job(
            EdgeName::Cloudflare,
            vec![format!("http://{addr}/ips-v4")],
        )];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, _) = run_test(&args, &NetworkHttp::default(), "", false, jobs, &dir);
        let err = result.unwrap_err();
        assert!(err.contains("500"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stalled_body_after_partial_cidrs_leaves_snapshot_untouched() {
        let dir = temp_dir("stall");
        let path = write_snapshot(
            &dir,
            "cloudflare.txt",
            &["173.245.48.0/20", "1.1.1.0/24", "2.2.2.0/24"],
        );
        let original = fs::read_to_string(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n173.245.48.0/20\n");
            thread::sleep(Duration::from_secs(2));
        });
        let jobs = vec![job(
            EdgeName::Cloudflare,
            vec![format!("http://{addr}/ips-v4")],
        )];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let http = NetworkHttp {
            timeout: Duration::from_millis(300),
        };
        let (result, _) = run_test(&args, &http, "", false, jobs, &dir);
        let err = result.unwrap_err();
        assert!(err.contains("tempo esgotado"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_content_length_leaves_snapshot_untouched() {
        let dir = temp_dir("truncated");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20", "1.1.1.0/24"]);
        let original = fs::read_to_string(&path).unwrap();
        let (addr, handle) = serve_once(
            b"HTTP/1.0 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n173.245.48.0/20\n",
        );
        let jobs = vec![job(
            EdgeName::Cloudflare,
            vec![format!("http://{addr}/ips-v4")],
        )];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, _) = run_test(&args, &NetworkHttp::default(), "", false, jobs, &dir);
        let err = result.unwrap_err();
        assert!(err.contains("truncada"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn diverging_fixture_shows_diff_and_yes_writes() {
        let dir = temp_dir("diff-write");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20", "1.1.1.0/24"]);
        let original = fs::read_to_string(&path).unwrap();
        let http = MapHttp {
            inner: vec![(
                "http://fixture/v4".into(),
                Ok("173.245.48.0/20\n9.9.9.0/24\n".into()),
            )],
        };
        let jobs = vec![job(EdgeName::Cloudflare, vec!["http://fixture/v4".into()])];
        let args_no = ["update", "--dir", dir.to_str().unwrap()];
        let (result, out) = run_test(&args_no, &http, "", false, jobs.clone(), &dir);
        let err = result.unwrap_err();
        assert!(err.contains("--yes"), "{err}");
        assert!(out.contains("+ 9.9.9.0/24"), "{out}");
        assert!(out.contains("- 1.1.1.0/24"), "{out}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);

        let args_yes = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, out) = run_test(&args_yes, &http, "", false, jobs, &dir);
        result.unwrap();
        assert!(out.contains("+ 9.9.9.0/24"), "{out}");
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("9.9.9.0/24"), "{written}");
        assert!(written.contains("173.245.48.0/20"), "{written}");
        assert!(!written.contains("1.1.1.0/24"), "{written}");
        assert!(written.contains("2026-09-09"), "{written}");
        assert!(written.contains(CLOUDFLARE_V4), "{written}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tty_no_keeps_snapshot() {
        let dir = temp_dir("tty-no");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();
        let http = MapHttp {
            inner: vec![("http://fixture/v4".into(), Ok("9.9.9.0/24\n".into()))],
        };
        let jobs = vec![job(EdgeName::Cloudflare, vec!["http://fixture/v4".into()])];
        let args = ["update", "--dir", dir.to_str().unwrap()];
        let (result, out) = run_test(&args, &http, "n\n", true, jobs, &dir);
        result.unwrap();
        assert!(out.contains("Cancelado"), "{out}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_url_failure_does_not_write_partial() {
        let dir = temp_dir("partial");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);
        let http = MapHttp {
            inner: vec![
                ("http://ok/v4".into(), Ok("173.245.48.0/20\n".into())),
                (format!("http://{dead}/v6"), Err("não ligou".into())),
            ],
        };
        let jobs = vec![job(
            EdgeName::Cloudflare,
            vec!["http://ok/v4".into(), format!("http://{dead}/v6")],
        )];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, _) = run_test(&args, &http, "", false, jobs, &dir);
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_keeps_caddy_peer_and_replaces_snapshot_cidrs() {
        let dir = temp_dir("env");
        write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let env_path = dir.join(".env");
        fs::write(
            &env_path,
            "DASHBOARD_TOKEN=abc\nTRUSTED_PROXIES=172.28.0.2/32,173.245.48.0/20\n",
        )
        .unwrap();
        let http = MapHttp {
            inner: vec![("http://fixture/v4".into(), Ok("9.9.9.0/24\n".into()))],
        };
        let jobs = vec![job(EdgeName::Cloudflare, vec!["http://fixture/v4".into()])];
        let env_arg = env_path.to_string_lossy().into_owned();
        let dir_arg = dir.to_string_lossy().into_owned();
        let args = [
            "update",
            "--yes",
            "--dir",
            dir_arg.as_str(),
            "--env",
            env_arg.as_str(),
            "--cidrs-from-network",
        ];
        let (result, out) = run_test(&args, &http, "", false, jobs, &dir);
        result.unwrap();
        assert!(out.contains("TRUSTED_PROXIES"), "{out}");
        let env = fs::read_to_string(&env_path).unwrap();
        assert!(
            env.contains("TRUSTED_PROXIES=172.28.0.2/32,9.9.9.0/24"),
            "{env}"
        );
        assert!(env.contains("DASHBOARD_TOKEN=abc"), "{env}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_lists_do_not_rewrite() {
        let dir = temp_dir("same");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();
        let http = MapHttp {
            inner: vec![("http://fixture/v4".into(), Ok("173.245.48.0/20\n".into()))],
        };
        let jobs = vec![job(EdgeName::Cloudflare, vec!["http://fixture/v4".into()])];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, out) = run_test(&args, &http, "", false, jobs, &dir);
        result.unwrap();
        assert!(out.contains("Nenhuma alteração"), "{out}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_args_accepts_cidrs_from_network_and_rejects_unknown() {
        let flags = parse_args(&[
            "update".into(),
            "--cidrs-from-network".into(),
            "--yes".into(),
            "--edge".into(),
            "fastly".into(),
        ])
        .unwrap();
        assert!(flags.cidrs_from_network);
        assert!(flags.yes);
        assert_eq!(flags.edge.as_deref(), Some("fastly"));
        let err =
            parse_args(&["update".into(), "--trusted-proxies".into(), "auto".into()]).unwrap_err();
        assert!(err.contains("desconhecida"), "{err}");
        let err = parse_args(&[]).unwrap_err();
        assert!(err.contains("falta o subcomando"), "{err}");
    }

    #[test]
    fn empty_body_does_not_write() {
        let dir = temp_dir("empty");
        let path = write_snapshot(&dir, "cloudflare.txt", &["173.245.48.0/20"]);
        let original = fs::read_to_string(&path).unwrap();
        let http = MapHttp {
            inner: vec![("http://fixture/v4".into(), Ok("# só comentário\n".into()))],
        };
        let jobs = vec![job(EdgeName::Cloudflare, vec!["http://fixture/v4".into()])];
        let args = ["update", "--yes", "--dir", dir.to_str().unwrap()];
        let (result, _) = run_test(&args, &http, "", false, jobs, &dir);
        let err = result.unwrap_err();
        assert!(err.contains("vazia"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let _ = fs::remove_dir_all(&dir);
    }
}
