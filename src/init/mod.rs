//! `ferroada init` — emit a topology pack from the embedded templates.
//! `--trusted-proxies auto` copies `deploy/cidrs/<edge>.txt`. Zero HTTP.

mod templates;

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::client_ip::TrustedProxies;

const HELP: &str = "\
ferroada init — gera um pack de topologia a partir dos templates embutidos (sem HTTP)

Uso:
  ferroada init --topology <modo> --origin <url> [opções]

Modos:
  vps-site, vps-api, vps-supabase-selfhost, vps-supabase-cloud,
  vps-full, hostinger-origin, vercel-origin, cdn-edge

Opções:
  --topology <modo>
  --out <dir>                 default: ./ferroada-deploy
  --public-host <host>        obrigatório (hostinger-origin e vercel-origin recusam sem VPS)
  --origin <url>              http:// ou https://; nunca inventado
  --edge none|cloudflare|fastly|akamai|caddy|nginx
  --trusted-proxies auto|none|<CIDR,CIDR>
                              auto copia o snapshot local de deploy/cidrs/<edge>.txt
  --dashboard-token auto|<token>
  --static-placement ferroada-front|public|cdn   (hostinger-origin)
  --supabase-host <host>      opção 2 de vps-supabase-cloud
  --listen-mode privileged|proxied
                              privileged = :80/:443 + CAP_NET_BIND_SERVICE
                              proxied = 127.0.0.1:3000 + Caddy
  --non-interactive
";

const CADDY_DOCKER_PEER: &str = "172.28.0.2/32";
const DEFAULT_OUT: &str = "ferroada-deploy";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topology {
    VpsSite,
    VpsApi,
    VpsSupabaseSelfhost,
    VpsSupabaseCloud,
    VpsFull,
    HostingerOrigin,
    VercelOrigin,
    CdnEdge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Edge {
    None,
    Cloudflare,
    Fastly,
    Akamai,
    Caddy,
    Nginx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenMode {
    Privileged,
    Proxied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TrustedSpec {
    Auto,
    None,
    List(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaticPlacement {
    FerroadaFront,
    Public,
    Cdn,
}

#[derive(Debug, Default)]
struct Flags {
    topology: Option<String>,
    out: Option<String>,
    public_host: Option<String>,
    origin: Option<String>,
    edge: Option<String>,
    trusted_proxies: Option<String>,
    dashboard_token: Option<String>,
    static_placement: Option<String>,
    supabase_host: Option<String>,
    listen_mode: Option<String>,
    non_interactive: bool,
}

#[derive(Debug)]
struct Plan {
    topology: Topology,
    out: PathBuf,
    public_host: Option<String>,
    origin: String,
    listen: ListenMode,
    trusted_csv: String,
    dashboard_token: String,
    static_placement: StaticPlacement,
    supabase_host: Option<String>,
}

pub fn run(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    let flags = parse_flags(args)?;
    let interactive = !flags.non_interactive && io::stdin().is_terminal();
    let plan = if interactive {
        resolve_interactive(flags, &mut io::stdin().lock(), &mut io::stdout())?
    } else {
        resolve_non_interactive(flags)?
    };
    emit(&plan)
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--non-interactive" {
            flags.non_interactive = true;
            i += 1;
            continue;
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
            "--topology" => take(&mut flags.topology, "--topology", inline)?,
            "--out" => take(&mut flags.out, "--out", inline)?,
            "--public-host" => take(&mut flags.public_host, "--public-host", inline)?,
            "--origin" => take(&mut flags.origin, "--origin", inline)?,
            "--edge" => take(&mut flags.edge, "--edge", inline)?,
            "--trusted-proxies" => take(&mut flags.trusted_proxies, "--trusted-proxies", inline)?,
            "--dashboard-token" => take(&mut flags.dashboard_token, "--dashboard-token", inline)?,
            "--static-placement" => {
                take(&mut flags.static_placement, "--static-placement", inline)?
            }
            "--supabase-host" => take(&mut flags.supabase_host, "--supabase-host", inline)?,
            "--listen-mode" => take(&mut flags.listen_mode, "--listen-mode", inline)?,
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

fn resolve_non_interactive(flags: Flags) -> Result<Plan, String> {
    let topology = match flags.topology.as_deref() {
        Some(value) => Topology::parse(value)?,
        None => return Err("indique --topology".into()),
    };
    let origin = match flags.origin.as_deref() {
        Some(value) => {
            validate_origin(value)?;
            value.to_string()
        }
        None => {
            return Err(
                "indique --origin (http:// ou https://). O init nunca inventa o origin.".into(),
            )
        }
    };
    if flags.public_host.is_none() {
        if topology.requires_public_host() {
            return Err(format!(
                "{} recusa --non-interactive sem --public-host. Este processo precisa de uma VM; o Ferroada não corre em shared hosting nem na Vercel.",
                topology.as_str()
            ));
        }
        return Err(
            "indique --public-host (nome de host, sem esquema). Sem isto o Caddyfile e o ferroada.toml ficam com placeholder.".into(),
        );
    }
    if flags.static_placement.is_some() && topology != Topology::HostingerOrigin {
        return Err("--static-placement só vale em hostinger-origin".into());
    }
    if flags.supabase_host.is_some() && topology != Topology::VpsSupabaseCloud {
        return Err("--supabase-host só vale em vps-supabase-cloud".into());
    }
    finish_plan(flags, topology, origin)
}

fn resolve_interactive(
    mut flags: Flags,
    stdin: &mut impl BufRead,
    stdout: &mut impl Write,
) -> Result<Plan, String> {
    if flags.topology.is_none() {
        writeln!(
            stdout,
            "Topologia (vps-site, vps-api, vps-supabase-selfhost, vps-supabase-cloud, vps-full, hostinger-origin, vercel-origin, cdn-edge):"
        )
        .map_err(io_err)?;
        flags.topology = Some(read_line(stdin)?);
    }
    let topology = Topology::parse(flags.topology.as_deref().unwrap_or(""))?;

    if flags.origin.is_none() {
        write!(stdout, "Origin (http:// ou https://): ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        flags.origin = Some(read_line(stdin)?);
    }
    let origin = flags.origin.as_deref().unwrap_or("").trim().to_string();
    if origin.is_empty() {
        return Err(
            "indique --origin (http:// ou https://). O init nunca inventa o origin.".into(),
        );
    }
    validate_origin(&origin)?;

    if flags.public_host.is_none() {
        write!(stdout, "Host público (obrigatório): ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.public_host = Some(line);
        }
    }
    if flags.public_host.is_none() {
        if topology.requires_public_host() {
            return Err(format!(
                "{} exige --public-host. Este processo precisa de uma VM.",
                topology.as_str()
            ));
        }
        return Err(
            "indique --public-host. Sem isto o Caddyfile e o ferroada.toml ficam com placeholder."
                .into(),
        );
    }

    if topology == Topology::VpsSupabaseCloud && flags.supabase_host.is_none() {
        writeln!(
            stdout,
            "vps-supabase-cloud: opção 1 = não proxyar a Cloud (Enter). Opção 2 = host dedicado."
        )
        .map_err(io_err)?;
        write!(stdout, "Host do BFF Supabase (opção 2, vazio = opção 1): ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.supabase_host = Some(line);
        }
    }

    if topology == Topology::HostingerOrigin && flags.static_placement.is_none() {
        write!(
            stdout,
            "static-placement (ferroada-front/public/cdn) [ferroada-front]: "
        )
        .map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.static_placement = Some(line);
        }
    }

    if flags.out.is_none() {
        write!(stdout, "Diretório de saída [{DEFAULT_OUT}]: ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.out = Some(line);
        }
    }

    if flags.listen_mode.is_none() {
        write!(stdout, "listen-mode (privileged/proxied) [proxied]: ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.listen_mode = Some(line);
        }
    }

    if flags.edge.is_none() {
        let hint = if topology == Topology::CdnEdge {
            "cloudflare"
        } else {
            "none"
        };
        write!(
            stdout,
            "edge (none/cloudflare/fastly/akamai/caddy/nginx) [{hint}]: "
        )
        .map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.edge = Some(line);
        }
    }

    if flags.trusted_proxies.is_none() {
        let hint = if topology == Topology::CdnEdge {
            "auto"
        } else {
            "none"
        };
        write!(stdout, "trusted-proxies (auto/none/CIDR,CIDR) [{hint}]: ").map_err(io_err)?;
        stdout.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        if !line.is_empty() {
            flags.trusted_proxies = Some(line);
        }
    }

    finish_plan(flags, topology, origin)
}

fn finish_plan(flags: Flags, topology: Topology, origin: String) -> Result<Plan, String> {
    let public_host = match flags.public_host {
        Some(host) => {
            validate_public_host(&host)?;
            Some(host)
        }
        None => None,
    };
    let edge = match flags.edge.as_deref() {
        None if topology == Topology::CdnEdge => Edge::Cloudflare,
        None => Edge::None,
        Some(value) => Edge::parse(value)?,
    };
    let listen = match flags.listen_mode.as_deref() {
        None | Some("") => ListenMode::Proxied,
        Some(value) => ListenMode::parse(value)?,
    };
    let trusted_spec = match flags.trusted_proxies.as_deref() {
        None if topology == Topology::CdnEdge => TrustedSpec::Auto,
        None | Some("") | Some("none") => TrustedSpec::None,
        Some("auto") => TrustedSpec::Auto,
        Some(list) => TrustedSpec::List(list.to_string()),
    };
    let static_placement = match flags.static_placement.as_deref() {
        None | Some("") => StaticPlacement::FerroadaFront,
        Some(value) => StaticPlacement::parse(value)?,
    };
    let supabase_host = match flags.supabase_host {
        Some(host) => {
            validate_public_host(&host)?;
            Some(host)
        }
        None => None,
    };
    let token = match flags.dashboard_token.as_deref() {
        None | Some("") | Some("auto") => random_token()?,
        Some(value) => value.to_string(),
    };
    let trusted_csv = build_trusted_csv(listen, edge, &trusted_spec)?;
    let out = PathBuf::from(flags.out.as_deref().unwrap_or(DEFAULT_OUT));
    Ok(Plan {
        topology,
        out,
        public_host,
        origin,
        listen,
        trusted_csv,
        dashboard_token: token,
        static_placement,
        supabase_host,
    })
}

fn build_trusted_csv(listen: ListenMode, edge: Edge, spec: &TrustedSpec) -> Result<String, String> {
    let mut parts: Vec<String> = Vec::new();
    if listen == ListenMode::Proxied {
        parts.push(CADDY_DOCKER_PEER.to_string());
    }
    match spec {
        TrustedSpec::None => {}
        TrustedSpec::Auto => {
            let name = match edge {
                Edge::Cloudflare => "cloudflare",
                Edge::Fastly => "fastly",
                Edge::Akamai => "akamai",
                Edge::None | Edge::Caddy | Edge::Nginx => {
                    return Err(
                        "--trusted-proxies auto precisa de --edge cloudflare, fastly ou akamai"
                            .into(),
                    );
                }
            };
            let snapshot = templates::cidr_snapshot(name)
                .ok_or_else(|| format!("snapshot de CIDR em falta para {name}"))?;
            parts.extend(templates::cidrs_from_snapshot(snapshot));
        }
        TrustedSpec::List(raw) => {
            TrustedProxies::parse(raw)?;
            for item in raw.split(',') {
                let trimmed = item.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
            }
        }
    }
    Ok(dedupe_keep_order(parts).join(","))
}

fn emit(plan: &Plan) -> Result<(), String> {
    prepare_out(&plan.out)?;
    let files = templates::init_topology(plan.topology.as_str())
        .ok_or_else(|| format!("topologia desconhecida: {}", plan.topology.as_str()))?;

    let mut wrote_env_example = false;
    for (name, content) in files {
        let Some(mapped) = map_output_name(name, plan.listen) else {
            continue;
        };
        let mut body = if mapped == "CHECKLIST.md" {
            interpolate(&adapt_checklist(content, plan), plan)
        } else if mapped == "README.md" {
            interpolate(&adapt_readme(content, plan), plan)
        } else {
            interpolate(content, plan)
        };
        if mapped == "ferroada.toml" {
            body = replace_first_backend(&body, &plan.origin);
            if plan.topology == Topology::VpsSupabaseCloud && plan.supabase_host.is_some() {
                let Some((_, bff)) = files
                    .iter()
                    .find(|(file_name, _)| *file_name == "ferroada.toml.bff.example")
                else {
                    return Err("template BFF em falta no embed".into());
                };
                let bff_body = interpolate(bff, plan);
                if !body.ends_with('\n') {
                    body.push('\n');
                }
                body.push('\n');
                body.push_str(&bff_body);
                if !bff_body.ends_with('\n') {
                    body.push('\n');
                }
            }
        }
        if mapped == "ferroada.service" && plan.listen == ListenMode::Proxied {
            body = interpolate(templates::PROXIED_UNIT, plan);
        }
        if mapped.ends_with("compose.yml") {
            body = rewrite_compose_for_standalone(&body, plan.listen);
        }
        if mapped != "ferroada.toml.bff.example"
            && (body.contains("{{PUBLIC_HOST}}") || body.contains("{{ORIGIN}}"))
        {
            return Err(format!(
                "{mapped} ainda tem placeholder; passe --public-host e --origin"
            ));
        }
        if mapped == ".env.example" {
            body = overlay_env(&body, plan, None);
            let live = overlay_env(&body, plan, Some(&plan.dashboard_token));
            write_file(&plan.out.join(".env"), &live)?;
            wrote_env_example = true;
        }
        if mapped == "VISIBILIDADE.md" && plan.topology == Topology::HostingerOrigin {
            body = prepend_placement_note(&body, plan.static_placement);
        }
        write_file(&plan.out.join(mapped), &ensure_trailing_newline(&body))?;
    }
    if !wrote_env_example {
        return Err("pack sem .env.example".into());
    }
    write_file(&plan.out.join(".gitignore"), ".env\n.env.caddy\ncerts/\n")?;
    let listen = match plan.listen {
        ListenMode::Privileged => "privileged (:80 + CAP_NET_BIND_SERVICE)",
        ListenMode::Proxied => "proxied (127.0.0.1:3000 + Caddy)",
    };
    println!(
        "Pack escrito em {}\n  topologia: {}\n  listen-mode: {}\n  O .env já tem o token do dashboard — não commite este ficheiro.\n  Próximo passo: leia CHECKLIST.md neste diretório.",
        plan.out.display(),
        plan.topology.as_str(),
        listen
    );
    Ok(())
}

fn map_output_name(name: &str, listen: ListenMode) -> Option<&str> {
    match (name, listen) {
        ("ferroada.privileged.service", ListenMode::Privileged) => Some("ferroada.service"),
        ("ferroada.privileged.service", ListenMode::Proxied) => None,
        ("ferroada.service", ListenMode::Privileged) => None,
        ("ferroada.service", ListenMode::Proxied) => Some("ferroada.service"),
        ("ferroada.proxied.service", _) => None,
        ("docker-compose.caddy.yml", ListenMode::Privileged) => None,
        ("docker-compose.yml", ListenMode::Proxied) => None,
        ("docker-compose.caddy.yml", ListenMode::Proxied) => Some("docker-compose.yml"),
        ("docker-compose.yml", ListenMode::Privileged) => Some("docker-compose.yml"),
        (".env.caddy.example", ListenMode::Privileged) => None,
        (".env.example", ListenMode::Proxied) => None,
        (".env.caddy.example", ListenMode::Proxied) => Some(".env.example"),
        (".env.example", ListenMode::Privileged) => Some(".env.example"),
        ("Caddyfile", ListenMode::Privileged) => None,
        ("nginx.conf.snippet", ListenMode::Privileged) => None,
        ("Caddyfile", ListenMode::Proxied) => Some("Caddyfile"),
        ("nginx.conf.snippet", ListenMode::Proxied) => Some("nginx.conf.snippet"),
        (other, _) => Some(other),
    }
}

fn interpolate(text: &str, plan: &Plan) -> String {
    let mut out = text.replace("{{ORIGIN}}", &plan.origin);
    if let Some(host) = &plan.public_host {
        out = out.replace("{{PUBLIC_HOST}}", host);
    }
    if let Some(host) = &plan.supabase_host {
        out = out.replace("{{SUPABASE_HOST}}", host);
    }
    out
}

fn overlay_env(content: &str, plan: &Plan, token: Option<&str>) -> String {
    let mut out = set_env_line(content, "ORIGIN", &plan.origin);
    if let Some(host) = &plan.public_host {
        out = set_env_line(&out, "PUBLIC_HOST", host);
    }
    out = set_env_line(&out, "TRUSTED_PROXIES", &plan.trusted_csv);
    if let Some(token) = token {
        out = set_env_line(&out, "DASHBOARD_TOKEN", token);
    }
    out
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
    join_lines(&lines, content.ends_with('\n'))
}

fn replace_first_backend(toml: &str, origin: &str) -> String {
    let escaped = origin.replace('\\', "\\\\").replace('"', "\\\"");
    let mut done = false;
    let lines: Vec<String> = toml
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if !done && trimmed.starts_with("backend = ") && !trimmed.starts_with('#') {
                done = true;
                let indent_len = line.len() - trimmed.len();
                format!("{}backend = \"{escaped}\"", &line[..indent_len])
            } else {
                line.to_string()
            }
        })
        .collect();
    join_lines(&lines, toml.ends_with('\n'))
}

fn rewrite_compose_for_standalone(content: &str, listen: ListenMode) -> String {
    let mut body = content.replace(
        "    build:\n      context: ../../..\n      dockerfile: Dockerfile\n",
        "",
    );
    if listen == ListenMode::Proxied {
        body = body.replace(".env.caddy", ".env");
        body = body.replace("docker-compose.caddy.yml", "docker-compose.yml");
    } else {
        body = body.replace(
            "Se não há fullchain, use docker-compose.caddy.yml — nunca os dois.\n",
            "",
        );
    }
    body
}

const TLS_CHOICE: &str = "4. Escolha **um** caminho de TLS — nunca os dois na :443:\n   - Há `fullchain.pem` e chave: copie `.env.example` → `.env`, descomente `TLS_CERT_PATH` / `TLS_KEY_PATH`, use `docker-compose.yml`.\n   - Não há: copie `.env.caddy.example` → `.env.caddy` e use `docker-compose.caddy.yml` (Caddy publica 80 e 443; Ferroada só na overlay).";

const SYSTEMD_GIT: &str = "O unit desta pasta (`ferroada.service`) escuta 0.0.0.0:3000/3443 via `PROXY_LISTEN`/`TLS_LISTEN`, sem cap. Não promete :80.\n`ferroada.privileged.service` publica :80/:443 **e** traz `AmbientCapabilities` + `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` — o binário não é setuid; knob sem cap falha o bind. Copie **um** dos dois para `/etc/systemd/system/ferroada.service`, nunca os dois.\n`ferroada init --listen-mode privileged` emite o unit :80+cap; `--listen-mode proxied` emite 127.0.0.1:3000 sem cap e o Caddy na frente.\nColoque o binário em `/usr/local/bin/ferroada` antes. Se o Caddy corre no host, `reverse_proxy 127.0.0.1:3000` e `TRUSTED_PROXIES=127.0.0.1/32,::1/128` (mais o snapshot CDN, se houver).";

fn pack_banner(plan: &Plan) -> String {
    match plan.listen {
        ListenMode::Privileged => format!(
            "Gerado por `ferroada init --topology {} --listen-mode privileged`.\nO `.env` já tem token e origin. Unit: :80/:443 + CAP_NET_BIND_SERVICE.\nCompose: `docker compose --env-file .env up -d` neste diretório. Não há Caddy neste pack.\n\n",
            plan.topology.as_str()
        ),
        ListenMode::Proxied => format!(
            "Gerado por `ferroada init --topology {} --listen-mode proxied`.\nO `.env` já tem token e origin. Unit: 127.0.0.1:3000, Caddy na frente.\nCompose: `docker compose --env-file .env up -d` neste diretório.\n\n",
            plan.topology.as_str()
        ),
    }
}

fn adapt_checklist(body: &str, plan: &Plan) -> String {
    let mut body = body.replacen(
        "Copie `.env.example` para `.env`.",
        "O `.env` já foi gerado com origin, host e token. Não o substitua pelo `.env.example`.",
        1,
    );
    body = body.replace(
        "   ```bash\n   openssl rand -hex 32\n   ```\n   Cole o resultado em `DASHBOARD_TOKEN`. Não deixe o placeholder.\n",
        "O token já está no `.env`. Não gere outro com openssl a menos que o queira rodar.\n",
    );
    let step3 = match plan.listen {
        ListenMode::Privileged => {
            "3. `ferroada.toml` já usa o host público. O `backend` no toml é o `--origin` (http:// ou https://; o processo resolve DNS no arranque). Não há Caddyfile neste diretório."
        }
        ListenMode::Proxied => {
            "3. `ferroada.toml` e o `Caddyfile` já usam o host público. O `backend` no toml é o `--origin` (http:// ou https://; o processo resolve DNS no arranque)."
        }
    };
    body = body.replace(
        "3. Substitua `{{PUBLIC_HOST}}` em `ferroada.toml` e no `Caddyfile`. O `backend` no toml já é um URL `http://`/`https://` (o processo resolve DNS no arranque — se for a sua app, mude esse URL **antes** de subir).",
        step3,
    );
    body = body.replace(
        "## TLS\n\n- Com certificado em `./certs/fullchain.pem` e `privkey.pem`: descomente `TLS_CERT_PATH` / `TLS_KEY_PATH` no `.env` e use `docker-compose.yml`.\n- Sem certificado: use `docker-compose.caddy.yml` e `.env.caddy`. O Caddy pede o certificado.\n- **Nunca** os dois a publicar 443. O unit systemd também fica em 3000/3443; firewall 80/443 só com Caddy à frente ou com o mapa Docker.",
        match plan.listen {
            ListenMode::Privileged => {
                "## TLS\n\nEste pack é privileged: o Ferroada termina TLS se `TLS_CERT_PATH`/`TLS_KEY_PATH` estiverem no `.env`. Não há Caddy neste diretório."
            }
            ListenMode::Proxied => {
                "## TLS\n\nEste pack é proxied: o Caddy termina TLS na frente. Não publique :443 no Ferroada."
            }
        },
    );
    const STEP7: &str = "7. Sem edge na frente, deixe `TRUSTED_PROXIES` vazio: o processo ignora `X-Forwarded-For` e já o diz no log. Isso é o esperado, não um furo silencioso.";
    let step7 = if plan.listen == ListenMode::Proxied || !plan.trusted_csv.is_empty() {
        "7. Não esvazie `TRUSTED_PROXIES`. Com Caddy na frente precisa do peer (`172.28.0.2/32` no Docker, `127.0.0.1/32,::1/128` no host). Com CDN, o snapshot já está nesta lista."
    } else {
        "7. Sem edge na frente, `TRUSTED_PROXIES` pode ficar vazio: o processo ignora `X-Forwarded-For` e já o diz no log. Isso é o esperado, não um furo silencioso."
    };
    body = body.replace(STEP7, step7);
    let tls = match plan.listen {
        ListenMode::Privileged => {
            "4. Este pack é `--listen-mode privileged`: o unit escuta :80/:443 com `CAP_NET_BIND_SERVICE`. Docker: `docker compose --env-file .env up -d` neste diretório (mapa 80:3000). Descomente `TLS_CERT_PATH`/`TLS_KEY_PATH` no `.env` se o Ferroada termina TLS. Não há Caddy neste diretório."
        }
        ListenMode::Proxied => {
            "4. Este pack é `--listen-mode proxied`: Caddy publica 80/443; o Ferroada escuta 127.0.0.1:3000 (systemd) ou a overlay (Docker). Suba com `docker compose --env-file .env up -d` neste diretório. Não há compose do Ferroada a publicar 443."
        }
    };
    body = body.replace(TLS_CHOICE, tls);
    let systemd = match plan.listen {
        ListenMode::Privileged => {
            "O `ferroada.service` deste pack já é o caminho privileged: `PROXY_LISTEN=0.0.0.0:80`, `TLS_LISTEN=0.0.0.0:443`, `AmbientCapabilities` e `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. Copie-o para `/etc/systemd/system/ferroada.service`. Não use Caddy a publicar 80/443 no mesmo host.\nColoque o binário em `/usr/local/bin/ferroada` antes."
        }
        ListenMode::Proxied => {
            "O `ferroada.service` deste pack já é o caminho proxied: `PROXY_LISTEN=127.0.0.1:3000` sem cap. Caddy na frente em :80/:443. Se o Caddy corre no host, `reverse_proxy 127.0.0.1:3000` e `TRUSTED_PROXIES=127.0.0.1/32,::1/128` (mais o snapshot CDN, se houver).\nColoque o binário em `/usr/local/bin/ferroada` antes."
        }
    };
    body = body.replace(SYSTEMD_GIT, systemd);
    format!("{}{body}", pack_banner(plan))
}

fn adapt_readme(body: &str, plan: &Plan) -> String {
    let mut body = body.to_string();
    match plan.listen {
        ListenMode::Privileged => {
            body = body.replace(
                "| `.env.caddy.example` | mesmo, com Caddy na frente |\n",
                "",
            );
            body = body.replace(
                "| `docker-compose.caddy.yml` | Caddy publica 80/443 |\n",
                "",
            );
            body = body.replace(
                "| `ferroada.service` | systemd em 3000/3443; `ferroada.privileged.service` é :80+:443+cap |",
                "| `ferroada.service` | systemd :80/:443 + CAP_NET_BIND_SERVICE |",
            );
            body = body.replace(
                "| `Caddyfile` / `nginx.conf.snippet` | TLS local na frente |\n",
                "",
            );
        }
        ListenMode::Proxied => {
            body = body.replace(
                "| `.env.caddy.example` | mesmo, com Caddy na frente |\n",
                "",
            );
            body = body.replace("| `docker-compose.yml` | Ferroada publica 80/443 |\n", "");
            body = body.replace(
                "| `docker-compose.caddy.yml` | Caddy publica 80/443 |",
                "| `docker-compose.yml` | Caddy publica 80/443 |",
            );
            body = body.replace(
                "| `ferroada.service` | systemd em 3000/3443; `ferroada.privileged.service` é :80+:443+cap |",
                "| `ferroada.service` | systemd 127.0.0.1:3000, sem cap |",
            );
        }
    }
    format!("{}{body}", pack_banner(plan))
}

fn prepend_placement_note(body: &str, placement: StaticPlacement) -> String {
    let note = match placement {
        StaticPlacement::FerroadaFront => {
            "Receita escolhida: ferroada-front — a VPS é o origin público; a Hostinger só aceita o IP desta VPS.\n\n"
        }
        StaticPlacement::Public => {
            "Receita escolhida: public — o estático na Hostinger NÃO passa pelo Ferroada.\n\n"
        }
        StaticPlacement::Cdn => {
            "Receita escolhida: cdn — Cloudflare na frente do Ferroada; Hostinger como origin do cache de estático. Junte o pack cdn-edge.\n\n"
        }
    };
    format!("{note}{body}")
}

fn prepare_out(out: &Path) -> Result<(), String> {
    if out.exists() {
        let empty = fs::read_dir(out)
            .map_err(|error| format!("não leu {}: {error}", out.display()))?
            .next()
            .is_none();
        if !empty {
            return Err(format!(
                "diretório de saída não está vazio: {}",
                out.display()
            ));
        }
    } else {
        fs::create_dir_all(out).map_err(|error| format!("não criou {}: {error}", out.display()))?;
    }
    Ok(())
}

fn write_file(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|error| format!("não escreveu {}: {error}", path.display()))
}

fn ensure_trailing_newline(body: &str) -> String {
    if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    }
}

fn join_lines(lines: &[String], trailing_newline: bool) -> String {
    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    out
}

fn dedupe_keep_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn validate_origin(origin: &str) -> Result<(), String> {
    if origin.starts_with("http://") || origin.starts_with("https://") {
        Ok(())
    } else {
        Err("--origin tem de começar por http:// ou https://".into())
    }
}

fn validate_public_host(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() || host.contains("://") || host.contains('/') || host.contains(' ') {
        Err("--public-host deve ser um nome de host, sem esquema".into())
    } else {
        Ok(())
    }
}

fn read_line(stdin: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .map_err(|error| format!("leitura do terminal: {error}"))?;
    Ok(line.trim().to_string())
}

fn io_err(error: io::Error) -> String {
    format!("escrita no terminal: {error}")
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    Ok(hex_lower(&bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(unix)]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buf))
        .map_err(|error| format!("falha a gerar DASHBOARD_TOKEN: {error}"))
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    let len = u32::try_from(buf.len()).map_err(|_| "token demasiado grande".to_string())?;
    // SAFETY: null algorithm + BCRYPT_USE_SYSTEM_PREFERRED_RNG is the
    // documented "system RNG" call; `buf` is a valid writable slice.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err("falha a gerar DASHBOARD_TOKEN".into())
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_random(_buf: &mut [u8]) -> Result<(), String> {
    Err("gerar DASHBOARD_TOKEN não é suportado nesta plataforma".into())
}

impl Topology {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "vps-site" => Ok(Self::VpsSite),
            "vps-api" => Ok(Self::VpsApi),
            "vps-supabase-selfhost" => Ok(Self::VpsSupabaseSelfhost),
            "vps-supabase-cloud" => Ok(Self::VpsSupabaseCloud),
            "vps-full" => Ok(Self::VpsFull),
            "hostinger-origin" => Ok(Self::HostingerOrigin),
            "vercel-origin" => Ok(Self::VercelOrigin),
            "cdn-edge" => Ok(Self::CdnEdge),
            other => Err(format!("topologia desconhecida: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::VpsSite => "vps-site",
            Self::VpsApi => "vps-api",
            Self::VpsSupabaseSelfhost => "vps-supabase-selfhost",
            Self::VpsSupabaseCloud => "vps-supabase-cloud",
            Self::VpsFull => "vps-full",
            Self::HostingerOrigin => "hostinger-origin",
            Self::VercelOrigin => "vercel-origin",
            Self::CdnEdge => "cdn-edge",
        }
    }

    fn requires_public_host(self) -> bool {
        matches!(self, Self::HostingerOrigin | Self::VercelOrigin)
    }
}

impl Edge {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "cloudflare" => Ok(Self::Cloudflare),
            "fastly" => Ok(Self::Fastly),
            "akamai" => Ok(Self::Akamai),
            "caddy" => Ok(Self::Caddy),
            "nginx" => Ok(Self::Nginx),
            other => Err(format!("--edge desconhecido: {other}")),
        }
    }
}

impl ListenMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "privileged" => Ok(Self::Privileged),
            "proxied" => Ok(Self::Proxied),
            other => Err(format!(
                "--listen-mode desconhecido: {other} (privileged|proxied)"
            )),
        }
    }
}

impl StaticPlacement {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ferroada-front" => Ok(Self::FerroadaFront),
            "public" => Ok(Self::Public),
            "cdn" => Ok(Self::Cdn),
            other => Err(format!(
                "--static-placement desconhecido: {other} (ferroada-front|public|cdn)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_out(label: &str) -> PathBuf {
        let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "ferroada-init-{}-{}-{}-{label}",
            std::process::id(),
            nanos,
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn env_line(dir: &Path, key: &str) -> String {
        let text = fs::read_to_string(dir.join(".env")).unwrap();
        text.lines()
            .find(|line| line.starts_with(&format!("{key}=")))
            .unwrap()
            .to_string()
    }

    fn run_init(args: &[&str]) -> Result<PathBuf, String> {
        let out = temp_out("case");
        let mut owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        owned.push("--out".into());
        owned.push(out.to_string_lossy().into_owned());
        owned.push("--non-interactive".into());
        run(&owned)?;
        Ok(out)
    }

    #[test]
    fn embedded_templates_match_deploy_tree() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy");
        let mut disk: Vec<(String, String)> = Vec::new();
        collect_files(&root.join("topologies"), "topologies", &mut disk);
        collect_files(&root.join("cidrs"), "cidrs", &mut disk);
        disk.sort_by(|a, b| a.0.cmp(&b.0));

        let mut embedded: Vec<(String, String)> = Vec::new();
        for (topo, files) in templates::all_topologies() {
            for (name, content) in *files {
                embedded.push((format!("topologies/{topo}/{name}"), (*content).to_string()));
            }
        }
        for (rel, content) in templates::extra_embedded() {
            embedded.push(((*rel).to_string(), (*content).to_string()));
        }
        embedded.sort_by(|a, b| a.0.cmp(&b.0));
        embedded.dedup_by(|a, b| a.0 == b.0);

        let disk_names: Vec<&str> = disk.iter().map(|(n, _)| n.as_str()).collect();
        let embedded_names: Vec<&str> = embedded.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            disk_names, embedded_names,
            "ficheiros em deploy/ ≠ include_str!"
        );
        for ((disk_name, disk_body), (emb_name, emb_body)) in disk.iter().zip(embedded.iter()) {
            assert_eq!(disk_name, emb_name);
            assert_eq!(disk_body, emb_body, "{disk_name} diverge do embed");
        }
    }

    fn collect_files(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                collect_files(&path, &format!("{prefix}/{name}"), out);
            } else {
                let body = fs::read_to_string(&path).unwrap();
                out.push((format!("{prefix}/{name}"), body));
            }
        }
    }

    #[test]
    fn auto_trusted_proxies_is_the_embedded_snapshot_twice() {
        let args = [
            "--topology",
            "cdn-edge",
            "--origin",
            "http://127.0.0.1:8080",
            "--public-host",
            "api.exemplo.com",
            "--listen-mode",
            "privileged",
            "--trusted-proxies",
            "auto",
            "--edge",
            "cloudflare",
            "--dashboard-token",
            "tok",
        ];
        let a = run_init(&args).unwrap();
        let b = run_init(&args).unwrap();
        let line_a = env_line(&a, "TRUSTED_PROXIES");
        let line_b = env_line(&b, "TRUSTED_PROXIES");
        assert_eq!(line_a, line_b);
        let expected = templates::cidrs_from_snapshot(templates::CLOUDFLARE_CIDRS).join(",");
        assert_eq!(line_a, format!("TRUSTED_PROXIES={expected}"));
        assert!(line_a.contains("173.245.48.0/20"));
        let _ = fs::remove_dir_all(a);
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn auto_without_cdn_edge_fails() {
        let err = run_init(&[
            "--topology",
            "vps-site",
            "--origin",
            "http://127.0.0.1:8080",
            "--public-host",
            "site.exemplo.com",
            "--trusted-proxies",
            "auto",
            "--dashboard-token",
            "tok",
        ])
        .unwrap_err();
        assert!(err.contains("auto precisa de --edge"), "{err}");
    }

    #[test]
    fn privileged_unit_has_listen_knob_and_cap() {
        let dir = run_init(&[
            "--topology",
            "vps-api",
            "--origin",
            "http://127.0.0.1:8080",
            "--public-host",
            "api.exemplo.com",
            "--listen-mode",
            "privileged",
            "--dashboard-token",
            "tok",
        ])
        .unwrap();
        let unit = fs::read_to_string(dir.join("ferroada.service")).unwrap();
        assert!(unit.contains("Environment=PROXY_LISTEN=0.0.0.0:80"));
        assert!(unit.contains("Environment=TLS_LISTEN=0.0.0.0:443"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(!dir.join("Caddyfile").exists());
        assert!(!dir.join("docker-compose.caddy.yml").exists());
        let compose = fs::read_to_string(dir.join("docker-compose.yml")).unwrap();
        assert!(!compose.contains("caddy:"));
        let checklist = fs::read_to_string(dir.join("CHECKLIST.md")).unwrap();
        assert!(checklist.contains("--listen-mode privileged"));
        assert!(checklist.contains("CAP_NET_BIND_SERVICE"));
        assert!(!checklist.contains("docker-compose.caddy.yml"));
        assert!(checklist.contains("já foi gerado"));
        assert!(!checklist.contains("openssl rand"));
        assert!(!checklist.contains("e no `Caddyfile`"));
        let readme = fs::read_to_string(dir.join("README.md")).unwrap();
        assert!(!readme.contains("docker-compose.caddy.yml"));
        assert!(!readme.contains(".env.caddy.example"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn proxied_unit_binds_loopback_without_cap() {
        let dir = run_init(&[
            "--topology",
            "vps-site",
            "--origin",
            "http://127.0.0.1:8080",
            "--public-host",
            "site.exemplo.com",
            "--listen-mode",
            "proxied",
            "--dashboard-token",
            "tok",
        ])
        .unwrap();
        let unit = fs::read_to_string(dir.join("ferroada.service")).unwrap();
        assert!(unit.contains("Environment=PROXY_LISTEN=127.0.0.1:3000"));
        assert!(unit.contains("Environment=TLS_LISTEN=127.0.0.1:3443"));
        assert!(!unit.contains("AmbientCapabilities"));
        assert!(dir.join("Caddyfile").exists());
        let compose = fs::read_to_string(dir.join("docker-compose.yml")).unwrap();
        assert!(compose.contains("caddy:"));
        assert!(!compose.contains("\"443:3443\""));
        assert!(
            !compose.contains(".env.caddy"),
            "compose proxied ainda aponta para .env.caddy"
        );
        assert!(compose.contains("- .env"));
        let checklist = fs::read_to_string(dir.join("CHECKLIST.md")).unwrap();
        assert!(checklist.contains("--listen-mode proxied"));
        assert!(!checklist.contains("ferroada.privileged.service"));
        assert!(checklist.contains("já foi gerado"));
        assert!(
            checklist.contains("Não esvazie `TRUSTED_PROXIES`"),
            "{checklist}"
        );
        assert!(!checklist.contains("openssl rand"));
        let trusted = env_line(&dir, "TRUSTED_PROXIES");
        assert_eq!(trusted, format!("TRUSTED_PROXIES={CADDY_DOCKER_PEER}"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_origin_is_refused() {
        let err = run(&[
            "--topology".into(),
            "vps-site".into(),
            "--non-interactive".into(),
        ])
        .unwrap_err();
        assert!(err.contains("origin"), "{err}");
    }

    #[test]
    fn vps_api_without_public_host_is_refused() {
        let err = run_init(&[
            "--topology",
            "vps-api",
            "--origin",
            "http://127.0.0.1:8080",
            "--dashboard-token",
            "tok",
        ])
        .unwrap_err();
        assert!(err.contains("public-host"), "{err}");
    }

    #[test]
    fn hostinger_and_vercel_require_public_host() {
        for topo in ["hostinger-origin", "vercel-origin"] {
            let err = run_init(&[
                "--topology",
                topo,
                "--origin",
                "https://app.exemplo.com",
                "--dashboard-token",
                "tok",
            ])
            .unwrap_err();
            assert!(err.contains("public-host"), "{topo}: {err}");
        }
    }

    #[test]
    fn supabase_cloud_option_two_appends_dedicated_host() {
        let dir = run_init(&[
            "--topology",
            "vps-supabase-cloud",
            "--origin",
            "http://app:8080",
            "--public-host",
            "api.exemplo.com",
            "--supabase-host",
            "supabase.exemplo.com",
            "--listen-mode",
            "privileged",
            "--dashboard-token",
            "tok",
        ])
        .unwrap();
        let toml = fs::read_to_string(dir.join("ferroada.toml")).unwrap();
        assert!(toml.contains("hosts = [\"supabase.exemplo.com\"]"));
        assert!(toml.contains("https://PROJECT_REF.supabase.co"));
        assert!(!toml.contains("location /supabase"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn supabase_cloud_option_one_skips_bff_block() {
        let dir = run_init(&[
            "--topology",
            "vps-supabase-cloud",
            "--origin",
            "http://app:8080",
            "--public-host",
            "api.exemplo.com",
            "--listen-mode",
            "privileged",
            "--dashboard-token",
            "tok",
        ])
        .unwrap();
        let toml = fs::read_to_string(dir.join("ferroada.toml")).unwrap();
        assert!(!toml.contains("PROJECT_REF.supabase.co"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dashboard_token_auto_is_64_hex() {
        let dir = run_init(&[
            "--topology",
            "vps-api",
            "--origin",
            "http://127.0.0.1:8080",
            "--public-host",
            "api.exemplo.com",
            "--listen-mode",
            "privileged",
        ])
        .unwrap();
        let value = env_line(&dir, "DASHBOARD_TOKEN")
            .strip_prefix("DASHBOARD_TOKEN=")
            .unwrap()
            .to_string();
        assert_eq!(value.len(), 64, "{value}");
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()), "{value}");
        let example = fs::read_to_string(dir.join(".env.example")).unwrap();
        assert!(example.contains("DASHBOARD_TOKEN=substitua-por-32-bytes-hex"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_non_empty_out() {
        let dir = temp_out("occupied");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stale.txt"), "nope").unwrap();
        let err = run(&[
            "--topology".into(),
            "vps-api".into(),
            "--origin".into(),
            "http://127.0.0.1:8080".into(),
            "--public-host".into(),
            "api.exemplo.com".into(),
            "--out".into(),
            dir.to_string_lossy().into_owned(),
            "--non-interactive".into(),
            "--dashboard-token".into(),
            "tok".into(),
        ])
        .unwrap_err();
        assert!(err.contains("não está vazio"), "{err}");
        assert!(err.contains("diretório"), "{err}");
        assert_eq!(fs::read_to_string(dir.join("stale.txt")).unwrap(), "nope");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshot_csv_skips_comments_and_does_not_fetch() {
        let csv = templates::cidrs_from_snapshot(templates::CLOUDFLARE_CIDRS);
        assert!(csv.iter().all(|cidr| !cidr.starts_with('#')));
        assert!(csv.iter().all(|cidr| !cidr.contains("https://")));
        assert_eq!(
            csv,
            templates::cidrs_from_snapshot(templates::CLOUDFLARE_CIDRS)
        );
    }
}
