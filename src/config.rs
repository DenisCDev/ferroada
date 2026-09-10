use serde::Deserialize;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use tracing::info;

use crate::jwt::{JwtPolicy, JwtSpec};
use crate::openapi::{OpenApiPolicy, UnknownEndpoint};
use crate::protocol::{ProtocolMatrix, ProtocolsSection};
use crate::waf::{self, InspectionOutcome, WafProfile};
use crate::waf_l1::{self, L1Exclusion, L1ExclusionFile, L1File, L1RequestPolicy, L1Settings};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    default_backend: Option<String>,
    #[serde(default)]
    sites: Vec<SiteEntry>,
    #[serde(default)]
    default_require_complete_waf_inspection: Vec<String>,
    #[serde(default)]
    default_waf_profile: Option<String>,
    #[serde(default)]
    protocols: ProtocolsSection,
    #[serde(default)]
    waf: WafSection,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WafSection {
    #[serde(default)]
    l1: L1File,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteEntry {
    hosts: Vec<String>,
    backend: String,
    #[serde(default)]
    require_complete_waf_inspection: Vec<String>,
    #[serde(default)]
    waf_profile: Option<String>,
    #[serde(default)]
    routes: Vec<SiteRouteEntry>,
    #[serde(default)]
    l1: L1File,
    #[serde(default)]
    openapi: Option<OpenApiFile>,
    #[serde(default)]
    jwt: Option<JwtFile>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OpenApiFile {
    Path(String),
    Table(OpenApiTable),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenApiTable {
    spec: String,
    #[serde(default)]
    unknown_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtFile {
    jwks: String,
    #[serde(alias = "iss")]
    issuer: String,
    #[serde(alias = "aud")]
    audience: String,
    #[serde(default)]
    algorithms: Vec<String>,
    #[serde(default)]
    bindings: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    hmac_secret_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteRouteEntry {
    prefix: String,
    #[serde(default)]
    inspection: InspectionPolicyFile,
    #[serde(default)]
    l1: L1File,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct InspectionPolicyFile {
    #[serde(default)]
    require_complete: Option<bool>,
    #[serde(default)]
    on_truncated: Option<String>,
    #[serde(default)]
    on_parse_error: Option<String>,
    #[serde(default)]
    max_decoded_body: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionAction {
    Deny,
    Monitor,
}

impl InspectionAction {
    fn parse(key: &str, raw: &str) -> Self {
        match raw.trim() {
            "deny" => Self::Deny,
            "monitor" => Self::Monitor,
            other => panic!("ação de inspeção inválida em {key} = {other:?}; use deny ou monitor"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionDisposition {
    Allow,
    Monitor,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionPolicy {
    pub require_complete: bool,
    pub on_truncated: InspectionAction,
    pub on_parse_error: InspectionAction,
    pub max_decoded_body: Option<usize>,
}

impl InspectionPolicy {
    pub fn fail_closed() -> Self {
        Self {
            require_complete: true,
            on_truncated: InspectionAction::Deny,
            on_parse_error: InspectionAction::Deny,
            max_decoded_body: None,
        }
    }

    pub fn open() -> Self {
        Self {
            require_complete: false,
            on_truncated: InspectionAction::Monitor,
            on_parse_error: InspectionAction::Monitor,
            max_decoded_body: None,
        }
    }

    pub fn uses_spool(self) -> bool {
        self.max_decoded_body.is_some()
    }

    pub fn disposition(self, outcome: InspectionOutcome) -> InspectionDisposition {
        match outcome {
            InspectionOutcome::Complete => InspectionDisposition::Allow,
            InspectionOutcome::Truncated { .. } => self.on_truncated.into(),
            InspectionOutcome::ParseError => self.on_parse_error.into(),
            InspectionOutcome::UnsupportedEncoding | InspectionOutcome::UnsupportedContentType => {
                if self.require_complete {
                    InspectionDisposition::Deny
                } else {
                    InspectionDisposition::Monitor
                }
            }
            InspectionOutcome::BudgetExceeded => InspectionDisposition::Deny,
            InspectionOutcome::TimedOut => {
                if self.require_complete {
                    InspectionDisposition::Deny
                } else {
                    InspectionDisposition::Monitor
                }
            }
        }
    }
}

impl From<InspectionAction> for InspectionDisposition {
    fn from(action: InspectionAction) -> Self {
        match action {
            InspectionAction::Deny => Self::Deny,
            InspectionAction::Monitor => Self::Monitor,
        }
    }
}

#[derive(Clone, Debug)]
struct RouteInspection {
    prefix: String,
    patch: InspectionPolicyFile,
    l1: L1File,
}

#[derive(Clone)]
struct SiteL1 {
    settings: L1Settings,
    exclusions: Vec<L1Exclusion>,
}

impl Default for SiteL1 {
    fn default() -> Self {
        Self {
            settings: L1Settings::default_crs(),
            exclusions: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct Backend {
    pub addr: SocketAddr,
    pub host: String,
    pub site_scope: String,
    pub redirect_host: Option<String>,
    pub tls: bool,
    pub waf_profile: WafProfile,
    routes: Vec<RouteInspection>,
    l1: SiteL1,
    pub openapi: Option<OpenApiPolicy>,
    pub jwt: Option<JwtPolicy>,
}

impl Backend {
    pub fn inspection_policy(&self, uri: &str) -> InspectionPolicy {
        let path = uri.split('?').next().unwrap_or(uri);
        let Some(path) = canonical_route_path(path) else {
            return if self
                .routes
                .iter()
                .any(|route| patch_denies_incomplete(&route.patch))
            {
                InspectionPolicy::fail_closed()
            } else {
                InspectionPolicy::open()
            };
        };
        let mut matching: Vec<&RouteInspection> = self
            .routes
            .iter()
            .filter(|route| path_matches_prefix(&path, &route.prefix))
            .collect();
        matching.sort_by_key(|route| route.prefix.len());
        let mut policy = InspectionPolicy::open();
        for route in matching {
            policy = overlay_inspection_policy(policy, &route.patch);
        }
        policy
    }

    pub fn requires_complete_waf_inspection(&self, uri: &str) -> bool {
        self.inspection_policy(uri).require_complete
    }

    pub fn uses_spool(&self) -> bool {
        self.routes.iter().any(|route| {
            self.inspection_policy(&route.prefix)
                .max_decoded_body
                .is_some()
        })
    }

    pub fn l1_for(&self, uri: &str, content_type: Option<&str>) -> L1RequestPolicy {
        let path = uri.split('?').next().unwrap_or(uri);
        let path = canonical_route_path(path);
        let patches: Vec<(String, L1File)> = self
            .routes
            .iter()
            .map(|route| (route.prefix.clone(), route.l1.clone()))
            .collect();
        waf_l1::resolve(
            self.l1.settings,
            &patches,
            &self.l1.exclusions,
            path.as_deref(),
            content_type,
        )
    }
}

pub struct Config {
    /// host (lowercase, no port) → index into backends
    route_table: HashMap<String, usize>,
    backends: Vec<Backend>,
    /// Default backend for requests that don't match any site
    default_idx: Option<usize>,
    pub protocols: ProtocolMatrix,
}

impl Config {
    /// Load from ferroada.toml if it exists, otherwise fall back to TARGET_URL env.
    pub fn load() -> Self {
        // Try config file first
        if let Ok(contents) = std::fs::read_to_string("ferroada.toml") {
            let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            return Self::from_toml_in(&contents, &base);
        }

        // Fallback: single TARGET_URL (backward compatible)
        let target_url = std::env::var("TARGET_URL").expect("TARGET_URL or ferroada.toml required");
        Self::from_target_url(&target_url)
    }

    pub fn from_target_url(target_url: &str) -> Self {
        let complete_waf_paths = std::env::var("WAF_REQUIRE_COMPLETE_PATHS")
            .ok()
            .map(|value| parse_path_prefixes(value.split(',')))
            .unwrap_or_default();
        let backend = resolve_url(
            target_url,
            complete_waf_paths,
            waf::default_profile(),
            SiteL1::default(),
            None,
            None,
        );
        info!(
            backend = %target_url,
            "Single-site mode (TARGET_URL)"
        );
        Config {
            route_table: HashMap::new(),
            backends: vec![backend],
            default_idx: Some(0),
            protocols: ProtocolMatrix::default(),
        }
    }

    pub fn from_toml(contents: &str) -> Self {
        Self::from_toml_in(contents, Path::new("."))
    }

    pub fn from_toml_in(contents: &str, base_dir: &Path) -> Self {
        let file: ConfigFile = toml::from_str(contents)
            .unwrap_or_else(|error| panic!("Invalid ferroada.toml: {error}"));
        let protocols =
            ProtocolMatrix::from_section(file.protocols).unwrap_or_else(|error| panic!("{error}"));
        let l1_defaults = L1Settings::default_crs().overlay(&file.waf.l1).validated();
        let global_exclusions = parse_l1_exclusions(file.waf.l1.exclusions);

        let mut backends = Vec::new();
        let mut route_table = HashMap::new();
        let site_count = file.sites.len();

        for site in file.sites {
            let site_l1 = SiteL1 {
                settings: l1_defaults.overlay(&site.l1).validated(),
                exclusions: merge_l1_exclusions(
                    global_exclusions.clone(),
                    parse_l1_exclusions(site.l1.exclusions),
                ),
            };
            let site_host = site.hosts.first().map(String::as_str);
            let openapi = site
                .openapi
                .as_ref()
                .map(|file| load_openapi(file, base_dir, site_host));
            let jwt = site
                .jwt
                .as_ref()
                .map(|file| load_jwt(file, base_dir, site_host));
            let mut backend = resolve_site(
                &site.backend,
                parse_path_prefixes(site.require_complete_waf_inspection.iter()),
                site.routes,
                site.waf_profile
                    .as_deref()
                    .map(WafProfile::parse)
                    .unwrap_or_else(waf::default_profile),
                site_l1,
                openapi,
                jwt,
            );
            backend.site_scope = site
                .hosts
                .first()
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .unwrap_or_else(|| panic!("Cada site precisa declarar ao menos um host"));
            backend.redirect_host = Some(backend.site_scope.clone());
            let idx = backends.len();
            info!(
                hosts = ?site.hosts,
                backend = %site.backend,
                "Site configured"
            );
            validate_spool_routes(&backend);
            validate_l1_routes(&backend);
            backends.push(backend);

            for host in &site.hosts {
                let key = host.trim().to_lowercase();
                if route_table.insert(key.clone(), idx).is_some() {
                    panic!("Duplicate host in ferroada.toml: {}", key);
                }
            }
        }

        let default_paths =
            parse_path_prefixes(file.default_require_complete_waf_inspection.iter());
        let default_profile = file
            .default_waf_profile
            .as_deref()
            .map(WafProfile::parse)
            .unwrap_or_else(waf::default_profile);
        let default_idx = file.default_backend.map(|url| {
            let mut backend = resolve_site(
                &url,
                default_paths,
                Vec::new(),
                default_profile,
                SiteL1 {
                    settings: l1_defaults,
                    exclusions: global_exclusions,
                },
                None,
                None,
            );
            backend.site_scope = "__default__".to_string();
            let idx = backends.len();
            info!(backend = %url, "Default backend configured");
            validate_spool_routes(&backend);
            validate_l1_routes(&backend);
            backends.push(backend);
            idx
        });

        if backends.is_empty() {
            panic!("ferroada.toml has no sites configured");
        }

        let host_count = route_table.len();
        info!(
            sites = site_count,
            hosts = host_count,
            has_default = default_idx.is_some(),
            "Multi-site mode loaded"
        );

        Config {
            route_table,
            backends,
            default_idx,
            protocols,
        }
    }

    /// Resolve a backend by Host header value. Returns None if no match.
    pub fn resolve(&self, host_header: &str) -> Option<&Backend> {
        // Strip port from Host header (e.g. "example.com:3000" → "example.com")
        let host = host_header
            .split(':')
            .next()
            .unwrap_or(host_header)
            .to_lowercase();

        if let Some(&idx) = self.route_table.get(&host) {
            return Some(&self.backends[idx]);
        }

        // Fall back to default backend (always exists in single-site mode)
        self.default_idx.map(|idx| &self.backends[idx])
    }

    /// Whether we're in multi-site mode (ferroada.toml with explicit hosts).
    pub fn is_multi_site(&self) -> bool {
        !self.route_table.is_empty()
    }

    /// All configured host names (for ALLOWED_HOSTS auto-derivation).
    pub fn all_hosts(&self) -> Vec<String> {
        self.route_table.keys().cloned().collect()
    }

    pub fn backend_addresses(&self) -> Vec<SocketAddr> {
        self.backends.iter().map(|backend| backend.addr).collect()
    }

    pub fn has_spool_routes(&self) -> bool {
        self.backends.iter().any(Backend::uses_spool)
    }
}

fn resolve_url(
    url: &str,
    require_complete_waf_inspection: Vec<String>,
    waf_profile: WafProfile,
    l1: SiteL1,
    openapi: Option<OpenApiPolicy>,
    jwt: Option<JwtPolicy>,
) -> Backend {
    resolve_site(
        url,
        require_complete_waf_inspection,
        Vec::new(),
        waf_profile,
        l1,
        openapi,
        jwt,
    )
}

fn load_openapi(file: &OpenApiFile, base_dir: &Path, site_host: Option<&str>) -> OpenApiPolicy {
    let (spec, unknown) = match file {
        OpenApiFile::Path(path) => (path.as_str(), None),
        OpenApiFile::Table(table) => (
            table.spec.as_str(),
            table
                .unknown_endpoint
                .as_deref()
                .map(|raw| UnknownEndpoint::parse("openapi.unknown_endpoint", raw)),
        ),
    };
    let path = Path::new(spec);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "OpenAPI spec não encontrado para {} ({}): {error}",
            site_host.unwrap_or("site"),
            path.display()
        )
    });
    let policy = OpenApiPolicy::from_bytes(&bytes, &path.display().to_string(), unknown)
        .unwrap_or_else(|error| panic!("{error}"));
    info!(spec = %path.display(), host = site_host.unwrap_or("-"), "OpenAPI compiled");
    policy
}

fn load_jwt(file: &JwtFile, base_dir: &Path, site_host: Option<&str>) -> JwtPolicy {
    JwtPolicy::load(
        JwtSpec {
            jwks: &file.jwks,
            issuer: &file.issuer,
            audience: &file.audience,
            algorithms: &file.algorithms,
            bindings: &file.bindings,
            paths: &file.paths,
            hmac_secret_env: file.hmac_secret_env.as_deref(),
        },
        base_dir,
        site_host,
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

fn resolve_site(
    url: &str,
    require_complete_waf_inspection: Vec<String>,
    route_entries: Vec<SiteRouteEntry>,
    waf_profile: WafProfile,
    l1: SiteL1,
    openapi: Option<OpenApiPolicy>,
    jwt: Option<JwtPolicy>,
) -> Backend {
    let tls = url.starts_with("https://");
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or_else(|| panic!("Backend URL must start with http:// or https://: {}", url));

    let authority = without_scheme.split('/').next().unwrap();
    let default_port: u16 = if tls { 443 } else { 80 };

    let (host, port) = if let Some(idx) = authority.rfind(':') {
        let h = &authority[..idx];
        let p = authority[idx + 1..].parse::<u16>().unwrap_or(default_port);
        (h.to_string(), p)
    } else {
        (authority.to_string(), default_port)
    };

    let addr_str = format!("{host}:{port}");
    let addr = addr_str
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("Cannot resolve {addr_str}: {e}"))
        .next()
        .unwrap_or_else(|| panic!("No addresses for {addr_str}"));

    Backend {
        addr,
        site_scope: host.to_ascii_lowercase(),
        redirect_host: None,
        host,
        tls,
        waf_profile,
        routes: merge_inspection_routes(require_complete_waf_inspection, route_entries),
        l1,
        openapi,
        jwt,
    }
}

fn fail_closed_patch() -> InspectionPolicyFile {
    InspectionPolicyFile {
        require_complete: Some(true),
        on_truncated: Some("deny".into()),
        on_parse_error: Some("deny".into()),
        max_decoded_body: None,
    }
}

fn merge_patches(
    base: InspectionPolicyFile,
    overlay: InspectionPolicyFile,
) -> InspectionPolicyFile {
    InspectionPolicyFile {
        require_complete: overlay.require_complete.or(base.require_complete),
        on_truncated: overlay.on_truncated.or(base.on_truncated),
        on_parse_error: overlay.on_parse_error.or(base.on_parse_error),
        max_decoded_body: overlay.max_decoded_body.or(base.max_decoded_body),
    }
}

fn merge_l1_files(base: L1File, overlay: L1File) -> L1File {
    L1File {
        blocking_paranoia: overlay.blocking_paranoia.or(base.blocking_paranoia),
        executing_paranoia: overlay.executing_paranoia.or(base.executing_paranoia),
        shadow: overlay.shadow.or(base.shadow),
        anomaly_score_threshold: overlay
            .anomaly_score_threshold
            .or(base.anomaly_score_threshold),
        exclude: overlay.exclude.or(base.exclude),
        exclusions: if overlay.exclusions.is_empty() {
            base.exclusions
        } else {
            overlay.exclusions
        },
    }
}

fn parse_l1_exclusions(files: Vec<L1ExclusionFile>) -> Vec<L1Exclusion> {
    files
        .into_iter()
        .map(|file| {
            let prefix = file.prefix.as_ref().map(|raw| {
                parse_path_prefixes(std::iter::once(raw))
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| {
                        panic!("exclusão L1 precisa de um prefixo de path absoluto: {raw}")
                    })
            });
            L1Exclusion::from_file(file, prefix)
        })
        .collect()
}

fn merge_l1_exclusions(mut base: Vec<L1Exclusion>, overlay: Vec<L1Exclusion>) -> Vec<L1Exclusion> {
    base.extend(overlay);
    base
}

fn validate_l1_routes(backend: &Backend) {
    let _ = backend.l1.settings.validated();
    for route in &backend.routes {
        let _ = backend.l1.settings.overlay(&route.l1).validated();
        if !route.l1.exclusions.is_empty() {
            panic!(
                "exclusões L1 na rota {} devem usar [[sites.l1.exclusions]] com prefix",
                route.prefix
            );
        }
    }
}

fn validate_spool_routes(backend: &Backend) {
    for route in &backend.routes {
        let policy = backend.inspection_policy(&route.prefix);
        if policy.max_decoded_body.is_some() && !policy.require_complete {
            panic!(
                "max_decoded_body exige inspection.require_complete na rota {}",
                route.prefix
            );
        }
    }
}

pub fn parse_byte_size(raw: &str) -> Result<usize, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("tamanho vazio".into());
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier) = if let Some(number) = lower.strip_suffix("kib") {
        (number.trim(), 1024usize)
    } else if let Some(number) = lower.strip_suffix("mib") {
        (number.trim(), 1024 * 1024)
    } else if let Some(number) = lower.strip_suffix("gib") {
        (number.trim(), 1024 * 1024 * 1024)
    } else {
        (trimmed, 1usize)
    };
    let value: usize = number
        .parse()
        .map_err(|_| format!("tamanho inválido: {raw}"))?;
    value
        .checked_mul(multiplier)
        .filter(|size| *size > 0)
        .ok_or_else(|| format!("tamanho inválido: {raw}"))
}

fn patch_denies_incomplete(patch: &InspectionPolicyFile) -> bool {
    patch.require_complete == Some(true)
        || patch
            .on_truncated
            .as_deref()
            .is_some_and(|value| value.trim() == "deny")
        || patch
            .on_parse_error
            .as_deref()
            .is_some_and(|value| value.trim() == "deny")
}

fn merge_inspection_routes(
    complete_prefixes: Vec<String>,
    route_entries: Vec<SiteRouteEntry>,
) -> Vec<RouteInspection> {
    let mut routes: Vec<RouteInspection> = complete_prefixes
        .into_iter()
        .map(|prefix| RouteInspection {
            prefix,
            patch: fail_closed_patch(),
            l1: L1File::default(),
        })
        .collect();
    for entry in route_entries {
        let prefix = parse_path_prefixes(std::iter::once(&entry.prefix))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("Rota de inspeção precisa de um prefixo de path"));
        if let Some(existing) = routes.iter_mut().find(|route| route.prefix == prefix) {
            existing.patch = merge_patches(existing.patch.clone(), entry.inspection);
            existing.l1 = merge_l1_files(existing.l1.clone(), entry.l1);
        } else {
            routes.push(RouteInspection {
                prefix,
                patch: entry.inspection,
                l1: entry.l1,
            });
        }
    }
    routes
}

fn overlay_inspection_policy(
    base: InspectionPolicy,
    patch: &InspectionPolicyFile,
) -> InspectionPolicy {
    let require_complete = patch.require_complete.unwrap_or(base.require_complete);
    let derived = if require_complete {
        InspectionAction::Deny
    } else {
        InspectionAction::Monitor
    };
    InspectionPolicy {
        require_complete,
        on_truncated: patch
            .on_truncated
            .as_deref()
            .map(|raw| InspectionAction::parse("on_truncated", raw))
            .unwrap_or(if patch.require_complete.is_some() {
                derived
            } else {
                base.on_truncated
            }),
        on_parse_error: patch
            .on_parse_error
            .as_deref()
            .map(|raw| InspectionAction::parse("on_parse_error", raw))
            .unwrap_or(if patch.require_complete.is_some() {
                derived
            } else {
                base.on_parse_error
            }),
        max_decoded_body: match patch.max_decoded_body.as_deref() {
            Some(raw) => Some(parse_byte_size(raw).unwrap_or_else(|error| panic!("{error}"))),
            None => base.max_decoded_body,
        },
    }
}

pub(crate) fn canonical_route_path(path: &str) -> Option<String> {
    let mut decoded = path.as_bytes().to_vec();
    let mut stable = false;
    for _ in 0..8 {
        let next = percent_decode(&decoded)?;
        if next == decoded {
            stable = true;
            break;
        }
        decoded = next;
    }
    if !stable && percent_decode(&decoded)? != decoded {
        return None;
    }
    let decoded = String::from_utf8(decoded).ok()?.replace('\\', "/");
    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    Some(format!("/{}", segments.join("/")))
}

fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'%' {
            output.push(input[index]);
            index += 1;
            continue;
        }
        let high = *input.get(index + 1)?;
        let low = *input.get(index + 2)?;
        output.push(hex_value(high)? << 4 | hex_value(low)?);
        index += 3;
    }
    Some(output)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_path_prefixes<'a, I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + ?Sized + 'a,
{
    values
        .into_iter()
        .map(|value| value.as_ref().trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if !value.starts_with('/') || value.contains('?') || value.contains('#') {
                panic!(
                    "Rotas de inspeção WAF completa devem ser paths absolutos sem query: {value}"
                );
            }
            canonical_route_path(&value).unwrap_or_else(|| {
                panic!("Rota de inspeção WAF completa contém encoding inválido: {value}")
            })
        })
        .collect()
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || prefix == "/"
        || (prefix.ends_with('/') && path.starts_with(prefix))
        || path
            .strip_prefix(prefix)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_waf_route_matches_only_path_boundary() {
        assert!(path_matches_prefix("/api/payment", "/api/payment"));
        assert!(path_matches_prefix("/api/payment/confirm", "/api/payment"));
        assert!(!path_matches_prefix("/api/payments", "/api/payment"));
        assert!(path_matches_prefix("/uploads/file", "/uploads/"));
    }

    #[test]
    fn complete_waf_route_ignores_query_string() {
        let backend = resolve_url(
            "http://127.0.0.1:8080",
            vec!["/api/payment".to_string()],
            WafProfile::Generic,
            SiteL1::default(),
            None,
            None,
        );
        assert!(backend.requires_complete_waf_inspection("/api/payment?id=1"));
    }

    #[test]
    fn complete_waf_route_matches_encoded_and_normalized_paths() {
        let backend = resolve_url(
            "http://127.0.0.1:8080",
            vec!["/api/payment".to_string()],
            WafProfile::Generic,
            SiteL1::default(),
            None,
            None,
        );
        assert!(backend.requires_complete_waf_inspection("/api/%70ayment"));
        assert!(backend.requires_complete_waf_inspection("/api/x/../payment"));
        assert!(backend.requires_complete_waf_inspection("/api/%2570ayment"));
        assert!(backend.requires_complete_waf_inspection("/api/%25252570ayment"));
        assert!(backend.requires_complete_waf_inspection("/api/%25252525252525252570ayment"));
        assert!(backend.requires_complete_waf_inspection("/api/%zz"));
    }

    #[test]
    fn default_backend_uses_one_fixed_site_scope_for_unknown_hosts() {
        let config = Config::from_toml(
            r#"
default_backend = "http://127.0.0.1:8080"

[[sites]]
hosts = ["known.example"]
backend = "http://127.0.0.1:8081"
"#,
        );
        assert_eq!(
            config.resolve("random-a.example").unwrap().site_scope,
            "__default__"
        );
        assert_eq!(
            config.resolve("random-b.example").unwrap().site_scope,
            "__default__"
        );
        assert_eq!(
            config.resolve("known.example").unwrap().site_scope,
            "known.example"
        );
    }

    #[test]
    fn protocols_section_loads_route_to_quarantine() {
        let config = Config::from_toml(
            r#"
[protocols]
grpc = "route-to-quarantine"
websocket = "deny"

[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
"#,
        );
        let grpc = config.protocols.evaluate(&crate::protocol::RequestFacts {
            version: http::Version::HTTP_11,
            upgrade: None,
            content_encoding: None,
            content_type: Some("application/grpc"),
            require_complete: false,
        });
        assert_eq!(grpc.event_type(), Some("quarantine"));
        assert_eq!(grpc.blocked_status(), Some(403));
        let websocket = config.protocols.evaluate(&crate::protocol::RequestFacts {
            version: http::Version::HTTP_11,
            upgrade: Some("websocket"),
            content_encoding: None,
            content_type: None,
            require_complete: false,
        });
        assert_eq!(websocket.blocked_status(), Some(403));
    }

    #[test]
    fn timed_out_follows_route_fail_closed_or_open() {
        assert_eq!(
            InspectionPolicy::fail_closed().disposition(InspectionOutcome::TimedOut),
            InspectionDisposition::Deny
        );
        assert_eq!(
            InspectionPolicy::open().disposition(InspectionOutcome::TimedOut),
            InspectionDisposition::Monitor
        );
        assert_eq!(
            InspectionPolicy::open().disposition(InspectionOutcome::BudgetExceeded),
            InspectionDisposition::Deny
        );
    }

    #[test]
    fn require_complete_sugar_denies_parse_error_with_403() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
require_complete_waf_inspection = ["/api/payment"]
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let policy = backend.inspection_policy("/api/payment");
        assert_eq!(policy, InspectionPolicy::fail_closed());
        let inspection = waf::inspect_body(
            b"{not json",
            "/api/payment",
            "1.1.1.1",
            Some("application/json"),
        );
        assert_eq!(inspection.status, InspectionOutcome::ParseError);
        assert_eq!(
            policy.disposition(inspection.status),
            InspectionDisposition::Deny
        );
        assert_eq!(inspection.status.denied_status(), 403);
    }

    fn nested_json_objects(depth: usize) -> Vec<u8> {
        let mut json = String::from("null");
        for _ in 0..depth {
            json = format!("{{\"n\":{json}}}");
        }
        json.into_bytes()
    }

    #[test]
    fn json_depth_40_on_fail_closed_route_is_403() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
require_complete_waf_inspection = ["/api/payment"]
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let policy = backend.inspection_policy("/api/payment");
        assert_eq!(policy, InspectionPolicy::fail_closed());
        let inspection = waf::inspect_body(
            &nested_json_objects(40),
            "/api/payment",
            "1.1.1.1",
            Some("application/json"),
        );
        assert_eq!(inspection.status, InspectionOutcome::ParseError);
        assert_eq!(
            policy.disposition(inspection.status),
            InspectionDisposition::Deny
        );
        assert_eq!(inspection.status.denied_status(), 403);
    }

    #[test]
    fn on_truncated_and_on_parse_error_are_per_prefix() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
require_complete_waf_inspection = ["/api/payment"]

[[sites.routes]]
prefix = "/api/search"
inspection.on_parse_error = "deny"

[[sites.routes]]
prefix = "/api/payment"
inspection.on_truncated = "monitor"
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let payment = backend.inspection_policy("/api/payment/confirm");
        assert!(payment.require_complete);
        assert_eq!(payment.on_truncated, InspectionAction::Monitor);
        assert_eq!(payment.on_parse_error, InspectionAction::Deny);
        let search = backend.inspection_policy("/api/search");
        assert!(!search.require_complete);
        assert_eq!(search.on_truncated, InspectionAction::Monitor);
        assert_eq!(search.on_parse_error, InspectionAction::Deny);
        let open = backend.inspection_policy("/health");
        assert_eq!(open, InspectionPolicy::open());
    }

    #[test]
    fn nested_route_inherits_fail_closed_sugar() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
require_complete_waf_inspection = ["/api/"]

[[sites.routes]]
prefix = "/api/webhooks"
inspection.on_parse_error = "monitor"
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let webhooks = backend.inspection_policy("/api/webhooks/stripe");
        assert!(webhooks.require_complete);
        assert_eq!(webhooks.on_truncated, InspectionAction::Deny);
        assert_eq!(webhooks.on_parse_error, InspectionAction::Monitor);
        let other = backend.inspection_policy("/api/payment");
        assert_eq!(other, InspectionPolicy::fail_closed());
    }

    #[test]
    fn undecodable_uri_fail_closes_when_parse_error_is_deny() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api/search"
inspection.on_parse_error = "deny"
"#,
        );
        let policy = config
            .resolve("api.example")
            .unwrap()
            .inspection_policy("/api/search/%zz");
        assert_eq!(policy, InspectionPolicy::fail_closed());
        assert_eq!(
            policy.disposition(InspectionOutcome::ParseError),
            InspectionDisposition::Deny
        );
    }

    #[test]
    fn parse_error_deny_survives_unsupported_encoding_combine() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api/search"
inspection.on_parse_error = "deny"
"#,
        );
        let policy = config
            .resolve("api.example")
            .unwrap()
            .inspection_policy("/api/search");
        let inflated = waf::inflate_for_inspect(b"{not json", Some("gzip"));
        let inspection = waf::inspect_body(
            &inflated.bytes,
            "/api/search",
            "1.1.1.1",
            Some("application/json"),
        );
        let outcome = inflated.status.combine(inspection.status);
        assert_eq!(outcome, InspectionOutcome::ParseError);
        assert_eq!(policy.disposition(outcome), InspectionDisposition::Deny);
        assert_eq!(outcome.denied_status(), 403);
    }

    #[test]
    fn max_decoded_body_loads_on_require_complete() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api/payment"
inspection.require_complete = true
inspection.max_decoded_body = "256KiB"
"#,
        );
        let policy = config
            .resolve("api.example")
            .unwrap()
            .inspection_policy("/api/payment");
        assert!(policy.require_complete);
        assert_eq!(policy.max_decoded_body, Some(256 * 1024));
        assert!(config.has_spool_routes());
    }

    #[test]
    fn max_decoded_body_without_require_complete_is_a_load_error() {
        let result = std::panic::catch_unwind(|| {
            Config::from_toml(
                r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api/search"
inspection.max_decoded_body = "256KiB"
"#,
            )
        });
        let Err(payload) = result else {
            panic!("load must fail without require_complete");
        };
        let message = payload
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains("require_complete"),
            "expected require_complete load error, got {message}"
        );
    }

    #[test]
    fn parse_byte_size_accepts_kib_mib() {
        assert_eq!(parse_byte_size("256KiB").unwrap(), 256 * 1024);
        assert_eq!(parse_byte_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("64").unwrap(), 64);
        assert!(parse_byte_size("0").is_err());
        assert!(parse_byte_size("").is_err());
    }

    #[test]
    fn max_decoded_body_on_site_is_a_parse_error() {
        let error = toml::from_str::<ConfigFile>(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
max_decoded_body = "2MiB"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("max_decoded_body"));
    }

    #[test]
    fn topology_packs_still_parse_with_deny_unknown_fields() {
        for path in [
            "ferroada.toml.example",
            "deploy/topologies/_skeleton/ferroada.toml",
            "deploy/topologies/vps-api/ferroada.toml",
            "deploy/topologies/vps-site/ferroada.toml",
            "deploy/topologies/cdn-edge/ferroada.toml",
        ] {
            let contents = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
            toml::from_str::<ConfigFile>(&contents)
                .unwrap_or_else(|error| panic!("{path} no longer parses: {error}"));
        }
    }

    #[test]
    fn route_require_complete_without_sugar_list() {
        let config = Config::from_toml(
            r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api/payment"
inspection.require_complete = true
inspection.on_truncated = "deny"
inspection.on_parse_error = "deny"
"#,
        );
        let policy = config
            .resolve("api.example")
            .unwrap()
            .inspection_policy("/api/payment");
        assert_eq!(policy, InspectionPolicy::fail_closed());
    }

    #[test]
    fn l1_toml_executing_differs_from_blocking_and_excludes_login() {
        let config = Config::from_toml(
            r#"
[waf.l1]
blocking_paranoia = 1
executing_paranoia = 4
shadow = true
anomaly_score_threshold = 5

[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.l1.exclusions]]
prefix = "/login"

[[sites.l1.exclusions]]
parameters = ["token"]

[[sites.l1.exclusions]]
content_types = ["application/pdf"]
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let login = backend.l1_for("/login", None);
        let api = backend.l1_for("/api", None);
        assert!(login.skip);
        assert!(!api.skip);
        assert!(api.settings.shadow);
        assert_eq!(api.settings.blocking_paranoia, 1);
        assert_eq!(api.settings.executing_paranoia, 4);
        assert_eq!(api.settings.anomaly_score_threshold, 5);
        assert_eq!(api.exclude_parameters, vec!["token"]);
        let pdf = backend.l1_for("/api", Some("application/pdf"));
        assert!(pdf.skip);
    }

    #[test]
    fn l1_route_can_turn_shadow_off() {
        let config = Config::from_toml(
            r#"
[waf.l1]
shadow = true
executing_paranoia = 4

[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"

[[sites.routes]]
prefix = "/api"
l1.shadow = false
l1.blocking_paranoia = 4
"#,
        );
        let backend = config.resolve("api.example").unwrap();
        let open = backend.l1_for("/health", None);
        assert!(open.settings.shadow);
        assert_eq!(open.settings.blocking_paranoia, 1);
        let api = backend.l1_for("/api/payment", None);
        assert!(!api.settings.shadow);
        assert_eq!(api.settings.blocking_paranoia, 4);
        assert_eq!(api.settings.executing_paranoia, 4);
    }

    #[test]
    fn openapi_is_opt_in_per_site() {
        let spec = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/openapi-pets.yaml")
            .to_string_lossy()
            .replace('\\', "/");
        let config = Config::from_toml(&format!(
            r#"
[[sites]]
hosts = ["pets.example"]
backend = "http://127.0.0.1:8080"
openapi = {{ spec = "{spec}", unknown_endpoint = "deny" }}

[[sites]]
hosts = ["plain.example"]
backend = "http://127.0.0.1:8081"
"#
        ));
        assert!(config.resolve("pets.example").unwrap().openapi.is_some());
        assert!(config.resolve("plain.example").unwrap().openapi.is_none());
    }

    #[test]
    fn jwt_is_opt_in_per_site() {
        let dir = std::env::temp_dir().join(format!(
            "ferroada-jwt-cfg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let jwks = dir.join("jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}]}"#,
        )
        .unwrap();
        let jwks_path = jwks.to_string_lossy().replace('\\', "/");
        let dir_path = dir.to_string_lossy().replace('\\', "/");
        let config = Config::from_toml_in(
            &format!(
                r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
jwt = {{ jwks = "{jwks_path}", issuer = "https://issuer.test", audience = "api.example" }}

[[sites]]
hosts = ["plain.example"]
backend = "http://127.0.0.1:8081"
"#
            ),
            std::path::Path::new(&dir_path),
        );
        assert!(config.resolve("api.example").unwrap().jwt.is_some());
        assert!(config.resolve("plain.example").unwrap().jwt.is_none());
    }

    #[test]
    fn missing_openapi_spec_is_a_load_error() {
        let result = std::panic::catch_unwind(|| {
            Config::from_toml(
                r#"
[[sites]]
hosts = ["api.example"]
backend = "http://127.0.0.1:8080"
openapi = "./nao-existe.yaml"
"#,
            )
        });
        let Err(payload) = result else {
            panic!("load must fail when the spec file is missing");
        };
        let message = payload
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains("OpenAPI"),
            "expected OpenAPI load error, got {message}"
        );
    }
}
