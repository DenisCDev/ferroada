use serde::Deserialize;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::info;

use crate::waf::{self, WafProfile};

#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    default_backend: Option<String>,
    #[serde(default)]
    sites: Vec<SiteEntry>,
    #[serde(default)]
    default_require_complete_waf_inspection: Vec<String>,
    #[serde(default)]
    default_waf_profile: Option<String>,
}

#[derive(Deserialize)]
struct SiteEntry {
    hosts: Vec<String>,
    backend: String,
    #[serde(default)]
    require_complete_waf_inspection: Vec<String>,
    #[serde(default)]
    waf_profile: Option<String>,
}

#[derive(Clone)]
pub struct Backend {
    pub addr: SocketAddr,
    pub host: String,
    pub site_scope: String,
    pub redirect_host: Option<String>,
    pub tls: bool,
    pub waf_profile: WafProfile,
    require_complete_waf_inspection: Vec<String>,
}

impl Backend {
    pub fn requires_complete_waf_inspection(&self, uri: &str) -> bool {
        let path = uri.split('?').next().unwrap_or(uri);
        let Some(path) = canonical_route_path(path) else {
            return !self.require_complete_waf_inspection.is_empty();
        };
        self.require_complete_waf_inspection
            .iter()
            .any(|prefix| path_matches_prefix(&path, prefix))
    }
}

pub struct Config {
    /// host (lowercase, no port) → index into backends
    route_table: HashMap<String, usize>,
    backends: Vec<Backend>,
    /// Default backend for requests that don't match any site
    default_idx: Option<usize>,
}

impl Config {
    /// Load from ferroada.toml if it exists, otherwise fall back to TARGET_URL env.
    pub fn load() -> Self {
        // Try config file first
        if let Ok(contents) = std::fs::read_to_string("ferroada.toml") {
            return Self::from_toml(&contents);
        }

        // Fallback: single TARGET_URL (backward compatible)
        let target_url = std::env::var("TARGET_URL").expect("TARGET_URL or ferroada.toml required");
        let complete_waf_paths = std::env::var("WAF_REQUIRE_COMPLETE_PATHS")
            .ok()
            .map(|value| parse_path_prefixes(value.split(',')))
            .unwrap_or_default();
        let backend = resolve_url(&target_url, complete_waf_paths, waf::default_profile());
        info!(
            backend = %target_url,
            "Single-site mode (TARGET_URL)"
        );
        Config {
            route_table: HashMap::new(),
            backends: vec![backend],
            default_idx: Some(0),
        }
    }

    fn from_toml(contents: &str) -> Self {
        let file: ConfigFile = toml::from_str(contents).expect("Invalid ferroada.toml");

        let mut backends = Vec::new();
        let mut route_table = HashMap::new();

        for site in &file.sites {
            let mut backend = resolve_url(
                &site.backend,
                parse_path_prefixes(site.require_complete_waf_inspection.iter()),
                site.waf_profile
                    .as_deref()
                    .map(WafProfile::parse)
                    .unwrap_or_else(waf::default_profile),
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
            let mut backend = resolve_url(&url, default_paths, default_profile);
            backend.site_scope = "__default__".to_string();
            let idx = backends.len();
            info!(backend = %url, "Default backend configured");
            backends.push(backend);
            idx
        });

        if backends.is_empty() {
            panic!("ferroada.toml has no sites configured");
        }

        let site_count = file.sites.len();
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
}

fn resolve_url(
    url: &str,
    require_complete_waf_inspection: Vec<String>,
    waf_profile: WafProfile,
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
        require_complete_waf_inspection,
    }
}

fn canonical_route_path(path: &str) -> Option<String> {
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
        );
        assert!(backend.requires_complete_waf_inspection("/api/payment?id=1"));
    }

    #[test]
    fn complete_waf_route_matches_encoded_and_normalized_paths() {
        let backend = resolve_url(
            "http://127.0.0.1:8080",
            vec!["/api/payment".to_string()],
            WafProfile::Generic,
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
}
