use serde::Deserialize;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::info;

#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    default_backend: Option<String>,
    #[serde(default)]
    sites: Vec<SiteEntry>,
}

#[derive(Deserialize)]
struct SiteEntry {
    hosts: Vec<String>,
    backend: String,
}

#[derive(Clone)]
pub struct Backend {
    pub addr: SocketAddr,
    pub host: String,
    pub tls: bool,
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
        let target_url =
            std::env::var("TARGET_URL").expect("TARGET_URL or ferroada.toml required");
        let backend = resolve_url(&target_url);
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
            let backend = resolve_url(&site.backend);
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

        let default_idx = file.default_backend.map(|url| {
            let backend = resolve_url(&url);
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
}

fn resolve_url(url: &str) -> Backend {
    let tls = url.starts_with("https://");
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or_else(|| panic!("Backend URL must start with http:// or https://: {}", url));

    let authority = without_scheme.split('/').next().unwrap();
    let default_port: u16 = if tls { 443 } else { 80 };

    let (host, port) = if let Some(idx) = authority.rfind(':') {
        let h = &authority[..idx];
        let p = authority[idx + 1..]
            .parse::<u16>()
            .unwrap_or(default_port);
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

    Backend { addr, host, tls }
}
