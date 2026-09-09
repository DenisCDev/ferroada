//! Embedded copies of `deploy/topologies/` and `deploy/cidrs/`.
//! `include_str!` is the only source `ferroada init` reads — no HTTP, no git tree.

macro_rules! pack_file {
    ($topo:literal, $file:literal) => {
        (
            $file,
            include_str!(concat!("../../deploy/topologies/", $topo, "/", $file)),
        )
    };
}

macro_rules! define_topo {
    ($name:ident, $topo:literal) => {
        pub static $name: &[(&str, &str)] = &[
            pack_file!($topo, ".env.caddy.example"),
            pack_file!($topo, ".env.example"),
            pack_file!($topo, "Caddyfile"),
            pack_file!($topo, "CHECKLIST.md"),
            pack_file!($topo, "docker-compose.caddy.yml"),
            pack_file!($topo, "docker-compose.yml"),
            pack_file!($topo, "ferroada.privileged.service"),
            pack_file!($topo, "ferroada.service"),
            pack_file!($topo, "ferroada.toml"),
            pack_file!($topo, "nginx.conf.snippet"),
            pack_file!($topo, "ORIGIN_LOCK.md"),
            pack_file!($topo, "README.md"),
            pack_file!($topo, "tmpfiles.d/ferroada.conf"),
            pack_file!($topo, "VISIBILIDADE.md"),
        ];
    };
    ($name:ident, $topo:literal, $($extra:literal),+ $(,)?) => {
        pub static $name: &[(&str, &str)] = &[
            pack_file!($topo, ".env.caddy.example"),
            pack_file!($topo, ".env.example"),
            pack_file!($topo, "Caddyfile"),
            pack_file!($topo, "CHECKLIST.md"),
            pack_file!($topo, "docker-compose.caddy.yml"),
            pack_file!($topo, "docker-compose.yml"),
            pack_file!($topo, "ferroada.privileged.service"),
            pack_file!($topo, "ferroada.service"),
            pack_file!($topo, "ferroada.toml"),
            pack_file!($topo, "nginx.conf.snippet"),
            pack_file!($topo, "ORIGIN_LOCK.md"),
            pack_file!($topo, "README.md"),
            pack_file!($topo, "tmpfiles.d/ferroada.conf"),
            pack_file!($topo, "VISIBILIDADE.md"),
            $(pack_file!($topo, $extra),)+
        ];
    };
}

define_topo!(VPS_SITE, "vps-site", "haproxy.cfg.snippet");
define_topo!(VPS_API, "vps-api", "haproxy.cfg.snippet");
define_topo!(
    VPS_SUPABASE_SELFHOST,
    "vps-supabase-selfhost",
    "haproxy.cfg.snippet"
);
define_topo!(
    VPS_SUPABASE_CLOUD,
    "vps-supabase-cloud",
    "ferroada.toml.bff.example",
    "haproxy.cfg.snippet"
);
define_topo!(VPS_FULL, "vps-full", "haproxy.cfg.snippet");
define_topo!(HOSTINGER_ORIGIN, "hostinger-origin", "haproxy.cfg.snippet");
define_topo!(VERCEL_ORIGIN, "vercel-origin", "haproxy.cfg.snippet");
define_topo!(CDN_EDGE, "cdn-edge");
define_topo!(
    SKELETON,
    "_skeleton",
    "ferroada.proxied.service",
    "haproxy.cfg.snippet"
);

pub const PROXIED_UNIT: &str =
    include_str!("../../deploy/topologies/_skeleton/ferroada.proxied.service");

pub const CLOUDFLARE_CIDRS: &str = include_str!("../../deploy/cidrs/cloudflare.txt");
pub const FASTLY_CIDRS: &str = include_str!("../../deploy/cidrs/fastly.txt");
pub const AKAMAI_CIDRS: &str = include_str!("../../deploy/cidrs/akamai.txt");

pub static ALL_TOPOLOGIES: &[(&str, &[(&str, &str)])] = &[
    ("_skeleton", SKELETON),
    ("cdn-edge", CDN_EDGE),
    ("hostinger-origin", HOSTINGER_ORIGIN),
    ("vercel-origin", VERCEL_ORIGIN),
    ("vps-api", VPS_API),
    ("vps-full", VPS_FULL),
    ("vps-site", VPS_SITE),
    ("vps-supabase-cloud", VPS_SUPABASE_CLOUD),
    ("vps-supabase-selfhost", VPS_SUPABASE_SELFHOST),
];

pub fn all_topologies() -> &'static [(&'static str, &'static [(&'static str, &'static str)])] {
    ALL_TOPOLOGIES
}

pub fn topology(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    all_topologies()
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, files)| *files)
}

/// Modes `ferroada init --topology` accepts. `_skeleton` is not one.
pub fn init_topology(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    if name == "_skeleton" {
        return None;
    }
    topology(name)
}

pub fn cidr_snapshot(edge: &str) -> Option<&'static str> {
    match edge {
        "cloudflare" => Some(CLOUDFLARE_CIDRS),
        "fastly" => Some(FASTLY_CIDRS),
        "akamai" => Some(AKAMAI_CIDRS),
        _ => None,
    }
}

pub fn cidrs_from_snapshot(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
pub fn extra_embedded() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "topologies/README.md",
            include_str!("../../deploy/topologies/README.md"),
        ),
        ("cidrs/cloudflare.txt", CLOUDFLARE_CIDRS),
        ("cidrs/fastly.txt", FASTLY_CIDRS),
        ("cidrs/akamai.txt", AKAMAI_CIDRS),
        (
            "cidrs/README.md",
            include_str!("../../deploy/cidrs/README.md"),
        ),
    ]
}
