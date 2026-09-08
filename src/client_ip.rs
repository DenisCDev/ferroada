use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct TrustedProxies {
    networks: Vec<IpNetwork>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SiteClientKey {
    pub site: String,
    pub network: IpAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskIdentity {
    pub site: String,
    pub network: IpAddr,
    pub route: String,
    pub session_hash: Option<u64>,
    pub api_key_hash: Option<u64>,
}

impl SiteClientKey {
    pub fn new(site: &str, ip: IpAddr) -> Self {
        Self {
            site: site.to_ascii_lowercase(),
            network: risk_network(ip),
        }
    }
}

impl RiskIdentity {
    pub fn new(
        site: &str,
        ip: IpAddr,
        uri: &str,
        session_id: Option<&str>,
        api_key: Option<&str>,
    ) -> Self {
        Self {
            site: site.to_ascii_lowercase(),
            network: risk_network(ip),
            route: route_group(uri),
            session_hash: bounded_hash(session_id),
            api_key_hash: bounded_hash(api_key),
        }
    }

    pub fn network_key(&self) -> SiteClientKey {
        SiteClientKey {
            site: self.site.clone(),
            network: self.network,
        }
    }
}

fn route_group(uri: &str) -> String {
    let mut segments = uri
        .split('?')
        .next()
        .unwrap_or(uri)
        .split('/')
        .filter(|segment| !segment.is_empty());
    match (segments.next(), segments.next()) {
        (Some(first), Some(second)) => format!("/{first}/{second}"),
        (Some(first), None) => format!("/{first}"),
        _ => "/".to_string(),
    }
}

fn bounded_hash(value: Option<&str>) -> Option<u64> {
    let value = value.map(str::trim).filter(|value| !value.is_empty())?;
    if value.len() > 512 {
        return None;
    }
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    Some(hasher.finish())
}

fn risk_network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => {
            let network = u128::from(ip) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(network))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum IpNetwork {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl TrustedProxies {
    pub fn from_env() -> Result<Self, String> {
        let value = std::env::var("TRUSTED_PROXIES").unwrap_or_default();
        Self::parse(&value)
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        let networks = value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(parse_network)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { networks })
    }

    pub fn resolve(
        &self,
        peer_ip: Option<IpAddr>,
        x_forwarded_for: Option<&str>,
    ) -> Option<IpAddr> {
        let peer_ip = peer_ip?;
        if !self.contains(peer_ip) {
            return Some(peer_ip);
        }

        let Some(x_forwarded_for) = x_forwarded_for else {
            return Some(peer_ip);
        };
        let mut client_ip = peer_ip;
        for value in x_forwarded_for.split(',').rev() {
            if !self.contains(client_ip) {
                break;
            }
            let Some(candidate) = parse_forwarded_ip(value.trim()) else {
                break;
            };
            client_ip = candidate;
        }
        Some(client_ip)
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.contains(ip)
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(ip))
    }
}

impl IpNetwork {
    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == network,
            (Self::V6 { network, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == network,
            _ => false,
        }
    }
}

fn parse_network(value: &str) -> Result<IpNetwork, String> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| format!("TRUSTED_PROXIES contém IP inválido: {value}"))?;

    match ip {
        IpAddr::V4(ip) => {
            let prefix = parse_prefix(prefix, 32, value)?;
            let mask = prefix_mask_v4(prefix);
            Ok(IpNetwork::V4 {
                network: u32::from(ip) & mask,
                mask,
            })
        }
        IpAddr::V6(ip) => {
            let prefix = parse_prefix(prefix, 128, value)?;
            let mask = prefix_mask_v6(prefix);
            Ok(IpNetwork::V6 {
                network: u128::from(ip) & mask,
                mask,
            })
        }
    }
}

fn parse_prefix(prefix: Option<&str>, max: u8, value: &str) -> Result<u8, String> {
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|_| format!("TRUSTED_PROXIES contém prefixo inválido: {value}"))?,
        None => max,
    };
    if prefix > max {
        return Err(format!("TRUSTED_PROXIES contém prefixo inválido: {value}"));
    }
    Ok(prefix)
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    value.parse::<IpAddr>().ok().or_else(|| {
        value
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|addr| addr.ip())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test IP")
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_header() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            proxies.resolve(Some(ip("203.0.113.10")), Some("198.51.100.4")),
            Some(ip("203.0.113.10"))
        );
    }

    #[test]
    fn trusted_chain_returns_first_untrusted_hop_from_the_right() {
        let proxies = TrustedProxies::parse("10.0.0.0/8, 192.168.0.0/16").unwrap();
        assert_eq!(
            proxies.resolve(
                Some(ip("10.0.0.2")),
                Some("198.51.100.4, 203.0.113.8, 192.168.1.3")
            ),
            Some(ip("203.0.113.8"))
        );
    }

    #[test]
    fn trusted_ipv6_proxy_resolves_ipv6_client() {
        let proxies = TrustedProxies::parse("2001:db8:abcd::/48").unwrap();
        assert_eq!(
            proxies.resolve(Some(ip("2001:db8:abcd::1")), Some("2001:db8:ffff::9")),
            Some(ip("2001:db8:ffff::9"))
        );
    }

    #[test]
    fn malformed_client_prefix_cannot_poison_resolved_identity() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            proxies.resolve(Some(ip("10.0.0.2")), Some("invalid, 198.51.100.4")),
            Some(ip("198.51.100.4"))
        );
    }

    #[test]
    fn malformed_hop_next_to_trusted_peer_stops_resolution() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            proxies.resolve(Some(ip("10.0.0.2")), Some("198.51.100.4, invalid")),
            Some(ip("10.0.0.2"))
        );
    }

    #[test]
    fn invalid_network_is_rejected() {
        assert!(TrustedProxies::parse("10.0.0.0/99").is_err());
        assert!(TrustedProxies::parse("not-an-ip").is_err());
    }

    #[test]
    fn risk_identity_groups_ipv6_rotation_by_64_prefix() {
        let first = SiteClientKey::new("api.example.com", ip("2001:db8:1:2::1"));
        let rotated = SiteClientKey::new("api.example.com", ip("2001:db8:1:2::ffff"));
        let other_prefix = SiteClientKey::new("api.example.com", ip("2001:db8:1:3::1"));
        assert_eq!(first, rotated);
        assert_ne!(first, other_prefix);
    }

    #[test]
    fn request_identity_is_pseudonymous_and_route_scoped() {
        let identity = RiskIdentity::new(
            "api.example.com",
            ip("203.0.113.10"),
            "/api/payment/123?debug=1",
            Some("session-secret"),
            Some("api-secret"),
        );
        assert_eq!(identity.route, "/api/payment");
        assert!(identity.session_hash.is_some());
        assert!(identity.api_key_hash.is_some());
    }
}
