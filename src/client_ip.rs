use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const DEFAULT_CLIENT_IP_ORDER: &str = "proxy_protocol,x-forwarded-for";

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
    pub jwt_sub_hash: Option<u64>,
    pub jwt_tenant_hash: Option<u64>,
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
            jwt_sub_hash: None,
            jwt_tenant_hash: None,
        }
    }

    pub fn set_jwt(&mut self, sub: Option<&str>, tenant: Option<&str>) {
        self.jwt_sub_hash = bounded_hash(sub);
        self.jwt_tenant_hash = bounded_hash(tenant);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpSource {
    ProxyProtocol,
    Forwarded,
    XForwardedFor,
    Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardedMode {
    Strip,
    Accept,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIpConfig {
    pub order: Vec<ClientIpSource>,
    pub forwarded: ForwardedMode,
    pub extra_header: Option<String>,
}

impl Default for ClientIpConfig {
    fn default() -> Self {
        Self {
            order: vec![ClientIpSource::ProxyProtocol, ClientIpSource::XForwardedFor],
            forwarded: ForwardedMode::Strip,
            extra_header: None,
        }
    }
}

impl ClientIpConfig {
    pub fn from_env() -> Result<Self, String> {
        let order_raw = std::env::var("CLIENT_IP_ORDER")
            .unwrap_or_else(|_| DEFAULT_CLIENT_IP_ORDER.to_string());
        let order = parse_client_ip_order(&order_raw)?;
        let forwarded = match std::env::var("FORWARDED_HEADER")
            .unwrap_or_else(|_| "strip".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "strip" => ForwardedMode::Strip,
            "accept" => ForwardedMode::Accept,
            other => {
                return Err(format!(
                    "FORWARDED_HEADER inválido ({other}); use strip ou accept"
                ));
            }
        };
        let extra_header = std::env::var("CLIENT_IP_HEADER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if order.contains(&ClientIpSource::Header) && extra_header.is_none() {
            return Err(
                "CLIENT_IP_ORDER inclui header mas CLIENT_IP_HEADER não está definido".into(),
            );
        }
        Ok(Self {
            order,
            forwarded,
            extra_header,
        })
    }
}

fn parse_client_ip_order(raw: &str) -> Result<Vec<ClientIpSource>, String> {
    let order = raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| match token {
            "proxy_protocol" => Ok(ClientIpSource::ProxyProtocol),
            "forwarded" => Ok(ClientIpSource::Forwarded),
            "x-forwarded-for" => Ok(ClientIpSource::XForwardedFor),
            "header" => Ok(ClientIpSource::Header),
            other => Err(format!(
                "CLIENT_IP_ORDER contém fonte desconhecida: {other}"
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if order.is_empty() {
        return Err("CLIENT_IP_ORDER está vazio".into());
    }
    Ok(order)
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
        self.resolve_sources(
            peer_ip,
            x_forwarded_for,
            None,
            None,
            &ClientIpConfig::default(),
        )
    }

    pub fn resolve_sources(
        &self,
        peer_ip: Option<IpAddr>,
        x_forwarded_for: Option<&str>,
        forwarded: Option<&str>,
        extra_header: Option<&str>,
        config: &ClientIpConfig,
    ) -> Option<IpAddr> {
        let mut current = peer_ip?;
        for source in &config.order {
            match source {
                ClientIpSource::ProxyProtocol => {}
                ClientIpSource::XForwardedFor => {
                    current = self.walk_xff(current, x_forwarded_for);
                }
                ClientIpSource::Forwarded => {
                    if config.forwarded == ForwardedMode::Accept {
                        current = self.walk_forwarded(current, forwarded);
                    }
                }
                ClientIpSource::Header => {
                    if self.contains(current) {
                        if let Some(candidate) = extra_header.and_then(parse_single_ip) {
                            current = candidate;
                        }
                    }
                }
            }
        }
        Some(current)
    }

    fn walk_xff(&self, peer_ip: IpAddr, x_forwarded_for: Option<&str>) -> IpAddr {
        if !self.contains(peer_ip) {
            return peer_ip;
        }
        let Some(x_forwarded_for) = x_forwarded_for else {
            return peer_ip;
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
        client_ip
    }

    fn walk_forwarded(&self, peer_ip: IpAddr, forwarded: Option<&str>) -> IpAddr {
        if !self.contains(peer_ip) {
            return peer_ip;
        }
        let Some(forwarded) = forwarded else {
            return peer_ip;
        };
        let mut client_ip = peer_ip;
        for element in split_forwarded_elements(forwarded).into_iter().rev() {
            if !self.contains(client_ip) {
                break;
            }
            let Some(candidate) = parse_forwarded_for_param(element) else {
                break;
            };
            client_ip = candidate;
        }
        client_ip
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
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

fn parse_single_ip(value: &str) -> Option<IpAddr> {
    parse_forwarded_ip(value.trim())
}

/// Split RFC 7239 `Forwarded` on commas that are not inside quotes.
fn split_forwarded_elements(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                let piece = value[start..index].trim();
                if !piece.is_empty() {
                    out.push(piece);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let piece = value[start..].trim();
    if !piece.is_empty() {
        out.push(piece);
    }
    out
}

fn parse_forwarded_for_param(element: &str) -> Option<IpAddr> {
    for pair in element.split(';') {
        let pair = pair.trim();
        let Some((name, raw)) = pair.split_once('=') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("for") {
            continue;
        }
        return parse_forwarded_for_value(raw.trim());
    }
    None
}

fn parse_forwarded_for_value(raw: &str) -> Option<IpAddr> {
    let value = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }
    if value.starts_with('[') {
        let end = value.find(']')?;
        return value[1..end].parse::<IpAddr>().ok();
    }
    parse_forwarded_ip(value)
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
    fn default_order_is_proxy_protocol_then_xff() {
        assert_eq!(
            ClientIpConfig::default().order,
            vec![ClientIpSource::ProxyProtocol, ClientIpSource::XForwardedFor,]
        );
        assert_eq!(ClientIpConfig::default().forwarded, ForwardedMode::Strip);
    }

    #[test]
    fn forwarded_header_is_ignored_when_stripped() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let config = ClientIpConfig {
            order: vec![
                ClientIpSource::ProxyProtocol,
                ClientIpSource::Forwarded,
                ClientIpSource::XForwardedFor,
            ],
            forwarded: ForwardedMode::Strip,
            extra_header: None,
        };
        assert_eq!(
            proxies.resolve_sources(
                Some(ip("10.0.0.2")),
                Some("203.0.113.8"),
                Some("for=198.51.100.4"),
                None,
                &config,
            ),
            Some(ip("203.0.113.8"))
        );
    }

    #[test]
    fn forwarded_accept_walks_for_like_xff() {
        let proxies = TrustedProxies::parse("10.0.0.0/8, 192.168.0.0/16").unwrap();
        let config = ClientIpConfig {
            order: vec![ClientIpSource::Forwarded],
            forwarded: ForwardedMode::Accept,
            extra_header: None,
        };
        assert_eq!(
            proxies.resolve_sources(
                Some(ip("10.0.0.2")),
                None,
                Some("for=198.51.100.4;proto=http, for=203.0.113.8, for=192.168.1.3"),
                None,
                &config,
            ),
            Some(ip("203.0.113.8"))
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_even_when_accepted() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let config = ClientIpConfig {
            order: vec![ClientIpSource::Forwarded],
            forwarded: ForwardedMode::Accept,
            extra_header: None,
        };
        assert_eq!(
            proxies.resolve_sources(
                Some(ip("203.0.113.10")),
                None,
                Some("for=198.51.100.4"),
                None,
                &config,
            ),
            Some(ip("203.0.113.10"))
        );
    }

    #[test]
    fn extra_header_only_from_trusted_peer() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let config = ClientIpConfig {
            order: vec![ClientIpSource::Header],
            forwarded: ForwardedMode::Strip,
            extra_header: Some("cf-connecting-ip".into()),
        };
        assert_eq!(
            proxies.resolve_sources(
                Some(ip("10.0.0.2")),
                None,
                None,
                Some("198.51.100.4"),
                &config,
            ),
            Some(ip("198.51.100.4"))
        );
        assert_eq!(
            proxies.resolve_sources(
                Some(ip("203.0.113.10")),
                None,
                None,
                Some("198.51.100.4"),
                &config,
            ),
            Some(ip("203.0.113.10"))
        );
    }

    #[test]
    fn forwarded_ipv6_quoted_for() {
        assert_eq!(
            parse_forwarded_for_value("\"[2001:db8:cafe::17]:4711\""),
            Some(ip("2001:db8:cafe::17"))
        );
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
