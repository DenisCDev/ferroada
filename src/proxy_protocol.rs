//! PROXY protocol v2 parser owned by Ferroada — not a Pingora flag.
//!
//! Pingora 0.8.1 has no `enable_proxy_protocol()` and no `PreTlsProcess`.
//! TCP: [`consume_and_apply`] from `BoundedHttpApp::process_new`.
//! TLS: [`PreTlsProcess::process`] on the cleartext stream, then we handshake.

use pingora::protocols::l4::socket::SocketAddr as L4SocketAddr;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream, UniqueID, IO};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// 12-byte v2 signature (`\r\n\r\n\0\r\nQUIT\n`).
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Prefix (16) + 64 KiB of address/TLV. Refuse anything larger.
pub const MAX_HEADER: usize = 16 + 64 * 1024;

const PREFIX: usize = 16;
const READ_DEADLINE: Duration = Duration::from_secs(5);

const CMD_LOCAL: u8 = 0x00;
const CMD_PROXY: u8 = 0x01;
const FAM_UNSPEC: u8 = 0x00;
const FAM_INET: u8 = 0x01;
const FAM_INET6: u8 = 0x02;
const FAM_UNIX: u8 = 0x03;
const INET_ADDR: usize = 12;
const INET6_ADDR: usize = 36;
const UNIX_ADDR: usize = 216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolError {
    NotV2,
    Truncated,
    Oversized,
    Invalid,
    Timeout,
}

impl ProxyProtocolError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotV2 => "prefixo não é PROXY protocol v2",
            Self::Truncated => "cabeçalho PROXY v2 truncado",
            Self::Oversized => "cabeçalho PROXY v2 excede 64 KiB+16",
            Self::Invalid => "cabeçalho PROXY v2 inválido",
            Self::Timeout => "tempo esgotado a ler PROXY v2",
        }
    }
}

/// `PROXY_PROTOCOL=true` (exact match). Unset is off.
pub fn enabled() -> bool {
    std::env::var("PROXY_PROTOCOL")
        .map(|value| value == "true")
        .unwrap_or(false)
}

/// PROXY v2 on the cleartext stream, before any TLS handshake.
///
/// Pingora 0.8.1 does not expose `listeners::PreTlsProcess`; this is the same
/// hook, run from `BoundedHttpApp::process_new` when the TLS listener is
/// `add_tcp` + our handshake.
pub struct PreTlsProcess;

impl PreTlsProcess {
    pub async fn process(&self, stream: &mut Stream) -> Result<(), ProxyProtocolError> {
        consume_and_apply(stream).await
    }
}

/// Read a v2 prefix, refuse anything else, and write the source IP into
/// `SocketDigest` when the command carries one.
pub async fn consume_and_apply(stream: &mut Stream) -> Result<(), ProxyProtocolError> {
    let source = consume_v2(stream).await?;
    if let Some(addr) = source {
        apply_peer(stream, addr);
    }
    Ok(())
}

pub async fn consume_v2(stream: &mut Stream) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    match timeout(READ_DEADLINE, read_v2(stream)).await {
        Ok(result) => result,
        Err(_) => Err(ProxyProtocolError::Timeout),
    }
}

async fn read_v2(stream: &mut Stream) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    let mut prefix = [0u8; PREFIX];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| ProxyProtocolError::Truncated)?;
    let rest_len = rest_len_from_prefix(&prefix)?;
    let mut body = vec![0u8; rest_len];
    if rest_len > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|_| ProxyProtocolError::Truncated)?;
    }
    let mut header = Vec::with_capacity(PREFIX + rest_len);
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&body);
    parse_v2(&header).map(|(source, _)| source)
}

fn rest_len_from_prefix(prefix: &[u8; PREFIX]) -> Result<usize, ProxyProtocolError> {
    if prefix[..12] != SIGNATURE {
        return Err(ProxyProtocolError::NotV2);
    }
    let version = prefix[12] >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::NotV2);
    }
    let len = u16::from_be_bytes([prefix[14], prefix[15]]) as usize;
    if PREFIX + len > MAX_HEADER {
        return Err(ProxyProtocolError::Oversized);
    }
    Ok(len)
}

/// Parse a complete v2 header. Returns (source address, total bytes consumed).
pub fn parse_v2(bytes: &[u8]) -> Result<(Option<SocketAddr>, usize), ProxyProtocolError> {
    if bytes.len() < PREFIX {
        return Err(ProxyProtocolError::Truncated);
    }
    let prefix: [u8; PREFIX] = bytes[..PREFIX]
        .try_into()
        .map_err(|_| ProxyProtocolError::Truncated)?;
    let rest = rest_len_from_prefix(&prefix)?;
    let total = PREFIX + rest;
    if bytes.len() < total {
        return Err(ProxyProtocolError::Truncated);
    }

    let command = bytes[12] & 0x0F;
    if command != CMD_LOCAL && command != CMD_PROXY {
        return Err(ProxyProtocolError::Invalid);
    }
    if command == CMD_LOCAL {
        return Ok((None, total));
    }

    let family = bytes[13] >> 4;
    let addr = &bytes[PREFIX..total];
    let source = match family {
        FAM_UNSPEC => None,
        FAM_INET => Some(parse_inet4(addr)?),
        FAM_INET6 => Some(parse_inet6(addr)?),
        FAM_UNIX => {
            if addr.len() < UNIX_ADDR {
                return Err(ProxyProtocolError::Invalid);
            }
            None
        }
        _ => return Err(ProxyProtocolError::Invalid),
    };
    Ok((source, total))
}

fn parse_inet4(addr: &[u8]) -> Result<SocketAddr, ProxyProtocolError> {
    if addr.len() < INET_ADDR {
        return Err(ProxyProtocolError::Invalid);
    }
    let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let port = u16::from_be_bytes([addr[8], addr[9]]);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

fn parse_inet6(addr: &[u8]) -> Result<SocketAddr, ProxyProtocolError> {
    if addr.len() < INET6_ADDR {
        return Err(ProxyProtocolError::Invalid);
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&addr[..16]);
    let port = u16::from_be_bytes([addr[32], addr[33]]);
    Ok(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(octets),
        port,
        0,
        0,
    )))
}

fn apply_peer(stream: &mut Stream, source: SocketAddr) {
    let io: &mut dyn IO = stream.as_mut();
    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(UniqueID::id(io));
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(UniqueID::id(io) as std::os::windows::io::RawSocket);

    let _ = digest.peer_addr.set(Some(L4SocketAddr::Inet(source)));
    if let Some(old) = GetSocketDigest::get_socket_digest(io) {
        if let Some(Some(local)) = old.local_addr.get().cloned() {
            let _ = digest.local_addr.set(Some(local));
        }
    }
    GetSocketDigest::set_socket_digest(io, digest);
}

/// Encode a v2 PROXY header for tests and fixtures.
pub fn encode_v2(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<Vec<u8>, ProxyProtocolError> {
    match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            let mut out = Vec::with_capacity(PREFIX + INET_ADDR);
            out.extend_from_slice(&SIGNATURE);
            out.push(0x20 | CMD_PROXY);
            out.push((FAM_INET << 4) | 0x01);
            out.extend_from_slice(&(INET_ADDR as u16).to_be_bytes());
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            Ok(out)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            let mut out = Vec::with_capacity(PREFIX + INET6_ADDR);
            out.extend_from_slice(&SIGNATURE);
            out.push(0x20 | CMD_PROXY);
            out.push((FAM_INET6 << 4) | 0x01);
            out.extend_from_slice(&(INET6_ADDR as u16).to_be_bytes());
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            Ok(out)
        }
        _ => Err(ProxyProtocolError::Invalid),
    }
}

pub fn encode_v2_local() -> Vec<u8> {
    let mut out = Vec::from(SIGNATURE);
    out.push(0x20 | CMD_LOCAL);
    out.push(0x00);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    fn v6(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn ipv4_roundtrip() {
        let src = v4("203.0.113.10", 54321);
        let dst = v4("10.0.0.1", 3000);
        let bytes = encode_v2(src, dst).unwrap();
        assert_eq!(bytes.len(), PREFIX + INET_ADDR);
        let (parsed, consumed) = parse_v2(&bytes).unwrap();
        assert_eq!(parsed, Some(src));
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn ipv6_roundtrip() {
        let src = v6("2001:db8::9", 443);
        let dst = v6("2001:db8::1", 3443);
        let bytes = encode_v2(src, dst).unwrap();
        let (parsed, consumed) = parse_v2(&bytes).unwrap();
        assert_eq!(parsed, Some(src));
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn local_has_no_address() {
        let bytes = encode_v2_local();
        let (parsed, consumed) = parse_v2(&bytes).unwrap();
        assert_eq!(parsed, None);
        assert_eq!(consumed, PREFIX);
    }

    #[test]
    fn http_get_is_not_v2() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(parse_v2(raw), Err(ProxyProtocolError::NotV2));
    }

    #[test]
    fn v1_text_is_not_v2() {
        let raw = b"PROXY TCP4 203.0.113.10 10.0.0.1 12345 80\r\n";
        assert_eq!(parse_v2(raw), Err(ProxyProtocolError::NotV2));
    }

    #[test]
    fn truncated_prefix_is_refused() {
        assert_eq!(
            parse_v2(&SIGNATURE[..8]),
            Err(ProxyProtocolError::Truncated)
        );
    }

    #[test]
    fn u16_length_fits_under_64kib_plus_prefix() {
        let mut prefix = [0u8; PREFIX];
        prefix[..12].copy_from_slice(&SIGNATURE);
        prefix[12] = 0x21;
        prefix[13] = 0x11;
        prefix[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(rest_len_from_prefix(&prefix), Ok(u16::MAX as usize));
        assert!(PREFIX + usize::from(u16::MAX) <= MAX_HEADER);
    }

    #[test]
    fn ipv4_with_tlv_tail_still_yields_source() {
        let src = v4("198.51.100.7", 80);
        let mut bytes = encode_v2(src, v4("10.0.0.1", 3000)).unwrap();
        bytes.extend_from_slice(&[0x03, 0x00, 0x01, b'x']);
        let new_len = (INET_ADDR + 4) as u16;
        bytes[14..16].copy_from_slice(&new_len.to_be_bytes());
        let (parsed, consumed) = parse_v2(&bytes).unwrap();
        assert_eq!(parsed, Some(src));
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn ipv4_shorter_than_address_is_invalid() {
        let mut bytes = encode_v2(v4("203.0.113.10", 1), v4("10.0.0.1", 2)).unwrap();
        bytes[14..16].copy_from_slice(&4u16.to_be_bytes());
        bytes.truncate(PREFIX + 4);
        assert_eq!(parse_v2(&bytes), Err(ProxyProtocolError::Invalid));
    }

    #[test]
    fn unknown_command_is_invalid() {
        let mut bytes = encode_v2_local();
        bytes[12] = 0x2F;
        assert_eq!(parse_v2(&bytes), Err(ProxyProtocolError::Invalid));
    }

    #[test]
    fn max_header_constant_is_64kib_plus_prefix() {
        assert_eq!(MAX_HEADER, 16 + 64 * 1024);
    }
}
