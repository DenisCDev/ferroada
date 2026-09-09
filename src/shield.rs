use once_cell::sync::Lazy;
use std::collections::HashSet;
use tracing::warn;

use crate::metrics;

/// Default allowed HTTP methods
const DEFAULT_ALLOWED: &str = "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS";

/// Pingora 0.8 can replay at most 64 KiB after pre-upstream inspection.
const MAX_REPLAYABLE_BODY: usize = 65_536;
const DEFAULT_MAX_BODY: usize = MAX_REPLAYABLE_BODY;

/// Default max URI length: 8KB
const DEFAULT_MAX_URI: usize = 8_192;
const DEFAULT_MAX_HEADER_COUNT: usize = 100;
const DEFAULT_MAX_HEADER_BYTES: usize = 65_536;

static ALLOWED_METHODS: Lazy<HashSet<String>> = Lazy::new(|| {
    let methods_str =
        std::env::var("ALLOWED_METHODS").unwrap_or_else(|_| DEFAULT_ALLOWED.to_string());
    methods_str
        .split(',')
        .map(|m| m.trim().to_uppercase())
        .filter(|m| !m.is_empty())
        .collect()
});

static MAX_BODY_SIZE: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_BODY_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_BODY)
        .min(MAX_REPLAYABLE_BODY)
});

static MAX_URI_LENGTH: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_URI_LENGTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_URI)
});

static MAX_HEADER_COUNT: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_HEADER_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_HEADER_COUNT)
});

static MAX_HEADER_BYTES: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_HEADER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_HEADER_BYTES)
});

static ALLOWED_HOSTS: Lazy<Option<HashSet<String>>> = Lazy::new(|| {
    std::env::var("ALLOWED_HOSTS").ok().map(|hosts_str| {
        hosts_str
            .split(',')
            .map(|h| h.trim().to_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    })
});

pub enum ShieldVerdict {
    Allow,
    BlockMethod,
    BlockBodySize,
    BlockUriLength,
    BlockHost,
    BlockBadBot,
    BlockSmuggling,
    BlockHeaders,
}

pub fn check_headers(
    header_count: usize,
    header_bytes: usize,
    uri: &str,
    client_addr: &str,
) -> ShieldVerdict {
    if header_count > *MAX_HEADER_COUNT || header_bytes > *MAX_HEADER_BYTES {
        warn!(
            client = client_addr,
            header_count,
            header_bytes,
            max_header_count = *MAX_HEADER_COUNT,
            max_header_bytes = *MAX_HEADER_BYTES,
            "Blocked: request headers exceed configured limits"
        );
        metrics::record_block(
            "header_limit",
            client_addr,
            uri,
            &format!("{header_count} headers, {header_bytes} bytes"),
        );
        return ShieldVerdict::BlockHeaders;
    }
    ShieldVerdict::Allow
}

/// Check if the HTTP method is allowed.
pub fn check_method(method: &str, uri: &str, client_addr: &str) -> ShieldVerdict {
    if !ALLOWED_METHODS.contains(&method.to_uppercase()) {
        warn!(
            client = client_addr,
            method = method,
            uri = uri,
            "Blocked disallowed HTTP method"
        );
        metrics::record_block(
            "method",
            client_addr,
            uri,
            &format!("Blocked method: {}", method),
        );
        return ShieldVerdict::BlockMethod;
    }
    ShieldVerdict::Allow
}

/// Check if the URI length exceeds the configured maximum.
pub fn check_uri_length(uri: &str, client_addr: &str) -> ShieldVerdict {
    if uri.len() > *MAX_URI_LENGTH {
        warn!(
            client = client_addr,
            uri_len = uri.len(),
            max = *MAX_URI_LENGTH,
            "Blocked: URI too long"
        );
        metrics::record_block(
            "size_limit",
            client_addr,
            &uri[..128.min(uri.len())],
            &format!("URI length {} > max {}", uri.len(), *MAX_URI_LENGTH),
        );
        return ShieldVerdict::BlockUriLength;
    }
    ShieldVerdict::Allow
}

pub fn max_body_size() -> usize {
    *MAX_BODY_SIZE
}

/// True when buffering `chunk_len` more bytes would exceed MAX_BODY_SIZE.
/// Used for chunked bodies that have no Content-Length.
pub fn body_would_exceed(current_len: usize, chunk_len: usize) -> bool {
    current_len.saturating_add(chunk_len) > *MAX_BODY_SIZE
}

/// Check if the request body size exceeds the configured maximum.
pub fn check_body_size(content_length: usize, uri: &str, client_addr: &str) -> ShieldVerdict {
    if content_length > *MAX_BODY_SIZE {
        warn!(
            client = client_addr,
            body_size = content_length,
            max = *MAX_BODY_SIZE,
            "Blocked: body too large"
        );
        metrics::record_block(
            "size_limit",
            client_addr,
            uri,
            &format!("Body size {} > max {}", content_length, *MAX_BODY_SIZE),
        );
        return ShieldVerdict::BlockBodySize;
    }
    ShieldVerdict::Allow
}

/// Check Host header against allowlist to prevent DNS rebinding attacks.
/// Only active when ALLOWED_HOSTS is set. If not set, all hosts are allowed.
pub fn check_host(host_header: &str, uri: &str, client_addr: &str) -> ShieldVerdict {
    if let Some(ref allowed) = *ALLOWED_HOSTS {
        // Strip port from Host header (e.g., "example.com:3000" -> "example.com")
        let host = host_header
            .split(':')
            .next()
            .unwrap_or(host_header)
            .to_lowercase();
        if !allowed.contains(&host) {
            warn!(
                client = client_addr,
                host = host_header,
                "Blocked: Host header not in allowlist"
            );
            metrics::record_block(
                "host",
                client_addr,
                uri,
                &format!("Blocked host: {}", host_header),
            );
            return ShieldVerdict::BlockHost;
        }
    }
    ShieldVerdict::Allow
}

/// RFC 9110 §7.6.1: tokens in `Connection` name hop-by-hop header fields.
pub fn connection_hop_by_hop_names<'a, I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut names = Vec::new();
    for value in values {
        for part in value.split(',') {
            let name = part.trim();
            if is_http_token(name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn is_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Host and `:authority` (URI authority) must name the same origin when both exist.
pub fn check_host_authority(
    host_header: Option<&str>,
    uri_authority: Option<&str>,
    uri: &str,
    client_addr: &str,
) -> ShieldVerdict {
    let host = host_header.map(str::trim).filter(|value| !value.is_empty());
    let authority = uri_authority
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (Some(host), Some(authority)) = (host, authority) else {
        return ShieldVerdict::Allow;
    };
    if authorities_match(host, authority) {
        return ShieldVerdict::Allow;
    }
    warn!(
        client = client_addr,
        host, authority, "Blocked: Host and :authority identify different origins"
    );
    metrics::record_block(
        "host",
        client_addr,
        uri,
        &format!("Host {host} != :authority {authority}"),
    );
    ShieldVerdict::BlockHost
}

fn authorities_match(host_header: &str, uri_authority: &str) -> bool {
    let Some((host_a, port_a)) = split_host_port(host_header) else {
        return false;
    };
    let Some((host_b, port_b)) = split_host_port(uri_authority) else {
        return false;
    };
    if !host_a.eq_ignore_ascii_case(host_b) {
        return false;
    }
    match (port_a, port_b) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn split_host_port(value: &str) -> Option<(&str, Option<&str>)> {
    let value = match value.rsplit_once('@') {
        Some((_, rest)) => rest,
        None => value,
    };
    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if rest.is_empty() {
            None
        } else {
            Some(rest.strip_prefix(':')?)
        };
        return Some((host, port));
    }
    match value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some((host, Some(port)))
        }
        _ if !value.is_empty() => Some((value, None)),
        _ => None,
    }
}

// --- Bad Bot Detection ---

static BAD_BOT_ENABLED: Lazy<bool> = Lazy::new(|| {
    std::env::var("BAD_BOT_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
});

const BAD_BOT_SIGNATURES: &[&str] = &[
    "nikto",
    "sqlmap",
    "nessus",
    "openvas",
    "nmap",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "ffuf",
    "hydra",
    "metasploit",
    "masscan",
    "zmeu",
    "w3af",
    "nuclei",
    "whatweb",
    "skipfish",
    "arachni",
];

/// Check if the User-Agent matches known attack tool signatures.
pub fn check_user_agent(ua: &str, uri: &str, client_addr: &str) -> ShieldVerdict {
    if !*BAD_BOT_ENABLED {
        return ShieldVerdict::Allow;
    }
    let ua_lower = ua.to_ascii_lowercase();
    for sig in BAD_BOT_SIGNATURES {
        if ua_lower.contains(sig) {
            warn!(
                client = client_addr,
                ua = ua,
                uri = uri,
                signature = *sig,
                "Blocked: bad bot user-agent"
            );
            metrics::record_block("bad_bot", client_addr, uri, &format!("Bad bot UA: {}", sig));
            return ShieldVerdict::BlockBadBot;
        }
    }
    ShieldVerdict::Allow
}

// --- HTTP Request Smuggling Detection ---

/// Check for HTTP request smuggling indicators per RFC 7230 §3.3.3.
pub fn check_smuggling(
    has_content_length: bool,
    content_length_count: usize,
    transfer_encoding_count: usize,
    transfer_encoding: Option<&str>,
    uri: &str,
    client_addr: &str,
) -> ShieldVerdict {
    // Multiple Content-Length headers
    if content_length_count > 1 {
        warn!(
            client = client_addr,
            uri = uri,
            cl_count = content_length_count,
            "Blocked: multiple Content-Length headers (smuggling)"
        );
        metrics::record_block(
            "smuggling",
            client_addr,
            uri,
            "Multiple Content-Length headers",
        );
        return ShieldVerdict::BlockSmuggling;
    }

    if transfer_encoding_count > 1 {
        warn!(
            client = client_addr,
            uri = uri,
            te_count = transfer_encoding_count,
            "Blocked: multiple Transfer-Encoding headers (smuggling)"
        );
        metrics::record_block(
            "smuggling",
            client_addr,
            uri,
            "Multiple Transfer-Encoding headers",
        );
        return ShieldVerdict::BlockSmuggling;
    }

    if has_content_length && transfer_encoding_count > 0 {
        warn!(
            client = client_addr,
            uri = uri,
            "Blocked: Content-Length + Transfer-Encoding (smuggling)"
        );
        metrics::record_block("smuggling", client_addr, uri, "CL + TE conflict");
        return ShieldVerdict::BlockSmuggling;
    }

    if let Some(te) = transfer_encoding {
        // The normalized view remains a fallback for non-HTTP/1 downstreams.
        if has_content_length {
            warn!(
                client = client_addr,
                uri = uri,
                "Blocked: Content-Length + Transfer-Encoding (smuggling)"
            );
            metrics::record_block("smuggling", client_addr, uri, "CL + TE conflict");
            return ShieldVerdict::BlockSmuggling;
        }

        // TE with unexpected value
        let te_lower = te.trim().to_ascii_lowercase();
        if te_lower != "chunked" && te_lower != "identity" {
            warn!(
                client = client_addr,
                uri = uri,
                te = te,
                "Blocked: suspicious Transfer-Encoding value (smuggling)"
            );
            metrics::record_block("smuggling", client_addr, uri, &format!("Bad TE: {}", te));
            return ShieldVerdict::BlockSmuggling;
        }
    }

    ShieldVerdict::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_without_content_length_still_has_a_cap() {
        assert!(!body_would_exceed(0, 100));
        assert!(body_would_exceed(max_body_size(), 1));
        assert!(body_would_exceed(max_body_size() - 10, 11));
        assert!(!body_would_exceed(max_body_size() - 10, 10));
    }

    #[test]
    fn duplicate_transfer_encoding_is_rejected() {
        assert!(matches!(
            check_smuggling(false, 0, 2, Some("chunked"), "/", "127.0.0.1"),
            ShieldVerdict::BlockSmuggling
        ));
    }

    #[test]
    fn header_count_and_bytes_are_bounded() {
        assert!(matches!(
            check_headers(*MAX_HEADER_COUNT + 1, 1, "/", "127.0.0.1"),
            ShieldVerdict::BlockHeaders
        ));
        assert!(matches!(
            check_headers(1, *MAX_HEADER_BYTES + 1, "/", "127.0.0.1"),
            ShieldVerdict::BlockHeaders
        ));
    }

    #[test]
    fn connection_lists_hop_by_hop_header_names() {
        let names = connection_hop_by_hop_names(["close, X-Evil", "Keep-Alive"]);
        assert_eq!(names, ["close", "X-Evil", "Keep-Alive"]);
        assert!(connection_hop_by_hop_names(["not a token"]).is_empty());
    }

    #[test]
    fn host_and_authority_must_name_the_same_origin() {
        assert!(matches!(
            check_host_authority(
                Some("victim.example"),
                Some("evil.example"),
                "/",
                "127.0.0.1"
            ),
            ShieldVerdict::BlockHost
        ));
        assert!(matches!(
            check_host_authority(
                Some("Example.COM:443"),
                Some("example.com:443"),
                "/",
                "127.0.0.1"
            ),
            ShieldVerdict::Allow
        ));
        assert!(matches!(
            check_host_authority(
                Some("example.com"),
                Some("example.com:443"),
                "/",
                "127.0.0.1"
            ),
            ShieldVerdict::Allow
        ));
        assert!(matches!(
            check_host_authority(Some("example.com"), None, "/", "127.0.0.1"),
            ShieldVerdict::Allow
        ));
        assert!(matches!(
            check_host_authority(
                Some("[2001:db8::1]:8080"),
                Some("[2001:DB8::1]:8080"),
                "/",
                "127.0.0.1"
            ),
            ShieldVerdict::Allow
        ));
        assert!(matches!(
            check_host_authority(
                Some("example.com:80"),
                Some("example.com:443"),
                "/",
                "127.0.0.1"
            ),
            ShieldVerdict::BlockHost
        ));
    }
}
