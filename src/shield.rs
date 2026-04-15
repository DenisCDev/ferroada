use once_cell::sync::Lazy;
use std::collections::HashSet;
use tracing::warn;

use crate::metrics;

/// Default allowed HTTP methods
const DEFAULT_ALLOWED: &str = "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS";

/// Default max body size: 10MB
const DEFAULT_MAX_BODY: usize = 10_485_760;

/// Default max URI length: 8KB
const DEFAULT_MAX_URI: usize = 8_192;

static ALLOWED_METHODS: Lazy<HashSet<String>> = Lazy::new(|| {
    let methods_str = std::env::var("ALLOWED_METHODS").unwrap_or_else(|_| DEFAULT_ALLOWED.to_string());
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
        .unwrap_or(DEFAULT_MAX_BODY)
});

static MAX_URI_LENGTH: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_URI_LENGTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_URI)
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
        metrics::record_block("method", client_addr, uri, &format!("Blocked method: {}", method));
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
        metrics::record_block("size_limit", client_addr, &uri[..128.min(uri.len())], &format!("URI length {} > max {}", uri.len(), *MAX_URI_LENGTH));
        return ShieldVerdict::BlockUriLength;
    }
    ShieldVerdict::Allow
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
        metrics::record_block("size_limit", client_addr, uri, &format!("Body size {} > max {}", content_length, *MAX_BODY_SIZE));
        return ShieldVerdict::BlockBodySize;
    }
    ShieldVerdict::Allow
}

/// Check Host header against allowlist to prevent DNS rebinding attacks.
/// Only active when ALLOWED_HOSTS is set. If not set, all hosts are allowed.
pub fn check_host(host_header: &str, uri: &str, client_addr: &str) -> ShieldVerdict {
    if let Some(ref allowed) = *ALLOWED_HOSTS {
        // Strip port from Host header (e.g., "example.com:3000" -> "example.com")
        let host = host_header.split(':').next().unwrap_or(host_header).to_lowercase();
        if !allowed.contains(&host) {
            warn!(
                client = client_addr,
                host = host_header,
                "Blocked: Host header not in allowlist"
            );
            metrics::record_block("host", client_addr, uri, &format!("Blocked host: {}", host_header));
            return ShieldVerdict::BlockHost;
        }
    }
    ShieldVerdict::Allow
}

// --- Bad Bot Detection ---

static BAD_BOT_ENABLED: Lazy<bool> = Lazy::new(|| {
    std::env::var("BAD_BOT_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
});

const BAD_BOT_SIGNATURES: &[&str] = &[
    "nikto", "sqlmap", "nessus", "openvas", "nmap", "dirbuster",
    "gobuster", "wfuzz", "ffuf", "hydra", "metasploit", "masscan",
    "zmeu", "w3af", "nuclei", "whatweb", "skipfish", "arachni",
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
        metrics::record_block("smuggling", client_addr, uri, "Multiple Content-Length headers");
        return ShieldVerdict::BlockSmuggling;
    }

    if let Some(te) = transfer_encoding {
        // CL + TE present simultaneously
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
