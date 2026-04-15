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

pub enum ShieldVerdict {
    Allow,
    BlockMethod,
    BlockBodySize,
    BlockUriLength,
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
