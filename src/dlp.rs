use bytes::Bytes;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::info;

use crate::metrics;

static CPF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{3}\.\d{3}\.\d{3}-\d{2}").expect("invalid CPF regex")
});

static BEARER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*").expect("invalid Bearer regex")
});

/// Check if DLP masking is enabled (default: true for backward compat).
fn is_enabled() -> bool {
    std::env::var("DLP_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
}

pub fn sanitize_body(body: &[u8], content_type: Option<&str>) -> Bytes {
    if !is_enabled() {
        return Bytes::copy_from_slice(body);
    }

    // Skip binary content types — no CPFs or tokens in images/videos/PDFs
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();
        if ct_lower.starts_with("image/")
            || ct_lower.starts_with("video/")
            || ct_lower.starts_with("audio/")
            || ct_lower.starts_with("application/octet-stream")
            || ct_lower.starts_with("application/pdf")
            || ct_lower.starts_with("application/zip")
            || ct_lower.starts_with("application/gzip")
        {
            return Bytes::copy_from_slice(body);
        }
    }

    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Bytes::copy_from_slice(body),
    };

    let cpf_count = CPF_RE.find_iter(text).count();
    let result = CPF_RE.replace_all(text, "***.***.***-**");

    let bearer_count = BEARER_RE.find_iter(&result).count();
    let result = BEARER_RE.replace_all(&result, "Bearer [REDACTED]");

    if cpf_count > 0 || bearer_count > 0 {
        info!(
            cpfs_masked = cpf_count,
            tokens_masked = bearer_count,
            "DLP: sensitive data masked in response body"
        );
        metrics::record_dlp(cpf_count as u64, bearer_count as u64);
    }

    Bytes::from(result.into_owned())
}
