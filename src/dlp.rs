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

pub fn sanitize_body(body: &[u8]) -> Bytes {
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
