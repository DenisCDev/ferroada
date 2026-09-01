use bytes::Bytes;
use flate2::read::{DeflateDecoder, MultiGzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use once_cell::sync::Lazy;
use regex::Regex;
use std::io::{Read, Write};
use tracing::{info, warn};

use crate::metrics;

static CPF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{3}\.\d{3}\.\d{3}-\d{2}").expect("invalid CPF regex"));

static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*").expect("invalid Bearer regex"));

/// Check if DLP masking is enabled (default: true for backward compat).
pub fn is_enabled() -> bool {
    std::env::var("DLP_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
}

pub fn can_inspect(content_type: Option<&str>, content_encoding: Option<&str>) -> bool {
    skip_reason(content_type, content_encoding).is_none()
}

pub fn skip_reason(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> Option<&'static str> {
    if !is_enabled() {
        return Some("DLP is disabled");
    }
    if let Some(content_type) = content_type {
        let content_type = content_type.to_ascii_lowercase();
        if content_type.starts_with("text/event-stream")
            || content_type.starts_with("application/grpc")
            || content_type.starts_with("application/x-ndjson")
            || content_type.starts_with("application/json-seq")
            || content_type.starts_with("application/stream+json")
        {
            return Some("Streaming response was not transformed");
        }
        if content_type.starts_with("image/")
            || content_type.starts_with("video/")
            || content_type.starts_with("audio/")
            || content_type.starts_with("application/octet-stream")
            || content_type.starts_with("application/pdf")
            || content_type.starts_with("application/zip")
            || content_type.starts_with("application/gzip")
        {
            return Some("Binary response was not transformed");
        }
    }
    if matches!(
        content_encoding
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "" | "identity" | "gzip" | "x-gzip" | "deflate"
    ) {
        None
    } else {
        Some("Unsupported response encoding was not transformed")
    }
}

pub struct DlpResult {
    pub bytes: Bytes,
    pub inspection_complete: bool,
}

pub fn sanitize_encoded_body(
    body: &[u8],
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    max_inflated_bytes: usize,
) -> DlpResult {
    let encoding = content_encoding.unwrap_or("").trim().to_ascii_lowercase();
    if encoding.is_empty() || encoding == "identity" {
        return DlpResult {
            bytes: sanitize_body(body, content_type),
            inspection_complete: true,
        };
    }

    let decoded = match encoding.as_str() {
        "gzip" | "x-gzip" => read_bounded(MultiGzDecoder::new(body), max_inflated_bytes),
        "deflate" => read_bounded(DeflateDecoder::new(body), max_inflated_bytes),
        _ => None,
    };
    let Some(decoded) = decoded else {
        warn!(
            encoding,
            "DLP skipped: compressed response could not be decoded within limit"
        );
        return DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: false,
        };
    };
    let sanitized = sanitize_body(&decoded, content_type);
    if sanitized.as_ref() == decoded.as_slice() {
        return DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: true,
        };
    }

    let encoded = match encoding.as_str() {
        "gzip" | "x-gzip" => gzip(&sanitized),
        "deflate" => deflate(&sanitized),
        _ => None,
    };
    match encoded {
        Some(bytes) => DlpResult {
            bytes: Bytes::from(bytes),
            inspection_complete: true,
        },
        None => DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: false,
        },
    }
}

fn read_bounded<R: Read>(reader: R, limit: usize) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut reader = reader.take(limit.saturating_add(1) as u64);
    reader.read_to_end(&mut output).ok()?;
    if output.len() > limit {
        return None;
    }
    Some(output)
}

fn gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).ok()?;
    encoder.finish().ok()
}

fn deflate(body: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).ok()?;
    encoder.finish().ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_response_is_masked_and_recompressed() {
        let compressed = gzip(b"CPF 123.456.789-00").unwrap();
        let result =
            sanitize_encoded_body(&compressed, Some("application/json"), Some("gzip"), 1024);
        assert!(result.inspection_complete);
        let mut decoded = Vec::new();
        MultiGzDecoder::new(result.bytes.as_ref())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"CPF ***.***.***-**");
    }

    #[test]
    fn compressed_response_expansion_is_bounded() {
        let compressed = gzip(&vec![b'a'; 2048]).unwrap();
        let result = sanitize_encoded_body(&compressed, Some("text/plain"), Some("gzip"), 1024);
        assert!(!result.inspection_complete);
        assert_eq!(result.bytes.as_ref(), compressed.as_slice());
    }

    #[test]
    fn streaming_response_is_not_buffered_for_dlp() {
        assert!(!can_inspect(Some("text/event-stream"), None));
        assert!(!can_inspect(Some("application/grpc+proto"), None));
        assert!(!can_inspect(Some("application/x-ndjson"), None));
        assert_eq!(
            skip_reason(Some("text/event-stream"), None),
            Some("Streaming response was not transformed")
        );
    }

    #[test]
    fn concatenated_gzip_members_are_all_masked() {
        let mut compressed = gzip(b"conteudo seguro ").unwrap();
        compressed.extend(gzip(b"CPF 123.456.789-00").unwrap());
        let result = sanitize_encoded_body(&compressed, Some("text/plain"), Some("gzip"), 1024);
        assert!(result.inspection_complete);
        let mut decoded = Vec::new();
        MultiGzDecoder::new(result.bytes.as_ref())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"conteudo seguro CPF ***.***.***-**");
    }
}
