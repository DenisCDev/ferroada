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

/// Process-wide DLP decision. Unset + `DLP_ENABLED=true` stays `redact` (compat).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DlpAction {
    Monitor,
    #[default]
    Redact,
    Block,
}

impl DlpAction {
    pub fn reject_incomplete_response(self) -> bool {
        matches!(self, Self::Block)
    }

    fn record_verb(self) -> &'static str {
        match self {
            Self::Monitor => "Detected",
            Self::Redact => "Masked",
            Self::Block => "Blocked",
        }
    }
}

/// Check if DLP is enabled (default: true for backward compat).
pub fn is_enabled() -> bool {
    std::env::var("DLP_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
}

pub fn parse_action(raw: Option<&str>) -> Result<DlpAction, String> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(DlpAction::Redact),
        Some("monitor") => Ok(DlpAction::Monitor),
        Some("redact") => Ok(DlpAction::Redact),
        Some("block") => Ok(DlpAction::Block),
        Some(other) => Err(format!(
            "DLP_ACTION inválido: {other} (use monitor, redact ou block)"
        )),
    }
}

pub fn action() -> DlpAction {
    parse_action(std::env::var("DLP_ACTION").ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"))
}

pub fn validate_config() {
    let _ = action();
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
    pub cpf_count: usize,
    pub bearer_count: usize,
}

impl DlpResult {
    pub fn found_sensitive(&self) -> bool {
        self.cpf_count > 0 || self.bearer_count > 0
    }

    fn passthrough(body: &[u8], complete: bool) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: complete,
            cpf_count: 0,
            bearer_count: 0,
        }
    }
}

pub fn sanitize_encoded_body(
    body: &[u8],
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    max_inflated_bytes: usize,
) -> DlpResult {
    sanitize_encoded_body_with(
        body,
        content_type,
        content_encoding,
        max_inflated_bytes,
        action(),
    )
}

pub fn sanitize_encoded_body_with(
    body: &[u8],
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    max_inflated_bytes: usize,
    dlp_action: DlpAction,
) -> DlpResult {
    let encoding = content_encoding.unwrap_or("").trim().to_ascii_lowercase();
    if encoding.is_empty() || encoding == "identity" {
        return sanitize_body_with(body, content_type, dlp_action);
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
        return DlpResult::passthrough(body, false);
    };
    let inspected = sanitize_body_with(&decoded, content_type, dlp_action);
    if inspected.bytes.as_ref() == decoded.as_slice() {
        return DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: true,
            cpf_count: inspected.cpf_count,
            bearer_count: inspected.bearer_count,
        };
    }

    let encoded = match encoding.as_str() {
        "gzip" | "x-gzip" => gzip(&inspected.bytes),
        "deflate" => deflate(&inspected.bytes),
        _ => None,
    };
    match encoded {
        Some(bytes) => DlpResult {
            bytes: Bytes::from(bytes),
            inspection_complete: true,
            cpf_count: inspected.cpf_count,
            bearer_count: inspected.bearer_count,
        },
        None => DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: false,
            cpf_count: inspected.cpf_count,
            bearer_count: inspected.bearer_count,
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
    sanitize_body_with(body, content_type, action()).bytes
}

pub fn sanitize_body_with(
    body: &[u8],
    content_type: Option<&str>,
    dlp_action: DlpAction,
) -> DlpResult {
    if !is_enabled() {
        return DlpResult::passthrough(body, true);
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
            return DlpResult::passthrough(body, true);
        }
    }

    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return DlpResult::passthrough(body, true),
    };

    let cpf_count = CPF_RE.find_iter(text).count();
    let redacted = CPF_RE.replace_all(text, "***.***.***-**");
    let bearer_count = BEARER_RE.find_iter(&redacted).count();
    let redacted = BEARER_RE.replace_all(&redacted, "Bearer [REDACTED]");

    if cpf_count > 0 || bearer_count > 0 {
        info!(
            cpfs = cpf_count,
            tokens = bearer_count,
            action = dlp_action.record_verb(),
            "DLP: sensitive data in response body"
        );
        metrics::record_dlp(
            cpf_count as u64,
            bearer_count as u64,
            dlp_action.record_verb(),
        );
    }

    let bytes = match dlp_action {
        DlpAction::Redact => Bytes::from(redacted.into_owned()),
        DlpAction::Monitor | DlpAction::Block => Bytes::copy_from_slice(body),
    };
    DlpResult {
        bytes,
        inspection_complete: true,
        cpf_count,
        bearer_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_response_is_masked_and_recompressed() {
        let compressed = gzip(b"CPF 123.456.789-00").unwrap();
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("application/json"),
            Some("gzip"),
            1024,
            DlpAction::Redact,
        );
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
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("text/plain"),
            Some("gzip"),
            1024,
            DlpAction::Redact,
        );
        assert!(result.inspection_complete);
        let mut decoded = Vec::new();
        MultiGzDecoder::new(result.bytes.as_ref())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"conteudo seguro CPF ***.***.***-**");
    }

    #[test]
    fn unset_and_empty_action_are_redact() {
        assert_eq!(parse_action(None).unwrap(), DlpAction::Redact);
        assert_eq!(parse_action(Some("")).unwrap(), DlpAction::Redact);
        assert_eq!(parse_action(Some(" redact ")).unwrap(), DlpAction::Redact);
        assert_eq!(parse_action(Some("monitor")).unwrap(), DlpAction::Monitor);
        assert_eq!(parse_action(Some("block")).unwrap(), DlpAction::Block);
        assert!(parse_action(Some("drop")).is_err());
    }

    #[test]
    fn monitor_leaves_cpf_intact_and_counts_detection() {
        let result = sanitize_body_with(
            b"CPF 123.456.789-00",
            Some("text/plain"),
            DlpAction::Monitor,
        );
        assert_eq!(result.bytes.as_ref(), b"CPF 123.456.789-00");
        assert_eq!(result.cpf_count, 1);
        assert!(result.found_sensitive());
        assert!(result.inspection_complete);
    }

    #[test]
    fn block_keeps_original_bytes_and_counts_so_proxy_can_reject() {
        let result = sanitize_body_with(
            b"token Bearer abc.def.ghi",
            Some("text/plain"),
            DlpAction::Block,
        );
        assert_eq!(result.bytes.as_ref(), b"token Bearer abc.def.ghi");
        assert_eq!(result.bearer_count, 1);
        assert!(DlpAction::Block.reject_incomplete_response());
        assert!(!DlpAction::Monitor.reject_incomplete_response());
        assert!(!DlpAction::Redact.reject_incomplete_response());
    }
}
