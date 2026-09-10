use bytes::Bytes;
use flate2::read::{DeflateDecoder, MultiGzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use serde_json::Value;
use std::io::{Read, Write};
use tracing::{info, warn};

use crate::metrics;

pub const MAX_FIELDS: usize = 32;

static CPF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{3}\.\d{3}\.\d{3}-\d{2}").expect("invalid CPF regex"));

static CNPJ_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}").expect("invalid CNPJ regex"));

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detector {
    Cpf,
    Cnpj,
    Card,
}

impl Detector {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "cpf" => Ok(Self::Cpf),
            "cnpj" => Ok(Self::Cnpj),
            "card" => Ok(Self::Card),
            other => Err(format!(
                "detector DLP inválido: {other} (use cpf, cnpj ou card)"
            )),
        }
    }

    fn matches(self, raw: &str) -> bool {
        let digits = digits_only(raw);
        match self {
            Self::Cpf => cpf_valid(&digits),
            Self::Cnpj => cnpj_valid(&digits),
            Self::Card => card_valid(&digits),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlpField {
    segments: Vec<String>,
    pub detector: Detector,
    raw: String,
}

impl DlpField {
    pub fn parse(path: &str, detector: &str) -> Result<Self, String> {
        let detector = Detector::parse(detector)?;
        let segments = parse_json_path(path)?;
        Ok(Self {
            segments,
            detector,
            raw: path.trim().to_string(),
        })
    }

    pub fn path(&self) -> &str {
        &self.raw
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
        "" | "identity" | "gzip" | "x-gzip" | "deflate" | "br" | "brotli" | "x-br"
    ) {
        None
    } else {
        Some("Unsupported response encoding was not transformed")
    }
}

#[derive(Default, Clone, Debug)]
struct Hits {
    cpf: usize,
    cnpj: usize,
    card: usize,
    bearer: usize,
    fields: Vec<String>,
}

impl Hits {
    fn add(&mut self, other: Self) {
        self.cpf += other.cpf;
        self.cnpj += other.cnpj;
        self.card += other.card;
        self.bearer += other.bearer;
        self.fields.extend(other.fields);
    }

    fn bump_detector(&mut self, detector: Detector) {
        match detector {
            Detector::Cpf => self.cpf += 1,
            Detector::Cnpj => self.cnpj += 1,
            Detector::Card => self.card += 1,
        }
    }

    fn any(&self) -> bool {
        self.cpf > 0 || self.cnpj > 0 || self.card > 0 || self.bearer > 0
    }
}

pub struct DlpResult {
    pub bytes: Bytes,
    pub inspection_complete: bool,
    pub cpf_count: usize,
    pub cnpj_count: usize,
    pub card_count: usize,
    pub bearer_count: usize,
}

impl DlpResult {
    pub fn found_sensitive(&self) -> bool {
        self.cpf_count > 0 || self.cnpj_count > 0 || self.card_count > 0 || self.bearer_count > 0
    }

    fn passthrough(body: &[u8], complete: bool) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: complete,
            cpf_count: 0,
            cnpj_count: 0,
            card_count: 0,
            bearer_count: 0,
        }
    }

    fn from_hits(bytes: Bytes, complete: bool, hits: &Hits) -> Self {
        Self {
            bytes,
            inspection_complete: complete,
            cpf_count: hits.cpf,
            cnpj_count: hits.cnpj,
            card_count: hits.card,
            bearer_count: hits.bearer,
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
        &[],
    )
}

pub fn sanitize_encoded_body_with(
    body: &[u8],
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    max_inflated_bytes: usize,
    dlp_action: DlpAction,
    fields: &[DlpField],
) -> DlpResult {
    let encoding = content_encoding.unwrap_or("").trim().to_ascii_lowercase();
    if encoding.is_empty() || encoding == "identity" {
        return sanitize_body_with(body, content_type, dlp_action, fields);
    }

    let decoded = match encoding.as_str() {
        "gzip" | "x-gzip" => read_bounded(MultiGzDecoder::new(body), max_inflated_bytes),
        "deflate" => read_bounded(DeflateDecoder::new(body), max_inflated_bytes),
        "br" | "brotli" | "x-br" => {
            read_bounded(brotli::Decompressor::new(body, 4096), max_inflated_bytes)
        }
        _ => None,
    };
    let Some(decoded) = decoded else {
        warn!(
            encoding,
            "DLP skipped: compressed response could not be decoded within limit"
        );
        return DlpResult::passthrough(body, false);
    };
    let inspected = sanitize_body_with(&decoded, content_type, dlp_action, fields);
    if inspected.bytes.as_ref() == decoded.as_slice() {
        return DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: true,
            cpf_count: inspected.cpf_count,
            cnpj_count: inspected.cnpj_count,
            card_count: inspected.card_count,
            bearer_count: inspected.bearer_count,
        };
    }

    let encoded = match encoding.as_str() {
        "gzip" | "x-gzip" => gzip(&inspected.bytes),
        "deflate" => deflate(&inspected.bytes),
        "br" | "brotli" | "x-br" => brotli_compress(&inspected.bytes),
        _ => None,
    };
    match encoded {
        Some(bytes) => DlpResult {
            bytes: Bytes::from(bytes),
            inspection_complete: true,
            cpf_count: inspected.cpf_count,
            cnpj_count: inspected.cnpj_count,
            card_count: inspected.card_count,
            bearer_count: inspected.bearer_count,
        },
        None => DlpResult {
            bytes: Bytes::copy_from_slice(body),
            inspection_complete: false,
            cpf_count: inspected.cpf_count,
            cnpj_count: inspected.cnpj_count,
            card_count: inspected.card_count,
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

fn brotli_compress(body: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    encoder.write_all(body).ok()?;
    encoder.flush().ok()?;
    Some(encoder.into_inner())
}

pub fn sanitize_body(body: &[u8], content_type: Option<&str>) -> Bytes {
    sanitize_body_with(body, content_type, action(), &[]).bytes
}

pub fn sanitize_body_with(
    body: &[u8],
    content_type: Option<&str>,
    dlp_action: DlpAction,
    fields: &[DlpField],
) -> DlpResult {
    if !is_enabled() {
        return DlpResult::passthrough(body, true);
    }

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

    let mut hits = Hits::default();
    let mut working = text.to_string();
    if !fields.is_empty() && is_json(content_type) {
        if let Ok(mut value) = serde_json::from_str::<Value>(text) {
            let (field_hits, mutated) = apply_fields(&mut value, fields, dlp_action);
            hits.add(field_hits);
            if mutated {
                if let Ok(serialized) = serde_json::to_string(&value) {
                    working = serialized;
                }
            }
        }
    }

    let (redacted, blob_hits) = redact_blob(&working, is_json(content_type));
    hits.add(blob_hits);

    if hits.any() {
        info!(
            cpfs = hits.cpf,
            cnpjs = hits.cnpj,
            cards = hits.card,
            tokens = hits.bearer,
            fields = hits.fields.join(","),
            action = dlp_action.record_verb(),
            "DLP: sensitive data in response body"
        );
        metrics::record_dlp(
            hits.cpf as u64,
            hits.cnpj as u64,
            hits.card as u64,
            hits.bearer as u64,
            dlp_action.record_verb(),
            &hits.fields,
        );
    }

    let bytes = match dlp_action {
        DlpAction::Redact => Bytes::from(redacted),
        DlpAction::Monitor | DlpAction::Block => Bytes::copy_from_slice(body),
    };
    DlpResult::from_hits(bytes, true, &hits)
}

fn is_json(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let mime = ct
        .split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase();
    mime == "application/json" || mime.ends_with("+json")
}

fn apply_fields(value: &mut Value, fields: &[DlpField], action: DlpAction) -> (Hits, bool) {
    let mut hits = Hits::default();
    let mut mutated = false;
    for field in fields {
        let Some(target) = navigate_mut(value, &field.segments) else {
            continue;
        };
        let raw = match target {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            _ => continue,
        };
        if !field.detector.matches(&raw) {
            continue;
        }
        hits.bump_detector(field.detector);
        hits.fields.push(field.raw.clone());
        if action == DlpAction::Redact {
            *target = Value::String(mask_digits(&raw));
            mutated = true;
        }
    }
    (hits, mutated)
}

fn navigate_mut<'a>(root: &'a mut Value, segments: &[String]) -> Option<&'a mut Value> {
    let mut current = root;
    for segment in segments {
        current = match current {
            Value::Object(map) => map.get_mut(segment)?,
            _ => return None,
        };
    }
    Some(current)
}

fn redact_blob(text: &str, json_body: bool) -> (String, Hits) {
    let mut hits = Hits::default();
    let after_cpf = CPF_RE.replace_all(text, |caps: &Captures| {
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if cpf_valid(&digits_only(matched)) {
            hits.cpf += 1;
            mask_digits(matched)
        } else {
            matched.to_string()
        }
    });
    let after_cnpj = CNPJ_RE.replace_all(&after_cpf, |caps: &Captures| {
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if cnpj_valid(&digits_only(matched)) {
            hits.cnpj += 1;
            mask_digits(matched)
        } else {
            matched.to_string()
        }
    });
    let (after_card, card_count) = mask_cards(&after_cnpj, json_body);
    hits.card += card_count;
    let after_bearer = BEARER_RE.replace_all(&after_card, |_caps: &Captures| {
        hits.bearer += 1;
        "Bearer [REDACTED]".to_string()
    });
    (after_bearer.into_owned(), hits)
}

fn mask_cards(text: &str, json_body: bool) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() + 8);
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            let ch = text[i..].chars().next().unwrap_or('\u{fffd}');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let run_end = card_run_end(bytes, i);
        if let Some(card_end) = best_card_end(bytes, i, run_end) {
            count += 1;
            let quote = json_body && is_json_number_token(text, i, card_end);
            if quote {
                out.push('"');
            }
            for &b in &bytes[i..card_end] {
                out.push(if b.is_ascii_digit() { '*' } else { b as char });
            }
            if quote {
                out.push('"');
            }
            i = card_end;
            continue;
        }
        out.push_str(&text[i..run_end]);
        i = run_end;
    }
    (out, count)
}

fn card_run_end(bytes: &[u8], start: usize) -> usize {
    let mut k = start;
    while k < bytes.len()
        && (bytes[k].is_ascii_digit()
            || (matches!(bytes[k], b' ' | b'-')
                && k + 1 < bytes.len()
                && bytes[k + 1].is_ascii_digit()))
    {
        k += 1;
    }
    k
}

fn best_card_end(bytes: &[u8], start: usize, run_end: usize) -> Option<usize> {
    let mut digits = Vec::new();
    let mut best = None;
    let mut k = start;
    while k < run_end {
        if bytes[k].is_ascii_digit() {
            digits.push(bytes[k] - b'0');
            let end = k + 1;
            let n = digits.len();
            if (13..=19).contains(&n) && card_valid(&digits) {
                let boundary = end == run_end || !bytes[end].is_ascii_digit();
                if boundary {
                    best = Some(end);
                }
            }
            k += 1;
        } else if matches!(bytes[k], b' ' | b'-') {
            k += 1;
        } else {
            break;
        }
    }
    best
}

fn is_json_number_token(text: &str, start: usize, end: usize) -> bool {
    if !text.as_bytes()[start..end].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let before = text[..start].chars().rev().find(|c| !c.is_whitespace());
    let after = text[end..].chars().find(|c| !c.is_whitespace());
    matches!(before, Some(':' | '[' | ',')) && matches!(after, None | Some(',' | '}' | ']'))
}

fn mask_digits(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_digit() { '*' } else { c })
        .collect()
}

fn digits_only(raw: &str) -> Vec<u8> {
    raw.chars()
        .filter(char::is_ascii_digit)
        .map(|c| (c as u8) - b'0')
        .collect()
}

fn all_same(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|first| digits.iter().all(|digit| digit == first))
}

fn cpf_valid(digits: &[u8]) -> bool {
    if digits.len() != 11 || all_same(digits) {
        return false;
    }
    let first = mod11(&digits[..9], 10);
    let second = mod11(&digits[..10], 11);
    digits[9] == first && digits[10] == second
}

fn cnpj_valid(digits: &[u8]) -> bool {
    if digits.len() != 14 || all_same(digits) {
        return false;
    }
    let first = cnpj_check(&digits[..12], 5);
    let second = cnpj_check(&digits[..13], 6);
    digits[12] == first && digits[13] == second
}

fn card_valid(digits: &[u8]) -> bool {
    (13..=19).contains(&digits.len()) && !all_same(digits) && luhn(digits)
}

fn mod11(digits: &[u8], start_weight: u32) -> u8 {
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, digit)| u32::from(*digit) * (start_weight - index as u32))
        .sum();
    let rem = sum % 11;
    if rem < 2 {
        0
    } else {
        (11 - rem) as u8
    }
}

fn cnpj_check(digits: &[u8], first_weight: u32) -> u8 {
    let mut weight = first_weight;
    let mut sum = 0u32;
    for digit in digits {
        sum += u32::from(*digit) * weight;
        weight = if weight == 2 { 9 } else { weight - 1 };
    }
    let rem = sum % 11;
    if rem < 2 {
        0
    } else {
        (11 - rem) as u8
    }
}

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut n = u32::from(*digit);
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn parse_json_path(raw: &str) -> Result<Vec<String>, String> {
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix('$').ok_or_else(|| {
        format!("path JSON DLP inválido {trimmed:?}: deve começar com $ (ex. $.user.cpf)")
    })?;
    if rest.is_empty() {
        return Err("path JSON DLP precisa de ao menos um segmento depois de $".into());
    }
    let mut segments = Vec::new();
    let bytes = rest.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            return Err(format!(
                "path JSON DLP inválido {trimmed:?}: use segmentos .nome"
            ));
        }
        index += 1;
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
                || bytes[index] == b'_'
                || bytes[index] == b'-')
        {
            index += 1;
        }
        if start == index || index - start > 64 {
            return Err(format!("path JSON DLP inválido {trimmed:?}"));
        }
        segments.push(rest[start..index].to_string());
        if segments.len() > 16 {
            return Err(format!("path JSON DLP {trimmed:?} excede 16 segmentos"));
        }
    }
    if segments.is_empty() {
        return Err(format!("path JSON DLP inválido {trimmed:?}"));
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CPF: &str = "390.533.447-05";
    const INVALID_CPF: &str = "123.456.789-00";
    const VALID_CNPJ: &str = "04.252.011/0001-10";
    const INVALID_CNPJ: &str = "04.252.011/0001-11";
    const VALID_CARD: &str = "4111111111111111";
    const INVALID_CARD: &str = "4111111111111112";

    fn cpf_field() -> DlpField {
        DlpField::parse("$.user.cpf", "cpf").unwrap()
    }

    #[test]
    fn check_digits_accept_known_valid_and_reject_invalid() {
        assert!(cpf_valid(&digits_only(VALID_CPF)));
        assert!(!cpf_valid(&digits_only(INVALID_CPF)));
        assert!(!cpf_valid(&digits_only("111.111.111-11")));
        assert!(cnpj_valid(&digits_only(VALID_CNPJ)));
        assert!(!cnpj_valid(&digits_only(INVALID_CNPJ)));
        assert!(card_valid(&digits_only(VALID_CARD)));
        assert!(!card_valid(&digits_only(INVALID_CARD)));
        assert!(!card_valid(&digits_only("0000000000000000")));
    }

    #[test]
    fn gzip_response_is_masked_and_recompressed() {
        let compressed = gzip(format!("CPF {VALID_CPF}").as_bytes()).unwrap();
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("application/json"),
            Some("gzip"),
            1024,
            DlpAction::Redact,
            &[],
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
        compressed.extend(gzip(format!("CPF {VALID_CPF}").as_bytes()).unwrap());
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("text/plain"),
            Some("gzip"),
            1024,
            DlpAction::Redact,
            &[],
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
        let body = format!("CPF {VALID_CPF}");
        let result =
            sanitize_body_with(body.as_bytes(), Some("text/plain"), DlpAction::Monitor, &[]);
        assert_eq!(result.bytes.as_ref(), body.as_bytes());
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
            &[],
        );
        assert_eq!(result.bytes.as_ref(), b"token Bearer abc.def.ghi");
        assert_eq!(result.bearer_count, 1);
        assert!(DlpAction::Block.reject_incomplete_response());
        assert!(!DlpAction::Monitor.reject_incomplete_response());
        assert!(!DlpAction::Redact.reject_incomplete_response());
    }

    #[test]
    fn invalid_cpf_is_not_masked() {
        let body = format!("CPF {INVALID_CPF}");
        let result =
            sanitize_body_with(body.as_bytes(), Some("text/plain"), DlpAction::Redact, &[]);
        assert_eq!(result.bytes.as_ref(), body.as_bytes());
        assert_eq!(result.cpf_count, 0);
        assert!(!result.found_sensitive());
    }

    #[test]
    fn json_field_redacts_valid_cpf_and_leaves_invalid() {
        let valid = serde_json::json!({"user":{"cpf": VALID_CPF}}).to_string();
        let result = sanitize_body_with(
            valid.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[cpf_field()],
        );
        let value: Value = serde_json::from_slice(&result.bytes).unwrap();
        assert_eq!(value["user"]["cpf"], "***.***.***-**");
        assert_eq!(result.cpf_count, 1);
        assert!(!String::from_utf8_lossy(&result.bytes).contains(VALID_CPF));

        let invalid = serde_json::json!({"user":{"cpf": INVALID_CPF}}).to_string();
        let result = sanitize_body_with(
            invalid.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[cpf_field()],
        );
        assert_eq!(result.bytes.as_ref(), invalid.as_bytes());
        assert_eq!(result.cpf_count, 0);
    }

    #[test]
    fn unformatted_cpf_needs_field_path() {
        let body = r#"{"user":{"cpf":"39053344705"}}"#;
        let blob = sanitize_body_with(
            body.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[],
        );
        assert_eq!(blob.bytes.as_ref(), body.as_bytes());
        assert_eq!(blob.cpf_count, 0);

        let field = sanitize_body_with(
            body.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[cpf_field()],
        );
        let value: Value = serde_json::from_slice(&field.bytes).unwrap();
        assert_eq!(value["user"]["cpf"], "***********");
        assert_eq!(field.cpf_count, 1);
    }

    #[test]
    fn luhn_card_is_detected_and_invalid_is_not() {
        let valid = format!("pay {VALID_CARD}");
        let result =
            sanitize_body_with(valid.as_bytes(), Some("text/plain"), DlpAction::Redact, &[]);
        assert_eq!(result.card_count, 1);
        assert!(!String::from_utf8_lossy(&result.bytes).contains(VALID_CARD));

        let invalid = format!("pay {INVALID_CARD}");
        let result = sanitize_body_with(
            invalid.as_bytes(),
            Some("text/plain"),
            DlpAction::Redact,
            &[],
        );
        assert_eq!(result.card_count, 0);
        assert_eq!(result.bytes.as_ref(), invalid.as_bytes());
    }

    #[test]
    fn json_number_card_redact_stays_json() {
        let body = r#"{"pay":4111111111111111}"#;
        let result = sanitize_body_with(
            body.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[],
        );
        assert_eq!(result.card_count, 1);
        let value: Value =
            serde_json::from_slice(&result.bytes).expect("blob card mask must keep JSON parseable");
        assert_eq!(value["pay"], "****************");
        assert!(!String::from_utf8_lossy(&result.bytes).contains(VALID_CARD));
    }

    #[test]
    fn card_before_expiry_is_masked() {
        let body = format!("{VALID_CARD} 12/25");
        let result =
            sanitize_body_with(body.as_bytes(), Some("text/plain"), DlpAction::Redact, &[]);
        assert_eq!(result.card_count, 1);
        let out = String::from_utf8_lossy(&result.bytes);
        assert!(!out.contains(VALID_CARD));
        assert!(out.contains("12/25"), "expiry must remain: {out}");
    }

    #[test]
    fn brotli_is_inspected_when_budget_allows() {
        assert!(can_inspect(Some("text/plain"), Some("br")));
        let compressed = brotli_compress(format!("CPF {VALID_CPF}").as_bytes()).unwrap();
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("text/plain"),
            Some("br"),
            1024,
            DlpAction::Redact,
            &[],
        );
        assert!(result.inspection_complete);
        assert_eq!(result.cpf_count, 1);
        let mut decoded = Vec::new();
        brotli::Decompressor::new(result.bytes.as_ref(), 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"CPF ***.***.***-**");
    }

    #[test]
    fn brotli_over_budget_is_incomplete_not_silent_redact() {
        let compressed = brotli_compress(&vec![b'a'; 2048]).unwrap();
        let result = sanitize_encoded_body_with(
            &compressed,
            Some("text/plain"),
            Some("br"),
            16,
            DlpAction::Redact,
            &[],
        );
        assert!(!result.inspection_complete);
        assert_eq!(result.bytes.as_ref(), compressed.as_slice());
        assert_eq!(result.cpf_count, 0);
    }

    #[test]
    fn dlp_event_does_not_include_secret_value() {
        let body = serde_json::json!({"user":{"cpf": VALID_CPF}}).to_string();
        let _ = sanitize_body_with(
            body.as_bytes(),
            Some("application/json"),
            DlpAction::Redact,
            &[cpf_field()],
        );
        let snap = metrics::snapshot_json();
        assert!(
            !snap.contains(VALID_CPF),
            "event must not log the CPF value: {snap}"
        );
        assert!(
            !snap.contains("39053344705"),
            "event must not log digits: {snap}"
        );
    }

    #[test]
    fn json_path_must_be_dotted_from_root() {
        assert!(DlpField::parse("user.cpf", "cpf").is_err());
        assert!(DlpField::parse("$", "cpf").is_err());
        assert!(DlpField::parse("$.user.cpf", "token").is_err());
        assert!(DlpField::parse("$.user.cpf", "cpf").is_ok());
    }
}
