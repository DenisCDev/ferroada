//! gRPC method allowlist via FileDescriptorSet (PR 17). Opt-in per site.
//! Events name service/method and never include the protobuf payload.

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, ServiceDescriptor};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_MAX_MESSAGE: usize = 64 * 1024;
const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);
const HARD_MAX_MESSAGE: usize = 16 * 1024 * 1024;
const HARD_MAX_DEADLINE: Duration = Duration::from_secs(600);
const HARD_MAX_ALLOW: usize = 10_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcFile {
    pub descriptor: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub max_message_bytes: Option<String>,
    #[serde(default)]
    pub reflection: Option<bool>,
    #[serde(default)]
    pub deadline: Option<String>,
    #[serde(default)]
    pub require_deadline: Option<bool>,
}

#[derive(Clone)]
pub struct GrpcPolicy {
    inner: Arc<GrpcInner>,
}

struct GrpcInner {
    pool: DescriptorPool,
    allow: HashSet<String>,
    max_message_bytes: usize,
    reflection: bool,
    deadline: Duration,
    require_deadline: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrpcVerdict {
    Skip,
    Allow { timeout: Option<String> },
    Deny(GrpcFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrpcFailure {
    ParseError,
    Method(String),
}

impl GrpcFailure {
    pub fn detail(&self) -> &str {
        match self {
            Self::ParseError => "ParseError",
            Self::Method(rpc) => rpc.as_str(),
        }
    }
}

impl std::fmt::Debug for GrpcPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcPolicy")
            .field("allow", &self.inner.allow)
            .field("max_message_bytes", &self.inner.max_message_bytes)
            .field("reflection", &self.inner.reflection)
            .field("deadline", &self.inner.deadline)
            .field("require_deadline", &self.inner.require_deadline)
            .finish()
    }
}

impl GrpcPolicy {
    pub fn from_bytes(bytes: &[u8], file: &GrpcFile) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("gRPC descriptor vazio".into());
        }
        let pool = DescriptorPool::decode(bytes)
            .map_err(|error| format!("gRPC descriptor inválido: {error}"))?;
        if file.allow.len() > HARD_MAX_ALLOW {
            return Err(format!(
                "gRPC allow aceita no máximo {HARD_MAX_ALLOW} métodos, veio {}",
                file.allow.len()
            ));
        }
        let mut allow = HashSet::new();
        for raw in &file.allow {
            let rpc = normalize_rpc(raw)
                .ok_or_else(|| format!("gRPC allow entrada inválida: {raw:?}"))?;
            if is_reflection(&rpc) {
                allow.insert(rpc);
                continue;
            }
            let (service, method) =
                split_rpc(&rpc).ok_or_else(|| format!("gRPC allow entrada inválida: {raw:?}"))?;
            let Some(svc) = pool.get_service_by_name(service) else {
                return Err(format!(
                    "gRPC allow lista {rpc} que não existe no descriptor"
                ));
            };
            if method_by_name(&svc, method).is_none() {
                return Err(format!(
                    "gRPC allow lista {rpc} que não existe no descriptor"
                ));
            }
            allow.insert(rpc);
        }
        let max_message_bytes = match file.max_message_bytes.as_deref() {
            Some(raw) => {
                let size = crate::config::parse_byte_size(raw)?;
                if size > HARD_MAX_MESSAGE {
                    return Err(format!(
                        "gRPC max_message_bytes {raw} excede o teto de {HARD_MAX_MESSAGE} bytes"
                    ));
                }
                size
            }
            None => DEFAULT_MAX_MESSAGE,
        };
        let deadline = match file.deadline.as_deref() {
            Some(raw) => parse_deadline(raw)?,
            None => DEFAULT_DEADLINE,
        };
        Ok(Self {
            inner: Arc::new(GrpcInner {
                pool,
                allow,
                max_message_bytes,
                reflection: file.reflection.unwrap_or(false),
                deadline,
                require_deadline: file.require_deadline.unwrap_or(false),
            }),
        })
    }

    pub fn check_headers(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        grpc_timeout: Option<&str>,
    ) -> GrpcVerdict {
        if !is_grpc_content_type(content_type) {
            return GrpcVerdict::Skip;
        }
        let rpc = rpc_from_path(path);
        if !method.eq_ignore_ascii_case("POST") {
            return GrpcVerdict::Deny(GrpcFailure::Method(rpc));
        }
        if is_reflection(&rpc) {
            if !self.inner.reflection {
                return GrpcVerdict::Deny(GrpcFailure::Method(rpc));
            }
            return timeout_verdict(&rpc, grpc_timeout, &self.inner);
        }
        if !self.inner.allow.contains(&rpc) {
            return GrpcVerdict::Deny(GrpcFailure::Method(rpc));
        }
        timeout_verdict(&rpc, grpc_timeout, &self.inner)
    }

    pub fn check_body(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> GrpcVerdict {
        if !is_grpc_content_type(content_type) {
            return GrpcVerdict::Skip;
        }
        if !method.eq_ignore_ascii_case("POST") {
            return GrpcVerdict::Deny(GrpcFailure::Method(rpc_from_path(path)));
        }
        let rpc = rpc_from_path(path);
        match iter_frames(body, self.inner.max_message_bytes) {
            Err(FrameFail::Size) => GrpcVerdict::Deny(GrpcFailure::Method(rpc)),
            Err(FrameFail::Parse) => GrpcVerdict::Deny(GrpcFailure::ParseError),
            Ok(frames) => {
                if is_reflection(&rpc) {
                    if !self.inner.reflection {
                        return GrpcVerdict::Deny(GrpcFailure::Method(rpc));
                    }
                    return GrpcVerdict::Allow { timeout: None };
                }
                if !self.inner.allow.contains(&rpc) {
                    return GrpcVerdict::Deny(GrpcFailure::Method(rpc));
                }
                let Some((service, method_name)) = split_rpc(&rpc) else {
                    return GrpcVerdict::Deny(GrpcFailure::ParseError);
                };
                let Some(input) = input_descriptor(&self.inner.pool, service, method_name) else {
                    return GrpcVerdict::Deny(GrpcFailure::ParseError);
                };
                for frame in frames {
                    if DynamicMessage::decode(input.clone(), frame).is_err() {
                        return GrpcVerdict::Deny(GrpcFailure::ParseError);
                    }
                }
                GrpcVerdict::Allow { timeout: None }
            }
        }
    }
}

pub fn is_grpc_content_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("application/grpc")
}

fn timeout_verdict(rpc: &str, grpc_timeout: Option<&str>, inner: &GrpcInner) -> GrpcVerdict {
    match grpc_timeout
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None if inner.require_deadline => GrpcVerdict::Deny(GrpcFailure::Method(rpc.to_string())),
        None => GrpcVerdict::Allow {
            timeout: Some(encode_grpc_timeout(inner.deadline)),
        },
        Some(raw) => match parse_grpc_timeout(raw) {
            None => GrpcVerdict::Deny(GrpcFailure::Method(rpc.to_string())),
            Some(got) if got > inner.deadline => GrpcVerdict::Allow {
                timeout: Some(encode_grpc_timeout(inner.deadline)),
            },
            Some(_) => GrpcVerdict::Allow { timeout: None },
        },
    }
}

fn method_by_name(
    svc: &ServiceDescriptor,
    method: &str,
) -> Option<prost_reflect::MethodDescriptor> {
    svc.methods().find(|item| item.name() == method)
}

fn input_descriptor(
    pool: &DescriptorPool,
    service: &str,
    method: &str,
) -> Option<prost_reflect::MessageDescriptor> {
    let svc: ServiceDescriptor = pool.get_service_by_name(service)?;
    Some(method_by_name(&svc, method)?.input())
}

fn rpc_from_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let path = crate::config::canonical_route_path(path).unwrap_or_else(|| path.to_string());
    normalize_rpc(&path).unwrap_or_else(|| path.trim_start_matches('/').to_string())
}

fn normalize_rpc(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let trimmed = trimmed.trim_start_matches('/');
    let (service, method) = trimmed.rsplit_once('/')?;
    if service.is_empty() || method.is_empty() {
        return None;
    }
    if service.contains('/') || method.contains('/') {
        return None;
    }
    if !service
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
        || !method
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(format!("{service}/{method}"))
}

fn split_rpc(rpc: &str) -> Option<(&str, &str)> {
    rpc.rsplit_once('/')
}

fn is_reflection(rpc: &str) -> bool {
    matches!(
        rpc,
        "grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
            | "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
    )
}

enum FrameFail {
    Parse,
    Size,
}

fn iter_frames(body: &[u8], max: usize) -> Result<Vec<&[u8]>, FrameFail> {
    let mut i = 0;
    let mut frames = Vec::new();
    while i < body.len() {
        let remaining = body.len() - i;
        if remaining < 5 {
            return Err(FrameFail::Parse);
        }
        let compressed = body[i];
        let claimed = u32::from_be_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]);
        let claimed = usize::try_from(claimed).map_err(|_| FrameFail::Size)?;
        if claimed > max {
            return Err(FrameFail::Size);
        }
        if compressed != 0 {
            return Err(FrameFail::Parse);
        }
        i += 5;
        if body.len() - i < claimed {
            return Err(FrameFail::Parse);
        }
        frames.push(&body[i..i + claimed]);
        i += claimed;
    }
    Ok(frames)
}

fn parse_deadline(raw: &str) -> Result<Duration, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("gRPC deadline vazio".into());
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, unit_ms) = if let Some(number) = lower.strip_suffix("ms") {
        (number.trim(), 1u64)
    } else if let Some(number) = lower.strip_suffix('s') {
        (number.trim(), 1000u64)
    } else if let Some(number) = lower.strip_suffix('m') {
        (number.trim(), 60_000u64)
    } else {
        (trimmed, 1000u64)
    };
    let value: u64 = number
        .parse()
        .map_err(|_| format!("gRPC deadline inválido: {raw}"))?;
    let millis = value
        .checked_mul(unit_ms)
        .ok_or_else(|| format!("gRPC deadline inválido: {raw}"))?;
    if millis == 0 {
        return Err(format!("gRPC deadline inválido: {raw}"));
    }
    let duration = Duration::from_millis(millis);
    if duration > HARD_MAX_DEADLINE {
        return Err(format!(
            "gRPC deadline {raw} excede o teto de {}s",
            HARD_MAX_DEADLINE.as_secs()
        ));
    }
    Ok(duration)
}

fn parse_grpc_timeout(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    if raw.len() < 2 || raw.len() > 9 {
        return None;
    }
    let (digits, unit) = raw.split_at(raw.len() - 1);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    let duration = match unit {
        "H" => Duration::from_secs(value.checked_mul(3600)?),
        "M" => Duration::from_secs(value.checked_mul(60)?),
        "S" => Duration::from_secs(value),
        "m" => Duration::from_millis(value),
        "u" => Duration::from_micros(value),
        "n" => Duration::from_nanos(value),
        _ => return None,
    };
    Some(duration)
}

fn encode_grpc_timeout(deadline: Duration) -> String {
    let millis = deadline.as_millis();
    if millis.is_multiple_of(1000) {
        let secs = (millis / 1000).min(99_999_999);
        format!("{secs}S")
    } else {
        format!("{}m", millis.min(99_999_999))
    }
}

/// FileDescriptorSet for `pkg.Service/{Allowed,Other}` — tests and load fixtures.
#[doc(hidden)]
pub fn test_hello_descriptor_bytes() -> Vec<u8> {
    hello_descriptor_set().encode_to_vec()
}

fn hello_descriptor_set() -> prost_types::FileDescriptorSet {
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
    };
    const TYPE_STRING: i32 = 9;
    const LABEL_OPTIONAL: i32 = 1;

    fn field(name: &str) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.into()),
            number: Some(1),
            label: Some(LABEL_OPTIONAL),
            r#type: Some(TYPE_STRING),
            json_name: Some(name.into()),
            ..Default::default()
        }
    }
    fn message(name: &str, field_name: &str) -> DescriptorProto {
        DescriptorProto {
            name: Some(name.into()),
            field: vec![field(field_name)],
            ..Default::default()
        }
    }
    fn rpc(name: &str) -> MethodDescriptorProto {
        MethodDescriptorProto {
            name: Some(name.into()),
            input_type: Some(".pkg.HelloReq".into()),
            output_type: Some(".pkg.HelloResp".into()),
            ..Default::default()
        }
    }

    FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("api.proto".into()),
            package: Some("pkg".into()),
            syntax: Some("proto3".into()),
            message_type: vec![message("HelloReq", "name"), message("HelloResp", "message")],
            service: vec![ServiceDescriptorProto {
                name: Some("Service".into()),
                method: vec![rpc("Allowed"), rpc("Other")],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> GrpcPolicy {
        GrpcPolicy::from_bytes(
            &test_hello_descriptor_bytes(),
            &GrpcFile {
                descriptor: "./api.pb".into(),
                allow: vec!["pkg.Service/Allowed".into()],
                max_message_bytes: Some("64".into()),
                reflection: Some(false),
                deadline: None,
                require_deadline: None,
            },
        )
        .unwrap()
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn hello(name: &str) -> Vec<u8> {
        let mut msg = vec![0x0A, name.len() as u8];
        msg.extend_from_slice(name.as_bytes());
        frame(&msg)
    }

    #[test]
    fn allowed_method_with_valid_message_allows() {
        let p = policy();
        assert!(matches!(
            p.check_headers(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                None
            ),
            GrpcVerdict::Allow { timeout: Some(_) }
        ));
        assert_eq!(
            p.check_body(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc+proto"),
                &hello("ok")
            ),
            GrpcVerdict::Allow { timeout: None }
        );
    }

    #[test]
    fn unknown_method_is_denied() {
        let p = policy();
        match p.check_headers(
            "POST",
            "/pkg.Service/Unknown",
            Some("application/grpc"),
            None,
        ) {
            GrpcVerdict::Deny(GrpcFailure::Method(rpc)) => {
                assert_eq!(rpc, "pkg.Service/Unknown");
            }
            other => panic!("expected method deny, got {other:?}"),
        }
    }

    #[test]
    fn other_method_in_descriptor_but_not_allowlist_is_denied() {
        let p = policy();
        match p.check_headers("POST", "/pkg.Service/Other", Some("application/grpc"), None) {
            GrpcVerdict::Deny(GrpcFailure::Method(rpc)) => {
                assert_eq!(rpc, "pkg.Service/Other");
            }
            other => panic!("expected method deny, got {other:?}"),
        }
    }

    #[test]
    fn length_prefix_over_max_is_size_deny() {
        let p = policy();
        let mut body = vec![0, 0, 0, 0, 65];
        body.extend(std::iter::repeat_n(0, 8));
        assert_eq!(
            p.check_body(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                &body
            ),
            GrpcVerdict::Deny(GrpcFailure::Method("pkg.Service/Allowed".into()))
        );
    }

    #[test]
    fn claimed_length_without_payload_is_size_deny() {
        let p = policy();
        let body = vec![0, 0, 0, 0, 65];
        assert_eq!(
            p.check_body(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                &body
            ),
            GrpcVerdict::Deny(GrpcFailure::Method("pkg.Service/Allowed".into()))
        );
    }

    #[test]
    fn compressed_oversize_is_size_deny_not_parse_error() {
        let p = policy();
        let body = vec![1, 0, 0, 0, 65];
        assert_eq!(
            p.check_body(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                &body
            ),
            GrpcVerdict::Deny(GrpcFailure::Method("pkg.Service/Allowed".into()))
        );
    }

    #[test]
    fn invalid_grpc_timeout_is_method_deny_not_parse_error() {
        let p = policy();
        assert_eq!(
            p.check_headers(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                Some("nope")
            ),
            GrpcVerdict::Deny(GrpcFailure::Method("pkg.Service/Allowed".into()))
        );
    }

    #[test]
    fn reflection_off_denies_server_reflection_info() {
        let p = policy();
        match p.check_headers(
            "POST",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            Some("application/grpc"),
            None,
        ) {
            GrpcVerdict::Deny(GrpcFailure::Method(rpc)) => {
                assert_eq!(
                    rpc,
                    "grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
                );
            }
            other => panic!("expected reflection deny, got {other:?}"),
        }
    }

    #[test]
    fn reflection_on_allows_without_descriptor_entry() {
        let p = GrpcPolicy::from_bytes(
            &test_hello_descriptor_bytes(),
            &GrpcFile {
                descriptor: "./api.pb".into(),
                allow: vec!["pkg.Service/Allowed".into()],
                max_message_bytes: None,
                reflection: Some(true),
                deadline: None,
                require_deadline: None,
            },
        )
        .unwrap();
        assert!(matches!(
            p.check_headers(
                "POST",
                "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                Some("application/grpc"),
                Some("1S")
            ),
            GrpcVerdict::Allow { timeout: None }
        ));
    }

    #[test]
    fn garbage_protobuf_is_parse_error() {
        let p = policy();
        assert_eq!(
            p.check_body(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                &frame(&[0xFF])
            ),
            GrpcVerdict::Deny(GrpcFailure::ParseError)
        );
    }

    #[test]
    fn json_content_type_is_skip() {
        let p = policy();
        assert_eq!(
            p.check_headers(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/json"),
                None
            ),
            GrpcVerdict::Skip
        );
    }

    #[test]
    fn grpc_web_is_detected_so_matrix_skip_cannot_bypass_allowlist() {
        let p = policy();
        match p.check_headers(
            "POST",
            "/pkg.Service/Unknown",
            Some("application/grpc-web"),
            None,
        ) {
            GrpcVerdict::Deny(GrpcFailure::Method(rpc)) => {
                assert_eq!(rpc, "pkg.Service/Unknown");
            }
            other => panic!("grpc-web unknown method must be denied, got {other:?}"),
        }
    }

    #[test]
    fn require_deadline_without_header_denies() {
        let p = GrpcPolicy::from_bytes(
            &test_hello_descriptor_bytes(),
            &GrpcFile {
                descriptor: "./api.pb".into(),
                allow: vec!["pkg.Service/Allowed".into()],
                max_message_bytes: None,
                reflection: Some(false),
                deadline: None,
                require_deadline: Some(true),
            },
        )
        .unwrap();
        assert_eq!(
            p.check_headers(
                "POST",
                "/pkg.Service/Allowed",
                Some("application/grpc"),
                None
            ),
            GrpcVerdict::Deny(GrpcFailure::Method("pkg.Service/Allowed".into()))
        );
    }

    #[test]
    fn missing_timeout_injects_default() {
        let p = policy();
        match p.check_headers(
            "POST",
            "/pkg.Service/Allowed",
            Some("application/grpc"),
            None,
        ) {
            GrpcVerdict::Allow {
                timeout: Some(value),
            } => assert_eq!(value, "10S"),
            other => panic!("expected inject, got {other:?}"),
        }
    }

    #[test]
    fn allow_entry_missing_from_descriptor_is_load_error() {
        let error = GrpcPolicy::from_bytes(
            &test_hello_descriptor_bytes(),
            &GrpcFile {
                descriptor: "./api.pb".into(),
                allow: vec!["pkg.Service/Missing".into()],
                max_message_bytes: None,
                reflection: None,
                deadline: None,
                require_deadline: None,
            },
        )
        .unwrap_err();
        assert!(error.contains("Missing"), "{error}");
    }

    #[test]
    fn event_detail_is_service_method_not_payload() {
        let failure = GrpcFailure::Method("pkg.Service/Allowed".into());
        assert_eq!(failure.detail(), "pkg.Service/Allowed");
        assert!(!failure.detail().contains("ok"));
    }
}
