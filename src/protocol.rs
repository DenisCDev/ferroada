use http::Version;
use serde::Deserialize;

use crate::metrics;

/// Fallback when the protocol is unsupported or cannot be inspected.
/// `inspect` is the other axis — a supported mode, not one of these four.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedAction {
    Deny,
    Monitor,
    BypassExplicit,
    RouteToQuarantine,
}

impl UnsupportedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Monitor => "monitor",
            Self::BypassExplicit => "bypass-explicit",
            Self::RouteToQuarantine => "route-to-quarantine",
        }
    }

    /// Label used in metrics. Quarantine v1 is the event/metric name `quarantine`.
    pub fn metric_action(self) -> &'static str {
        match self {
            Self::RouteToQuarantine => "quarantine",
            other => other.as_str(),
        }
    }

    fn severity(self) -> u8 {
        match self {
            Self::RouteToQuarantine => 4,
            Self::Deny => 3,
            Self::Monitor => 2,
            Self::BypassExplicit => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolId {
    Http10,
    Http11,
    Http2,
    Http3,
    Websocket,
    Grpc,
    Brotli,
    Multipart,
    Sse,
    Json,
    GzipDeflate,
    UnknownHttpVersion,
    UnknownUpgrade,
    UnknownEncoding,
    UnknownContentType,
}

impl ProtocolId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "http_1_0",
            Self::Http11 => "http_1_1",
            Self::Http2 => "http_2",
            Self::Http3 => "http_3",
            Self::Websocket => "websocket",
            Self::Grpc => "grpc",
            Self::Brotli => "brotli",
            Self::Multipart => "multipart",
            Self::Sse => "sse",
            Self::Json => "json",
            Self::GzipDeflate => "gzip_deflate",
            Self::UnknownHttpVersion => "unknown_http_version",
            Self::UnknownUpgrade => "unknown_upgrade",
            Self::UnknownEncoding => "unknown_encoding",
            Self::UnknownContentType => "unknown_content_type",
        }
    }

    pub fn deny_reason(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0 não é suportado",
            Self::Http11 => "HTTP/1.1 não é permitido nesta política",
            Self::Http2 => "HTTP/2 não é permitido nesta política",
            Self::Http3 => "HTTP/3 não é suportado",
            Self::Websocket => "WebSocket não é suportado",
            Self::Grpc => "gRPC não é suportado",
            Self::Brotli => "Content-Encoding brotli não é suportado",
            Self::Multipart => "multipart não é suportado",
            Self::Sse => "SSE não é permitido nesta política",
            Self::Json => "JSON não é permitido nesta política",
            Self::GzipDeflate => "gzip/deflate não é permitido nesta política",
            Self::UnknownHttpVersion => "versão HTTP não suportada",
            Self::UnknownUpgrade => "Upgrade HTTP não suportado",
            Self::UnknownEncoding => "Content-Encoding não suportado",
            Self::UnknownContentType => "Content-Type não suportado",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVerdict {
    Inspect,
    Unsupported {
        protocol: ProtocolId,
        action: UnsupportedAction,
    },
}

impl ProtocolVerdict {
    pub fn blocked_status(self) -> Option<u16> {
        match self {
            Self::Unsupported {
                action: UnsupportedAction::Deny | UnsupportedAction::RouteToQuarantine,
                ..
            } => Some(403),
            _ => None,
        }
    }

    pub fn skips_body_waf(self) -> bool {
        matches!(
            self,
            Self::Unsupported {
                action: UnsupportedAction::Monitor | UnsupportedAction::BypassExplicit,
                ..
            }
        )
    }

    pub fn event_type(self) -> Option<&'static str> {
        match self {
            Self::Inspect => None,
            Self::Unsupported {
                action: UnsupportedAction::Deny,
                ..
            } => Some("protocol_deny"),
            Self::Unsupported {
                action: UnsupportedAction::Monitor,
                ..
            } => Some("protocol_monitor"),
            Self::Unsupported {
                action: UnsupportedAction::BypassExplicit,
                ..
            } => Some("protocol_bypass"),
            Self::Unsupported {
                action: UnsupportedAction::RouteToQuarantine,
                ..
            } => Some("quarantine"),
        }
    }
}

#[derive(Debug)]
pub struct RequestFacts<'a> {
    pub version: Version,
    pub upgrade: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub require_complete: bool,
    /// Site opted into a gRPC descriptor allowlist. Does not change the
    /// matrix default: without a block, gRPC stays an unsupported line.
    pub grpc_policy: bool,
}

/// Process-wide protocol matrix. Missing TOML keys keep the documented defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolMatrix {
    http_1_0: UnsupportedAction,
    /// None = inspect (supported).
    http_1_1: Option<UnsupportedAction>,
    http_2: Option<UnsupportedAction>,
    http_3: UnsupportedAction,
    websocket: UnsupportedAction,
    grpc: UnsupportedAction,
    /// None = deny on `require_complete`, monitor otherwise.
    brotli: Option<UnsupportedAction>,
    multipart: Option<UnsupportedAction>,
    unknown_http_version: UnsupportedAction,
    unknown_upgrade: UnsupportedAction,
    unknown_encoding: Option<UnsupportedAction>,
    unknown_content_type: Option<UnsupportedAction>,
}

impl Default for ProtocolMatrix {
    fn default() -> Self {
        Self {
            http_1_0: UnsupportedAction::Deny,
            http_1_1: None,
            http_2: None,
            http_3: UnsupportedAction::Deny,
            websocket: UnsupportedAction::BypassExplicit,
            grpc: UnsupportedAction::Deny,
            brotli: None,
            multipart: None,
            unknown_http_version: UnsupportedAction::Deny,
            unknown_upgrade: UnsupportedAction::Deny,
            unknown_encoding: None,
            unknown_content_type: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolsSection {
    #[serde(default)]
    http_1_0: Option<String>,
    #[serde(default)]
    http_1_1: Option<String>,
    #[serde(default)]
    http_2: Option<String>,
    #[serde(default)]
    http_3: Option<String>,
    #[serde(default)]
    websocket: Option<String>,
    #[serde(default)]
    grpc: Option<String>,
    #[serde(default)]
    brotli: Option<String>,
    #[serde(default)]
    multipart: Option<String>,
    #[serde(default)]
    sse: Option<String>,
    #[serde(default)]
    json: Option<String>,
    #[serde(default)]
    gzip_deflate: Option<String>,
    #[serde(default)]
    unknown_http_version: Option<String>,
    #[serde(default)]
    unknown_upgrade: Option<String>,
    #[serde(default)]
    unknown_encoding: Option<String>,
    #[serde(default)]
    unknown_content_type: Option<String>,
}

impl ProtocolMatrix {
    pub fn from_section(section: ProtocolsSection) -> Result<Self, String> {
        let mut matrix = Self::default();
        if let Some(raw) = section.http_1_0.as_deref() {
            matrix.http_1_0 = parse_unsupported("http_1_0", raw)?;
        }
        if let Some(raw) = section.http_1_1.as_deref() {
            matrix.http_1_1 = parse_supported_override("http_1_1", raw)?;
        }
        if let Some(raw) = section.http_2.as_deref() {
            matrix.http_2 = parse_supported_override("http_2", raw)?;
        }
        if let Some(raw) = section.http_3.as_deref() {
            matrix.http_3 = parse_unsupported("http_3", raw)?;
        }
        if let Some(raw) = section.websocket.as_deref() {
            matrix.websocket = parse_unsupported("websocket", raw)?;
        }
        if let Some(raw) = section.grpc.as_deref() {
            matrix.grpc = parse_unsupported("grpc", raw)?;
        }
        if let Some(raw) = section.brotli.as_deref() {
            matrix.brotli = Some(parse_unsupported("brotli", raw)?);
        }
        if let Some(raw) = section.multipart.as_deref() {
            matrix.multipart = Some(parse_unsupported("multipart", raw)?);
        }
        if let Some(raw) = section.unknown_http_version.as_deref() {
            matrix.unknown_http_version = parse_unsupported("unknown_http_version", raw)?;
        }
        if let Some(raw) = section.unknown_upgrade.as_deref() {
            matrix.unknown_upgrade = parse_unsupported("unknown_upgrade", raw)?;
        }
        if let Some(raw) = section.unknown_encoding.as_deref() {
            matrix.unknown_encoding = Some(parse_unsupported("unknown_encoding", raw)?);
        }
        if let Some(raw) = section.unknown_content_type.as_deref() {
            matrix.unknown_content_type = Some(parse_unsupported("unknown_content_type", raw)?);
        }
        if let Some(raw) = section.sse.as_deref() {
            parse_inspect_only("sse", raw)?;
        }
        if let Some(raw) = section.json.as_deref() {
            parse_inspect_only("json", raw)?;
        }
        if let Some(raw) = section.gzip_deflate.as_deref() {
            parse_inspect_only("gzip_deflate", raw)?;
        }
        Ok(matrix)
    }

    pub fn evaluate(&self, facts: &RequestFacts<'_>) -> ProtocolVerdict {
        pick_most_severe(self.matches(facts))
    }

    fn matches(&self, facts: &RequestFacts<'_>) -> Vec<(ProtocolId, UnsupportedAction)> {
        let mut matches = Vec::new();

        if facts.version == Version::HTTP_10 {
            matches.push((ProtocolId::Http10, self.http_1_0));
        } else if facts.version == Version::HTTP_3 {
            matches.push((ProtocolId::Http3, self.http_3));
        } else if facts.version == Version::HTTP_11 {
            if let Some(action) = self.http_1_1 {
                matches.push((ProtocolId::Http11, action));
            }
        } else if facts.version == Version::HTTP_2 {
            if let Some(action) = self.http_2 {
                matches.push((ProtocolId::Http2, action));
            }
        } else {
            matches.push((ProtocolId::UnknownHttpVersion, self.unknown_http_version));
        }

        if let Some(upgrade) = facts.upgrade {
            if upgrade_is_websocket(upgrade) {
                matches.push((ProtocolId::Websocket, self.websocket));
            } else if !upgrade.trim().is_empty() {
                matches.push((ProtocolId::UnknownUpgrade, self.unknown_upgrade));
            }
        }

        if let Some(protocol) = classify_encoding(facts.content_encoding) {
            let action = match protocol {
                ProtocolId::Brotli => contextual(self.brotli, facts.require_complete),
                _ => contextual(self.unknown_encoding, facts.require_complete),
            };
            matches.push((protocol, action));
        }

        if let Some(protocol) = classify_content_type(facts.content_type) {
            if protocol == ProtocolId::Grpc && facts.grpc_policy {
                // Descriptor allowlist is inspecting this request. The matrix
                // line stays deny/bypass for sites without the block.
            } else {
                let action = match protocol {
                    ProtocolId::Grpc => self.grpc,
                    ProtocolId::Multipart => contextual(self.multipart, facts.require_complete),
                    _ => contextual(self.unknown_content_type, facts.require_complete),
                };
                matches.push((protocol, action));
            }
        }

        matches
    }
}

pub fn record(verdict: ProtocolVerdict, client_ip: &str, uri: &str, site_scope: &str) {
    let ProtocolVerdict::Unsupported { protocol, action } = verdict else {
        return;
    };
    metrics::record_protocol_in(
        site_scope,
        protocol.as_str(),
        action.metric_action(),
        client_ip,
        uri,
        protocol.as_str(),
    );
}

/// L0 can look at this content-type as text. Multipart has no part parser in v1.
pub fn is_l0_inspectable_content_type(content_type: Option<&str>) -> bool {
    classify_content_type(content_type).is_none()
}

fn unsupported(protocol: ProtocolId, action: UnsupportedAction) -> ProtocolVerdict {
    ProtocolVerdict::Unsupported { protocol, action }
}

fn pick_most_severe(matches: Vec<(ProtocolId, UnsupportedAction)>) -> ProtocolVerdict {
    let mut best: Option<(ProtocolId, UnsupportedAction)> = None;
    for (protocol, action) in matches {
        match best {
            Some((_, best_action)) if action.severity() <= best_action.severity() => {}
            _ => best = Some((protocol, action)),
        }
    }
    match best {
        None => ProtocolVerdict::Inspect,
        Some((protocol, action)) => unsupported(protocol, action),
    }
}

fn contextual(explicit: Option<UnsupportedAction>, require_complete: bool) -> UnsupportedAction {
    explicit.unwrap_or(if require_complete {
        UnsupportedAction::Deny
    } else {
        UnsupportedAction::Monitor
    })
}

fn classify_encoding(content_encoding: Option<&str>) -> Option<ProtocolId> {
    let encoding = content_encoding.unwrap_or("").trim();
    if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
        return None;
    }
    let tokens: Vec<String> = encoding
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.len() != 1 {
        return Some(ProtocolId::UnknownEncoding);
    }
    match tokens[0].as_str() {
        "gzip" | "x-gzip" | "deflate" => None,
        "br" | "brotli" | "x-br" => Some(ProtocolId::Brotli),
        _ => Some(ProtocolId::UnknownEncoding),
    }
}

fn classify_content_type(content_type: Option<&str>) -> Option<ProtocolId> {
    let content_type = content_type?;
    let content_type = content_type.to_ascii_lowercase();
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(&content_type)
        .trim();
    if mime.starts_with("application/grpc") {
        return Some(ProtocolId::Grpc);
    }
    if mime.starts_with("multipart/") {
        return Some(ProtocolId::Multipart);
    }
    if mime.starts_with("text/")
        || mime.contains("application/json")
        || mime.ends_with("+json")
        || mime.contains("application/xml")
        || mime.ends_with("+xml")
        || mime == "application/x-www-form-urlencoded"
        || mime.contains("application/graphql")
    {
        return None;
    }
    Some(ProtocolId::UnknownContentType)
}

fn upgrade_is_websocket(upgrade: &str) -> bool {
    upgrade
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
}

fn parse_unsupported(key: &str, raw: &str) -> Result<UnsupportedAction, String> {
    match parse_policy(key, raw)? {
        Policy::Inspect => Err(format!(
            "[{key}] não pode ser inspect: não há inspeção suportada nesta linha da matriz"
        )),
        Policy::Unsupported(action) => Ok(action),
    }
}

fn parse_supported_override(key: &str, raw: &str) -> Result<Option<UnsupportedAction>, String> {
    match parse_policy(key, raw)? {
        Policy::Inspect => Ok(None),
        Policy::Unsupported(action) => Ok(Some(action)),
    }
}

fn parse_inspect_only(key: &str, raw: &str) -> Result<(), String> {
    match parse_policy(key, raw)? {
        Policy::Inspect => Ok(()),
        Policy::Unsupported(_) => Err(format!(
            "[{key}] é um modo suportado; a única política válida é inspect"
        )),
    }
}

enum Policy {
    Inspect,
    Unsupported(UnsupportedAction),
}

fn parse_policy(key: &str, raw: &str) -> Result<Policy, String> {
    match raw.trim() {
        "inspect" => Ok(Policy::Inspect),
        "deny" => Ok(Policy::Unsupported(UnsupportedAction::Deny)),
        "monitor" => Ok(Policy::Unsupported(UnsupportedAction::Monitor)),
        "bypass-explicit" => Ok(Policy::Unsupported(UnsupportedAction::BypassExplicit)),
        "route-to-quarantine" => Ok(Policy::Unsupported(UnsupportedAction::RouteToQuarantine)),
        "unknown" => Err(format!(
            "chave ambígua recusada em [{key}]: use unknown_http_version, unknown_upgrade, unknown_encoding ou unknown_content_type"
        )),
        other => Err(format!(
            "ação de protocolo inválida em [{key}] = {other:?}; use inspect, deny, monitor, bypass-explicit ou route-to-quarantine"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(
        version: Version,
        upgrade: Option<&'a str>,
        encoding: Option<&'a str>,
        content_type: Option<&'a str>,
        require_complete: bool,
    ) -> RequestFacts<'a> {
        RequestFacts {
            version,
            upgrade,
            content_encoding: encoding,
            content_type,
            require_complete,
            grpc_policy: false,
        }
    }

    fn default_eval(
        version: Version,
        upgrade: Option<&str>,
        encoding: Option<&str>,
        content_type: Option<&str>,
        require_complete: bool,
    ) -> ProtocolVerdict {
        ProtocolMatrix::default().evaluate(&facts(
            version,
            upgrade,
            encoding,
            content_type,
            require_complete,
        ))
    }

    fn assert_deny(verdict: ProtocolVerdict, protocol: ProtocolId) {
        assert_eq!(verdict.blocked_status(), Some(403));
        assert_eq!(verdict.event_type(), Some("protocol_deny"));
        assert_eq!(
            verdict,
            ProtocolVerdict::Unsupported {
                protocol,
                action: UnsupportedAction::Deny,
            }
        );
    }

    fn assert_bypass(verdict: ProtocolVerdict, protocol: ProtocolId) {
        assert_eq!(verdict.blocked_status(), None);
        assert!(verdict.skips_body_waf());
        assert_eq!(verdict.event_type(), Some("protocol_bypass"));
        assert_eq!(
            verdict,
            ProtocolVerdict::Unsupported {
                protocol,
                action: UnsupportedAction::BypassExplicit,
            }
        );
    }

    fn assert_monitor(verdict: ProtocolVerdict, protocol: ProtocolId) {
        assert_eq!(verdict.blocked_status(), None);
        assert!(verdict.skips_body_waf());
        assert_eq!(verdict.event_type(), Some("protocol_monitor"));
        assert_eq!(
            verdict,
            ProtocolVerdict::Unsupported {
                protocol,
                action: UnsupportedAction::Monitor,
            }
        );
    }

    #[test]
    fn http_1_0_default_deny_is_403() {
        assert_deny(
            default_eval(Version::HTTP_10, None, None, None, false),
            ProtocolId::Http10,
        );
    }

    #[test]
    fn http_3_default_deny_is_403() {
        assert_deny(
            default_eval(Version::HTTP_3, None, None, None, false),
            ProtocolId::Http3,
        );
    }

    #[test]
    fn unknown_http_version_default_deny_is_403() {
        assert_deny(
            default_eval(Version::HTTP_09, None, None, None, false),
            ProtocolId::UnknownHttpVersion,
        );
    }

    #[test]
    fn http_1_1_and_http_2_default_inspect() {
        assert_eq!(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("application/json"),
                false
            ),
            ProtocolVerdict::Inspect
        );
        assert_eq!(
            default_eval(Version::HTTP_2, None, None, Some("text/plain"), false),
            ProtocolVerdict::Inspect
        );
    }

    #[test]
    fn websocket_default_bypass_skips_body_waf() {
        assert_bypass(
            default_eval(Version::HTTP_11, Some("websocket"), None, None, false),
            ProtocolId::Websocket,
        );
        assert_bypass(
            default_eval(Version::HTTP_11, Some("WebSocket"), None, None, true),
            ProtocolId::Websocket,
        );
    }

    #[test]
    fn websocket_deny_is_403() {
        let toml = ProtocolMatrix::from_section(ProtocolsSection {
            websocket: Some("deny".into()),
            ..ProtocolsSection::default()
        })
        .unwrap();
        assert_deny(
            toml.evaluate(&facts(
                Version::HTTP_11,
                Some("websocket"),
                None,
                None,
                false,
            )),
            ProtocolId::Websocket,
        );
    }

    #[test]
    fn unknown_upgrade_default_deny_is_403() {
        assert_deny(
            default_eval(Version::HTTP_11, Some("h2c"), None, None, false),
            ProtocolId::UnknownUpgrade,
        );
    }

    #[test]
    fn grpc_default_deny_is_403() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("application/grpc"),
                false,
            ),
            ProtocolId::Grpc,
        );
        assert_deny(
            default_eval(
                Version::HTTP_2,
                None,
                None,
                Some("application/grpc+proto"),
                true,
            ),
            ProtocolId::Grpc,
        );
    }

    #[test]
    fn websocket_upgrade_does_not_cloak_grpc_deny() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                Some("websocket"),
                None,
                Some("application/grpc"),
                false,
            ),
            ProtocolId::Grpc,
        );
    }

    #[test]
    fn websocket_upgrade_does_not_cloak_multipart_require_complete() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                Some("websocket"),
                None,
                Some("multipart/form-data; boundary=x"),
                true,
            ),
            ProtocolId::Multipart,
        );
    }

    #[test]
    fn brotli_monitor_does_not_cloak_grpc_deny() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                Some("br"),
                Some("application/grpc"),
                false,
            ),
            ProtocolId::Grpc,
        );
    }

    #[test]
    fn websocket_bypass_still_skips_inspectable_json_body() {
        assert_bypass(
            default_eval(
                Version::HTTP_11,
                Some("websocket"),
                None,
                Some("application/json"),
                false,
            ),
            ProtocolId::Websocket,
        );
    }

    #[test]
    fn multipart_require_complete_default_deny_is_403() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("multipart/form-data; boundary=x"),
                true,
            ),
            ProtocolId::Multipart,
        );
    }

    #[test]
    fn explicit_multipart_monitor_overrides_require_complete() {
        let matrix = ProtocolMatrix::from_section(ProtocolsSection {
            multipart: Some("monitor".into()),
            ..ProtocolsSection::default()
        })
        .unwrap();
        assert_monitor(
            matrix.evaluate(&facts(
                Version::HTTP_11,
                None,
                None,
                Some("multipart/form-data; boundary=x"),
                true,
            )),
            ProtocolId::Multipart,
        );
    }

    #[test]
    fn multipart_open_route_default_monitor_allows() {
        assert_monitor(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("multipart/form-data; boundary=x"),
                false,
            ),
            ProtocolId::Multipart,
        );
    }

    #[test]
    fn brotli_require_complete_default_deny_is_403() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                Some("br"),
                Some("application/json"),
                true,
            ),
            ProtocolId::Brotli,
        );
    }

    #[test]
    fn brotli_open_route_default_monitor_allows() {
        assert_monitor(
            default_eval(
                Version::HTTP_11,
                None,
                Some("br"),
                Some("application/json"),
                false,
            ),
            ProtocolId::Brotli,
        );
    }

    #[test]
    fn unknown_encoding_require_complete_default_deny_is_403() {
        assert_deny(
            default_eval(Version::HTTP_11, None, Some("zstd"), None, true),
            ProtocolId::UnknownEncoding,
        );
    }

    #[test]
    fn unknown_encoding_open_route_default_monitor_allows() {
        assert_monitor(
            default_eval(Version::HTTP_11, None, Some("zstd"), None, false),
            ProtocolId::UnknownEncoding,
        );
    }

    #[test]
    fn unknown_content_type_require_complete_default_deny_is_403() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("application/octet-stream"),
                true,
            ),
            ProtocolId::UnknownContentType,
        );
    }

    #[test]
    fn unknown_content_type_open_route_default_monitor_allows() {
        assert_monitor(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("application/octet-stream"),
                false,
            ),
            ProtocolId::UnknownContentType,
        );
    }

    #[test]
    fn gzip_json_and_sse_request_stay_inspect() {
        assert_eq!(
            default_eval(
                Version::HTTP_11,
                None,
                Some("gzip"),
                Some("application/json"),
                true,
            ),
            ProtocolVerdict::Inspect
        );
        assert_eq!(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("text/event-stream"),
                false,
            ),
            ProtocolVerdict::Inspect
        );
        assert!(is_l0_inspectable_content_type(Some("text/event-stream")));
        assert!(is_l0_inspectable_content_type(Some("application/json")));
        assert!(!is_l0_inspectable_content_type(Some(
            "multipart/form-data; boundary=x"
        )));
        assert!(!is_l0_inspectable_content_type(Some("application/grpc")));
    }

    #[test]
    fn route_to_quarantine_is_403_with_quarantine_event() {
        let matrix = ProtocolMatrix::from_section(ProtocolsSection {
            grpc: Some("route-to-quarantine".into()),
            ..ProtocolsSection::default()
        })
        .unwrap();
        let verdict = matrix.evaluate(&facts(
            Version::HTTP_11,
            None,
            None,
            Some("application/grpc"),
            false,
        ));
        assert_eq!(verdict.blocked_status(), Some(403));
        assert_eq!(verdict.event_type(), Some("quarantine"));
        assert_eq!(
            verdict,
            ProtocolVerdict::Unsupported {
                protocol: ProtocolId::Grpc,
                action: UnsupportedAction::RouteToQuarantine,
            }
        );

        let uri = "/protocol-matrix/quarantine-grpc";
        record(verdict, "203.0.113.9", uri, "api.example");
        let snapshot = metrics::snapshot_json();
        assert!(snapshot.contains("\"event_type\": \"quarantine\""));
        assert!(snapshot.contains(uri));
        assert!(snapshot.contains("grpc"));
        let prometheus = metrics::snapshot_prometheus();
        assert!(prometheus.contains("ferroada_protocol_total{id=\"grpc\",action=\"quarantine\"}"));
    }

    #[test]
    fn deny_records_protocol_id_metric_and_event() {
        let verdict = default_eval(Version::HTTP_10, None, None, None, false);
        let uri = "/protocol-matrix/http10-deny";
        record(verdict, "198.51.100.4", uri, "api.example");
        let snapshot = metrics::snapshot_json();
        assert!(snapshot.contains("\"event_type\": \"protocol_deny\""));
        assert!(snapshot.contains(uri));
        assert!(snapshot.contains("http_1_0"));
        let prometheus = metrics::snapshot_prometheus();
        assert!(prometheus.contains("ferroada_protocol_total{id=\"http_1_0\",action=\"deny\"}"));
    }

    #[test]
    fn bypass_records_protocol_bypass_event() {
        let verdict = default_eval(Version::HTTP_11, Some("websocket"), None, None, false);
        let uri = "/protocol-matrix/websocket-bypass";
        record(verdict, "192.0.2.8", uri, "api.example");
        let snapshot = metrics::snapshot_json();
        assert!(snapshot.contains("\"event_type\": \"protocol_bypass\""));
        assert!(snapshot.contains(uri));
        assert!(snapshot.contains("websocket"));
    }

    #[test]
    fn inspect_is_rejected_on_unsupported_rows() {
        let err = ProtocolMatrix::from_section(ProtocolsSection {
            websocket: Some("inspect".into()),
            ..ProtocolsSection::default()
        })
        .unwrap_err();
        assert!(err.contains("websocket"));
        assert!(err.contains("inspect"));
    }

    #[test]
    fn ambiguous_unknown_key_is_rejected() {
        let err = toml::from_str::<ProtocolsSection>("unknown = \"deny\"").unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn json_cannot_leave_inspect() {
        let err = ProtocolMatrix::from_section(ProtocolsSection {
            json: Some("deny".into()),
            ..ProtocolsSection::default()
        })
        .unwrap_err();
        assert!(err.contains("json"));
    }

    #[test]
    fn unsupported_rows_never_silent_inspect() {
        let matrix = ProtocolMatrix::default();
        let cases = [
            facts(Version::HTTP_10, None, None, None, false),
            facts(Version::HTTP_3, None, None, None, false),
            facts(Version::HTTP_09, None, None, None, false),
            facts(Version::HTTP_11, Some("websocket"), None, None, false),
            facts(Version::HTTP_11, Some("h2c"), None, None, false),
            facts(
                Version::HTTP_11,
                None,
                None,
                Some("application/grpc"),
                false,
            ),
            facts(
                Version::HTTP_11,
                None,
                None,
                Some("multipart/form-data"),
                true,
            ),
            facts(
                Version::HTTP_11,
                None,
                None,
                Some("multipart/form-data"),
                false,
            ),
            facts(Version::HTTP_11, None, Some("br"), None, true),
            facts(Version::HTTP_11, None, Some("br"), None, false),
            facts(Version::HTTP_11, None, Some("zstd"), None, true),
            facts(
                Version::HTTP_11,
                None,
                None,
                Some("application/octet-stream"),
                true,
            ),
        ];
        for case in cases {
            assert!(
                !matches!(matrix.evaluate(&case), ProtocolVerdict::Inspect),
                "silent inspect for {case:?}"
            );
        }
    }

    #[test]
    fn grpc_policy_does_not_invent_matrix_inspect_without_the_block() {
        assert_deny(
            default_eval(
                Version::HTTP_11,
                None,
                None,
                Some("application/grpc"),
                false,
            ),
            ProtocolId::Grpc,
        );
        let mut opted = facts(
            Version::HTTP_11,
            None,
            None,
            Some("application/grpc"),
            false,
        );
        opted.grpc_policy = true;
        assert_eq!(
            ProtocolMatrix::default().evaluate(&opted),
            ProtocolVerdict::Inspect
        );
        let mut plus_proto = facts(
            Version::HTTP_2,
            None,
            None,
            Some("application/grpc+proto"),
            true,
        );
        plus_proto.grpc_policy = true;
        assert_eq!(
            ProtocolMatrix::default().evaluate(&plus_proto),
            ProtocolVerdict::Inspect
        );
    }
}
