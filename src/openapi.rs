//! OpenAPI 3.0/3.1 request validation, compiled at config load.
//!
//! Extra JSON object fields are denied unless the spec sets
//! `additionalProperties: true` (mass-assignment is the failure mode the
//! product exists to catch). Response bodies are out of scope.

use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::config;

const MAX_REF_DEPTH: u8 = 32;
const MAX_SCHEMA_DEPTH: u8 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownEndpoint {
    Observe,
    Deny,
}

impl UnknownEndpoint {
    pub fn parse(key: &str, raw: &str) -> Self {
        match raw.trim() {
            "observe" => Self::Observe,
            "deny" => Self::Deny,
            other => panic!("política inválida em {key} = {other:?}; use observe ou deny"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenApiPolicy {
    spec: Arc<CompiledSpec>,
    unknown_endpoint: Option<UnknownEndpoint>,
}

#[derive(Clone, Debug)]
struct CompiledSpec {
    doc: Arc<Value>,
    paths: Vec<CompiledPath>,
    prefixes: Vec<String>,
}

#[derive(Clone, Debug)]
struct CompiledPath {
    template: String,
    segments: Vec<Segment>,
    methods: HashMap<String, Arc<CompiledOp>>,
}

#[derive(Clone, Debug)]
enum Segment {
    Literal(String),
    Param(String),
}

#[derive(Clone, Debug)]
struct CompiledOp {
    path_params: Vec<CompiledParam>,
    query_params: Vec<CompiledParam>,
    header_params: Vec<CompiledParam>,
    cookie_params: Vec<CompiledParam>,
    body: Option<CompiledBody>,
}

#[derive(Clone, Debug)]
struct CompiledParam {
    name: String,
    required: bool,
    schema: Value,
}

#[derive(Clone, Debug)]
struct CompiledBody {
    required: bool,
    content: Vec<CompiledMedia>,
}

#[derive(Clone, Debug)]
struct CompiledMedia {
    pattern: String,
    schema: Value,
}

#[derive(Clone, Debug)]
pub struct MatchedOp {
    pub template: String,
    pub method: String,
    op: Arc<CompiledOp>,
    doc: Arc<Value>,
}

#[derive(Debug)]
pub enum EnvelopeVerdict {
    Allow(MatchedOp),
    Observe { detail: String },
    Deny { detail: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum BodyVerdict {
    Allow,
    Deny { detail: String },
}

struct Fail {
    pointer: String,
    reason: &'static str,
}

impl OpenApiPolicy {
    pub fn from_bytes(
        bytes: &[u8],
        origin: &str,
        unknown_endpoint: Option<UnknownEndpoint>,
    ) -> Result<Self, String> {
        let spec = compile(bytes, origin)?;
        Ok(Self {
            spec: Arc::new(spec),
            unknown_endpoint,
        })
    }

    pub fn from_str(
        contents: &str,
        origin: &str,
        unknown_endpoint: Option<UnknownEndpoint>,
    ) -> Result<Self, String> {
        Self::from_bytes(contents.as_bytes(), origin, unknown_endpoint)
    }

    fn unknown_action(&self, require_complete: bool) -> UnknownEndpoint {
        self.unknown_endpoint.unwrap_or(if require_complete {
            UnknownEndpoint::Deny
        } else {
            UnknownEndpoint::Observe
        })
    }

    pub fn path_params(&self, path: &str) -> BTreeMap<String, String> {
        let normalized = config::canonical_route_path(path.split('?').next().unwrap_or(path))
            .unwrap_or_else(|| path.split('?').next().unwrap_or("/").to_string());
        for prefix in &self.spec.prefixes {
            let Some(stripped) = strip_prefix(&normalized, prefix) else {
                continue;
            };
            for compiled in &self.spec.paths {
                if let Some(params) = match_segments(&compiled.segments, stripped) {
                    return params;
                }
            }
        }
        BTreeMap::new()
    }

    pub fn validate_envelope(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &[(String, String)],
        content_type: Option<&str>,
        require_complete: bool,
    ) -> EnvelopeVerdict {
        let method_lc = method.to_ascii_lowercase();
        let normalized = config::canonical_route_path(path.split('?').next().unwrap_or(path))
            .unwrap_or_else(|| path.split('?').next().unwrap_or("/").to_string());
        let Some((template, params, op)) = match_path(&self.spec, &normalized, &method_lc) else {
            if match_path_any_method(&self.spec, &normalized) {
                return EnvelopeVerdict::Deny {
                    detail: format!("{method} {normalized} unknown_method"),
                };
            }
            let detail = format!("{method} {normalized} unknown_endpoint");
            return match self.unknown_action(require_complete) {
                UnknownEndpoint::Deny => EnvelopeVerdict::Deny { detail },
                UnknownEndpoint::Observe => EnvelopeVerdict::Observe { detail },
            };
        };

        for param in &op.path_params {
            let Some(raw) = params.get(&param.name) else {
                return deny(method, &template, &format!("path /{} required", param.name));
            };
            if let Err(fail) = validate_stringy(self.spec.doc.as_ref(), &param.schema, raw) {
                return deny(
                    method,
                    &template,
                    &format!(
                        "path {} {}",
                        named_pointer(&param.name, &fail.pointer),
                        fail.reason
                    ),
                );
            }
        }

        let query_map = parse_query(query.unwrap_or(""));
        for param in &op.query_params {
            match query_map.get(&param.name) {
                None if param.required => {
                    return deny(
                        method,
                        &template,
                        &format!("query /{} required", param.name),
                    );
                }
                None => {}
                Some(values) => {
                    if let Err(fail) =
                        validate_query_values(self.spec.doc.as_ref(), &param.schema, values)
                    {
                        return deny(
                            method,
                            &template,
                            &format!(
                                "query {} {}",
                                named_pointer(&param.name, &fail.pointer),
                                fail.reason
                            ),
                        );
                    }
                }
            }
        }

        for param in &op.header_params {
            let found = header_values(headers, &param.name);
            if found.is_empty() {
                if param.required {
                    return deny(
                        method,
                        &template,
                        &format!("header /{} required", param.name),
                    );
                }
                continue;
            }
            if let Err(fail) = validate_query_values(self.spec.doc.as_ref(), &param.schema, &found)
            {
                return deny(
                    method,
                    &template,
                    &format!(
                        "header {} {}",
                        named_pointer(&param.name, &fail.pointer),
                        fail.reason
                    ),
                );
            }
        }

        if !op.cookie_params.is_empty() {
            let cookies = cookie_map(headers);
            for param in &op.cookie_params {
                match cookies.get(&param.name) {
                    None if param.required => {
                        return deny(
                            method,
                            &template,
                            &format!("cookie /{} required", param.name),
                        );
                    }
                    None => {}
                    Some(raw) => {
                        if let Err(fail) =
                            validate_stringy(self.spec.doc.as_ref(), &param.schema, raw)
                        {
                            return deny(
                                method,
                                &template,
                                &format!(
                                    "cookie {} {}",
                                    named_pointer(&param.name, &fail.pointer),
                                    fail.reason
                                ),
                            );
                        }
                    }
                }
            }
        }

        if let Some(body) = op.body.as_ref() {
            if let Some(ct) = content_type {
                if !content_allowed(&body.content, ct) {
                    return deny(method, &template, "unknown_content_type");
                }
            }
        }

        EnvelopeVerdict::Allow(MatchedOp {
            template,
            method: method_lc,
            op,
            doc: Arc::clone(&self.spec.doc),
        })
    }
}

impl MatchedOp {
    pub fn validate_body(&self, content_type: Option<&str>, body: &[u8]) -> BodyVerdict {
        let Some(spec_body) = self.op.body.as_ref() else {
            return BodyVerdict::Allow;
        };
        let empty = body.iter().all(|b| b.is_ascii_whitespace());
        if empty {
            if spec_body.required {
                return BodyVerdict::Deny {
                    detail: format!(
                        "{} {} body required",
                        self.method.to_ascii_uppercase(),
                        self.template
                    ),
                };
            }
            return BodyVerdict::Allow;
        }
        let Some(ct) = content_type else {
            return BodyVerdict::Deny {
                detail: format!(
                    "{} {} unknown_content_type",
                    self.method.to_ascii_uppercase(),
                    self.template
                ),
            };
        };
        let Some(media) = matching_media(&spec_body.content, ct) else {
            return BodyVerdict::Deny {
                detail: format!(
                    "{} {} unknown_content_type",
                    self.method.to_ascii_uppercase(),
                    self.template
                ),
            };
        };
        if !is_json_media(&media.pattern, ct) {
            return BodyVerdict::Allow;
        }
        let parsed = match serde_json::from_slice::<Value>(body) {
            Ok(value) => value,
            Err(_) => {
                return BodyVerdict::Deny {
                    detail: format!(
                        "{} {} body parse",
                        self.method.to_ascii_uppercase(),
                        self.template
                    ),
                };
            }
        };
        if let Err(fail) = schema_ok(
            &self.doc,
            &media.schema,
            &parsed,
            "",
            MAX_SCHEMA_DEPTH,
            true,
        ) {
            let pointer = if fail.pointer.is_empty() {
                "/".to_string()
            } else {
                fail.pointer
            };
            return BodyVerdict::Deny {
                detail: format!(
                    "{} {} body {} {}",
                    self.method.to_ascii_uppercase(),
                    self.template,
                    pointer,
                    fail.reason
                ),
            };
        }
        BodyVerdict::Allow
    }
}

fn deny(method: &str, template: &str, rest: &str) -> EnvelopeVerdict {
    EnvelopeVerdict::Deny {
        detail: format!("{method} {template} {rest}"),
    }
}

fn named_pointer(name: &str, pointer: &str) -> String {
    if pointer.is_empty() {
        format!("/{name}")
    } else if pointer.starts_with('/') {
        pointer.to_string()
    } else {
        format!("/{pointer}")
    }
}

fn compile(bytes: &[u8], origin: &str) -> Result<CompiledSpec, String> {
    let doc = parse_document(bytes)?;
    openapi_version(&doc)?;
    let prefixes = server_prefixes(&doc);
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Err(format!("{origin}: campo paths ausente"));
    };
    let mut compiled = Vec::new();
    for (template, item) in paths {
        if template.starts_with("x-") {
            continue;
        }
        let item = freeze(&doc, item).map_err(|e| format!("{origin} {template}: {e}"))?;
        let shared = parse_params(&doc, item.get("parameters"))
            .map_err(|e| format!("{origin} {template}: {e}"))?;
        let segments = parse_template(template).map_err(|e| format!("{origin} {template}: {e}"))?;
        let mut methods = HashMap::new();
        for method in [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(op_node) = item.get(method) else {
                continue;
            };
            let op_node =
                freeze(&doc, op_node).map_err(|e| format!("{origin} {template} {method}: {e}"))?;
            let op = compile_op(&doc, &op_node, &shared, &segments)
                .map_err(|e| format!("{origin} {template} {method}: {e}"))?;
            methods.insert(method.to_string(), Arc::new(op));
        }
        if methods.is_empty() {
            continue;
        }
        compiled.push(CompiledPath {
            template: template.clone(),
            segments,
            methods,
        });
    }
    compiled.sort_by(|left, right| {
        literal_count(&right.segments)
            .cmp(&literal_count(&left.segments))
            .then_with(|| right.segments.len().cmp(&left.segments.len()))
    });
    Ok(CompiledSpec {
        doc: Arc::new(doc),
        paths: compiled,
        prefixes,
    })
}

fn parse_document(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "spec não é UTF-8".to_string())?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        serde_json::from_str(text).map_err(|error| format!("JSON inválido: {error}"))
    } else {
        serde_yaml::from_str(text).map_err(|error| format!("YAML inválido: {error}"))
    }
}

fn openapi_version(doc: &Value) -> Result<(), String> {
    if doc.get("swagger").is_some() && doc.get("openapi").is_none() {
        return Err("OpenAPI 2.0 (swagger) não é suportado; use 3.0 ou 3.1".into());
    }
    match doc.get("openapi") {
        Some(Value::String(raw)) if raw.starts_with("3.0") || raw.starts_with("3.1") => Ok(()),
        Some(Value::Number(n)) if n.as_f64() == Some(3.0) || n.as_f64() == Some(3.1) => Ok(()),
        Some(other) => Err(format!(
            "versão OpenAPI {other} não suportada; use 3.0 ou 3.1"
        )),
        None => Err("campo openapi ausente".into()),
    }
}

fn server_prefixes(doc: &Value) -> Vec<String> {
    let mut prefixes = vec![String::new()];
    let Some(servers) = doc.get("servers").and_then(Value::as_array) else {
        return prefixes;
    };
    for server in servers {
        let Some(url) = server.get("url").and_then(Value::as_str) else {
            continue;
        };
        let prefix = server_path_prefix(url);
        if !prefix.is_empty() && !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    prefixes.sort_by_key(|a| std::cmp::Reverse(a.len()));
    prefixes
}

fn server_path_prefix(url: &str) -> String {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let path = if rest.starts_with('/') {
        rest
    } else if let Some(slash) = rest.find('/') {
        &rest[slash..]
    } else {
        return String::new();
    };
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        String::new()
    } else {
        path.to_string()
    }
}

fn parse_template(template: &str) -> Result<Vec<Segment>, String> {
    if !template.starts_with('/') {
        return Err("path deve começar com /".into());
    }
    let mut segments = Vec::new();
    for raw in template.split('/') {
        if raw.is_empty() {
            continue;
        }
        if let Some(name) = raw.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if name.is_empty() || name.contains(['{', '}', '/']) {
                return Err(format!("parâmetro de path inválido: {raw}"));
            }
            segments.push(Segment::Param(name.to_string()));
        } else if raw.contains('{') {
            return Err(format!("segmento de path inválido: {raw}"));
        } else {
            segments.push(Segment::Literal(raw.to_string()));
        }
    }
    Ok(segments)
}

fn literal_count(segments: &[Segment]) -> usize {
    segments
        .iter()
        .filter(|segment| matches!(segment, Segment::Literal(_)))
        .count()
}

fn compile_op(
    doc: &Value,
    op: &Value,
    shared: &[CompiledParamSlot],
    segments: &[Segment],
) -> Result<CompiledOp, String> {
    let mut slots = shared.to_vec();
    for extra in parse_params(doc, op.get("parameters"))? {
        if let Some(existing) = slots
            .iter_mut()
            .find(|slot| slot.location == extra.location && slot.param.name == extra.param.name)
        {
            *existing = extra;
        } else {
            slots.push(extra);
        }
    }
    let mut compiled = CompiledOp {
        path_params: Vec::new(),
        query_params: Vec::new(),
        header_params: Vec::new(),
        cookie_params: Vec::new(),
        body: None,
    };
    for slot in slots {
        match slot.location.as_str() {
            "path" => compiled.path_params.push(slot.param),
            "query" => compiled.query_params.push(slot.param),
            "header" => compiled.header_params.push(slot.param),
            "cookie" => compiled.cookie_params.push(slot.param),
            other => return Err(format!("parameter in {other:?} não suportado")),
        }
    }
    let template_params: Vec<&str> = segments
        .iter()
        .filter_map(|segment| match segment {
            Segment::Param(name) => Some(name.as_str()),
            Segment::Literal(_) => None,
        })
        .collect();
    for name in &template_params {
        if !compiled.path_params.iter().any(|param| param.name == *name) {
            compiled.path_params.push(CompiledParam {
                name: (*name).to_string(),
                required: true,
                schema: serde_json::json!({"type": "string"}),
            });
        }
    }
    for param in &mut compiled.path_params {
        param.required = true;
    }
    compiled.body = parse_body(doc, op.get("requestBody"))?;
    Ok(compiled)
}

#[derive(Clone, Debug)]
struct CompiledParamSlot {
    location: String,
    param: CompiledParam,
}

fn parse_params(doc: &Value, node: Option<&Value>) -> Result<Vec<CompiledParamSlot>, String> {
    let Some(list) = node.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in list {
        let item = freeze(doc, item)?;
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or("parameter sem name")?
            .to_string();
        let location = item
            .get("in")
            .and_then(Value::as_str)
            .ok_or("parameter sem in")?
            .to_string();
        let required = item
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(location == "path");
        let schema = item
            .get("schema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "string"}));
        let schema = freeze(doc, &schema)?;
        out.push(CompiledParamSlot {
            location,
            param: CompiledParam {
                name,
                required,
                schema,
            },
        });
    }
    Ok(out)
}

fn parse_body(doc: &Value, node: Option<&Value>) -> Result<Option<CompiledBody>, String> {
    let Some(node) = node else {
        return Ok(None);
    };
    let node = freeze(doc, node)?;
    let required = node
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let Some(content) = node.get("content").and_then(Value::as_object) else {
        return Ok(Some(CompiledBody {
            required,
            content: Vec::new(),
        }));
    };
    let mut medias = Vec::new();
    for (pattern, media) in content {
        let schema = media
            .get("schema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let schema = freeze(doc, &schema)?;
        medias.push(CompiledMedia {
            pattern: pattern.to_ascii_lowercase(),
            schema,
        });
    }
    Ok(Some(CompiledBody {
        required,
        content: medias,
    }))
}

fn freeze(doc: &Value, node: &Value) -> Result<Value, String> {
    if let Some(rel) = node.get("$ref").and_then(Value::as_str) {
        if node.as_object().is_some_and(|map| map.len() > 1) {
            json_pointer(doc, rel).ok_or_else(|| format!("$ref inválido: {rel}"))?;
            return Ok(node.clone());
        }
        let target = json_pointer(doc, rel).ok_or_else(|| format!("$ref inválido: {rel}"))?;
        if target.get("$ref").is_some() {
            return freeze(doc, target);
        }
        return Ok(target.clone());
    }
    Ok(node.clone())
}

fn json_pointer<'a>(doc: &'a Value, rel: &str) -> Option<&'a Value> {
    let rel = rel.strip_prefix('#')?;
    if rel.is_empty() {
        return Some(doc);
    }
    if !rel.starts_with('/') {
        return None;
    }
    let mut cur = doc;
    for raw in rel.split('/').skip(1) {
        let key = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(map) => map.get(&key)?,
            Value::Array(arr) => arr.get(key.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn match_path(
    spec: &CompiledSpec,
    path: &str,
    method: &str,
) -> Option<(String, BTreeMap<String, String>, Arc<CompiledOp>)> {
    for prefix in &spec.prefixes {
        let Some(stripped) = strip_prefix(path, prefix) else {
            continue;
        };
        for compiled in &spec.paths {
            let Some(params) = match_segments(&compiled.segments, stripped) else {
                continue;
            };
            if let Some(op) = compiled.methods.get(method) {
                return Some((compiled.template.clone(), params, Arc::clone(op)));
            }
        }
    }
    None
}

fn match_path_any_method(spec: &CompiledSpec, path: &str) -> bool {
    for prefix in &spec.prefixes {
        let Some(stripped) = strip_prefix(path, prefix) else {
            continue;
        };
        for compiled in &spec.paths {
            if match_segments(&compiled.segments, stripped).is_some() {
                return true;
            }
        }
    }
    false
}

fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        return Some(path);
    }
    if path == prefix {
        return Some("/");
    }
    path.strip_prefix(prefix).and_then(|rest| {
        if rest.is_empty() {
            Some("/")
        } else if rest.starts_with('/') {
            Some(rest)
        } else {
            None
        }
    })
}

fn match_segments(segments: &[Segment], path: &str) -> Option<BTreeMap<String, String>> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() != segments.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (segment, part) in segments.iter().zip(parts) {
        match segment {
            Segment::Literal(literal) => {
                if literal != part {
                    return None;
                }
            }
            Segment::Param(name) => {
                params.insert(name.clone(), part.to_string());
            }
        }
    }
    Some(params)
}

fn parse_query(query: &str) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    if query.is_empty() {
        return map;
    }
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode_plus(key);
        let value = percent_decode_plus(value);
        map.entry(key).or_default().push(value);
    }
    map
}

fn percent_decode_plus(input: &str) -> String {
    let input = input.replace('+', " ");
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn header_values(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .collect()
}

fn cookie_map(headers: &[(String, String)]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for value in header_values(headers, "cookie") {
        for cookie in value.split(';') {
            let Some((name, raw)) = cookie.trim().split_once('=') else {
                continue;
            };
            map.insert(name.to_string(), raw.to_string());
        }
    }
    map
}

fn content_allowed(content: &[CompiledMedia], content_type: &str) -> bool {
    matching_media(content, content_type).is_some()
}

fn matching_media<'a>(
    content: &'a [CompiledMedia],
    content_type: &str,
) -> Option<&'a CompiledMedia> {
    let key = media_type_key(content_type);
    content
        .iter()
        .find(|media| media_matches(&media.pattern, &key))
}

fn media_type_key(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase()
}

fn media_matches(pattern: &str, key: &str) -> bool {
    if pattern == "*/*" || pattern == key {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return key.starts_with(&format!("{prefix}/"));
    }
    false
}

fn is_json_media(pattern: &str, content_type: &str) -> bool {
    let key = media_type_key(content_type);
    key == "application/json"
        || key.ends_with("+json")
        || pattern == "application/json"
        || pattern.ends_with("+json")
}

fn type_names(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn deref<'a>(doc: &'a Value, node: &'a Value, depth: u8) -> Result<&'a Value, Fail> {
    let Some(rel) = node.get("$ref").and_then(Value::as_str) else {
        return Ok(node);
    };
    if depth == 0 {
        return Err(Fail {
            pointer: String::new(),
            reason: "depth",
        });
    }
    let target = json_pointer(doc, rel).ok_or(Fail {
        pointer: String::new(),
        reason: "ref",
    })?;
    deref(doc, target, depth - 1)
}

fn validate_stringy(doc: &Value, schema: &Value, raw: &str) -> Result<(), Fail> {
    let schema = deref(doc, schema, MAX_REF_DEPTH)?;
    let types = type_names(schema);
    if types.contains(&"integer") {
        if let Ok(n) = raw.parse::<i64>() {
            return schema_ok(doc, schema, &Value::from(n), "", MAX_SCHEMA_DEPTH, true);
        }
        if !types.contains(&"string") {
            return Err(Fail {
                pointer: String::new(),
                reason: "type",
            });
        }
    }
    if types.contains(&"number") {
        if let Ok(n) = raw.parse::<f64>() {
            if let Some(number) = serde_json::Number::from_f64(n) {
                return schema_ok(
                    doc,
                    schema,
                    &Value::Number(number),
                    "",
                    MAX_SCHEMA_DEPTH,
                    true,
                );
            }
        }
        if !types.contains(&"string") {
            return Err(Fail {
                pointer: String::new(),
                reason: "type",
            });
        }
    }
    if types.contains(&"boolean") {
        let value = match raw {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        if let Some(flag) = value {
            return schema_ok(doc, schema, &Value::Bool(flag), "", MAX_SCHEMA_DEPTH, true);
        }
        if !types.contains(&"string") {
            return Err(Fail {
                pointer: String::new(),
                reason: "type",
            });
        }
    }
    schema_ok(
        doc,
        schema,
        &Value::String(raw.to_string()),
        "",
        MAX_SCHEMA_DEPTH,
        true,
    )
}

fn validate_query_values(doc: &Value, schema: &Value, values: &[String]) -> Result<(), Fail> {
    let schema = deref(doc, schema, MAX_REF_DEPTH)?;
    let types = type_names(schema);
    if types.contains(&"array") {
        let items = schema
            .get("items")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "string"}));
        let mut arr = Vec::new();
        for value in values {
            arr.push(coerce_item(doc, &items, value)?);
        }
        return schema_ok(doc, schema, &Value::Array(arr), "", MAX_SCHEMA_DEPTH, true);
    }
    for raw in values {
        validate_stringy(doc, schema, raw)?;
    }
    Ok(())
}

fn coerce_item(doc: &Value, schema: &Value, raw: &str) -> Result<Value, Fail> {
    let schema = deref(doc, schema, MAX_REF_DEPTH)?;
    let types = type_names(schema);
    if types.contains(&"integer") {
        if let Ok(n) = raw.parse::<i64>() {
            return Ok(Value::from(n));
        }
    }
    if types.contains(&"number") {
        if let Ok(n) = raw.parse::<f64>() {
            if let Some(number) = serde_json::Number::from_f64(n) {
                return Ok(Value::Number(number));
            }
        }
    }
    if types.contains(&"boolean") {
        match raw {
            "true" => return Ok(Value::Bool(true)),
            "false" => return Ok(Value::Bool(false)),
            _ => {}
        }
    }
    Ok(Value::String(raw.to_string()))
}

fn schema_ok(
    doc: &Value,
    schema: &Value,
    instance: &Value,
    pointer: &str,
    depth: u8,
    strict: bool,
) -> Result<(), Fail> {
    if depth == 0 {
        return Err(Fail {
            pointer: pointer.to_string(),
            reason: "depth",
        });
    }
    if let Some(rel) = schema.get("$ref").and_then(Value::as_str) {
        let target = json_pointer(doc, rel).ok_or(Fail {
            pointer: pointer.to_string(),
            reason: "ref",
        })?;
        if schema.as_object().is_some_and(|map| map.len() > 1) {
            schema_ok(doc, target, instance, pointer, depth - 1, false)?;
            let mut rest = schema.clone();
            if let Some(map) = rest.as_object_mut() {
                map.remove("$ref");
            }
            schema_ok(doc, &rest, instance, pointer, depth - 1, false)?;
            if let Value::Object(map) = instance {
                deny_undeclared(doc, schema, map, pointer, depth, strict)?;
            }
            return Ok(());
        }
        return schema_ok(doc, target, instance, pointer, depth - 1, strict);
    }
    if let Some(cst) = schema.get("const") {
        if instance != cst {
            return Err(Fail {
                pointer: pointer.to_string(),
                reason: "enum",
            });
        }
    }
    if let Some(en) = schema.get("enum").and_then(Value::as_array) {
        if !en.iter().any(|value| value == instance) {
            return Err(Fail {
                pointer: pointer.to_string(),
                reason: "enum",
            });
        }
    }
    if instance.is_null() {
        if schema.get("nullable").and_then(Value::as_bool) == Some(true) {
            return Ok(());
        }
        let types = type_names(schema);
        if types.contains(&"null") {
            return Ok(());
        }
        if types.is_empty()
            && schema.get("enum").is_none()
            && schema.get("const").is_none()
            && schema.get("properties").is_none()
        {
            return Ok(());
        }
        if !types.is_empty() {
            return Err(Fail {
                pointer: pointer.to_string(),
                reason: "type",
            });
        }
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for sub in all {
            schema_ok(doc, sub, instance, pointer, depth - 1, false)?;
        }
        if let Value::Object(map) = instance {
            deny_undeclared(doc, schema, map, pointer, depth, strict)?;
        }
    }
    if let Some(any) = schema.get("anyOf").and_then(Value::as_array) {
        if !any.is_empty()
            && any
                .iter()
                .all(|sub| schema_ok(doc, sub, instance, pointer, depth - 1, false).is_err())
        {
            return Err(Fail {
                pointer: pointer.to_string(),
                reason: "anyOf",
            });
        }
    }
    if let Some(one) = schema.get("oneOf").and_then(Value::as_array) {
        if !one.is_empty() {
            let hits = one
                .iter()
                .filter(|sub| schema_ok(doc, sub, instance, pointer, depth - 1, false).is_ok())
                .count();
            if hits != 1 {
                return Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "oneOf",
                });
            }
        }
    }
    let object_strict = strict && schema.get("allOf").is_none();
    match schema.get("type") {
        Some(Value::String(t)) => {
            check_type(doc, schema, t, instance, pointer, depth, object_strict)?
        }
        Some(Value::Array(types)) => {
            let ok = types.iter().filter_map(Value::as_str).any(|t| {
                check_type(doc, schema, t, instance, pointer, depth, object_strict).is_ok()
            });
            if !ok {
                return Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                });
            }
        }
        None => {
            if schema.get("properties").is_some()
                || schema.get("additionalProperties").is_some()
                || schema.get("required").is_some()
            {
                check_type(
                    doc,
                    schema,
                    "object",
                    instance,
                    pointer,
                    depth,
                    object_strict,
                )?;
            } else if schema.get("items").is_some() {
                check_type(
                    doc,
                    schema,
                    "array",
                    instance,
                    pointer,
                    depth,
                    object_strict,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_type(
    doc: &Value,
    schema: &Value,
    type_name: &str,
    instance: &Value,
    pointer: &str,
    depth: u8,
    strict: bool,
) -> Result<(), Fail> {
    match type_name {
        "null" => {
            if instance.is_null() {
                Ok(())
            } else {
                Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                })
            }
        }
        "boolean" => {
            if instance.is_boolean() {
                Ok(())
            } else {
                Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                })
            }
        }
        "string" => {
            if instance.is_string() {
                Ok(())
            } else {
                Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                })
            }
        }
        "integer" => {
            if is_json_integer(instance) {
                Ok(())
            } else {
                Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                })
            }
        }
        "number" => {
            if instance.is_number() {
                Ok(())
            } else {
                Err(Fail {
                    pointer: pointer.to_string(),
                    reason: "type",
                })
            }
        }
        "array" => check_array(doc, schema, instance, pointer, depth),
        "object" => check_object(doc, schema, instance, pointer, depth, strict),
        _ => Ok(()),
    }
}

fn is_json_integer(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_i64() || n.is_u64(),
        _ => false,
    }
}

fn check_array(
    doc: &Value,
    schema: &Value,
    instance: &Value,
    pointer: &str,
    depth: u8,
) -> Result<(), Fail> {
    let Value::Array(items) = instance else {
        return Err(Fail {
            pointer: pointer.to_string(),
            reason: "type",
        });
    };
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            let child = format!("{pointer}/{index}");
            schema_ok(doc, item_schema, item, &child, depth - 1, true)?;
        }
    }
    Ok(())
}

fn check_object(
    doc: &Value,
    schema: &Value,
    instance: &Value,
    pointer: &str,
    depth: u8,
    strict: bool,
) -> Result<(), Fail> {
    let Value::Object(map) = instance else {
        return Err(Fail {
            pointer: pointer.to_string(),
            reason: "type",
        });
    };
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(name) {
                return Err(Fail {
                    pointer: child_pointer(pointer, name),
                    reason: "required",
                });
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (key, value) in map {
        let child = child_pointer(pointer, key);
        if let Some(properties) = properties {
            if let Some(sub) = properties.get(key) {
                schema_ok(doc, sub, value, &child, depth - 1, true)?;
                continue;
            }
        }
        match additional {
            Some(Value::Bool(false)) => {
                return Err(Fail {
                    pointer: child,
                    reason: "additionalProperties",
                });
            }
            Some(Value::Bool(true)) => {}
            Some(subschema) => schema_ok(doc, subschema, value, &child, depth - 1, true)?,
            None if strict => {
                return Err(Fail {
                    pointer: child,
                    reason: "additionalProperties",
                });
            }
            None => {}
        }
    }
    Ok(())
}

fn deny_undeclared(
    doc: &Value,
    schema: &Value,
    map: &serde_json::Map<String, Value>,
    pointer: &str,
    depth: u8,
    strict: bool,
) -> Result<(), Fail> {
    if composition_allows_additional(doc, schema, depth) {
        return Ok(());
    }
    if !strict && !matches!(schema.get("additionalProperties"), Some(Value::Bool(false))) {
        return Ok(());
    }
    let mut allowed = HashSet::new();
    collect_property_names(doc, schema, depth, &mut allowed);
    for (key, value) in map {
        if allowed.contains(key) {
            continue;
        }
        let child = child_pointer(pointer, key);
        match schema.get("additionalProperties") {
            Some(Value::Bool(true)) => {}
            Some(subschema) if !subschema.is_boolean() => {
                schema_ok(doc, subschema, value, &child, depth.saturating_sub(1), true)?;
            }
            _ => {
                return Err(Fail {
                    pointer: child,
                    reason: "additionalProperties",
                });
            }
        }
    }
    Ok(())
}

fn composition_allows_additional(doc: &Value, schema: &Value, depth: u8) -> bool {
    if depth == 0 {
        return false;
    }
    if let Some(rel) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(target) = json_pointer(doc, rel) {
            if composition_allows_additional(doc, target, depth - 1) {
                return true;
            }
        }
    }
    if matches!(schema.get("additionalProperties"), Some(Value::Bool(true))) {
        return true;
    }
    schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|all| {
            all.iter()
                .any(|sub| composition_allows_additional(doc, sub, depth - 1))
        })
}

fn collect_property_names(doc: &Value, schema: &Value, depth: u8, out: &mut HashSet<String>) {
    if depth == 0 {
        return;
    }
    if let Some(rel) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(target) = json_pointer(doc, rel) {
            collect_property_names(doc, target, depth - 1, out);
        }
    }
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        out.extend(props.keys().cloned());
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for sub in all {
            collect_property_names(doc, sub, depth - 1, out);
        }
    }
}

fn child_pointer(parent: &str, key: &str) -> String {
    format!("{parent}/{}", json_pointer_escape(key))
}

fn json_pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETS_30: &str = r##"
openapi: "3.0.3"
info:
  title: Pets
  version: "1.0"
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        "200":
          description: ok
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/NewPet"
      responses:
        "201":
          description: created
  /pets/{petId}:
    get:
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: ok
components:
  schemas:
    NewPet:
      type: object
      required: [name]
      properties:
        name:
          type: string
        status:
          type: string
          enum: [available, pending, sold]
"##;

    const PETS_31: &str = r#"
openapi: "3.1.0"
info:
  title: Pets
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /pets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
                count:
                  type: [integer, "null"]
      responses:
        "201":
          description: created
  /pets/{petId}:
    get:
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: ok
"#;

    fn policy(spec: &str, unknown: Option<UnknownEndpoint>) -> OpenApiPolicy {
        OpenApiPolicy::from_str(spec, "test.yaml", unknown).expect("compile")
    }

    fn envelope(
        policy: &OpenApiPolicy,
        method: &str,
        path: &str,
        ct: Option<&str>,
        require_complete: bool,
    ) -> EnvelopeVerdict {
        policy.validate_envelope(method, path, None, &[], ct, require_complete)
    }

    #[test]
    fn compiles_openapi_3_0_and_3_1() {
        policy(PETS_30, None);
        policy(PETS_31, None);
    }

    #[test]
    fn get_known_pet_is_allow() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        assert!(matches!(
            envelope(&p, "GET", "/pets/1", None, false),
            EnvelopeVerdict::Allow(_)
        ));
    }

    #[test]
    fn unknown_endpoint_deny_or_observe() {
        let deny = policy(PETS_30, Some(UnknownEndpoint::Deny));
        match envelope(&deny, "GET", "/nao-existe", None, false) {
            EnvelopeVerdict::Deny { detail } => {
                assert!(detail.contains("unknown_endpoint"));
                assert!(detail.contains("/nao-existe"));
            }
            other => panic!("{other:?}"),
        }
        let observe = policy(PETS_30, Some(UnknownEndpoint::Observe));
        assert!(matches!(
            envelope(&observe, "GET", "/nao-existe", None, false),
            EnvelopeVerdict::Observe { .. }
        ));
    }

    #[test]
    fn require_complete_defaults_unknown_to_deny() {
        let p = policy(PETS_30, None);
        assert!(matches!(
            envelope(&p, "GET", "/nao-existe", None, true),
            EnvelopeVerdict::Deny { .. }
        ));
        assert!(matches!(
            envelope(&p, "GET", "/nao-existe", None, false),
            EnvelopeVerdict::Observe { .. }
        ));
    }

    #[test]
    fn unknown_method_is_always_deny() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Observe));
        match envelope(&p, "DELETE", "/pets/1", None, false) {
            EnvelopeVerdict::Deny { detail } => assert!(detail.contains("unknown_method")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn path_param_type_is_enforced() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        match envelope(&p, "GET", "/pets/abc", None, false) {
            EnvelopeVerdict::Deny { detail } => {
                assert!(detail.contains("path"));
                assert!(detail.contains("type"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn extra_body_field_is_denied_and_value_stays_out_of_the_event() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("POST /pets must match");
        };
        let secret = r#"{"name":"secret-value-xyz","is_admin":true}"#;
        match matched.validate_body(Some("application/json"), secret.as_bytes()) {
            BodyVerdict::Deny { detail } => {
                assert!(detail.contains("/is_admin"));
                assert!(detail.contains("additionalProperties"));
                assert!(
                    !detail.contains("secret-value-xyz"),
                    "event must not dump body values: {detail}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn valid_json_body_is_allow() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("POST /pets must match");
        };
        assert_eq!(
            matched.validate_body(
                Some("application/json"),
                br#"{"name":"rex","status":"available"}"#
            ),
            BodyVerdict::Allow
        );
    }

    #[test]
    fn enum_and_required_are_enforced() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("POST /pets must match");
        };
        match matched.validate_body(Some("application/json"), br#"{"status":"available"}"#) {
            BodyVerdict::Deny { detail } => {
                assert!(detail.contains("/name"));
                assert!(detail.contains("required"));
            }
            other => panic!("{other:?}"),
        }
        match matched.validate_body(
            Some("application/json"),
            br#"{"name":"rex","status":"nope"}"#,
        ) {
            BodyVerdict::Deny { detail } => {
                assert!(detail.contains("/status"));
                assert!(detail.contains("enum"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_content_type_is_deny() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Observe));
        match envelope(&p, "POST", "/pets", Some("application/xml"), false) {
            EnvelopeVerdict::Deny { detail } => assert!(detail.contains("unknown_content_type")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn json_charset_is_accepted() {
        let p = policy(PETS_30, Some(UnknownEndpoint::Deny));
        assert!(matches!(
            envelope(
                &p,
                "POST",
                "/pets",
                Some("application/json; charset=utf-8"),
                false
            ),
            EnvelopeVerdict::Allow(_)
        ));
    }

    #[test]
    fn openapi_31_type_array_and_server_prefix() {
        let p = policy(PETS_31, Some(UnknownEndpoint::Deny));
        assert!(matches!(
            envelope(&p, "GET", "/v1/pets/1", None, false),
            EnvelopeVerdict::Allow(_)
        ));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/v1/pets", Some("application/json"), false)
        else {
            panic!("POST /v1/pets must match");
        };
        assert_eq!(
            matched.validate_body(Some("application/json"), br#"{"name":"rex","count":null}"#),
            BodyVerdict::Allow
        );
        match matched.validate_body(Some("application/json"), br#"{"name":"rex","count":"x"}"#) {
            BodyVerdict::Deny { detail } => assert!(detail.contains("type")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn required_header_and_query() {
        let spec = r#"
openapi: "3.0.3"
info: { title: t, version: "1" }
paths:
  /ping:
    get:
      parameters:
        - name: X-Request-Id
          in: header
          required: true
          schema: { type: string }
        - name: limit
          in: query
          required: true
          schema: { type: integer, enum: [10, 20] }
      responses:
        "200": { description: ok }
"#;
        let p = policy(spec, Some(UnknownEndpoint::Deny));
        match p.validate_envelope("GET", "/ping", Some("limit=10"), &[], None, false) {
            EnvelopeVerdict::Deny { detail } => assert!(detail.contains("header")),
            other => panic!("{other:?}"),
        }
        let headers = vec![("X-Request-Id".into(), "abc".into())];
        match p.validate_envelope(
            "GET",
            "/ping?limit=5",
            Some("limit=5"),
            &headers,
            None,
            false,
        ) {
            EnvelopeVerdict::Deny { detail } => {
                assert!(detail.contains("query"));
                assert!(detail.contains("enum") || detail.contains("type"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            p.validate_envelope(
                "GET",
                "/ping?limit=10",
                Some("limit=10"),
                &headers,
                None,
                false
            ),
            EnvelopeVerdict::Allow(_)
        ));
    }

    #[test]
    fn swagger_2_is_a_load_error() {
        let err = OpenApiPolicy::from_str(
            "swagger: '2.0'\ninfo: {title: t, version: '1'}\npaths: {}",
            "old.yaml",
            None,
        )
        .unwrap_err();
        assert!(err.contains("2.0"), "{err}");
    }

    #[test]
    fn additional_properties_true_allows_extras() {
        let spec = r#"
openapi: "3.0.3"
info: { title: t, version: "1" }
paths:
  /pets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              additionalProperties: true
              properties:
                name: { type: string }
      responses:
        "201": { description: created }
"#;
        let p = policy(spec, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("match");
        };
        assert_eq!(
            matched.validate_body(
                Some("application/json"),
                br#"{"name":"rex","is_admin":true}"#
            ),
            BodyVerdict::Allow
        );
    }

    #[test]
    fn all_of_composition_allows_union_of_properties() {
        let spec = r##"
openapi: "3.0.3"
info: { title: t, version: "1" }
paths:
  /pets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              allOf:
                - $ref: "#/components/schemas/NewPet"
                - type: object
                  required: [id]
                  properties:
                    id: { type: integer }
      responses:
        "201": { description: created }
components:
  schemas:
    NewPet:
      type: object
      required: [name]
      properties:
        name: { type: string }
"##;
        let p = policy(spec, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("match");
        };
        assert_eq!(
            matched.validate_body(Some("application/json"), br#"{"name":"rex","id":1}"#),
            BodyVerdict::Allow
        );
        match matched.validate_body(
            Some("application/json"),
            br#"{"name":"rex","id":1,"is_admin":true}"#,
        ) {
            BodyVerdict::Deny { detail } => {
                assert!(detail.contains("/is_admin"));
                assert!(detail.contains("additionalProperties"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn openapi_31_ref_siblings_are_all_of() {
        let spec = r##"
openapi: "3.1.0"
info: { title: t, version: "1" }
paths:
  /pets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/NewPet"
              required: [status]
      responses:
        "201": { description: created }
components:
  schemas:
    NewPet:
      type: object
      required: [name]
      properties:
        name: { type: string }
        status: { type: string }
"##;
        let p = policy(spec, Some(UnknownEndpoint::Deny));
        let EnvelopeVerdict::Allow(matched) =
            envelope(&p, "POST", "/pets", Some("application/json"), false)
        else {
            panic!("match");
        };
        match matched.validate_body(Some("application/json"), br#"{"name":"rex"}"#) {
            BodyVerdict::Deny { detail } => {
                assert!(detail.contains("/status"));
                assert!(detail.contains("required"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            matched.validate_body(Some("application/json"), br#"{"name":"rex","status":"ok"}"#),
            BodyVerdict::Allow
        );
    }

    #[test]
    fn every_query_value_must_match_not_only_the_last() {
        let spec = r#"
openapi: "3.0.3"
info: { title: t, version: "1" }
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          schema: { type: integer, enum: [10, 20] }
      responses:
        "200": { description: ok }
"#;
        let p = policy(spec, Some(UnknownEndpoint::Deny));
        match p.validate_envelope(
            "GET",
            "/pets?limit=nope&limit=10",
            Some("limit=nope&limit=10"),
            &[],
            None,
            false,
        ) {
            EnvelopeVerdict::Deny { detail } => assert!(detail.contains("query")),
            other => panic!("duplicate invalid query must deny, got {other:?}"),
        }
        assert!(matches!(
            p.validate_envelope("GET", "/pets?limit=10", Some("limit=10"), &[], None, false),
            EnvelopeVerdict::Allow(_)
        ));
    }
}
