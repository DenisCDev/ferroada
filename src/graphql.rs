//! GraphQL AST limits (PR 16). Opt-in per site/route. Never logs the query.

use dashmap::DashMap;
use openssl::hash::{hash, MessageDigest};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HARD_DEPTH: u32 = 64;
const HARD_COMPLEXITY: u64 = 100_000;
const HARD_OPERATIONS: u32 = 64;
const HARD_VALUE_DEPTH: usize = 32;
const DEFAULT_LIST_SIZE: u32 = 10;
const DEFAULT_QUOTA_WINDOW_SECS: u64 = 60;
const QUOTA_MAX_KEYS: usize = 50_000;
const SWEEP_EVERY: u64 = 256;
const MAX_CONFIG_DEPTH: u32 = 256;
const MAX_CONFIG_COMPLEXITY: u64 = 1_000_000;
const MAX_CONFIG_ALIASES: u32 = 10_000;
const MAX_CONFIG_FRAGMENTS: u32 = 1_024;
const MAX_CONFIG_OPERATIONS: u32 = 1_024;
const MAX_CONFIG_QUOTA: u64 = 1_000_000_000;
const MAX_CONFIG_WINDOW: u64 = 86_400;
const MAX_CONFIG_LIST: u32 = 10_000;

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GraphqlFile {
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub max_complexity: Option<u64>,
    #[serde(default)]
    pub max_aliases: Option<u32>,
    #[serde(default)]
    pub max_fragments: Option<u32>,
    #[serde(default)]
    pub max_operations: Option<u32>,
    #[serde(default)]
    pub introspection: Option<bool>,
    #[serde(default)]
    pub persisted_only: Option<bool>,
    #[serde(default)]
    pub persisted_queries: Vec<String>,
    #[serde(default)]
    pub quota: Option<u64>,
    #[serde(default)]
    pub quota_window: Option<u64>,
    #[serde(default)]
    pub default_list_size: Option<u32>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Clone, Debug)]
struct GraphqlLimits {
    max_depth: Option<u32>,
    max_complexity: Option<u64>,
    max_aliases: Option<u32>,
    max_fragments: Option<u32>,
    max_operations: Option<u32>,
    introspection: bool,
    introspection_set: bool,
    persisted_only: bool,
    persisted_only_set: bool,
    default_list_size: u32,
    quota: Option<u64>,
    quota_window: Duration,
}

#[derive(Clone)]
pub struct GraphqlPolicy {
    inner: Arc<GraphqlInner>,
}

struct GraphqlInner {
    limits: GraphqlLimits,
    paths: Vec<String>,
    persisted: HashSet<String>,
    book: Arc<QuotaBook>,
}

struct QuotaBook {
    hits: DashMap<String, Vec<(Instant, u64)>>,
    n: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct GraphqlIdentity<'a> {
    pub sub: Option<&'a str>,
    pub ip: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphqlVerdict {
    Skip,
    Allow,
    Deny(GraphqlFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphqlFailure {
    ParseError,
    Limit(&'static str),
}

impl GraphqlFailure {
    pub fn detail(self) -> &'static str {
        match self {
            Self::ParseError => "ParseError",
            Self::Limit(name) => name,
        }
    }
}

impl std::fmt::Debug for GraphqlPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphqlPolicy")
            .field("max_depth", &self.inner.limits.max_depth)
            .field("max_complexity", &self.inner.limits.max_complexity)
            .field("max_aliases", &self.inner.limits.max_aliases)
            .field("max_fragments", &self.inner.limits.max_fragments)
            .field("max_operations", &self.inner.limits.max_operations)
            .field("introspection", &self.inner.limits.introspection)
            .field("persisted_only", &self.inner.limits.persisted_only)
            .field("paths", &self.inner.paths)
            .finish()
    }
}

impl GraphqlPolicy {
    pub fn from_file(file: GraphqlFile, paths: Vec<String>) -> Self {
        let limits = limits_from_file(&file);
        let persisted = parse_hashes(&file.persisted_queries);
        Self {
            inner: Arc::new(GraphqlInner {
                limits,
                paths,
                persisted,
                book: Arc::new(QuotaBook {
                    hits: DashMap::new(),
                    n: AtomicU64::new(0),
                }),
            }),
        }
    }

    pub fn overlay(&self, other: &GraphqlPolicy) -> GraphqlPolicy {
        let limits = overlay_limits(&self.inner.limits, &other.inner.limits);
        let paths = if other.inner.paths.is_empty() {
            self.inner.paths.clone()
        } else {
            other.inner.paths.clone()
        };
        let persisted = if other.inner.persisted.is_empty() {
            self.inner.persisted.clone()
        } else {
            other.inner.persisted.clone()
        };
        GraphqlPolicy {
            inner: Arc::new(GraphqlInner {
                limits,
                paths,
                persisted,
                book: Arc::clone(&self.inner.book),
            }),
        }
    }

    pub fn check(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
        identity: GraphqlIdentity<'_>,
        site_scope: &str,
    ) -> GraphqlVerdict {
        if !method.eq_ignore_ascii_case("POST") {
            return GraphqlVerdict::Skip;
        }
        let path = path.split('?').next().unwrap_or(path);
        let path = crate::config::canonical_route_path(path).unwrap_or_else(|| path.to_string());
        if !path_ok(&self.inner.paths, &path) {
            return GraphqlVerdict::Skip;
        }
        let dedicated = !self.inner.paths.is_empty();
        match extract_ops(content_type, body, dedicated) {
            Extract::Skip => GraphqlVerdict::Skip,
            Extract::Err(failure) => GraphqlVerdict::Deny(failure),
            Extract::Ops(ops) => match self.evaluate(&ops, identity, site_scope) {
                Ok(()) => GraphqlVerdict::Allow,
                Err(failure) => GraphqlVerdict::Deny(failure),
            },
        }
    }

    fn evaluate(
        &self,
        ops: &[RawOp],
        identity: GraphqlIdentity<'_>,
        site_scope: &str,
    ) -> Result<(), GraphqlFailure> {
        let max_ops = self.inner.limits.max_operations.unwrap_or(HARD_OPERATIONS);
        if ops.len() as u32 > max_ops {
            return Err(GraphqlFailure::Limit("operations"));
        }
        let mut total_operations = 0u32;
        let mut total_complexity = 0u64;
        for op in ops {
            if let Some(claimed) = op.persisted.as_deref() {
                let claimed = claimed.trim().to_ascii_lowercase();
                if !is_sha256_hex(&claimed) {
                    return Err(GraphqlFailure::Limit("persisted_query"));
                }
                if let Some(query) = op.query.as_deref() {
                    if query_hash(query) != claimed {
                        return Err(GraphqlFailure::Limit("persisted_query"));
                    }
                } else if self.inner.limits.persisted_only {
                    return Err(GraphqlFailure::Limit("persisted_query"));
                } else {
                    return Err(GraphqlFailure::ParseError);
                }
            }
            let query = op.query.as_deref().ok_or(GraphqlFailure::ParseError)?;
            if self.inner.limits.persisted_only {
                let digest = query_hash(query);
                if !self.inner.persisted.contains(&digest) {
                    return Err(GraphqlFailure::Limit("persisted_query"));
                }
            }
            let document = match parse_document(query) {
                Ok(document) => document,
                Err(ParseFail::TooDeep) => return Err(GraphqlFailure::Limit("depth")),
                Err(ParseFail::Invalid) => return Err(GraphqlFailure::ParseError),
            };
            total_operations = total_operations
                .checked_add(document.operations.len() as u32)
                .ok_or(GraphqlFailure::Limit("operations"))?;
            if total_operations > max_ops {
                return Err(GraphqlFailure::Limit("operations"));
            }
            if document.operations.is_empty() {
                return Err(GraphqlFailure::ParseError);
            }
            let fragments = document.fragments.len() as u32;
            if let Some(max) = self.inner.limits.max_fragments {
                if fragments > max {
                    return Err(GraphqlFailure::Limit("fragments"));
                }
            }
            let stats = analyze_document(&document, op.variables.as_ref(), &self.inner.limits)?;
            if !self.inner.limits.introspection && stats.introspection {
                return Err(GraphqlFailure::Limit("introspection"));
            }
            if let Some(max) = self.inner.limits.max_depth {
                if stats.depth > max {
                    return Err(GraphqlFailure::Limit("depth"));
                }
            }
            if let Some(max) = self.inner.limits.max_complexity {
                if stats.complexity > max {
                    return Err(GraphqlFailure::Limit("complexity"));
                }
            }
            if let Some(max) = self.inner.limits.max_aliases {
                if stats.aliases > max {
                    return Err(GraphqlFailure::Limit("aliases"));
                }
            }
            total_complexity = total_complexity.saturating_add(stats.complexity.max(1));
        }
        self.consume_quota(identity, site_scope, total_complexity.max(1))
    }

    fn consume_quota(
        &self,
        identity: GraphqlIdentity<'_>,
        site_scope: &str,
        cost: u64,
    ) -> Result<(), GraphqlFailure> {
        let Some(max) = self.inner.limits.quota else {
            return Ok(());
        };
        let window = self.inner.limits.quota_window;
        let key = quota_key(site_scope, identity);
        let book = &self.inner.book;
        let n = book.n.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(SWEEP_EVERY) {
            let now = Instant::now();
            book.hits.retain(|_, stamps| {
                stamps.retain(|(at, _)| now.duration_since(*at) < window);
                !stamps.is_empty()
            });
        }
        let now = Instant::now();
        if !book.hits.contains_key(&key) && book.hits.len() >= QUOTA_MAX_KEYS {
            return Err(GraphqlFailure::Limit("quota"));
        }
        let mut entry = book.hits.entry(key).or_default();
        entry.retain(|(at, _)| now.duration_since(*at) < window);
        let used: u64 = entry
            .iter()
            .map(|(_, cost)| *cost)
            .fold(0, u64::saturating_add);
        if used.saturating_add(cost) > max {
            return Err(GraphqlFailure::Limit("quota"));
        }
        entry.push((now, cost));
        Ok(())
    }
}

fn limits_from_file(file: &GraphqlFile) -> GraphqlLimits {
    GraphqlLimits {
        max_depth: file
            .max_depth
            .map(|value| require_u32("max_depth", value, MAX_CONFIG_DEPTH)),
        max_complexity: file
            .max_complexity
            .map(|value| require_u64("max_complexity", value, MAX_CONFIG_COMPLEXITY)),
        max_aliases: file
            .max_aliases
            .map(|value| require_u32("max_aliases", value, MAX_CONFIG_ALIASES)),
        max_fragments: file
            .max_fragments
            .map(|value| require_u32("max_fragments", value, MAX_CONFIG_FRAGMENTS)),
        max_operations: file
            .max_operations
            .map(|value| require_u32("max_operations", value, MAX_CONFIG_OPERATIONS)),
        introspection: file.introspection.unwrap_or(!production_enabled()),
        introspection_set: file.introspection.is_some(),
        persisted_only: file.persisted_only.unwrap_or(false),
        persisted_only_set: file.persisted_only.is_some(),
        default_list_size: file
            .default_list_size
            .map(|value| require_u32("default_list_size", value, MAX_CONFIG_LIST))
            .unwrap_or(DEFAULT_LIST_SIZE),
        quota: file
            .quota
            .map(|value| require_u64("quota", value, MAX_CONFIG_QUOTA)),
        quota_window: Duration::from_secs(
            file.quota_window
                .map(|value| require_u64("quota_window", value, MAX_CONFIG_WINDOW))
                .unwrap_or(DEFAULT_QUOTA_WINDOW_SECS),
        ),
    }
}

fn overlay_limits(base: &GraphqlLimits, other: &GraphqlLimits) -> GraphqlLimits {
    GraphqlLimits {
        max_depth: other.max_depth.or(base.max_depth),
        max_complexity: other.max_complexity.or(base.max_complexity),
        max_aliases: other.max_aliases.or(base.max_aliases),
        max_fragments: other.max_fragments.or(base.max_fragments),
        max_operations: other.max_operations.or(base.max_operations),
        introspection: if other.introspection_set {
            other.introspection
        } else {
            base.introspection
        },
        introspection_set: base.introspection_set || other.introspection_set,
        persisted_only: if other.persisted_only_set {
            other.persisted_only
        } else {
            base.persisted_only
        },
        persisted_only_set: base.persisted_only_set || other.persisted_only_set,
        default_list_size: if other.default_list_size != DEFAULT_LIST_SIZE {
            other.default_list_size
        } else {
            base.default_list_size
        },
        quota: other.quota.or(base.quota),
        quota_window: if other.quota_window != Duration::from_secs(DEFAULT_QUOTA_WINDOW_SECS) {
            other.quota_window
        } else {
            base.quota_window
        },
    }
}

fn production_enabled() -> bool {
    std::env::var("FERROADA_PRODUCTION")
        .map(|value| value == "true")
        .unwrap_or(false)
}

fn require_u32(key: &str, value: u32, max: u32) -> u32 {
    if value == 0 || value > max {
        panic!("{key} deve estar entre 1 e {max}, veio {value}");
    }
    value
}

fn require_u64(key: &str, value: u64, max: u64) -> u64 {
    if value == 0 || value > max {
        panic!("{key} deve estar entre 1 e {max}, veio {value}");
    }
    value
}

fn parse_hashes(raw: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    for item in raw {
        let hex = item.trim().to_ascii_lowercase();
        if !is_sha256_hex(&hex) {
            panic!("graphql.persisted_queries exige SHA-256 hex (64 chars), veio {item:?}");
        }
        out.insert(hex);
    }
    out
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn path_ok(paths: &[String], path: &str) -> bool {
    if paths.is_empty() {
        return true;
    }
    paths.iter().any(|prefix| {
        path == prefix
            || prefix == "/"
            || (prefix.ends_with('/') && path.starts_with(prefix))
            || path
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn quota_key(site: &str, identity: GraphqlIdentity<'_>) -> String {
    match identity.sub {
        Some(sub) => format!("sub:{site}:{sub}"),
        None => format!("ip:{site}:{}", identity.ip),
    }
}

pub fn query_hash(query: &str) -> String {
    let digest = hash(MessageDigest::sha256(), query.as_bytes()).expect("sha256");
    to_hex(digest.as_ref())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

struct RawOp {
    query: Option<String>,
    variables: Option<Value>,
    persisted: Option<String>,
}

enum Extract {
    Skip,
    Ops(Vec<RawOp>),
    Err(GraphqlFailure),
}

fn extract_ops(content_type: Option<&str>, body: &[u8], dedicated: bool) -> Extract {
    let mime = mime_type(content_type);
    if mime == "application/graphql" {
        return match std::str::from_utf8(body) {
            Ok(text) if !text.trim().is_empty() => Extract::Ops(vec![RawOp {
                query: Some(text.to_string()),
                variables: None,
                persisted: None,
            }]),
            _ => Extract::Err(GraphqlFailure::ParseError),
        };
    }
    let jsonish =
        mime == "application/json" || mime.ends_with("+json") || mime == "application/graphql+json";
    if !jsonish {
        return if dedicated {
            Extract::Err(GraphqlFailure::ParseError)
        } else {
            Extract::Skip
        };
    }
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(_) => return Extract::Err(GraphqlFailure::ParseError),
    };
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return if dedicated {
                Extract::Err(GraphqlFailure::ParseError)
            } else {
                Extract::Skip
            }
        }
    };
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Extract::Err(GraphqlFailure::ParseError);
            }
            let mut ops = Vec::with_capacity(items.len());
            for item in items {
                match op_from_json(&item) {
                    Some(op) => ops.push(op),
                    None => return Extract::Err(GraphqlFailure::ParseError),
                }
            }
            Extract::Ops(ops)
        }
        Value::Object(_) => match op_from_json(&value) {
            Some(op) => Extract::Ops(vec![op]),
            None if dedicated => Extract::Err(GraphqlFailure::ParseError),
            None => Extract::Skip,
        },
        _ => {
            if dedicated {
                Extract::Err(GraphqlFailure::ParseError)
            } else {
                Extract::Skip
            }
        }
    }
}

fn op_from_json(value: &Value) -> Option<RawOp> {
    let object = value.as_object()?;
    let query = object
        .get("query")
        .and_then(Value::as_str)
        .map(str::to_string);
    let persisted = object
        .get("extensions")
        .and_then(|ext| ext.get("persistedQuery"))
        .and_then(|pq| pq.get("sha256Hash"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if query.is_none() && persisted.is_none() {
        return None;
    }
    let variables = object.get("variables").cloned();
    Some(RawOp {
        query,
        variables,
        persisted,
    })
}

fn mime_type(content_type: Option<&str>) -> String {
    content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

struct Document {
    operations: Vec<SelectionSet>,
    fragments: HashMap<String, SelectionSet>,
}

#[derive(Clone)]
struct SelectionSet {
    items: Vec<Selection>,
}

#[derive(Clone)]
enum Selection {
    Field {
        alias: bool,
        name: String,
        args: Vec<(String, GqlValue)>,
        selection: Option<SelectionSet>,
    },
    Spread(String),
    Inline(SelectionSet),
}

#[derive(Clone)]
enum GqlValue {
    Int(i64),
    Variable(String),
    Other,
}

struct Stats {
    depth: u32,
    complexity: u64,
    aliases: u32,
    introspection: bool,
}

fn analyze_document(
    document: &Document,
    variables: Option<&Value>,
    limits: &GraphqlLimits,
) -> Result<Stats, GraphqlFailure> {
    let ints = int_variables(variables);
    let mut stats = Stats {
        depth: 0,
        complexity: 0,
        aliases: 0,
        introspection: false,
    };
    let depth_cap = limits.max_depth.unwrap_or(HARD_DEPTH).min(HARD_DEPTH);
    let complexity_cap = limits
        .max_complexity
        .unwrap_or(HARD_COMPLEXITY)
        .min(HARD_COMPLEXITY);
    let mut env = WalkEnv {
        fragments: &document.fragments,
        stack: Vec::new(),
        stats: &mut stats,
        variables: &ints,
        default_list: limits.default_list_size,
        depth_cap,
        complexity_cap,
    };
    for operation in &document.operations {
        walk(operation, 1, &mut env)?;
    }
    Ok(stats)
}

fn int_variables(variables: Option<&Value>) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    let Some(Value::Object(map)) = variables else {
        return out;
    };
    for (key, value) in map {
        if let Some(n) = value.as_i64() {
            out.insert(key.clone(), n);
        }
    }
    out
}

struct WalkEnv<'a> {
    fragments: &'a HashMap<String, SelectionSet>,
    stack: Vec<String>,
    stats: &'a mut Stats,
    variables: &'a HashMap<String, i64>,
    default_list: u32,
    depth_cap: u32,
    complexity_cap: u64,
}

fn walk(set: &SelectionSet, depth: u32, env: &mut WalkEnv<'_>) -> Result<(), GraphqlFailure> {
    if depth > env.depth_cap {
        return Err(GraphqlFailure::Limit("depth"));
    }
    env.stats.depth = env.stats.depth.max(depth);
    for item in &set.items {
        match item {
            Selection::Field {
                alias,
                name,
                args,
                selection,
            } => {
                if *alias {
                    env.stats.aliases = env.stats.aliases.saturating_add(1);
                }
                if name == "__schema" || name == "__type" {
                    env.stats.introspection = true;
                }
                env.stats.complexity = env.stats.complexity.saturating_add(1);
                if env.stats.complexity > env.complexity_cap {
                    return Err(GraphqlFailure::Limit("complexity"));
                }
                if let Some(child) = selection {
                    let before = env.stats.complexity;
                    walk(child, depth + 1, env)?;
                    let child_cost = env.stats.complexity.saturating_sub(before);
                    let mult = list_multiplier(args, env.variables, env.default_list);
                    if mult > 1 {
                        env.stats.complexity = env
                            .stats
                            .complexity
                            .saturating_add(child_cost.saturating_mul(mult - 1));
                        if env.stats.complexity > env.complexity_cap {
                            return Err(GraphqlFailure::Limit("complexity"));
                        }
                    }
                }
            }
            Selection::Spread(name) => {
                if env.stack.iter().any(|seen| seen == name) {
                    return Err(GraphqlFailure::Limit("fragments"));
                }
                let Some(fragment) = env.fragments.get(name).cloned() else {
                    return Err(GraphqlFailure::ParseError);
                };
                env.stack.push(name.clone());
                walk(&fragment, depth, env)?;
                env.stack.pop();
            }
            Selection::Inline(child) => {
                walk(child, depth, env)?;
            }
        }
    }
    Ok(())
}

fn list_multiplier(
    args: &[(String, GqlValue)],
    variables: &HashMap<String, i64>,
    default_list: u32,
) -> u64 {
    let mut best = 1u64;
    for (name, value) in args {
        if !matches!(name.as_str(), "first" | "last" | "limit") {
            continue;
        }
        let n = match value {
            GqlValue::Int(n) => *n,
            GqlValue::Variable(var) => variables
                .get(var)
                .copied()
                .unwrap_or(i64::from(default_list)),
            GqlValue::Other => i64::from(default_list),
        };
        if n > 1 {
            best = best.max(n as u64);
        }
    }
    best
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
    Int(String),
    Float,
    String,
    Bang,
    Dollar,
    Amp,
    ParenL,
    ParenR,
    Spread,
    Colon,
    Eq,
    At,
    BracketL,
    BracketR,
    BraceL,
    BraceR,
    Pipe,
}

struct Parser<'a> {
    src: &'a str,
    i: usize,
    nesting: u32,
    too_deep: bool,
}

enum ParseFail {
    Invalid,
    TooDeep,
}

fn parse_document(source: &str) -> Result<Document, ParseFail> {
    let mut p = Parser {
        src: source,
        i: 0,
        nesting: 0,
        too_deep: false,
    };
    let mut operations = Vec::new();
    let mut fragments = HashMap::new();
    p.skip_ignored();
    if p.eof() {
        return Err(ParseFail::Invalid);
    }
    let parsed = (|| -> Result<(), ()> {
        while !p.eof() {
            match p.peek_token()? {
                Token::BraceL => operations.push(p.parse_selection_set()?),
                Token::Name(name) if name == "fragment" => {
                    p.bump_name()?;
                    let frag_name = p.expect_name()?;
                    if frag_name == "on" {
                        return Err(());
                    }
                    let on = p.expect_name()?;
                    if on != "on" {
                        return Err(());
                    }
                    let _ty = p.expect_name()?;
                    p.parse_directives()?;
                    let set = p.parse_selection_set()?;
                    if fragments.insert(frag_name, set).is_some() {
                        return Err(());
                    }
                }
                Token::Name(name)
                    if matches!(name.as_str(), "query" | "mutation" | "subscription") =>
                {
                    p.bump_name()?;
                    if matches!(p.peek_token()?, Token::Name(_)) {
                        let _ = p.expect_name()?;
                    }
                    if p.peek_token()? == Token::ParenL {
                        p.parse_variable_defs()?;
                    }
                    p.parse_directives()?;
                    operations.push(p.parse_selection_set()?);
                }
                _ => return Err(()),
            }
            p.skip_ignored();
        }
        Ok(())
    })();
    match parsed {
        Ok(()) => Ok(Document {
            operations,
            fragments,
        }),
        Err(()) if p.too_deep => Err(ParseFail::TooDeep),
        Err(()) => Err(ParseFail::Invalid),
    }
}

impl Parser<'_> {
    fn eof(&self) -> bool {
        self.i >= self.src.len()
    }

    fn rest(&self) -> &str {
        &self.src[self.i..]
    }

    fn skip_ignored(&mut self) {
        loop {
            self.skip_ws_comma();
            if self.rest().starts_with('#') {
                if let Some(nl) = self.rest().find(['\n', '\r']) {
                    self.i += nl + 1;
                } else {
                    self.i = self.src.len();
                }
                continue;
            }
            if self.rest().starts_with('\u{FEFF}') {
                self.i += '\u{FEFF}'.len_utf8();
                continue;
            }
            break;
        }
    }

    fn skip_ws_comma(&mut self) {
        while let Some(c) = self.rest().chars().next() {
            if c == ',' || c.is_whitespace() {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek_token(&mut self) -> Result<Token, ()> {
        let saved = self.i;
        let token = self.next_token()?;
        self.i = saved;
        Ok(token)
    }

    fn next_token(&mut self) -> Result<Token, ()> {
        self.skip_ignored();
        if self.eof() {
            return Err(());
        }
        let rest = self.rest();
        let bytes = rest.as_bytes();
        match bytes[0] {
            b'!' => {
                self.i += 1;
                Ok(Token::Bang)
            }
            b'$' => {
                self.i += 1;
                Ok(Token::Dollar)
            }
            b'&' => {
                self.i += 1;
                Ok(Token::Amp)
            }
            b'(' => {
                self.i += 1;
                Ok(Token::ParenL)
            }
            b')' => {
                self.i += 1;
                Ok(Token::ParenR)
            }
            b':' => {
                self.i += 1;
                Ok(Token::Colon)
            }
            b'=' => {
                self.i += 1;
                Ok(Token::Eq)
            }
            b'@' => {
                self.i += 1;
                Ok(Token::At)
            }
            b'[' => {
                self.i += 1;
                Ok(Token::BracketL)
            }
            b']' => {
                self.i += 1;
                Ok(Token::BracketR)
            }
            b'{' => {
                self.i += 1;
                Ok(Token::BraceL)
            }
            b'}' => {
                self.i += 1;
                Ok(Token::BraceR)
            }
            b'|' => {
                self.i += 1;
                Ok(Token::Pipe)
            }
            b'.' => {
                if rest.starts_with("...") {
                    self.i += 3;
                    Ok(Token::Spread)
                } else {
                    Err(())
                }
            }
            b'"' => {
                self.consume_string()?;
                Ok(Token::String)
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => Ok(Token::Name(self.take_name())),
            b'-' | b'0'..=b'9' => self.take_number(),
            _ => Err(()),
        }
    }

    fn take_name(&mut self) -> String {
        let start = self.i;
        self.i += 1;
        while let Some(b) = self.src.as_bytes().get(self.i) {
            if b.is_ascii_alphanumeric() || *b == b'_' {
                self.i += 1;
            } else {
                break;
            }
        }
        self.src[start..self.i].to_string()
    }

    fn take_number(&mut self) -> Result<Token, ()> {
        let start = self.i;
        if self.rest().starts_with('-') {
            self.i += 1;
        }
        let digits_start = self.i;
        while self
            .src
            .as_bytes()
            .get(self.i)
            .is_some_and(|b| b.is_ascii_digit())
        {
            self.i += 1;
        }
        if self.i == digits_start {
            return Err(());
        }
        let mut is_float = false;
        if self.rest().starts_with('.') {
            is_float = true;
            self.i += 1;
            let frac = self.i;
            while self
                .src
                .as_bytes()
                .get(self.i)
                .is_some_and(|b| b.is_ascii_digit())
            {
                self.i += 1;
            }
            if self.i == frac {
                return Err(());
            }
        }
        if let Some(b'e' | b'E') = self.src.as_bytes().get(self.i) {
            is_float = true;
            self.i += 1;
            if matches!(self.src.as_bytes().get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            let exp = self.i;
            while self
                .src
                .as_bytes()
                .get(self.i)
                .is_some_and(|b| b.is_ascii_digit())
            {
                self.i += 1;
            }
            if self.i == exp {
                return Err(());
            }
        }
        if is_float {
            Ok(Token::Float)
        } else {
            Ok(Token::Int(self.src[start..self.i].to_string()))
        }
    }

    fn consume_string(&mut self) -> Result<(), ()> {
        if self.rest().starts_with("\"\"\"") {
            self.i += 3;
            loop {
                if self.eof() {
                    return Err(());
                }
                if self.rest().starts_with("\"\"\"") {
                    self.i += 3;
                    return Ok(());
                }
                if self.rest().starts_with('\\') {
                    let ch = self.rest().chars().nth(1).ok_or(())?;
                    self.i += 1 + ch.len_utf8();
                    continue;
                }
                let ch = self.rest().chars().next().ok_or(())?;
                self.i += ch.len_utf8();
            }
        }
        self.i += 1;
        loop {
            if self.eof() {
                return Err(());
            }
            let b = self.src.as_bytes()[self.i];
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.i += 1;
                    let escape = *self.src.as_bytes().get(self.i).ok_or(())?;
                    self.i += 1;
                    if escape == b'u' {
                        for _ in 0..4 {
                            let h = *self.src.as_bytes().get(self.i).ok_or(())?;
                            if !h.is_ascii_hexdigit() {
                                return Err(());
                            }
                            self.i += 1;
                        }
                    }
                }
                b'\n' | b'\r' => return Err(()),
                _ => self.i += 1,
            }
        }
    }

    fn bump_name(&mut self) -> Result<String, ()> {
        match self.next_token()? {
            Token::Name(name) => Ok(name),
            _ => Err(()),
        }
    }

    fn expect_name(&mut self) -> Result<String, ()> {
        self.bump_name()
    }

    fn eat(&mut self, expected: Token) -> Result<(), ()> {
        if self.next_token()? == expected {
            Ok(())
        } else {
            Err(())
        }
    }

    fn parse_selection_set(&mut self) -> Result<SelectionSet, ()> {
        if self.nesting >= HARD_DEPTH {
            self.too_deep = true;
            return Err(());
        }
        self.nesting += 1;
        let parsed = self.parse_selection_set_inner();
        self.nesting -= 1;
        parsed
    }

    fn parse_selection_set_inner(&mut self) -> Result<SelectionSet, ()> {
        self.eat(Token::BraceL)?;
        let mut items = Vec::new();
        loop {
            self.skip_ignored();
            if self.peek_token()? == Token::BraceR {
                self.eat(Token::BraceR)?;
                break;
            }
            items.push(self.parse_selection()?);
        }
        if items.is_empty() {
            return Err(());
        }
        Ok(SelectionSet { items })
    }

    fn parse_selection(&mut self) -> Result<Selection, ()> {
        if self.peek_token()? == Token::Spread {
            self.eat(Token::Spread)?;
            match self.peek_token()? {
                Token::Name(name) if name == "on" => {
                    self.bump_name()?;
                    let _ty = self.expect_name()?;
                    self.parse_directives()?;
                    Ok(Selection::Inline(self.parse_selection_set()?))
                }
                Token::Name(name) => {
                    self.bump_name()?;
                    self.parse_directives()?;
                    Ok(Selection::Spread(name))
                }
                Token::BraceL => {
                    self.parse_directives()?;
                    Ok(Selection::Inline(self.parse_selection_set()?))
                }
                Token::At => {
                    self.parse_directives()?;
                    Ok(Selection::Inline(self.parse_selection_set()?))
                }
                _ => Err(()),
            }
        } else {
            self.parse_field()
        }
    }

    fn parse_field(&mut self) -> Result<Selection, ()> {
        let first = self.expect_name()?;
        let (alias, name) = if self.peek_token()? == Token::Colon {
            self.eat(Token::Colon)?;
            let _alias = first;
            (true, self.expect_name()?)
        } else {
            (false, first)
        };
        let args = if self.peek_token()? == Token::ParenL {
            self.parse_arguments()?
        } else {
            Vec::new()
        };
        self.parse_directives()?;
        let selection = if self.peek_token()? == Token::BraceL {
            Some(self.parse_selection_set()?)
        } else {
            None
        };
        Ok(Selection::Field {
            alias,
            name,
            args,
            selection,
        })
    }

    fn parse_arguments(&mut self) -> Result<Vec<(String, GqlValue)>, ()> {
        self.eat(Token::ParenL)?;
        let mut args = Vec::new();
        loop {
            if self.peek_token()? == Token::ParenR {
                self.eat(Token::ParenR)?;
                break;
            }
            let name = self.expect_name()?;
            self.eat(Token::Colon)?;
            let value = self.parse_value(0)?;
            args.push((name, value));
        }
        if args.is_empty() {
            return Err(());
        }
        Ok(args)
    }

    fn parse_directives(&mut self) -> Result<(), ()> {
        while self.peek_token() == Ok(Token::At) {
            self.eat(Token::At)?;
            let _ = self.expect_name()?;
            if self.peek_token()? == Token::ParenL {
                let _ = self.parse_arguments()?;
            }
        }
        Ok(())
    }

    fn parse_variable_defs(&mut self) -> Result<(), ()> {
        self.eat(Token::ParenL)?;
        loop {
            if self.peek_token()? == Token::ParenR {
                self.eat(Token::ParenR)?;
                break;
            }
            self.eat(Token::Dollar)?;
            let _ = self.expect_name()?;
            self.eat(Token::Colon)?;
            self.parse_type()?;
            if self.peek_token()? == Token::Eq {
                self.eat(Token::Eq)?;
                let _ = self.parse_value(0)?;
            }
            self.parse_directives()?;
        }
        Ok(())
    }

    fn parse_type(&mut self) -> Result<(), ()> {
        if self.peek_token()? == Token::BracketL {
            self.eat(Token::BracketL)?;
            self.parse_type()?;
            self.eat(Token::BracketR)?;
        } else {
            let _ = self.expect_name()?;
        }
        if self.peek_token()? == Token::Bang {
            self.eat(Token::Bang)?;
        }
        Ok(())
    }

    fn parse_value(&mut self, depth: usize) -> Result<GqlValue, ()> {
        if depth > HARD_VALUE_DEPTH {
            return Err(());
        }
        match self.peek_token()? {
            Token::Dollar => {
                self.eat(Token::Dollar)?;
                Ok(GqlValue::Variable(self.expect_name()?))
            }
            Token::Int(raw) => {
                let _ = self.next_token()?;
                let n = raw.parse::<i64>().map_err(|_| ())?;
                Ok(GqlValue::Int(n))
            }
            Token::Float | Token::String | Token::Name(_) => {
                let _ = self.next_token()?;
                Ok(GqlValue::Other)
            }
            Token::BracketL => {
                self.eat(Token::BracketL)?;
                while self.peek_token()? != Token::BracketR {
                    let _ = self.parse_value(depth + 1)?;
                }
                self.eat(Token::BracketR)?;
                Ok(GqlValue::Other)
            }
            Token::BraceL => {
                self.eat(Token::BraceL)?;
                while self.peek_token()? != Token::BraceR {
                    let _ = self.expect_name()?;
                    self.eat(Token::Colon)?;
                    let _ = self.parse_value(depth + 1)?;
                }
                self.eat(Token::BraceR)?;
                Ok(GqlValue::Other)
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(file: GraphqlFile) -> GraphqlPolicy {
        GraphqlPolicy::from_file(file, Vec::new())
    }

    fn post(policy: &GraphqlPolicy, body: &str) -> GraphqlVerdict {
        policy.check(
            "POST",
            "/graphql",
            Some("application/json"),
            format!(r#"{{"query":{}}}"#, serde_json::to_string(body).unwrap()).as_bytes(),
            GraphqlIdentity {
                sub: None,
                ip: "192.0.2.1",
            },
            "gql.test",
        )
    }

    fn post_raw(policy: &GraphqlPolicy, body: &str) -> GraphqlVerdict {
        policy.check(
            "POST",
            "/graphql",
            Some("application/graphql"),
            body.as_bytes(),
            GraphqlIdentity {
                sub: None,
                ip: "192.0.2.1",
            },
            "gql.test",
        )
    }

    #[test]
    fn shallow_query_allows() {
        let p = policy(GraphqlFile {
            max_depth: Some(8),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(post(&p, "{ user { id } }"), GraphqlVerdict::Allow);
        assert_eq!(post_raw(&p, "{ user { id } }"), GraphqlVerdict::Allow);
    }

    #[test]
    fn depth_overflow_is_depth() {
        let p = policy(GraphqlFile {
            max_depth: Some(3),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "{ a { b { c { d } } } }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("depth"))
        );
    }

    #[test]
    fn introspection_schema_denied_when_off() {
        let p = policy(GraphqlFile {
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "{ __schema { types { name } } }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("introspection"))
        );
        assert_eq!(
            post(&p, r#"{ user(name: "__schema") { id } }"#),
            GraphqlVerdict::Allow
        );
        assert_eq!(post(&p, "{ user { __typename } }"), GraphqlVerdict::Allow);
    }

    #[test]
    fn aliases_and_fragments_and_cycle() {
        let p = policy(GraphqlFile {
            max_aliases: Some(1),
            max_fragments: Some(1),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "{ a1: user { id } a2: user { id } }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("aliases"))
        );
        assert_eq!(
            post(&p, "fragment A on T { id } fragment B on T { id } { ...A }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("fragments"))
        );
        let p = policy(GraphqlFile {
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "fragment A on T { ...A } { ...A }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("fragments"))
        );
    }

    #[test]
    fn invalid_query_is_parse_error() {
        let p = policy(GraphqlFile {
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "not graphql"),
            GraphqlVerdict::Deny(GraphqlFailure::ParseError)
        );
    }

    #[test]
    fn batch_overflow_is_operations() {
        let p = policy(GraphqlFile {
            max_operations: Some(5),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        let item = r#"{"query":"{ user { id } }"}"#;
        let body = format!("[{}]", vec![item; 20].join(","));
        let verdict = p.check(
            "POST",
            "/graphql",
            Some("application/json"),
            body.as_bytes(),
            GraphqlIdentity {
                sub: None,
                ip: "192.0.2.1",
            },
            "gql.test",
        );
        assert_eq!(
            verdict,
            GraphqlVerdict::Deny(GraphqlFailure::Limit("operations"))
        );
    }

    #[test]
    fn persisted_only_denies_unknown_hash() {
        let query = "{ user { id } }";
        let digest = query_hash(query);
        let p = policy(GraphqlFile {
            persisted_only: Some(true),
            persisted_queries: vec![digest],
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(post(&p, query), GraphqlVerdict::Allow);
        assert_eq!(
            post(&p, "{ other { id } }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("persisted_query"))
        );
    }

    #[test]
    fn quota_keys_by_sub_when_present() {
        let p = policy(GraphqlFile {
            quota: Some(2),
            quota_window: Some(60),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        let body = r#"{"query":"{ ping }"}"#;
        let a = GraphqlIdentity {
            sub: Some("alice"),
            ip: "192.0.2.1",
        };
        let b = GraphqlIdentity {
            sub: Some("bob"),
            ip: "192.0.2.1",
        };
        let ip = GraphqlIdentity {
            sub: None,
            ip: "192.0.2.1",
        };
        let run = |id: GraphqlIdentity<'_>| {
            p.check(
                "POST",
                "/graphql",
                Some("application/json"),
                body.as_bytes(),
                id,
                "gql.test",
            )
        };
        assert_eq!(run(a), GraphqlVerdict::Allow);
        assert_eq!(run(a), GraphqlVerdict::Allow);
        assert_eq!(run(a), GraphqlVerdict::Deny(GraphqlFailure::Limit("quota")));
        assert_eq!(run(b), GraphqlVerdict::Allow);
        assert_eq!(run(ip), GraphqlVerdict::Allow);
    }

    #[test]
    fn rest_json_without_query_is_skipped() {
        let p = policy(GraphqlFile {
            max_depth: Some(1),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        let verdict = p.check(
            "POST",
            "/pets",
            Some("application/json"),
            br#"{"name":"rex"}"#,
            GraphqlIdentity {
                sub: None,
                ip: "192.0.2.1",
            },
            "gql.test",
        );
        assert_eq!(verdict, GraphqlVerdict::Skip);
    }

    #[test]
    fn explicit_introspection_flag_wins() {
        let on = GraphqlFile {
            introspection: Some(true),
            ..GraphqlFile::default()
        };
        assert!(limits_from_file(&on).introspection);
        let off = GraphqlFile {
            introspection: Some(false),
            ..GraphqlFile::default()
        };
        assert!(!limits_from_file(&off).introspection);
        if production_enabled() {
            assert!(!limits_from_file(&GraphqlFile::default()).introspection);
        }
    }

    #[test]
    fn event_detail_is_the_limit_name_not_the_query() {
        assert_eq!(GraphqlFailure::Limit("depth").detail(), "depth");
        assert_eq!(GraphqlFailure::ParseError.detail(), "ParseError");
        assert!(!GraphqlFailure::Limit("depth").detail().contains('{'));
    }

    #[test]
    fn deeply_nested_braces_are_depth_not_a_panic() {
        let p = policy(GraphqlFile {
            max_depth: Some(3),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        let mut query = String::from("{id}");
        for _ in 0..4000 {
            query = format!("{{a{query}}}");
        }
        assert_eq!(
            post(&p, &query),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("depth"))
        );
    }

    #[test]
    fn encoded_path_still_matches_route_prefix() {
        let p = GraphqlPolicy::from_file(
            GraphqlFile {
                max_depth: Some(3),
                introspection: Some(false),
                ..GraphqlFile::default()
            },
            vec!["/graphql".into()],
        );
        let verdict = p.check(
            "POST",
            "/%67raphql",
            Some("application/json"),
            br#"{"query":"{ a { b { c { d } } } }"}"#,
            GraphqlIdentity {
                sub: None,
                ip: "192.0.2.1",
            },
            "gql.test",
        );
        assert_eq!(
            verdict,
            GraphqlVerdict::Deny(GraphqlFailure::Limit("depth"))
        );
    }

    #[test]
    fn list_multiplier_uses_largest_first_last_limit() {
        let p = policy(GraphqlFile {
            max_complexity: Some(50),
            introspection: Some(false),
            ..GraphqlFile::default()
        });
        assert_eq!(
            post(&p, "{ users(first: 1, last: 1000) { a { b { c } } } }"),
            GraphqlVerdict::Deny(GraphqlFailure::Limit("complexity"))
        );
    }
}
