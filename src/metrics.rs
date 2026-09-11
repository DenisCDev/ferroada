use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Events kept per `site_scope`. One tenant filling its ring must not
/// erase another tenant's events (was a single global ring of 100).
pub const MAX_EVENTS_PER_SITE: usize = 50;
pub const UNSCOPED_SITE: &str = "__unscoped__";

pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub blocked_sqli: AtomicU64,
    pub blocked_xss: AtomicU64,
    pub blocked_path_traversal: AtomicU64,
    pub blocked_rate_limit: AtomicU64,
    pub blocked_sensitive_path: AtomicU64,
    pub blocked_body_sqli: AtomicU64,
    pub blocked_body_xss: AtomicU64,
    pub blocked_method: AtomicU64,
    pub blocked_size_limit: AtomicU64,
    pub blocked_host: AtomicU64,
    pub blocked_crlf: AtomicU64,
    pub blocked_smuggling: AtomicU64,
    pub blocked_jndi: AtomicU64,
    pub blocked_bad_bot: AtomicU64,
    pub blocked_behavioral_throttle: AtomicU64,
    pub blocked_behavioral_block: AtomicU64,
    pub blocked_waf_incomplete: AtomicU64,
    pub blocked_inspection_parse_error: AtomicU64,
    pub blocked_header_limit: AtomicU64,
    pub blocked_concurrency_limit: AtomicU64,
    pub blocked_connection_limit: AtomicU64,
    pub blocked_request_buffer_limit: AtomicU64,
    pub blocked_spool_limit: AtomicU64,
    pub blocked_waf_l1: AtomicU64,
    pub blocked_openapi: AtomicU64,
    pub blocked_jwt: AtomicU64,
    pub blocked_jwt_binding: AtomicU64,
    pub blocked_graphql: AtomicU64,
    pub blocked_grpc: AtomicU64,
    pub blocked_dlp_partial: AtomicU64,
    pub https_redirect: AtomicU64,
    pub waf_inspection_complete: AtomicU64,
    pub waf_inspection_truncated: AtomicU64,
    pub waf_inspection_unsupported_encoding: AtomicU64,
    pub waf_inspection_unsupported_content_type: AtomicU64,
    pub waf_inspection_parse_error: AtomicU64,
    pub waf_inspection_budget_exceeded: AtomicU64,
    pub waf_inspection_timed_out: AtomicU64,
    pub waf_engine_unavailable: AtomicU64,
    pub waf_l1_shadow: AtomicU64,
    pub openapi_observed: AtomicU64,
    pub waf_monitored: AtomicU64,
    pub dlp_cpf_masked: AtomicU64,
    pub dlp_cnpj_masked: AtomicU64,
    pub dlp_card_masked: AtomicU64,
    pub dlp_tokens_masked: AtomicU64,
    pub protocol_deny: AtomicU64,
    pub protocol_monitor: AtomicU64,
    pub protocol_bypass: AtomicU64,
    pub protocol_quarantine: AtomicU64,
    protocol_by_id: Mutex<HashMap<(String, String), u64>>,
    events_by_site: Mutex<HashMap<String, VecDeque<StoredEvent>>>,
    event_seq: AtomicU64,
}

#[derive(Clone)]
struct StoredEvent {
    seq: u64,
    event: SecurityEvent,
}

#[derive(Serialize, Clone)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub event_type: String,
    pub client_ip: String,
    pub uri: String,
    pub detail: String,
    pub site_scope: String,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            blocked_sqli: AtomicU64::new(0),
            blocked_xss: AtomicU64::new(0),
            blocked_path_traversal: AtomicU64::new(0),
            blocked_rate_limit: AtomicU64::new(0),
            blocked_sensitive_path: AtomicU64::new(0),
            blocked_body_sqli: AtomicU64::new(0),
            blocked_body_xss: AtomicU64::new(0),
            blocked_method: AtomicU64::new(0),
            blocked_size_limit: AtomicU64::new(0),
            blocked_host: AtomicU64::new(0),
            blocked_crlf: AtomicU64::new(0),
            blocked_smuggling: AtomicU64::new(0),
            blocked_jndi: AtomicU64::new(0),
            blocked_bad_bot: AtomicU64::new(0),
            blocked_behavioral_throttle: AtomicU64::new(0),
            blocked_behavioral_block: AtomicU64::new(0),
            blocked_waf_incomplete: AtomicU64::new(0),
            blocked_inspection_parse_error: AtomicU64::new(0),
            blocked_header_limit: AtomicU64::new(0),
            blocked_concurrency_limit: AtomicU64::new(0),
            blocked_connection_limit: AtomicU64::new(0),
            blocked_request_buffer_limit: AtomicU64::new(0),
            blocked_spool_limit: AtomicU64::new(0),
            blocked_waf_l1: AtomicU64::new(0),
            blocked_openapi: AtomicU64::new(0),
            blocked_jwt: AtomicU64::new(0),
            blocked_jwt_binding: AtomicU64::new(0),
            blocked_graphql: AtomicU64::new(0),
            blocked_grpc: AtomicU64::new(0),
            blocked_dlp_partial: AtomicU64::new(0),
            https_redirect: AtomicU64::new(0),
            waf_inspection_complete: AtomicU64::new(0),
            waf_inspection_truncated: AtomicU64::new(0),
            waf_inspection_unsupported_encoding: AtomicU64::new(0),
            waf_inspection_unsupported_content_type: AtomicU64::new(0),
            waf_inspection_parse_error: AtomicU64::new(0),
            waf_inspection_budget_exceeded: AtomicU64::new(0),
            waf_inspection_timed_out: AtomicU64::new(0),
            waf_engine_unavailable: AtomicU64::new(0),
            waf_l1_shadow: AtomicU64::new(0),
            openapi_observed: AtomicU64::new(0),
            waf_monitored: AtomicU64::new(0),
            dlp_cpf_masked: AtomicU64::new(0),
            dlp_cnpj_masked: AtomicU64::new(0),
            dlp_card_masked: AtomicU64::new(0),
            dlp_tokens_masked: AtomicU64::new(0),
            protocol_deny: AtomicU64::new(0),
            protocol_monitor: AtomicU64::new(0),
            protocol_bypass: AtomicU64::new(0),
            protocol_quarantine: AtomicU64::new(0),
            protocol_by_id: Mutex::new(HashMap::new()),
            events_by_site: Mutex::new(HashMap::new()),
            event_seq: AtomicU64::new(0),
        }
    }

    fn push_event(&self, site_scope: &str, mut event: SecurityEvent) {
        let site = normalize_site(site_scope);
        event.site_scope = site.clone();
        let seq = self.event_seq.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut by_site) = self.events_by_site.lock() {
            let ring = by_site
                .entry(site)
                .or_insert_with(|| VecDeque::with_capacity(MAX_EVENTS_PER_SITE));
            if ring.len() >= MAX_EVENTS_PER_SITE {
                ring.pop_front();
            }
            ring.push_back(StoredEvent { seq, event });
        }
    }

    fn snapshot_events(&self) -> Vec<SecurityEvent> {
        let Ok(by_site) = self.events_by_site.lock() else {
            return Vec::new();
        };
        let mut collected: Vec<(u64, SecurityEvent)> = by_site
            .values()
            .flat_map(|ring| ring.iter().map(|stored| (stored.seq, stored.event.clone())))
            .collect();
        collected.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
        collected.into_iter().map(|(_, event)| event).collect()
    }
}

fn normalize_site(site_scope: &str) -> String {
    let trimmed = site_scope.trim();
    if trimmed.is_empty() {
        UNSCOPED_SITE.to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn now_iso() -> String {
    // Simple UTC-ish timestamp without chrono dependency
    // Uses elapsed since a fixed point — good enough for event ordering
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds = rem % 60;

    // Approximate date from epoch days (good enough for logging)
    let (year, month, day) = epoch_days_to_date(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub fn increment_requests() {
    METRICS.requests_total.fetch_add(1, Ordering::Relaxed);
}

pub fn record_block(event_type: &str, client_ip: &str, uri: &str, detail: &str) {
    record_block_in(UNSCOPED_SITE, event_type, client_ip, uri, detail);
}

pub fn record_block_in(
    site_scope: &str,
    event_type: &str,
    client_ip: &str,
    uri: &str,
    detail: &str,
) {
    let counter = match event_type {
        "sqli" => &METRICS.blocked_sqli,
        "xss" => &METRICS.blocked_xss,
        "path_traversal" => &METRICS.blocked_path_traversal,
        "rate_limit" => &METRICS.blocked_rate_limit,
        "sensitive_path" => &METRICS.blocked_sensitive_path,
        "body_sqli" => &METRICS.blocked_body_sqli,
        "body_xss" => &METRICS.blocked_body_xss,
        "method" => &METRICS.blocked_method,
        "size_limit" => &METRICS.blocked_size_limit,
        "host" => &METRICS.blocked_host,
        "crlf" => &METRICS.blocked_crlf,
        "smuggling" => &METRICS.blocked_smuggling,
        "jndi" => &METRICS.blocked_jndi,
        "bad_bot" => &METRICS.blocked_bad_bot,
        "behavioral_throttle" => &METRICS.blocked_behavioral_throttle,
        "behavioral_block" => &METRICS.blocked_behavioral_block,
        "waf_incomplete" => &METRICS.blocked_waf_incomplete,
        "inspection_parse_error" => &METRICS.blocked_inspection_parse_error,
        "header_limit" => &METRICS.blocked_header_limit,
        "concurrency_limit" => &METRICS.blocked_concurrency_limit,
        "connection_limit" => &METRICS.blocked_connection_limit,
        "request_buffer_limit" => &METRICS.blocked_request_buffer_limit,
        "spool_limit" => &METRICS.blocked_spool_limit,
        "waf_l1" => &METRICS.blocked_waf_l1,
        "openapi" => &METRICS.blocked_openapi,
        "jwt" => &METRICS.blocked_jwt,
        "jwt_binding" => &METRICS.blocked_jwt_binding,
        "graphql" => &METRICS.blocked_graphql,
        "grpc" => &METRICS.blocked_grpc,
        "dlp_partial_block" => &METRICS.blocked_dlp_partial,
        "https_redirect" => &METRICS.https_redirect,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);

    METRICS.push_event(
        site_scope,
        SecurityEvent {
            timestamp: now_iso(),
            event_type: event_type.to_string(),
            client_ip: client_ip.to_string(),
            uri: uri.to_string(),
            detail: detail.to_string(),
            site_scope: String::new(),
        },
    );
}

pub fn record_protocol(protocol_id: &str, action: &str, client_ip: &str, uri: &str, detail: &str) {
    record_protocol_in(UNSCOPED_SITE, protocol_id, action, client_ip, uri, detail);
}

pub fn record_protocol_in(
    site_scope: &str,
    protocol_id: &str,
    action: &str,
    client_ip: &str,
    uri: &str,
    detail: &str,
) {
    let counter = match action {
        "deny" => &METRICS.protocol_deny,
        "monitor" => &METRICS.protocol_monitor,
        "bypass-explicit" => &METRICS.protocol_bypass,
        "quarantine" => &METRICS.protocol_quarantine,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);

    if let Ok(mut by_id) = METRICS.protocol_by_id.lock() {
        *by_id
            .entry((protocol_id.to_string(), action.to_string()))
            .or_insert(0) += 1;
    }

    let event_type = match action {
        "quarantine" => "quarantine",
        "deny" => "protocol_deny",
        "monitor" => "protocol_monitor",
        "bypass-explicit" => "protocol_bypass",
        _ => return,
    };
    METRICS.push_event(
        site_scope,
        SecurityEvent {
            timestamp: now_iso(),
            event_type: event_type.to_string(),
            client_ip: client_ip.to_string(),
            uri: uri.to_string(),
            detail: detail.to_string(),
            site_scope: String::new(),
        },
    );
}

pub fn record_waf_inspection(status: &str) {
    let counter = match status {
        "complete" => &METRICS.waf_inspection_complete,
        "truncated" => &METRICS.waf_inspection_truncated,
        "unsupported_encoding" => &METRICS.waf_inspection_unsupported_encoding,
        "unsupported_content_type" => &METRICS.waf_inspection_unsupported_content_type,
        "parse_error" => &METRICS.waf_inspection_parse_error,
        "budget_exceeded" => &METRICS.waf_inspection_budget_exceeded,
        "timed_out" => &METRICS.waf_inspection_timed_out,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn record_waf_engine_unavailable(site_scope: &str, client_ip: &str, uri: &str, detail: &str) {
    METRICS
        .waf_engine_unavailable
        .fetch_add(1, Ordering::Relaxed);
    record_observation_in(site_scope, "waf_engine_unavailable", client_ip, uri, detail);
}

pub fn record_l1_shadow(site_scope: &str, client_ip: &str, uri: &str, detail: &str) {
    record_observation_in(site_scope, "waf_l1_shadow", client_ip, uri, detail);
}

pub fn record_observation(event_type: &str, client_ip: &str, uri: &str, detail: &str) {
    record_observation_in(UNSCOPED_SITE, event_type, client_ip, uri, detail);
}

pub fn record_observation_in(
    site_scope: &str,
    event_type: &str,
    client_ip: &str,
    uri: &str,
    detail: &str,
) {
    if event_type == "waf_monitor" {
        METRICS.waf_monitored.fetch_add(1, Ordering::Relaxed);
    } else if event_type == "waf_l1_shadow" {
        METRICS.waf_l1_shadow.fetch_add(1, Ordering::Relaxed);
        METRICS.waf_monitored.fetch_add(1, Ordering::Relaxed);
    } else if event_type == "openapi_observe" {
        METRICS.openapi_observed.fetch_add(1, Ordering::Relaxed);
    } else if !matches!(
        event_type,
        "dlp_skip"
            | "range_removed"
            | "inspection_parse_error"
            | "inspection_timeout"
            | "inspection_budget"
            | "waf_incomplete"
            | "waf_engine_unavailable"
    ) {
        return;
    }
    METRICS.push_event(
        site_scope,
        SecurityEvent {
            timestamp: now_iso(),
            event_type: event_type.to_string(),
            client_ip: client_ip.to_string(),
            uri: uri.to_string(),
            detail: detail.to_string(),
            site_scope: String::new(),
        },
    );
}

pub fn record_dlp(
    cpf_count: u64,
    cnpj_count: u64,
    card_count: u64,
    token_count: u64,
    verb: &str,
    fields: &[String],
) {
    if cpf_count > 0 {
        METRICS
            .dlp_cpf_masked
            .fetch_add(cpf_count, Ordering::Relaxed);
    }
    if cnpj_count > 0 {
        METRICS
            .dlp_cnpj_masked
            .fetch_add(cnpj_count, Ordering::Relaxed);
    }
    if card_count > 0 {
        METRICS
            .dlp_card_masked
            .fetch_add(card_count, Ordering::Relaxed);
    }
    if token_count > 0 {
        METRICS
            .dlp_tokens_masked
            .fetch_add(token_count, Ordering::Relaxed);
    }
    if cpf_count > 0 || cnpj_count > 0 || card_count > 0 || token_count > 0 {
        let mut detail = format!(
            "{verb} {cpf_count} CPFs, {cnpj_count} CNPJs, {card_count} cards, {token_count} tokens"
        );
        if !fields.is_empty() {
            detail.push_str("; campos ");
            detail.push_str(&fields.join(", "));
        }
        METRICS.push_event(
            UNSCOPED_SITE,
            SecurityEvent {
                timestamp: now_iso(),
                event_type: "dlp".to_string(),
                client_ip: "-".to_string(),
                uri: "-".to_string(),
                detail,
                site_scope: String::new(),
            },
        );
    }
}

pub fn snapshot_json() -> String {
    let m = &*METRICS;
    let events = m.snapshot_events();

    let json = serde_json::json!({
        "requests_total": m.requests_total.load(Ordering::Relaxed),
        "blocked": {
            "sqli": m.blocked_sqli.load(Ordering::Relaxed),
            "xss": m.blocked_xss.load(Ordering::Relaxed),
            "path_traversal": m.blocked_path_traversal.load(Ordering::Relaxed),
            "rate_limit": m.blocked_rate_limit.load(Ordering::Relaxed),
            "sensitive_path": m.blocked_sensitive_path.load(Ordering::Relaxed),
            "body_sqli": m.blocked_body_sqli.load(Ordering::Relaxed),
            "body_xss": m.blocked_body_xss.load(Ordering::Relaxed),
            "method": m.blocked_method.load(Ordering::Relaxed),
            "size_limit": m.blocked_size_limit.load(Ordering::Relaxed),
            "host": m.blocked_host.load(Ordering::Relaxed),
            "crlf": m.blocked_crlf.load(Ordering::Relaxed),
            "smuggling": m.blocked_smuggling.load(Ordering::Relaxed),
            "jndi": m.blocked_jndi.load(Ordering::Relaxed),
            "bad_bot": m.blocked_bad_bot.load(Ordering::Relaxed),
            "behavioral_throttle": m.blocked_behavioral_throttle.load(Ordering::Relaxed),
            "behavioral_block": m.blocked_behavioral_block.load(Ordering::Relaxed),
            "waf_incomplete": m.blocked_waf_incomplete.load(Ordering::Relaxed),
            "inspection_parse_error": m.blocked_inspection_parse_error.load(Ordering::Relaxed),
            "header_limit": m.blocked_header_limit.load(Ordering::Relaxed),
            "concurrency_limit": m.blocked_concurrency_limit.load(Ordering::Relaxed),
            "connection_limit": m.blocked_connection_limit.load(Ordering::Relaxed),
            "request_buffer_limit": m.blocked_request_buffer_limit.load(Ordering::Relaxed),
            "spool_limit": m.blocked_spool_limit.load(Ordering::Relaxed),
            "waf_l1": m.blocked_waf_l1.load(Ordering::Relaxed),
            "openapi": m.blocked_openapi.load(Ordering::Relaxed),
            "jwt": m.blocked_jwt.load(Ordering::Relaxed),
            "jwt_binding": m.blocked_jwt_binding.load(Ordering::Relaxed),
            "graphql": m.blocked_graphql.load(Ordering::Relaxed),
            "grpc": m.blocked_grpc.load(Ordering::Relaxed),
            "dlp_partial_block": m.blocked_dlp_partial.load(Ordering::Relaxed)
        },
        "waf_inspection": {
            "complete": m.waf_inspection_complete.load(Ordering::Relaxed),
            "truncated": m.waf_inspection_truncated.load(Ordering::Relaxed),
            "unsupported_encoding": m.waf_inspection_unsupported_encoding.load(Ordering::Relaxed),
            "unsupported_content_type": m.waf_inspection_unsupported_content_type.load(Ordering::Relaxed),
            "parse_error": m.waf_inspection_parse_error.load(Ordering::Relaxed),
            "budget_exceeded": m.waf_inspection_budget_exceeded.load(Ordering::Relaxed),
            "timed_out": m.waf_inspection_timed_out.load(Ordering::Relaxed)
        },
        "waf_engine_unavailable": m.waf_engine_unavailable.load(Ordering::Relaxed),
        "waf_l1_shadow": m.waf_l1_shadow.load(Ordering::Relaxed),
        "openapi_observed": m.openapi_observed.load(Ordering::Relaxed),
        "waf_monitored": m.waf_monitored.load(Ordering::Relaxed),
        "https_redirect": m.https_redirect.load(Ordering::Relaxed),
        "dlp": {
            "cpf_masked": m.dlp_cpf_masked.load(Ordering::Relaxed),
            "cnpj_masked": m.dlp_cnpj_masked.load(Ordering::Relaxed),
            "card_masked": m.dlp_card_masked.load(Ordering::Relaxed),
            "tokens_masked": m.dlp_tokens_masked.load(Ordering::Relaxed)
        },
        "protocol": {
            "deny": m.protocol_deny.load(Ordering::Relaxed),
            "monitor": m.protocol_monitor.load(Ordering::Relaxed),
            "bypass_explicit": m.protocol_bypass.load(Ordering::Relaxed),
            "quarantine": m.protocol_quarantine.load(Ordering::Relaxed)
        },
        "recent_events": events
    });

    serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
}

pub fn snapshot_prometheus() -> String {
    let metrics = &*METRICS;
    let blocks = [
        ("sqli", &metrics.blocked_sqli),
        ("xss", &metrics.blocked_xss),
        ("path_traversal", &metrics.blocked_path_traversal),
        ("rate_limit", &metrics.blocked_rate_limit),
        ("sensitive_path", &metrics.blocked_sensitive_path),
        ("body_sqli", &metrics.blocked_body_sqli),
        ("body_xss", &metrics.blocked_body_xss),
        ("method", &metrics.blocked_method),
        ("size_limit", &metrics.blocked_size_limit),
        ("header_limit", &metrics.blocked_header_limit),
        ("host", &metrics.blocked_host),
        ("crlf", &metrics.blocked_crlf),
        ("smuggling", &metrics.blocked_smuggling),
        ("jndi", &metrics.blocked_jndi),
        ("bad_bot", &metrics.blocked_bad_bot),
        ("behavioral_throttle", &metrics.blocked_behavioral_throttle),
        ("behavioral_block", &metrics.blocked_behavioral_block),
        ("waf_incomplete", &metrics.blocked_waf_incomplete),
        (
            "inspection_parse_error",
            &metrics.blocked_inspection_parse_error,
        ),
        ("concurrency_limit", &metrics.blocked_concurrency_limit),
        ("connection_limit", &metrics.blocked_connection_limit),
        (
            "request_buffer_limit",
            &metrics.blocked_request_buffer_limit,
        ),
        ("spool_limit", &metrics.blocked_spool_limit),
        ("waf_l1", &metrics.blocked_waf_l1),
        ("openapi", &metrics.blocked_openapi),
        ("jwt", &metrics.blocked_jwt),
        ("jwt_binding", &metrics.blocked_jwt_binding),
        ("graphql", &metrics.blocked_graphql),
        ("grpc", &metrics.blocked_grpc),
        ("dlp_partial_block", &metrics.blocked_dlp_partial),
    ];
    let mut output = format!(
        "# TYPE ferroada_requests_total counter\nferroada_requests_total {}\n# TYPE ferroada_blocks_total counter\n",
        metrics.requests_total.load(Ordering::Relaxed)
    );
    for (event_type, counter) in blocks {
        output.push_str(&format!(
            "ferroada_blocks_total{{type=\"{event_type}\"}} {}\n",
            counter.load(Ordering::Relaxed)
        ));
    }
    output.push_str("# TYPE ferroada_waf_inspection_total counter\n");
    for (status, counter) in [
        ("complete", &metrics.waf_inspection_complete),
        ("truncated", &metrics.waf_inspection_truncated),
        (
            "unsupported_encoding",
            &metrics.waf_inspection_unsupported_encoding,
        ),
        (
            "unsupported_content_type",
            &metrics.waf_inspection_unsupported_content_type,
        ),
        ("parse_error", &metrics.waf_inspection_parse_error),
        ("budget_exceeded", &metrics.waf_inspection_budget_exceeded),
        ("timed_out", &metrics.waf_inspection_timed_out),
    ] {
        output.push_str(&format!(
            "ferroada_waf_inspection_total{{status=\"{status}\"}} {}\n",
            counter.load(Ordering::Relaxed)
        ));
    }
    output.push_str(&format!(
        "# TYPE ferroada_waf_engine_unavailable_total counter\nferroada_waf_engine_unavailable_total {}\n",
        metrics.waf_engine_unavailable.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "# TYPE ferroada_waf_l1_shadow_total counter\nferroada_waf_l1_shadow_total {}\n",
        metrics.waf_l1_shadow.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "# TYPE ferroada_openapi_observed_total counter\nferroada_openapi_observed_total {}\n",
        metrics.openapi_observed.load(Ordering::Relaxed)
    ));
    output.push_str("# TYPE ferroada_protocol_total counter\n");
    for (action, counter) in [
        ("deny", &metrics.protocol_deny),
        ("monitor", &metrics.protocol_monitor),
        ("bypass-explicit", &metrics.protocol_bypass),
        ("quarantine", &metrics.protocol_quarantine),
    ] {
        output.push_str(&format!(
            "ferroada_protocol_total{{action=\"{action}\"}} {}\n",
            counter.load(Ordering::Relaxed)
        ));
    }
    if let Ok(by_id) = metrics.protocol_by_id.lock() {
        let mut rows: Vec<_> = by_id.iter().collect();
        rows.sort_by(|left, right| left.0.cmp(right.0));
        for ((id, action), count) in rows {
            output.push_str(&format!(
                "ferroada_protocol_total{{id=\"{id}\",action=\"{action}\"}} {count}\n"
            ));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_snapshot_exposes_bounded_metric_names() {
        let snapshot = snapshot_prometheus();
        assert!(snapshot.contains("ferroada_requests_total"));
        assert!(snapshot.contains("ferroada_waf_inspection_total{status=\"truncated\"}"));
        assert!(snapshot.contains("ferroada_waf_inspection_total{status=\"parse_error\"}"));
        assert!(snapshot.contains("ferroada_waf_inspection_total{status=\"timed_out\"}"));
        assert!(snapshot.contains("ferroada_waf_engine_unavailable_total"));
        assert!(snapshot.contains("ferroada_waf_l1_shadow_total"));
        assert!(snapshot.contains("ferroada_protocol_total{action=\"quarantine\"}"));
    }

    fn unique_sites() -> (String, String) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        (
            format!("quota-a-{n}.example"),
            format!("quota-b-{n}.example"),
        )
    }

    fn event_uris(snapshot: &str) -> Vec<String> {
        let value: serde_json::Value =
            serde_json::from_str(snapshot).expect("metrics snapshot is JSON");
        value["recent_events"]
            .as_array()
            .expect("recent_events")
            .iter()
            .map(|event| event["uri"].as_str().expect("event uri").to_string())
            .collect()
    }

    #[test]
    fn noisy_site_does_not_evict_another_site_events() {
        let (site_a, site_b) = unique_sites();
        for i in 0..(MAX_EVENTS_PER_SITE + 10) {
            record_block_in(
                &site_a,
                "sqli",
                "192.0.2.1",
                &format!("/flood-a/{i}"),
                "flood",
            );
        }
        record_block_in(&site_b, "xss", "192.0.2.2", "/kept-from-b", "keep");

        let snapshot = snapshot_json();
        let uris = event_uris(&snapshot);
        assert!(
            uris.iter().any(|uri| uri == "/kept-from-b"),
            "site B event must survive site A filling its ring: {uris:?}"
        );
        let a_count = uris
            .iter()
            .filter(|uri| uri.starts_with("/flood-a/"))
            .count();
        assert_eq!(
            a_count, MAX_EVENTS_PER_SITE,
            "site A must keep only its own cap, got {a_count}"
        );
        assert!(
            !uris.iter().any(|uri| uri == "/flood-a/0"),
            "site A oldest event must be evicted from its own ring"
        );
        assert!(snapshot.contains(&site_a), "{snapshot}");
        assert!(snapshot.contains(&site_b), "{snapshot}");
    }

    #[test]
    fn waf_l1_block_event_keeps_rule_ids_in_detail() {
        let site = format!(
            "l1-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        record_block_in(
            &site,
            "waf_l1",
            "192.0.2.4",
            "/search",
            "CRS 942100,942110: SQLi",
        );
        let snapshot = snapshot_json();
        assert!(snapshot.contains("\"waf_l1\""), "{snapshot}");
        assert!(snapshot.contains("942100"), "{snapshot}");
        assert!(snapshot.contains("942110"), "{snapshot}");
        record_waf_engine_unavailable(&site, "192.0.2.4", "/search", "TimedOut");
        let snapshot = snapshot_json();
        assert!(snapshot.contains("waf_engine_unavailable"), "{snapshot}");
        assert!(snapshot.contains("TimedOut"), "{snapshot}");
        record_l1_shadow(&site, "192.0.2.4", "/search", "CRS 942100 score=8: SQLi");
        let snapshot = snapshot_json();
        assert!(snapshot.contains("waf_l1_shadow"), "{snapshot}");
        assert!(snapshot.contains("942100"), "{snapshot}");
        let prometheus = snapshot_prometheus();
        assert!(prometheus.contains("ferroada_blocks_total{type=\"waf_l1\"}"));
        assert!(prometheus.contains("ferroada_waf_engine_unavailable_total"));
        assert!(prometheus.contains("ferroada_waf_l1_shadow_total"));
    }

    #[test]
    fn unscoped_flood_does_not_evict_scoped_events() {
        let (_, site_b) = unique_sites();
        for i in 0..(MAX_EVENTS_PER_SITE + 10) {
            record_block(
                "sqli",
                "192.0.2.3",
                &format!("/flood-unscoped/{i}"),
                "flood",
            );
        }
        record_block_in(&site_b, "xss", "192.0.2.4", "/kept-scoped", "keep");
        let uris = event_uris(&snapshot_json());
        assert!(
            uris.iter().any(|uri| uri == "/kept-scoped"),
            "scoped event must survive an unscoped flood: {uris:?}"
        );
    }
}
