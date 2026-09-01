use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const MAX_EVENTS: usize = 100;

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
    pub blocked_header_limit: AtomicU64,
    pub blocked_concurrency_limit: AtomicU64,
    pub blocked_connection_limit: AtomicU64,
    pub blocked_request_buffer_limit: AtomicU64,
    pub blocked_dlp_partial: AtomicU64,
    pub https_redirect: AtomicU64,
    pub waf_inspection_complete: AtomicU64,
    pub waf_inspection_truncated: AtomicU64,
    pub waf_inspection_unsupported_encoding: AtomicU64,
    pub waf_inspection_unsupported_content_type: AtomicU64,
    pub waf_monitored: AtomicU64,
    pub dlp_cpf_masked: AtomicU64,
    pub dlp_tokens_masked: AtomicU64,
    pub recent_events: Mutex<VecDeque<SecurityEvent>>,
}

#[derive(Serialize, Clone)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub event_type: String,
    pub client_ip: String,
    pub uri: String,
    pub detail: String,
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
            blocked_header_limit: AtomicU64::new(0),
            blocked_concurrency_limit: AtomicU64::new(0),
            blocked_connection_limit: AtomicU64::new(0),
            blocked_request_buffer_limit: AtomicU64::new(0),
            blocked_dlp_partial: AtomicU64::new(0),
            https_redirect: AtomicU64::new(0),
            waf_inspection_complete: AtomicU64::new(0),
            waf_inspection_truncated: AtomicU64::new(0),
            waf_inspection_unsupported_encoding: AtomicU64::new(0),
            waf_inspection_unsupported_content_type: AtomicU64::new(0),
            waf_monitored: AtomicU64::new(0),
            dlp_cpf_masked: AtomicU64::new(0),
            dlp_tokens_masked: AtomicU64::new(0),
            recent_events: Mutex::new(VecDeque::with_capacity(MAX_EVENTS)),
        }
    }

    fn push_event(&self, event: SecurityEvent) {
        if let Ok(mut events) = self.recent_events.lock() {
            if events.len() >= MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
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
        "header_limit" => &METRICS.blocked_header_limit,
        "concurrency_limit" => &METRICS.blocked_concurrency_limit,
        "connection_limit" => &METRICS.blocked_connection_limit,
        "request_buffer_limit" => &METRICS.blocked_request_buffer_limit,
        "dlp_partial_block" => &METRICS.blocked_dlp_partial,
        "https_redirect" => &METRICS.https_redirect,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);

    METRICS.push_event(SecurityEvent {
        timestamp: now_iso(),
        event_type: event_type.to_string(),
        client_ip: client_ip.to_string(),
        uri: uri.to_string(),
        detail: detail.to_string(),
    });
}

pub fn record_waf_inspection(status: &str) {
    let counter = match status {
        "complete" => &METRICS.waf_inspection_complete,
        "truncated" => &METRICS.waf_inspection_truncated,
        "unsupported_encoding" => &METRICS.waf_inspection_unsupported_encoding,
        "unsupported_content_type" => &METRICS.waf_inspection_unsupported_content_type,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn record_observation(event_type: &str, client_ip: &str, uri: &str, detail: &str) {
    if event_type == "waf_monitor" {
        METRICS.waf_monitored.fetch_add(1, Ordering::Relaxed);
    } else if !matches!(event_type, "dlp_skip" | "range_removed") {
        return;
    }
    METRICS.push_event(SecurityEvent {
        timestamp: now_iso(),
        event_type: event_type.to_string(),
        client_ip: client_ip.to_string(),
        uri: uri.to_string(),
        detail: detail.to_string(),
    });
}

pub fn record_dlp(cpf_count: u64, token_count: u64) {
    if cpf_count > 0 {
        METRICS
            .dlp_cpf_masked
            .fetch_add(cpf_count, Ordering::Relaxed);
    }
    if token_count > 0 {
        METRICS
            .dlp_tokens_masked
            .fetch_add(token_count, Ordering::Relaxed);
    }
    if cpf_count > 0 || token_count > 0 {
        METRICS.push_event(SecurityEvent {
            timestamp: now_iso(),
            event_type: "dlp".to_string(),
            client_ip: "-".to_string(),
            uri: "-".to_string(),
            detail: format!("Masked {} CPFs, {} tokens", cpf_count, token_count),
        });
    }
}

pub fn snapshot_json() -> String {
    let m = &*METRICS;
    let events: Vec<SecurityEvent> = m
        .recent_events
        .lock()
        .map(|e| e.iter().rev().cloned().collect())
        .unwrap_or_default();

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
            "header_limit": m.blocked_header_limit.load(Ordering::Relaxed),
            "concurrency_limit": m.blocked_concurrency_limit.load(Ordering::Relaxed),
            "connection_limit": m.blocked_connection_limit.load(Ordering::Relaxed),
            "request_buffer_limit": m.blocked_request_buffer_limit.load(Ordering::Relaxed),
            "dlp_partial_block": m.blocked_dlp_partial.load(Ordering::Relaxed)
        },
        "waf_inspection": {
            "complete": m.waf_inspection_complete.load(Ordering::Relaxed),
            "truncated": m.waf_inspection_truncated.load(Ordering::Relaxed),
            "unsupported_encoding": m.waf_inspection_unsupported_encoding.load(Ordering::Relaxed),
            "unsupported_content_type": m.waf_inspection_unsupported_content_type.load(Ordering::Relaxed)
        },
        "waf_monitored": m.waf_monitored.load(Ordering::Relaxed),
        "https_redirect": m.https_redirect.load(Ordering::Relaxed),
        "dlp": {
            "cpf_masked": m.dlp_cpf_masked.load(Ordering::Relaxed),
            "tokens_masked": m.dlp_tokens_masked.load(Ordering::Relaxed)
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
        ("concurrency_limit", &metrics.blocked_concurrency_limit),
        ("connection_limit", &metrics.blocked_connection_limit),
        (
            "request_buffer_limit",
            &metrics.blocked_request_buffer_limit,
        ),
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
    ] {
        output.push_str(&format!(
            "ferroada_waf_inspection_total{{status=\"{status}\"}} {}\n",
            counter.load(Ordering::Relaxed)
        ));
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
    }
}
