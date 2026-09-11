//! Optional OTLP/HTTP JSON export (Fase 8 / PR 20).
//!
//! Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` or `FERROADA_OTLP_ENDPOINT` is set.
//! The request path never waits on the collector: spans are `try_send` onto a
//! bounded queue and a worker posts with a short timeout. A dead collector
//! increments `otel_export_failed` and is logged; inspection keeps running.
//!
//! Never sends `Authorization`. Span attributes are method, route (path only),
//! decision, event_type, rule_id, site_scope, inspection_outcome. Metric labels
//! are only site_scope, event_type, inspection_outcome, backend.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::metrics;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
const DEFAULT_METRICS_INTERVAL: Duration = Duration::from_secs(1);
const QUEUE_CAP: usize = 256;
const MAX_ROUTE: usize = 128;
const MAX_BATCH: usize = 32;

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_SEQ: AtomicU64 = AtomicU64::new(1);
static STATE: OnceLock<Mutex<Option<Worker>>> = OnceLock::new();

struct Worker {
    tx: mpsc::Sender<Job>,
    handle: Option<std::thread::JoinHandle<()>>,
}

enum Job {
    Span(RequestSpan),
}

#[derive(Clone, Debug)]
pub struct RequestSpan {
    pub method: String,
    pub route: String,
    pub decision: String,
    pub event_type: String,
    pub rule_id: String,
    pub site_scope: String,
    pub inspection_outcome: String,
    pub start: Instant,
    pub end: Instant,
}

#[derive(Clone, Debug)]
struct Endpoint {
    host: String,
    port: u16,
    base_path: String,
    timeout: Duration,
    metrics_interval: Duration,
}

impl Endpoint {
    fn traces_path(&self) -> String {
        signal_path(&self.base_path, "traces")
    }

    fn metrics_path(&self) -> String {
        signal_path(&self.base_path, "metrics")
    }

    fn host_header(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn state_lock() -> std::sync::MutexGuard<'static, Option<Worker>> {
    STATE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Start or stop the exporter from the current environment. Idempotent.
/// Calling with the endpoint unset joins the worker and leaves zero sockets.
pub fn boot() {
    let mut slot = state_lock();
    if let Some(previous) = slot.take() {
        ENABLED.store(false, Ordering::Release);
        drop(previous.tx);
        if let Some(handle) = previous.handle {
            let _ = handle.join();
        }
    }
    ENABLED.store(false, Ordering::Release);
    let Some(endpoint) = endpoint_from_env() else {
        return;
    };
    let (tx, rx) = mpsc::channel::<Job>(QUEUE_CAP);
    let worker_endpoint = endpoint.clone();
    let handle = match std::thread::Builder::new()
        .name("ferroada-otlp".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            else {
                warn!("OTLP worker runtime failed to start; export disabled");
                metrics::record_otel_export_failed();
                return;
            };
            runtime.block_on(run_worker(rx, worker_endpoint));
        }) {
        Ok(handle) => handle,
        Err(error) => {
            warn!(error = %error, "OTLP worker thread failed");
            metrics::record_otel_export_failed();
            return;
        }
    };
    info!(
        host = %endpoint.host,
        port = endpoint.port,
        timeout_ms = endpoint.timeout.as_millis() as u64,
        "OTLP export ligado"
    );
    ENABLED.store(true, Ordering::Release);
    *slot = Some(Worker {
        tx,
        handle: Some(handle),
    });
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

pub fn emit_request(span: RequestSpan) {
    if !enabled() {
        return;
    }
    let slot = state_lock();
    let Some(worker) = slot.as_ref() else {
        return;
    };
    if worker.tx.try_send(Job::Span(span)).is_err() {
        metrics::record_otel_export_failed();
    }
}

pub fn sanitize_route(uri: &str) -> String {
    let path = uri.split(['?', '#']).next().unwrap_or("/");
    let path = if path.is_empty() { "/" } else { path };
    if path.len() <= MAX_ROUTE {
        path.to_string()
    } else {
        path[..MAX_ROUTE].to_string()
    }
}

pub fn event_type_from_waf_reason(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("sql") {
        "sqli"
    } else if lower.contains("xss") {
        "xss"
    } else if lower.contains("path traversal") {
        "path_traversal"
    } else if lower.contains("crlf") {
        "crlf"
    } else if lower.contains("jndi") {
        "jndi"
    } else if lower.contains("wordpress") || lower.contains("access denied") {
        "sensitive_path"
    } else {
        "waf"
    }
}

pub fn format_rule_ids(ids: &[u32]) -> String {
    ids.iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn endpoint_from_env() -> Option<Endpoint> {
    let raw = first_env(&["OTEL_EXPORTER_OTLP_ENDPOINT", "FERROADA_OTLP_ENDPOINT"])?;
    parse_endpoint(&raw, timeout_from_env(), metrics_interval_from_env())
}

fn first_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn timeout_from_env() -> Duration {
    duration_millis_env("OTEL_EXPORTER_OTLP_TIMEOUT", DEFAULT_TIMEOUT)
}

fn metrics_interval_from_env() -> Duration {
    duration_millis_env(
        "FERROADA_OTLP_METRICS_INTERVAL_MS",
        DEFAULT_METRICS_INTERVAL,
    )
}

fn duration_millis_env(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or(default)
        .min(Duration::from_secs(5))
}

fn parse_endpoint(raw: &str, timeout: Duration, metrics_interval: Duration) -> Option<Endpoint> {
    let trimmed = raw.trim();
    if trimmed.starts_with("https://") {
        warn!("OTLP HTTPS não é suportado; use HTTP no Collector (porta 4318)");
        return None;
    }
    let rest = trimmed.strip_prefix("http://")?;
    if rest.contains('@') {
        warn!("OTLP endpoint com userinfo recusado; o export nunca envia Authorization");
        return None;
    }
    let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return None;
    }
    Some(Endpoint {
        host,
        port,
        base_path: format!("/{path}"),
        timeout,
        metrics_interval,
    })
}

fn split_host_port(hostport: &str) -> Option<(String, u16)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some("") | None => 4318,
            Some(p) => p.parse().ok()?,
        };
        return Some((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        None if !hostport.is_empty() => Some((hostport.to_string(), 4318)),
        _ => None,
    }
}

fn signal_path(base_path: &str, signal: &str) -> String {
    let base = base_path.trim_end_matches('/');
    let base = if base.is_empty() { "" } else { base };
    if base.ends_with("/v1/traces") || base.ends_with("/v1/metrics") {
        let prefix = base.rsplit_once('/').map(|(head, _)| head).unwrap_or("");
        return format!("{prefix}/{signal}");
    }
    format!("{base}/v1/{signal}")
}

async fn run_worker(mut rx: mpsc::Receiver<Job>, endpoint: Endpoint) {
    let mut ticker = tokio::time::interval(endpoint.metrics_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            job = rx.recv() => {
                match job {
                    None => break,
                    Some(Job::Span(span)) => {
                        let mut batch = vec![span];
                        while batch.len() < MAX_BATCH {
                            match rx.try_recv() {
                                Ok(Job::Span(next)) => batch.push(next),
                                Err(_) => break,
                            }
                        }
                        export_json(&endpoint, &endpoint.traces_path(), traces_payload(&batch)).await;
                    }
                }
            }
            _ = ticker.tick() => {
                export_json(&endpoint, &endpoint.metrics_path(), metrics_payload()).await;
            }
        }
    }
}

async fn export_json(endpoint: &Endpoint, path: &str, body: Value) {
    let bytes = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(error = %error, "OTLP payload serialize failed");
            metrics::record_otel_export_failed();
            return;
        }
    };
    let result = tokio::time::timeout(endpoint.timeout, post_json(endpoint, path, &bytes)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(error = %error, host = %endpoint.host, "OTLP export failed");
            metrics::record_otel_export_failed();
        }
        Err(_) => {
            warn!(host = %endpoint.host, "OTLP export timed out");
            metrics::record_otel_export_failed();
        }
    }
}

async fn post_json(endpoint: &Endpoint, path: &str, body: &[u8]) -> Result<(), String> {
    let mut stream = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(|error| error.to_string())?;
    let host = endpoint.host_header();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;
    let mut discard = [0u8; 256];
    let read = stream
        .read(&mut discard)
        .await
        .map_err(|error| error.to_string())?;
    let head = std::str::from_utf8(&discard[..read]).unwrap_or("");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("collector HTTP {status}"));
    }
    Ok(())
}

fn traces_payload(spans: &[RequestSpan]) -> Value {
    let now_end = unix_nanos(SystemTime::now());
    let otel_spans: Vec<Value> = spans
        .iter()
        .map(|span| {
            let duration = span.end.saturating_duration_since(span.start);
            let end_ns = now_end;
            let start_ns = end_ns.saturating_sub(duration.as_nanos() as u64);
            let mut attributes = vec![
                kv_str("http.method", &span.method),
                kv_str("http.route", &span.route),
                kv_str("decision", &span.decision),
            ];
            if !span.event_type.is_empty() {
                attributes.push(kv_str("event_type", &span.event_type));
            }
            if !span.rule_id.is_empty() {
                attributes.push(kv_str("rule_id", &span.rule_id));
            }
            if !span.site_scope.is_empty() {
                attributes.push(kv_str("site_scope", &span.site_scope));
            }
            if !span.inspection_outcome.is_empty() {
                attributes.push(kv_str("inspection_outcome", &span.inspection_outcome));
            }
            json!({
                "traceId": hex_encode(&next_trace_id()),
                "spanId": hex_encode(&next_span_id()),
                "name": format!("{} {}", span.method, span.route),
                "kind": 2,
                "startTimeUnixNano": start_ns.to_string(),
                "endTimeUnixNano": end_ns.to_string(),
                "attributes": attributes,
            })
        })
        .collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": resource_attributes() },
            "scopeSpans": [{
                "scope": { "name": "ferroada", "version": env!("CARGO_PKG_VERSION") },
                "spans": otel_spans
            }]
        }]
    })
}

fn metrics_payload() -> Value {
    let now = unix_nanos(SystemTime::now()).to_string();
    let m = &*metrics::METRICS;
    let mut items = vec![
        sum_metric(
            "ferroada_requests_total",
            m.requests_total.load(Ordering::Relaxed),
            &now,
            vec![],
        ),
        sum_metric(
            "ferroada_otel_export_failed_total",
            metrics::otel_export_failed(),
            &now,
            vec![],
        ),
        gauge_metric("ferroada_spool_bytes", metrics::spool_bytes(), &now, vec![]),
        gauge_metric("ferroada_policy_info", 1, &now, vec![]),
    ];

    for (event_type, counter) in block_series(m) {
        items.push(sum_metric(
            "ferroada_blocks_total",
            counter,
            &now,
            vec![("event_type", event_type.to_string())],
        ));
    }
    for (outcome, counter) in [
        (
            "complete",
            m.waf_inspection_complete.load(Ordering::Relaxed),
        ),
        (
            "truncated",
            m.waf_inspection_truncated.load(Ordering::Relaxed),
        ),
        (
            "unsupported_encoding",
            m.waf_inspection_unsupported_encoding
                .load(Ordering::Relaxed),
        ),
        (
            "unsupported_content_type",
            m.waf_inspection_unsupported_content_type
                .load(Ordering::Relaxed),
        ),
        (
            "parse_error",
            m.waf_inspection_parse_error.load(Ordering::Relaxed),
        ),
        (
            "budget_exceeded",
            m.waf_inspection_budget_exceeded.load(Ordering::Relaxed),
        ),
        (
            "timed_out",
            m.waf_inspection_timed_out.load(Ordering::Relaxed),
        ),
    ] {
        items.push(sum_metric(
            "ferroada_inspection_outcome_total",
            counter,
            &now,
            vec![("inspection_outcome", outcome.to_string())],
        ));
    }
    json!({
        "resourceMetrics": [{
            "resource": { "attributes": resource_attributes() },
            "scopeMetrics": [{
                "scope": { "name": "ferroada", "version": env!("CARGO_PKG_VERSION") },
                "metrics": items
            }]
        }]
    })
}

fn block_series(m: &metrics::Metrics) -> [(&'static str, u64); 33] {
    [
        ("sqli", m.blocked_sqli.load(Ordering::Relaxed)),
        ("xss", m.blocked_xss.load(Ordering::Relaxed)),
        (
            "path_traversal",
            m.blocked_path_traversal.load(Ordering::Relaxed),
        ),
        ("rate_limit", m.blocked_rate_limit.load(Ordering::Relaxed)),
        (
            "sensitive_path",
            m.blocked_sensitive_path.load(Ordering::Relaxed),
        ),
        ("body_sqli", m.blocked_body_sqli.load(Ordering::Relaxed)),
        ("body_xss", m.blocked_body_xss.load(Ordering::Relaxed)),
        ("method", m.blocked_method.load(Ordering::Relaxed)),
        ("size_limit", m.blocked_size_limit.load(Ordering::Relaxed)),
        ("host", m.blocked_host.load(Ordering::Relaxed)),
        ("crlf", m.blocked_crlf.load(Ordering::Relaxed)),
        ("smuggling", m.blocked_smuggling.load(Ordering::Relaxed)),
        ("jndi", m.blocked_jndi.load(Ordering::Relaxed)),
        ("bad_bot", m.blocked_bad_bot.load(Ordering::Relaxed)),
        (
            "behavioral_throttle",
            m.blocked_behavioral_throttle.load(Ordering::Relaxed),
        ),
        (
            "behavioral_block",
            m.blocked_behavioral_block.load(Ordering::Relaxed),
        ),
        (
            "waf_incomplete",
            m.blocked_waf_incomplete.load(Ordering::Relaxed),
        ),
        (
            "inspection_parse_error",
            m.blocked_inspection_parse_error.load(Ordering::Relaxed),
        ),
        (
            "header_limit",
            m.blocked_header_limit.load(Ordering::Relaxed),
        ),
        (
            "concurrency_limit",
            m.blocked_concurrency_limit.load(Ordering::Relaxed),
        ),
        (
            "connection_limit",
            m.blocked_connection_limit.load(Ordering::Relaxed),
        ),
        (
            "request_buffer_limit",
            m.blocked_request_buffer_limit.load(Ordering::Relaxed),
        ),
        ("spool_limit", m.blocked_spool_limit.load(Ordering::Relaxed)),
        ("waf_l1", m.blocked_waf_l1.load(Ordering::Relaxed)),
        ("openapi", m.blocked_openapi.load(Ordering::Relaxed)),
        ("jwt", m.blocked_jwt.load(Ordering::Relaxed)),
        ("jwt_binding", m.blocked_jwt_binding.load(Ordering::Relaxed)),
        ("graphql", m.blocked_graphql.load(Ordering::Relaxed)),
        ("grpc", m.blocked_grpc.load(Ordering::Relaxed)),
        (
            "dlp_partial_block",
            m.blocked_dlp_partial.load(Ordering::Relaxed),
        ),
        (
            "origin_unavailable",
            m.blocked_origin_unavailable.load(Ordering::Relaxed),
        ),
        ("protocol_deny", m.protocol_deny.load(Ordering::Relaxed)),
        ("https_redirect", m.https_redirect.load(Ordering::Relaxed)),
    ]
}

fn resource_attributes() -> Vec<Value> {
    let (version, signed) = metrics::policy_info();
    vec![
        kv_str("service.name", "ferroada"),
        kv_str("service.version", env!("CARGO_PKG_VERSION")),
        kv_str("ferroada.policy_version", &version),
        kv_str(
            "ferroada.policy_signed",
            if signed { "true" } else { "false" },
        ),
    ]
}

fn sum_metric(name: &str, value: u64, time: &str, labels: Vec<(&str, String)>) -> Value {
    json!({
        "name": name,
        "sum": {
            "aggregationTemporality": 2,
            "isMonotonic": true,
            "dataPoints": [{
                "asInt": value.to_string(),
                "timeUnixNano": time,
                "attributes": label_attrs(&labels),
            }]
        }
    })
}

fn gauge_metric(name: &str, value: u64, time: &str, labels: Vec<(&str, String)>) -> Value {
    json!({
        "name": name,
        "gauge": {
            "dataPoints": [{
                "asInt": value.to_string(),
                "timeUnixNano": time,
                "attributes": label_attrs(&labels),
            }]
        }
    })
}

fn label_attrs(labels: &[(&str, String)]) -> Vec<Value> {
    labels
        .iter()
        .filter(|(key, _)| is_allowed_label(key))
        .map(|(key, value)| kv_str(key, value))
        .collect()
}

fn is_allowed_label(key: &str) -> bool {
    matches!(
        key,
        "site_scope" | "event_type" | "inspection_outcome" | "backend"
    )
}

fn kv_str(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn next_trace_id() -> [u8; 16] {
    let n = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    let t = unix_nanos(SystemTime::now());
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&t.to_be_bytes());
    id[8..].copy_from_slice(&n.to_be_bytes());
    if id.iter().all(|byte| *byte == 0) {
        id[15] = 1;
    }
    id
}

fn next_span_id() -> [u8; 8] {
    let n = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut id = n.to_be_bytes();
    if id.iter().all(|byte| *byte == 0) {
        id[7] = 1;
    }
    id
}

fn unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_blank_endpoint_does_not_parse() {
        assert!(parse_endpoint("", DEFAULT_TIMEOUT, DEFAULT_METRICS_INTERVAL).is_none());
        assert!(parse_endpoint("   ", DEFAULT_TIMEOUT, DEFAULT_METRICS_INTERVAL).is_none());
    }

    #[test]
    fn parse_http_endpoint_and_signal_paths() {
        let parsed = parse_endpoint(
            "http://127.0.0.1:4318",
            Duration::from_millis(500),
            Duration::from_millis(200),
        )
        .expect("endpoint");
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 4318);
        assert_eq!(parsed.traces_path(), "/v1/traces");
        assert_eq!(parsed.metrics_path(), "/v1/metrics");
    }

    #[test]
    fn https_and_userinfo_are_refused() {
        assert!(parse_endpoint(
            "https://collector.example:4318",
            DEFAULT_TIMEOUT,
            DEFAULT_METRICS_INTERVAL
        )
        .is_none());
        assert!(parse_endpoint(
            "http://user:secret@127.0.0.1:4318",
            DEFAULT_TIMEOUT,
            DEFAULT_METRICS_INTERVAL
        )
        .is_none());
    }

    #[test]
    fn sanitize_route_strips_query_and_caps_length() {
        assert_eq!(
            sanitize_route("/search?cpf=39053344705&token=sekrit"),
            "/search"
        );
        assert_eq!(sanitize_route(""), "/");
        let long = format!("/{}", "a".repeat(200));
        assert_eq!(sanitize_route(&long).len(), MAX_ROUTE);
    }

    #[test]
    fn span_payload_has_no_secrets_or_query() {
        let payload = traces_payload(&[RequestSpan {
            method: "GET".into(),
            route: sanitize_route("/login?token=sekrit"),
            decision: "deny".into(),
            event_type: "sqli".into(),
            rule_id: "942100".into(),
            site_scope: "api.example".into(),
            inspection_outcome: "complete".into(),
            start: Instant::now(),
            end: Instant::now(),
        }]);
        let text = payload.to_string();
        assert!(text.contains("\"decision\""));
        assert!(text.contains("sqli"));
        assert!(text.contains("942100"));
        assert!(text.contains("/login"));
        assert!(!text.contains("sekrit"));
        assert!(!text.contains("Authorization"));
        assert!(!text.contains("Cookie"));
        assert!(!text.contains("cpf"));
        assert!(!text.contains("token="));
    }

    #[test]
    fn metric_payload_uses_only_allowed_labels() {
        let payload = metrics_payload();
        let text = payload.to_string();
        assert!(text.contains("ferroada_requests_total"));
        assert!(text.contains("ferroada_inspection_outcome_total"));
        assert!(text.contains("ferroada_spool_bytes"));
        assert!(text.contains("event_type"));
        assert!(text.contains("inspection_outcome"));
        assert!(!text.contains("client_ip"));
        assert!(!text.contains("\"http.route\""));
        assert!(!text.contains("Authorization"));
        let dumped = text.to_ascii_lowercase();
        assert!(!dumped.contains("\"ip\""));
    }
}
