use once_cell::sync::Lazy;
use regex::Regex;
use tracing::warn;

use crate::metrics;

pub enum WafVerdict {
    Allow,
    Block(String),
}

static SQL_INJECTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|'\s*--|;\s*DROP|'\s*;\s*--)"
    )
    .expect("invalid SQL injection regex")
});

static PATH_TRAVERSAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\.\.\/|\.\./|%2e%2e)")
        .expect("invalid path traversal regex")
});

static XSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(<script[\s>]|javascript\s*:|on(load|error|click|mouseover)\s*=|<img[^>]+onerror|<svg[^>]+onload|<iframe|<object|<embed|alert\s*\(|document\.(cookie|write|location)|eval\s*\()"
    )
    .expect("invalid XSS regex")
});

/// Sensitive paths that should never be exposed publicly
const BLOCKED_PATHS: &[&str] = &[
    "/.env",
    "/.git",
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.svn",
    "/.hg",
    "/.DS_Store",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/phpinfo.php",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/console",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/database.yml",
    "/docker-compose.yml",
    "/Dockerfile",
    "/.dockerenv",
    "/id_rsa",
    "/id_ed25519",
    "/.ssh",
    "/.bash_history",
    "/.npmrc",
    "/.aws/credentials",
    "/wp-config.php",
    "/web.config",
    "/.vscode",
    "/.idea",
];

/// Patterns that indicate sensitive path access (prefix match)
const BLOCKED_PATH_PREFIXES: &[&str] = &[
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/actuator/",
    "/.aws/",
    "/.ssh/",
];

/// Inspect URI, headers, and optionally request body
pub fn inspect_request(uri: &str, header_values: &[String], client_addr: &str) -> WafVerdict {
    let decoded_uri = recursive_urldecode(uri);

    // Extract just the path (before query string) for sensitive path check
    let path = decoded_uri.split('?').next().unwrap_or(&decoded_uri);
    let path_lower = path.to_lowercase();

    // 1. Sensitive path blocking
    for blocked in BLOCKED_PATHS {
        if path_lower == *blocked {
            warn!(
                client = client_addr,
                uri = uri,
                path = *blocked,
                "WAF blocked: sensitive path access"
            );
            metrics::record_block("sensitive_path", client_addr, uri, &format!("Blocked path: {}", blocked));
            return WafVerdict::Block(format!("Access denied: {}", blocked));
        }
    }

    for prefix in BLOCKED_PATH_PREFIXES {
        if path_lower.starts_with(prefix) {
            warn!(
                client = client_addr,
                uri = uri,
                prefix = *prefix,
                "WAF blocked: sensitive path prefix"
            );
            metrics::record_block("sensitive_path", client_addr, uri, &format!("Blocked prefix: {}", prefix));
            return WafVerdict::Block(format!("Access denied: {}", prefix));
        }
    }

    // 2. SQL Injection on URI
    if let Some(m) = SQL_INJECTION_RE.find(&decoded_uri) {
        warn!(client = client_addr, uri = uri, pattern = m.as_str(), "WAF blocked: SQL injection in URI");
        metrics::record_block("sqli", client_addr, uri, &format!("SQL injection: {}", m.as_str()));
        return WafVerdict::Block(format!("SQL injection detected: {}", m.as_str()));
    }

    // 3. Path Traversal on URI
    if let Some(m) = PATH_TRAVERSAL_RE.find(&decoded_uri) {
        warn!(client = client_addr, uri = uri, pattern = m.as_str(), "WAF blocked: path traversal in URI");
        metrics::record_block("path_traversal", client_addr, uri, &format!("Path traversal: {}", m.as_str()));
        return WafVerdict::Block(format!("Path traversal detected: {}", m.as_str()));
    }

    // 4. XSS on URI
    if let Some(m) = XSS_RE.find(&decoded_uri) {
        warn!(client = client_addr, uri = uri, pattern = m.as_str(), "WAF blocked: XSS in URI");
        metrics::record_block("xss", client_addr, uri, &format!("XSS: {}", m.as_str()));
        return WafVerdict::Block(format!("XSS detected: {}", m.as_str()));
    }

    // 5. Check header values
    for val in header_values {
        if let Some(m) = SQL_INJECTION_RE.find(val) {
            warn!(client = client_addr, uri = uri, header_value = val.as_str(), "WAF blocked: SQL injection in header");
            metrics::record_block("sqli", client_addr, uri, &format!("SQLi in header: {}", m.as_str()));
            return WafVerdict::Block(format!("SQL injection detected in header: {}", m.as_str()));
        }
        if let Some(m) = PATH_TRAVERSAL_RE.find(val) {
            warn!(client = client_addr, uri = uri, header_value = val.as_str(), "WAF blocked: path traversal in header");
            metrics::record_block("path_traversal", client_addr, uri, &format!("Path traversal in header: {}", m.as_str()));
            return WafVerdict::Block(format!("Path traversal detected in header: {}", m.as_str()));
        }
        if let Some(m) = XSS_RE.find(val) {
            warn!(client = client_addr, uri = uri, header_value = val.as_str(), "WAF blocked: XSS in header");
            metrics::record_block("xss", client_addr, uri, &format!("XSS in header: {}", m.as_str()));
            return WafVerdict::Block(format!("XSS detected in header: {}", m.as_str()));
        }
    }

    WafVerdict::Allow
}

/// Inspect request body (POST/PUT/PATCH) for SQLi and XSS payloads
pub fn inspect_body(body: &[u8], uri: &str, client_addr: &str) -> WafVerdict {
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return WafVerdict::Allow, // binary body, skip
    };

    // Limit inspection to first 64KB to avoid DoS on large uploads
    let text = if text.len() > 65536 { &text[..65536] } else { text };
    let decoded = recursive_urldecode(text);

    if let Some(m) = SQL_INJECTION_RE.find(&decoded) {
        warn!(client = client_addr, uri = uri, pattern = m.as_str(), "WAF blocked: SQL injection in request body");
        metrics::record_block("sqli", client_addr, uri, &format!("SQLi in body: {}", m.as_str()));
        return WafVerdict::Block(format!("SQL injection detected in body: {}", m.as_str()));
    }

    if let Some(m) = XSS_RE.find(&decoded) {
        warn!(client = client_addr, uri = uri, pattern = m.as_str(), "WAF blocked: XSS in request body");
        metrics::record_block("xss", client_addr, uri, &format!("XSS in body: {}", m.as_str()));
        return WafVerdict::Block(format!("XSS detected in body: {}", m.as_str()));
    }

    WafVerdict::Allow
}

/// Recursively URL-decode to defeat double/triple encoding bypass attempts.
/// Max 3 iterations to prevent infinite loops.
fn recursive_urldecode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..3 {
        let decoded = urldecode(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn urldecode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push(b as char);
                result.push(h as char);
                result.push(l as char);
            } else {
                result.push(b as char);
            }
        } else {
            result.push(b as char);
        }
    }
    result
}
