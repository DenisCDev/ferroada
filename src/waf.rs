use once_cell::sync::Lazy;
use regex::Regex;
use tracing::warn;

use crate::metrics;

pub enum WafVerdict {
    Allow,
    Block(String),
}

// --- SQLi detection: 5 categories for robust coverage ---

// Category 1: Classic injection (UNION, OR-based, comment termination)
static SQLI_CLASSIC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(\bUNION\b[\s/\*]+\bSELECT\b|\bUNION\b\s+\bALL\b\s+\bSELECT\b|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|'\s*\bOR\b\s*'|'\s*--|;\s*\bDROP\b|'\s*;\s*--)"
    )
    .expect("sqli classic regex")
});

// Category 2: Stacked queries / destructive operations
static SQLI_STACKED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(;\s*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE|GRANT|REVOKE)\b|;\s*\bWAITFOR\b)"
    )
    .expect("sqli stacked regex")
});

// Category 3: Time-based / boolean blind SQLi
static SQLI_BLIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(\bSLEEP\s*\(|\bBENCHMARK\s*\(\s*\d|\bWAITFOR\s+DELAY\b|\bPG_SLEEP\s*\(|\bDBMS_PIPE\.RECEIVE_MESSAGE\b)"
    )
    .expect("sqli blind regex")
});

// Category 4: SQL function abuse (data extraction, file access)
static SQLI_FUNCTIONS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(\bCONCAT\s*\(.*\bSELECT\b|\bCHAR\s*\(\s*\d+\s*(,\s*\d+\s*)+\)|\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\(|\bINTO\s+(OUT|DUMP)FILE\b|\bLOAD_FILE\s*\(|\bINFORMATION_SCHEMA\b|\bGROUP_CONCAT\s*\()"
    )
    .expect("sqli functions regex")
});

// Category 5: Comment-based evasion (MySQL /*!*/, inline comments)
static SQLI_EVASION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(/\*!\d*\s*\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b|/\*.*\*/\s*\b(UNION|SELECT)\b)"
    )
    .expect("sqli evasion regex")
});

/// Check input against all SQLi categories. Returns the category name on match.
fn check_sqli(input: &str) -> Option<&'static str> {
    if SQLI_CLASSIC_RE.is_match(input) {
        return Some("sqli_classic");
    }
    if SQLI_STACKED_RE.is_match(input) {
        return Some("sqli_stacked");
    }
    if SQLI_BLIND_RE.is_match(input) {
        return Some("sqli_blind");
    }
    if SQLI_FUNCTIONS_RE.is_match(input) {
        return Some("sqli_functions");
    }
    if SQLI_EVASION_RE.is_match(input) {
        return Some("sqli_evasion");
    }
    None
}

static PATH_TRAVERSAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(\.\.\/|\.\./|%2e%2e)").expect("invalid path traversal regex"));

static CRLF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(%0[dD]%0[aA]|\r\n)").expect("invalid CRLF regex"));

static JNDI_DEOBFUSCATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{(?:lower:|upper:|::-?)(\w)\}").expect("invalid JNDI deobfuscation regex")
});

static XSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(<script[\s>]|javascript\s*:|on(load|error|click|mouseover|mouseout|mousemove|mousedown|mouseup|keydown|keyup|keypress|submit|reset|focus|blur|change|input|select|copy|paste|cut|drag|drop|touchstart|touchend|touchmove|animationstart|animationend|transitionend|toggle|pointerover|pointerout|beforeunload|hashchange|popstate|message|storage|beforeprint|afterprint|begin)\s*=|<img[^>]+onerror|<svg[^>]+on\w+|<iframe|<object|<embed|alert\s*\(|confirm\s*\(|prompt\s*\(|document\.(cookie|write|writeln|location|domain)|eval\s*\(|Function\s*\(|setTimeout\s*\([^)]*['"]|setInterval\s*\([^)]*['"]|<details[^>]+ontoggle|<math|<base\s|<form[^>]+action\s*=\s*["']?\s*javascript|expression\s*\(|url\s*\(\s*javascript)"#
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
            metrics::record_block(
                "sensitive_path",
                client_addr,
                uri,
                &format!("Blocked path: {}", blocked),
            );
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
            metrics::record_block(
                "sensitive_path",
                client_addr,
                uri,
                &format!("Blocked prefix: {}", prefix),
            );
            return WafVerdict::Block(format!("Access denied: {}", prefix));
        }
    }

    // 2. CRLF Injection on URI
    if CRLF_RE.is_match(uri) || CRLF_RE.is_match(&decoded_uri) {
        warn!(
            client = client_addr,
            uri = uri,
            "WAF blocked: CRLF injection in URI"
        );
        metrics::record_block("crlf", client_addr, uri, "CRLF injection in URI");
        return WafVerdict::Block("CRLF injection detected".to_string());
    }

    // 3. JNDI/Log4Shell on URI
    if contains_jndi(&decoded_uri) {
        warn!(
            client = client_addr,
            uri = uri,
            "WAF blocked: JNDI/Log4Shell in URI"
        );
        metrics::record_block("jndi", client_addr, uri, "JNDI/Log4Shell in URI");
        return WafVerdict::Block("JNDI injection detected".to_string());
    }

    // 4. SQL Injection on URI (5 categories)
    if let Some(category) = check_sqli(&decoded_uri) {
        warn!(
            client = client_addr,
            uri = uri,
            category = category,
            "WAF blocked: SQL injection in URI"
        );
        metrics::record_block("sqli", client_addr, uri, &format!("SQLi ({})", category));
        return WafVerdict::Block(format!("SQL injection detected ({})", category));
    }

    // 3. Path Traversal on URI
    if let Some(m) = PATH_TRAVERSAL_RE.find(&decoded_uri) {
        warn!(
            client = client_addr,
            uri = uri,
            pattern = m.as_str(),
            "WAF blocked: path traversal in URI"
        );
        metrics::record_block(
            "path_traversal",
            client_addr,
            uri,
            &format!("Path traversal: {}", m.as_str()),
        );
        return WafVerdict::Block(format!("Path traversal detected: {}", m.as_str()));
    }

    // 4. XSS on URI
    if let Some(m) = XSS_RE.find(&decoded_uri) {
        warn!(
            client = client_addr,
            uri = uri,
            pattern = m.as_str(),
            "WAF blocked: XSS in URI"
        );
        metrics::record_block("xss", client_addr, uri, &format!("XSS: {}", m.as_str()));
        return WafVerdict::Block(format!("XSS detected: {}", m.as_str()));
    }

    // 5. Check header values
    for val in header_values {
        if CRLF_RE.is_match(val) {
            warn!(
                client = client_addr,
                uri = uri,
                header_value = val.as_str(),
                "WAF blocked: CRLF injection in header"
            );
            metrics::record_block("crlf", client_addr, uri, "CRLF injection in header");
            return WafVerdict::Block("CRLF injection detected in header".to_string());
        }
        if contains_jndi(val) {
            warn!(
                client = client_addr,
                uri = uri,
                header_value = val.as_str(),
                "WAF blocked: JNDI/Log4Shell in header"
            );
            metrics::record_block("jndi", client_addr, uri, "JNDI/Log4Shell in header");
            return WafVerdict::Block("JNDI injection detected in header".to_string());
        }
        if let Some(category) = check_sqli(val) {
            warn!(
                client = client_addr,
                uri = uri,
                header_value = val.as_str(),
                "WAF blocked: SQL injection in header"
            );
            metrics::record_block(
                "sqli",
                client_addr,
                uri,
                &format!("SQLi in header ({})", category),
            );
            return WafVerdict::Block(format!("SQL injection detected in header ({})", category));
        }
        if let Some(m) = PATH_TRAVERSAL_RE.find(val) {
            warn!(
                client = client_addr,
                uri = uri,
                header_value = val.as_str(),
                "WAF blocked: path traversal in header"
            );
            metrics::record_block(
                "path_traversal",
                client_addr,
                uri,
                &format!("Path traversal in header: {}", m.as_str()),
            );
            return WafVerdict::Block(format!("Path traversal detected in header: {}", m.as_str()));
        }
        if let Some(m) = XSS_RE.find(val) {
            warn!(
                client = client_addr,
                uri = uri,
                header_value = val.as_str(),
                "WAF blocked: XSS in header"
            );
            metrics::record_block(
                "xss",
                client_addr,
                uri,
                &format!("XSS in header: {}", m.as_str()),
            );
            return WafVerdict::Block(format!("XSS detected in header: {}", m.as_str()));
        }
    }

    WafVerdict::Allow
}

/// Inspect request body (POST/PUT/PATCH) for SQLi, XSS, CRLF and JNDI payloads.
/// `content_type` is used to skip CRLF checks on multipart/form-data (legitimate \r\n in uploads).
pub fn inspect_body(
    body: &[u8],
    uri: &str,
    client_addr: &str,
    content_type: Option<&str>,
) -> WafVerdict {
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return WafVerdict::Allow, // binary body, skip
    };

    // Limit inspection to first 64KB to avoid DoS on large uploads
    let text = if text.len() > 65536 {
        &text[..65536]
    } else {
        text
    };
    let decoded = recursive_urldecode(text);

    // CRLF check — skip for multipart/form-data (legitimate \r\n in uploads)
    let is_multipart = content_type
        .map(|ct| ct.to_ascii_lowercase().contains("multipart/form-data"))
        .unwrap_or(false);
    if !is_multipart && CRLF_RE.is_match(&decoded) {
        warn!(
            client = client_addr,
            uri = uri,
            "WAF blocked: CRLF injection in request body"
        );
        metrics::record_block("crlf", client_addr, uri, "CRLF injection in body");
        return WafVerdict::Block("CRLF injection detected in body".to_string());
    }

    // JNDI/Log4Shell check
    if contains_jndi(&decoded) {
        warn!(
            client = client_addr,
            uri = uri,
            "WAF blocked: JNDI/Log4Shell in request body"
        );
        metrics::record_block("jndi", client_addr, uri, "JNDI/Log4Shell in body");
        return WafVerdict::Block("JNDI injection detected in body".to_string());
    }

    if let Some(category) = check_sqli(&decoded) {
        warn!(
            client = client_addr,
            uri = uri,
            category = category,
            "WAF blocked: SQL injection in request body"
        );
        metrics::record_block(
            "sqli",
            client_addr,
            uri,
            &format!("SQLi in body ({})", category),
        );
        return WafVerdict::Block(format!("SQL injection detected in body ({})", category));
    }

    if let Some(m) = XSS_RE.find(&decoded) {
        warn!(
            client = client_addr,
            uri = uri,
            pattern = m.as_str(),
            "WAF blocked: XSS in request body"
        );
        metrics::record_block(
            "xss",
            client_addr,
            uri,
            &format!("XSS in body: {}", m.as_str()),
        );
        return WafVerdict::Block(format!("XSS detected in body: {}", m.as_str()));
    }

    WafVerdict::Allow
}

/// Detect JNDI injection patterns including obfuscated variants.
/// Fast-path: if input doesn't contain "${", return false immediately (99.9%+ of requests).
fn contains_jndi(input: &str) -> bool {
    if !input.contains("${") {
        return false;
    }
    let lower = input.to_lowercase();
    if lower.contains("${jndi:") {
        return true;
    }
    // Deobfuscate: ${lower:j} -> j, ${upper:N} -> N, ${::-d} -> d, etc.
    let collapsed = collapse_jndi_obfuscation(&lower);
    collapsed.contains("${jndi:")
}

/// Collapse JNDI obfuscation patterns like ${lower:j}, ${upper:N}, ${::-d}.
/// Iterates up to 5 times to resolve nested obfuscation.
fn collapse_jndi_obfuscation(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..5 {
        let replaced = JNDI_DEOBFUSCATE_RE.replace_all(&current, "$1").to_string();
        if replaced == current {
            break;
        }
        current = replaced;
    }
    current
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
