use flate2::read::{DeflateDecoder, GzDecoder};
use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;
use std::io::Read;
use tracing::warn;

use crate::metrics;

/// Bytes of inflated body the WAF will look at. Caps zip bombs.
const MAX_INFLATE_FOR_INSPECT: u64 = 256 * 1024;
const INSPECT_TEXT_LIMIT: usize = 65_536;
/// Percent-decode passes. 3 was shallow: `%2525252e` (4 layers) survived.
const MAX_DECODE_PASSES: usize = 8;

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
    let decoded_uri = decode_uri(uri);

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

    // 5. Check header values (raw and decoded — encoded XSS/SQLi in Referer etc.)
    for val in header_values {
        let decoded_header = recursive_urldecode(val);
        let to_check: [&str; 2] = [val.as_str(), decoded_header.as_str()];
        for inspected in to_check {
            if CRLF_RE.is_match(inspected) {
                warn!(
                    client = client_addr,
                    uri = uri,
                    header_value = val.as_str(),
                    "WAF blocked: CRLF injection in header"
                );
                metrics::record_block("crlf", client_addr, uri, "CRLF injection in header");
                return WafVerdict::Block("CRLF injection detected in header".to_string());
            }
            if contains_jndi(inspected) {
                warn!(
                    client = client_addr,
                    uri = uri,
                    header_value = val.as_str(),
                    "WAF blocked: JNDI/Log4Shell in header"
                );
                metrics::record_block("jndi", client_addr, uri, "JNDI/Log4Shell in header");
                return WafVerdict::Block("JNDI injection detected in header".to_string());
            }
            if let Some(category) = check_sqli(inspected) {
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
                return WafVerdict::Block(format!(
                    "SQL injection detected in header ({})",
                    category
                ));
            }
            if let Some(m) = PATH_TRAVERSAL_RE.find(inspected) {
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
                return WafVerdict::Block(format!(
                    "Path traversal detected in header: {}",
                    m.as_str()
                ));
            }
            if let Some(m) = XSS_RE.find(inspected) {
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

    // Limit inspection to first 64KB to avoid DoS on large uploads.
    // Cut on a char boundary so a multibyte UTF-8 scalar at 64KB cannot panic.
    let text = if text.len() > INSPECT_TEXT_LIMIT {
        let mut end = INSPECT_TEXT_LIMIT;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };

    let is_form = content_type
        .map(|ct| {
            ct.to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);
    let decoded = if is_form {
        recursive_urldecode(&text.replace('+', " "))
    } else {
        recursive_urldecode(text)
    };

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
            "body_sqli",
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
            "body_xss",
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

/// Inflate gzip/deflate for WAF inspection only. The original bytes stay on
/// the wire to the upstream. Unknown encodings (br, zstd) and corrupt streams
/// fall back to the raw bytes so a declared encoding cannot hide plaintext.
pub fn inflate_for_inspect<'a>(body: &'a [u8], content_encoding: Option<&str>) -> Cow<'a, [u8]> {
    let enc = content_encoding.unwrap_or("").to_ascii_lowercase();
    if enc.is_empty() || enc == "identity" {
        return Cow::Borrowed(body);
    }
    let tokens: Vec<&str> = enc.split(',').map(|t| t.trim()).collect();
    if tokens.iter().any(|t| *t == "gzip" || *t == "x-gzip") {
        return inflate_with(GzDecoder::new(body), body);
    }
    if tokens.iter().any(|t| *t == "deflate") {
        return inflate_with(DeflateDecoder::new(body), body);
    }
    Cow::Borrowed(body)
}

fn inflate_with<'a, R: Read>(decoder: R, fallback: &'a [u8]) -> Cow<'a, [u8]> {
    let mut out = Vec::new();
    let mut limited = decoder.take(MAX_INFLATE_FOR_INSPECT);
    match limited.read_to_end(&mut out) {
        Ok(_) if !out.is_empty() => Cow::Owned(out),
        _ => Cow::Borrowed(fallback),
    }
}

fn decode_uri(uri: &str) -> String {
    match uri.split_once('?') {
        Some((path, query)) => {
            let path = recursive_urldecode(path);
            let query = recursive_urldecode(&query.replace('+', " "));
            format!("{path}?{query}")
        }
        None => recursive_urldecode(uri),
    }
}

/// Recursively URL-decode to defeat multi-layer encoding bypasses.
/// Also collapses IIS-style `%uXXXX` unicode escapes.
fn recursive_urldecode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..MAX_DECODE_PASSES {
        let decoded = urldecode(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn urldecode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 6 <= bytes.len() && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U') {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 2..i + 6]) {
                    if let Ok(cp) = u32::from_str_radix(hex, 16) {
                        if let Some(ch) = char::from_u32(cp) {
                            result.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                }
            }
            if i + 3 <= bytes.len() {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        result.push(byte as char);
                        i += 3;
                        continue;
                    }
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{DeflateEncoder, GzEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).expect("deflate write");
        enc.finish().expect("deflate finish")
    }

    fn blocked(v: WafVerdict) -> bool {
        matches!(v, WafVerdict::Block(_))
    }

    #[test]
    fn quadruple_encoded_traversal_is_blocked() {
        // 4 layers of %25 — the old 3-pass decoder stopped at `%2e%2e`.
        let uri = "/%2525252e%2525252e%2525252fetc%2525252fpasswd";
        assert!(
            blocked(inspect_request(uri, &[], "1.1.1.1")),
            "4-layer encoded ../ must not slip past the WAF"
        );
    }

    #[test]
    fn unicode_percent_u_traversal_is_blocked() {
        let uri = "/%u002e%u002e/%u002e%u002e/etc/passwd";
        assert!(blocked(inspect_request(uri, &[], "1.1.1.1")));
    }

    #[test]
    fn plus_as_space_in_query_sqli_is_blocked() {
        let uri = "/search?q=1+OR+1=1";
        assert!(
            blocked(inspect_request(uri, &[], "1.1.1.1")),
            "form-style + in the query string is a space"
        );
    }

    #[test]
    fn encoded_xss_in_header_is_blocked() {
        let headers = vec!["%3Cscript%3Ealert(1)%3C/script%3E".to_string()];
        assert!(
            blocked(inspect_request("/", &headers, "1.1.1.1")),
            "percent-encoded XSS in a header must be decoded then blocked"
        );
    }

    #[test]
    fn gzip_body_sqli_is_blocked() {
        let payload = gzip(br#"{"id":"1 UNION SELECT * FROM users"}"#);
        let inflated = inflate_for_inspect(&payload, Some("gzip"));
        assert!(
            blocked(inspect_body(
                &inflated,
                "/",
                "1.1.1.1",
                Some("application/json")
            )),
            "SQLi inside gzip must be visible to the WAF"
        );
    }

    #[test]
    fn deflate_body_xss_is_blocked() {
        let payload = deflate(b"<script>alert(1)</script>");
        let inflated = inflate_for_inspect(&payload, Some("deflate"));
        assert!(blocked(inspect_body(
            &inflated,
            "/",
            "1.1.1.1",
            Some("text/html")
        )));
    }

    #[test]
    fn gzip_inspect_does_not_mutate_original() {
        let payload = gzip(b"hello");
        let original = payload.clone();
        let _ = inflate_for_inspect(&payload, Some("gzip"));
        assert_eq!(payload, original);
    }

    #[test]
    fn corrupt_gzip_falls_back_to_raw_so_plaintext_still_matches() {
        let raw = b"1 UNION SELECT password FROM users";
        let inflated = inflate_for_inspect(raw, Some("gzip"));
        assert!(blocked(inspect_body(
            &inflated,
            "/",
            "1.1.1.1",
            Some("text/plain")
        )));
    }

    #[test]
    fn form_urlencoded_plus_sqli_in_body_is_blocked() {
        let body = b"q=1+OR+1=1";
        assert!(blocked(inspect_body(
            body,
            "/",
            "1.1.1.1",
            Some("application/x-www-form-urlencoded")
        )));
    }

    #[test]
    fn zip_bomb_inflate_is_capped() {
        let zeros = vec![0u8; 1024 * 1024];
        let payload = gzip(&zeros);
        let inflated = inflate_for_inspect(&payload, Some("gzip"));
        assert!(
            inflated.len() as u64 <= MAX_INFLATE_FOR_INSPECT,
            "inflate must stop at the inspect cap, got {}",
            inflated.len()
        );
    }

    #[test]
    fn sqli_split_across_chunks_is_blocked_once_assembled() {
        let first = br#"{"q":"1 UNI"#;
        let second = br#"ON SELECT * FROM users"}"#;
        let mut assembled = first.to_vec();
        assembled.extend_from_slice(second);
        assert!(
            blocked(inspect_body(
                &assembled,
                "/",
                "1.1.1.1",
                Some("application/json")
            )),
            "payload split across chunks must still match after assembly"
        );
        assert!(
            !blocked(inspect_body(
                first,
                "/",
                "1.1.1.1",
                Some("application/json")
            )),
            "sanity: the first chunk alone is not a SQLi"
        );
    }

    #[test]
    fn identity_encoding_is_borrowed() {
        let body = b"ok";
        match inflate_for_inspect(body, Some("identity")) {
            Cow::Borrowed(b) => assert_eq!(b, body),
            Cow::Owned(_) => panic!("identity must not copy"),
        }
    }
}
