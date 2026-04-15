use pingora::http::ResponseHeader;

/// Headers that leak server/framework information
const STRIP_HEADERS: &[&str] = &[
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Debug-Token",
    "X-Runtime",
];

/// Remove headers that reveal infrastructure details from upstream responses.
pub fn strip_server_headers(resp: &mut ResponseHeader) {
    for name in STRIP_HEADERS {
        resp.remove_header(name);
    }
}

/// Inject security hardening headers into every response.
pub fn apply_security_headers(resp: &mut ResponseHeader) {
    let enabled = std::env::var("SECURITY_HEADERS")
        .map(|v| v != "false")
        .unwrap_or(true);

    if !enabled {
        return;
    }

    let csp = std::env::var("CSP_POLICY").unwrap_or_else(|_| "default-src 'self'".to_string());

    let headers: &[(&str, &str)] = &[
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("X-XSS-Protection", "0"),
    ];

    for (name, value) in headers {
        let _ = resp.insert_header(*name, *value);
    }

    // CSP is dynamic from env, so handle separately
    let _ = resp.insert_header("Content-Security-Policy", &csp);
}
