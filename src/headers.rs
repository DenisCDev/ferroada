use pingora::http::ResponseHeader;

/// Headers that leak server/framework information — always safe to remove.
const STRIP_HEADERS: &[&str] = &[
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Debug-Token",
    "X-Runtime",
];

/// Remove headers that reveal infrastructure details from upstream responses.
/// This is always safe — no website depends on these headers for functionality.
pub fn strip_server_headers(resp: &mut ResponseHeader) {
    for name in STRIP_HEADERS {
        resp.remove_header(name);
    }
}

/// Inject security hardening headers into every response.
///
/// SAFETY PHILOSOPHY: Only inject headers that won't break existing sites.
/// - Headers that STRIP info → always on (zero risk)
/// - Headers that ADD restrictions → conservative defaults only
/// - CSP → OFF by default (breaks CDNs, inline scripts, fonts, analytics)
/// - HSTS → only when FORCE_HTTPS=true (user explicitly opted into HTTPS)
/// - X-Frame-Options → SAMEORIGIN not DENY (allows same-site iframes)
pub fn apply_security_headers(resp: &mut ResponseHeader) {
    let enabled = std::env::var("SECURITY_HEADERS")
        .map(|v| v != "false")
        .unwrap_or(true);

    if !enabled {
        return;
    }

    // --- SAFE: These don't break any functioning website ---

    // Prevents MIME-type sniffing attacks. Only "breaks" sites serving JS with
    // wrong Content-Type, which are already broken.
    let _ = resp.insert_header("X-Content-Type-Options", "nosniff");

    // Disables the old, buggy XSS filter in IE/Chrome that could itself be
    // exploited. OWASP recommends setting to 0.
    let _ = resp.insert_header("X-XSS-Protection", "0");

    // Browser default since Chrome 85+. Sends full URL for same-origin,
    // only origin for cross-origin. Low risk — most analytics already handle this.
    let _ = resp.insert_header("Referrer-Policy", "strict-origin-when-cross-origin");

    // Prevents Flash/Acrobat from loading data cross-domain.
    let _ = resp.insert_header("X-Permitted-Cross-Domain-Policies", "none");

    // --- CONDITIONAL: Only inject if user explicitly opted in ---

    // HSTS: Only inject when FORCE_HTTPS=true, meaning the user has confirmed
    // their site runs on HTTPS. Without this, HSTS can lock users out for 1 year
    // if HTTPS isn't fully configured.
    let force_https = std::env::var("FORCE_HTTPS")
        .map(|v| v == "true")
        .unwrap_or(false);
    if force_https {
        let _ = resp.insert_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        );
    }

    // X-Frame-Options: SAMEORIGIN allows the site to iframe itself (common for
    // admin panels, payment modals, etc.) while blocking cross-site framing
    // (clickjacking). DENY would break OAuth popups, embedded payment flows, etc.
    let _ = resp.insert_header("X-Frame-Options", "SAMEORIGIN");

    // Permissions-Policy: Only set if explicitly configured via env.
    // Default OFF because camera=()/microphone=()/geolocation=() breaks
    // video call apps, map apps, and any site that legitimately uses these APIs.
    if let Ok(policy) = std::env::var("PERMISSIONS_POLICY") {
        if !policy.is_empty() {
            let _ = resp.insert_header("Permissions-Policy", &policy);
        }
    }

    // CSP: Only set if explicitly configured via env.
    // Default OFF because "default-src 'self'" blocks:
    //   - Inline <script> and <style> tags (every legacy site uses these)
    //   - CDN resources (Bootstrap, jQuery, Google Fonts, analytics)
    //   - External images, videos, iframes (YouTube, Google Maps, payment widgets)
    //   - WebSocket connections
    // A wrong CSP is worse than no CSP — it silently breaks the site.
    if let Ok(csp) = std::env::var("CSP_POLICY") {
        if !csp.is_empty() {
            let _ = resp.insert_header("Content-Security-Policy", &csp);
        }
    }
}
