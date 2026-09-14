//! Append-only admin audit log. Never writes tokens, OIDC codes, or verifiers.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const MAX_DETAIL: usize = 200;

#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub action: &'static str,
    pub method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'static str>,
    pub result: &'static str,
    pub peer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct AdminAudit {
    file: Option<Mutex<File>>,
    path: Option<PathBuf>,
}

impl AdminAudit {
    pub fn disabled() -> Self {
        Self {
            file: None,
            path: None,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        match std::env::var("DASHBOARD_AUDIT_LOG") {
            Ok(path) if !path.trim().is_empty() => Self::open(Path::new(path.trim())),
            _ => Ok(Self::disabled()),
        }
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| {
                format!(
                    "DASHBOARD_AUDIT_LOG não pôde ser aberto ({}): {error}",
                    path.display()
                )
            })?;
        Ok(Self {
            file: Some(Mutex::new(file)),
            path: Some(path.to_path_buf()),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn record(&self, mut event: AuditEvent) {
        event.detail = event.detail.and_then(|detail| sanitize_detail(&detail));
        event.subject = event.subject.and_then(|subject| sanitize_detail(&subject));
        let line = match serde_json::to_string(&event) {
            Ok(line) => line,
            Err(error) => {
                warn!("audit JSON falhou: {error}");
                return;
            }
        };
        info!(
            action = event.action,
            method = event.method,
            result = event.result,
            peer = %event.peer,
            "admin audit"
        );
        let Some(file) = &self.file else {
            return;
        };
        let mut guard = file.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Err(error) = writeln!(guard, "{line}").and_then(|_| guard.flush()) {
            warn!("audit append falhou: {error}");
        }
    }

    pub fn login_ok(
        &self,
        method: &'static str,
        role: &'static str,
        peer: &str,
        subject: Option<String>,
    ) {
        self.record(AuditEvent {
            ts: now_rfc3339(),
            action: "login",
            method,
            role: Some(role),
            result: "ok",
            peer: peer.to_string(),
            subject,
            detail: None,
        });
    }

    pub fn auth_failure(&self, method: &'static str, peer: &str, detail: &'static str) {
        self.record(AuditEvent {
            ts: now_rfc3339(),
            action: "auth_failure",
            method,
            role: None,
            result: "denied",
            peer: peer.to_string(),
            subject: None,
            detail: Some(detail.to_string()),
        });
    }

    pub fn reload(
        &self,
        method: &'static str,
        role: &'static str,
        peer: &str,
        result: &'static str,
        detail: Option<String>,
    ) {
        self.record(AuditEvent {
            ts: now_rfc3339(),
            action: "reload",
            method,
            role: Some(role),
            result,
            peer: peer.to_string(),
            subject: None,
            detail,
        });
    }
}

fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", now.as_secs(), now.subsec_millis())
}

fn sanitize_detail(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("bearer ")
        || lower.contains("code=")
        || lower.contains("token=")
        || lower.contains("code_verifier")
        || lower.contains("client_secret")
        || lower.contains("id_token")
    {
        return Some("redacted".into());
    }
    let mut out = trimmed.to_string();
    if out.len() > MAX_DETAIL {
        out.truncate(MAX_DETAIL);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ferroada-audit-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn append_only_line_has_no_token_or_code() {
        let path = temp_log();
        let audit = AdminAudit::open(&path).unwrap();
        audit.auth_failure("token", "127.0.0.1", "bad_token");
        audit.login_ok("oidc", "operator", "127.0.0.1", Some("user-1".into()));
        audit.record(AuditEvent {
            ts: now_rfc3339(),
            action: "auth_failure",
            method: "oidc",
            role: None,
            result: "denied",
            peer: "10.0.0.2".into(),
            subject: None,
            detail: Some("code=secret-code&token=super-secret".into()),
        });
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"action\":\"auth_failure\""));
        assert!(body.contains("\"action\":\"login\""));
        assert!(!body.contains("super-secret"));
        assert!(!body.contains("secret-code"));
        assert!(!body.contains("code="));
        assert!(body.contains("redacted"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disabled_audit_does_not_create_file() {
        let audit = AdminAudit::disabled();
        audit.auth_failure("token", "127.0.0.1", "bad_token");
        assert!(audit.path().is_none());
    }
}
