//! L1 CRS policy: executing paranoia ≠ blocking, shadow, anomaly threshold, exclusions.

use serde::Deserialize;

pub const DEFAULT_ANOMALY_THRESHOLD: u32 = 5;
pub const MIN_PARANOIA: u8 = 1;
pub const MAX_PARANOIA: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L1Settings {
    pub blocking_paranoia: u8,
    pub executing_paranoia: u8,
    pub shadow: bool,
    pub anomaly_score_threshold: u32,
    pub exclude: bool,
}

impl L1Settings {
    pub fn default_crs() -> Self {
        Self {
            blocking_paranoia: 1,
            executing_paranoia: 1,
            shadow: false,
            anomaly_score_threshold: DEFAULT_ANOMALY_THRESHOLD,
            exclude: false,
        }
    }

    pub fn overlay(self, patch: &L1File) -> Self {
        let blocking = patch.blocking_paranoia.unwrap_or(self.blocking_paranoia);
        let executing = patch
            .executing_paranoia
            .unwrap_or(self.executing_paranoia.max(blocking));
        Self {
            blocking_paranoia: blocking,
            executing_paranoia: executing,
            shadow: patch.shadow.unwrap_or(self.shadow),
            anomaly_score_threshold: patch
                .anomaly_score_threshold
                .unwrap_or(self.anomaly_score_threshold),
            exclude: patch.exclude.unwrap_or(self.exclude),
        }
    }

    pub fn validated(self) -> Self {
        validate_paranoia("blocking_paranoia", self.blocking_paranoia);
        validate_paranoia("executing_paranoia", self.executing_paranoia);
        if self.executing_paranoia < self.blocking_paranoia {
            panic!(
                "waf.l1.executing_paranoia ({}) não pode ser menor que blocking_paranoia ({})",
                self.executing_paranoia, self.blocking_paranoia
            );
        }
        if self.anomaly_score_threshold == 0 || self.anomaly_score_threshold > 10_000 {
            panic!(
                "waf.l1.anomaly_score_threshold deve estar entre 1 e 10000, não {}",
                self.anomaly_score_threshold
            );
        }
        self
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct L1File {
    #[serde(default)]
    pub blocking_paranoia: Option<u8>,
    #[serde(default)]
    pub executing_paranoia: Option<u8>,
    #[serde(default)]
    pub shadow: Option<bool>,
    #[serde(default)]
    pub anomaly_score_threshold: Option<u32>,
    #[serde(default)]
    pub exclude: Option<bool>,
    #[serde(default)]
    pub exclusions: Vec<L1ExclusionFile>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct L1ExclusionFile {
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub parameters: Vec<String>,
    #[serde(default)]
    pub content_types: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L1Exclusion {
    pub prefix: Option<String>,
    pub parameters: Vec<String>,
    pub content_types: Vec<String>,
}

impl L1Exclusion {
    pub fn from_file(file: L1ExclusionFile, prefix: Option<String>) -> Self {
        let parameters: Vec<String> = file
            .parameters
            .into_iter()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();
        let content_types: Vec<String> = file
            .content_types
            .into_iter()
            .map(|value| normalize_media_type(&value))
            .filter(|value| !value.is_empty())
            .collect();
        let exclusion = Self {
            prefix,
            parameters,
            content_types,
        };
        if exclusion.prefix.is_none()
            && exclusion.parameters.is_empty()
            && exclusion.content_types.is_empty()
        {
            panic!("exclusão L1 vazia: informe prefix, parameters ou content_types");
        }
        exclusion
    }

    pub fn skips_engine(&self) -> bool {
        self.parameters.is_empty() && (self.prefix.is_some() || !self.content_types.is_empty())
    }

    pub fn matches(&self, path: Option<&str>, media: Option<&str>) -> bool {
        if let Some(prefix) = self.prefix.as_deref() {
            let Some(path) = path else {
                return false;
            };
            if !prefix_matches(path, prefix) {
                return false;
            }
        }
        if !self.content_types.is_empty() {
            let Some(media) = media else {
                return false;
            };
            if !self.content_types.iter().any(|allowed| allowed == media) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L1RequestPolicy {
    pub skip: bool,
    pub settings: L1Settings,
    pub exclude_parameters: Vec<String>,
}

pub fn resolve(
    mut settings: L1Settings,
    route_patches: &[(String, L1File)],
    exclusions: &[L1Exclusion],
    path: Option<&str>,
    content_type: Option<&str>,
) -> L1RequestPolicy {
    if let Some(path) = path {
        let mut matching: Vec<&(String, L1File)> = route_patches
            .iter()
            .filter(|(prefix, _)| prefix_matches(path, prefix))
            .collect();
        matching.sort_by_key(|(prefix, _)| prefix.len());
        for (_, patch) in matching {
            settings = settings.overlay(patch).validated();
        }
    }
    let media = content_type.map(normalize_media_type);
    let media = media.as_deref().filter(|value| !value.is_empty());
    let mut skip = settings.exclude;
    let mut exclude_parameters = Vec::new();
    for exclusion in exclusions {
        if !exclusion.matches(path, media) {
            continue;
        }
        if exclusion.skips_engine() {
            skip = true;
        }
        for parameter in &exclusion.parameters {
            if !exclude_parameters
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(parameter))
            {
                exclude_parameters.push(parameter.clone());
            }
        }
    }
    L1RequestPolicy {
        skip,
        settings,
        exclude_parameters,
    }
}

pub fn strip_query_params(uri: &str, names: &[String]) -> String {
    if names.is_empty() {
        return uri.to_string();
    }
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            if pair.is_empty() {
                return false;
            }
            let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
            !param_excluded(key, names)
        })
        .collect();
    if kept.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

pub fn strip_excluded_body(body: &[u8], content_type: Option<&str>, names: &[String]) -> Vec<u8> {
    if names.is_empty() || body.is_empty() {
        return body.to_vec();
    }
    let media = normalize_media_type(content_type.unwrap_or(""));
    if media == "application/x-www-form-urlencoded" {
        return strip_form_body(body, names);
    }
    if media == "application/json" || media.ends_with("+json") {
        return strip_json_object_keys(body, names);
    }
    body.to_vec()
}

pub fn normalize_media_type(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase()
}

fn strip_form_body(body: &[u8], names: &[String]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec();
    };
    let kept: Vec<&str> = text
        .split('&')
        .filter(|pair| {
            if pair.is_empty() {
                return false;
            }
            let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
            !param_excluded(key, names)
        })
        .collect();
    kept.join("&").into_bytes()
}

fn strip_json_object_keys(body: &[u8], names: &[String]) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    let Some(object) = value.as_object_mut() else {
        return body.to_vec();
    };
    object.retain(|key, _| !param_excluded(key, names));
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

fn param_excluded(key: &str, names: &[String]) -> bool {
    names.iter().any(|name| name.eq_ignore_ascii_case(key))
}

fn prefix_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || prefix == "/"
        || (prefix.ends_with('/') && path.starts_with(prefix))
        || path
            .strip_prefix(prefix)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn validate_paranoia(field: &str, value: u8) {
    if !(MIN_PARANOIA..=MAX_PARANOIA).contains(&value) {
        panic!("waf.l1.{field} deve ser 1–4, não {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executing_may_exceed_blocking() {
        let settings = L1Settings::default_crs()
            .overlay(&L1File {
                blocking_paranoia: Some(1),
                executing_paranoia: Some(4),
                ..L1File::default()
            })
            .validated();
        assert_eq!(settings.blocking_paranoia, 1);
        assert_eq!(settings.executing_paranoia, 4);
        assert_ne!(
            settings.executing_paranoia, settings.blocking_paranoia,
            "executing ≠ blocking is the CRS tuning model"
        );
    }

    #[test]
    fn raising_blocking_without_executing_raises_executing() {
        let settings = L1Settings::default_crs()
            .overlay(&L1File {
                blocking_paranoia: Some(4),
                ..L1File::default()
            })
            .validated();
        assert_eq!(settings.blocking_paranoia, 4);
        assert_eq!(settings.executing_paranoia, 4);
    }

    #[test]
    fn executing_below_blocking_is_a_load_error() {
        let result = std::panic::catch_unwind(|| {
            L1Settings {
                blocking_paranoia: 3,
                executing_paranoia: 1,
                shadow: false,
                anomaly_score_threshold: 5,
                exclude: false,
            }
            .validated()
        });
        assert!(result.is_err());
    }

    #[test]
    fn login_exclusion_skips_login_not_api() {
        let exclusions = vec![L1Exclusion::from_file(
            L1ExclusionFile {
                prefix: Some("/login".into()),
                ..L1ExclusionFile::default()
            },
            Some("/login".into()),
        )];
        let login = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/login"),
            None,
        );
        let api = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/api"),
            None,
        );
        assert!(login.skip, "/login must skip L1");
        assert!(!api.skip, "/api must still run L1");
    }

    #[test]
    fn content_type_exclusion_skips_only_that_type() {
        let exclusions = vec![L1Exclusion::from_file(
            L1ExclusionFile {
                content_types: vec!["application/pdf".into()],
                ..L1ExclusionFile::default()
            },
            None,
        )];
        let pdf = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/upload"),
            Some("application/pdf; charset=utf-8"),
        );
        let json = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/upload"),
            Some("application/json"),
        );
        assert!(pdf.skip);
        assert!(!json.skip);
    }

    #[test]
    fn parameter_exclusion_strips_query_and_keeps_inspecting() {
        let exclusions = vec![L1Exclusion::from_file(
            L1ExclusionFile {
                parameters: vec!["token".into(), "password".into()],
                ..L1ExclusionFile::default()
            },
            None,
        )];
        let policy = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/login"),
            None,
        );
        assert!(!policy.skip);
        assert_eq!(policy.exclude_parameters, vec!["token", "password"]);
        let stripped = strip_query_params(
            "/login?user=a&token=1%27+OR+1%3D1&x=1",
            &policy.exclude_parameters,
        );
        assert_eq!(stripped, "/login?user=a&x=1");
    }

    #[test]
    fn parameter_on_prefix_does_not_skip_engine() {
        let exclusions = vec![L1Exclusion::from_file(
            L1ExclusionFile {
                prefix: Some("/login".into()),
                parameters: vec!["password".into()],
                ..L1ExclusionFile::default()
            },
            Some("/login".into()),
        )];
        let login = resolve(
            L1Settings::default_crs(),
            &[],
            &exclusions,
            Some("/login"),
            None,
        );
        assert!(!login.skip);
        assert_eq!(login.exclude_parameters, vec!["password"]);
    }

    #[test]
    fn strip_form_and_json_keys() {
        let names = vec!["password".to_string()];
        assert_eq!(
            strip_excluded_body(
                b"user=a&password=1'+OR+1=1&ok=1",
                Some("application/x-www-form-urlencoded"),
                &names
            ),
            b"user=a&ok=1"
        );
        let json = strip_excluded_body(
            br#"{"user":"a","password":"1' OR 1=1","ok":1}"#,
            Some("application/json"),
            &names,
        );
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["user"], "a");
        assert!(value.get("password").is_none());
        assert_eq!(value["ok"], 1);
    }

    #[test]
    fn route_shadow_overlay() {
        let patch = L1File {
            shadow: Some(true),
            executing_paranoia: Some(4),
            ..L1File::default()
        };
        let policy = resolve(
            L1Settings::default_crs(),
            &[("/api".into(), patch)],
            &[],
            Some("/api/payment"),
            None,
        );
        assert!(policy.settings.shadow);
        assert_eq!(policy.settings.executing_paranoia, 4);
        assert_eq!(policy.settings.blocking_paranoia, 1);
    }
}
