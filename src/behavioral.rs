use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use crate::client_ip::{RiskIdentity, SiteClientKey};
use crate::metrics;

// --- Configuration via env ---

static BEHAVIORAL_ENABLED: Lazy<bool> = Lazy::new(|| {
    std::env::var("BEHAVIORAL_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true)
});

static SCORE_THRESHOLD_SLOW: Lazy<f32> = Lazy::new(|| {
    let configured = std::env::var("BEHAVIORAL_SLOW_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50.0);
    (configured / replica_count() as f32).max(1.0)
});

static SCORE_THRESHOLD_BLOCK: Lazy<f32> = Lazy::new(|| {
    let configured = std::env::var("BEHAVIORAL_BLOCK_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80.0);
    (configured / replica_count() as f32).max(1.0)
});

fn replica_count() -> u64 {
    std::env::var("REPLICA_COUNT")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

static BAN_DURATION_SECS: Lazy<u64> = Lazy::new(|| {
    std::env::var("BEHAVIORAL_BAN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
});

static MAX_TRACKED_IPS: Lazy<usize> = Lazy::new(|| {
    std::env::var("BEHAVIORAL_MAX_IPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000)
});

/// Decay rate: points lost per second
const DECAY_RATE: f32 = 5.0;

/// Max unique paths/UAs tracked per IP profile
const MAX_HASHES: usize = 64;

/// Path diversity threshold (scan detection)
const PATH_DIVERSITY_THRESHOLD: usize = 30;

/// Path diversity time window in seconds
const PATH_DIVERSITY_WINDOW_SECS: u64 = 60;

/// UA rotation threshold
const UA_ROTATION_THRESHOLD: usize = 3;

/// Cleanup runs every N requests
const CLEANUP_INTERVAL: u64 = 1000;

// --- Global state ---

static PROFILES: Lazy<DashMap<SiteClientKey, IpProfile>> = Lazy::new(DashMap::new);
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct IpProfile {
    score: f32,
    last_decay: Instant,
    last_seen: Instant,
    path_window_started: Instant,
    banned_until: Option<Instant>,
    waf_blocks: u16,
    not_found: u16,
    auth_failures: u16,
    unique_paths: Vec<u64>,
    user_agents: Vec<u64>,
    path_diversity_flagged: bool,
    ua_rotation_flagged: bool,
}

impl IpProfile {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            score: 0.0,
            last_decay: now,
            last_seen: now,
            path_window_started: now,
            banned_until: None,
            waf_blocks: 0,
            not_found: 0,
            auth_failures: 0,
            unique_paths: Vec::new(),
            user_agents: Vec::new(),
            path_diversity_flagged: false,
            ua_rotation_flagged: false,
        }
    }

    fn apply_decay(&mut self) {
        let elapsed = self.last_decay.elapsed().as_secs_f32();
        if elapsed > 0.1 {
            self.score = (self.score - elapsed * DECAY_RATE).max(0.0);
            self.last_decay = Instant::now();
        }
    }

    fn add_score(&mut self, points: f32) {
        self.apply_decay();
        self.score += points;
    }

    fn is_banned(&self) -> bool {
        self.banned_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    fn reset_path_window_if_expired(&mut self) {
        if self.path_window_started.elapsed().as_secs() >= PATH_DIVERSITY_WINDOW_SECS {
            self.path_window_started = Instant::now();
            self.unique_paths.clear();
            self.path_diversity_flagged = false;
        }
    }

    fn is_stale(&self, threshold: std::time::Duration) -> bool {
        self.score < 0.1 && self.last_seen.elapsed() > threshold
    }
}

pub enum BehavioralVerdict {
    Allow,
    Throttle,
    Block,
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

fn add_hash(vec: &mut Vec<u64>, hash: u64) -> bool {
    if vec.contains(&hash) {
        return false; // already tracked
    }
    if vec.len() < MAX_HASHES {
        vec.push(hash);
    }
    true // new unique value
}

/// Check behavioral score and record request. Called at the start of every request.
pub fn check_and_record(
    identity: &RiskIdentity,
    uri: &str,
    ua: Option<&str>,
    client_addr: &str,
) -> BehavioralVerdict {
    if !*BEHAVIORAL_ENABLED {
        return BehavioralVerdict::Allow;
    }

    // Periodic cleanup
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    if count.is_multiple_of(CLEANUP_INTERVAL) && count > 0 {
        cleanup_stale();
    }

    let key = identity.network_key();
    let mut entry = PROFILES.entry(key).or_insert_with(IpProfile::new);
    let profile = entry.value_mut();
    profile.last_seen = Instant::now();

    // Check if currently banned
    if profile.is_banned() {
        metrics::record_block_in(
            &identity.site,
            "behavioral_block",
            client_addr,
            uri,
            "IP temporarily banned",
        );
        return BehavioralVerdict::Block;
    }

    // Apply decay
    profile.apply_decay();

    // Record path diversity
    profile.reset_path_window_if_expired();
    let path = uri.split('?').next().unwrap_or(uri);
    let path_hash = hash_str(path);
    add_hash(&mut profile.unique_paths, path_hash);

    // Check path diversity (scan detection)
    if !profile.path_diversity_flagged && profile.unique_paths.len() > PATH_DIVERSITY_THRESHOLD {
        profile.path_diversity_flagged = true;
        profile.add_score(20.0);
        warn!(
            client = client_addr,
            paths = profile.unique_paths.len(),
            "Behavioral: path diversity scan detected"
        );
    }

    // Record UA and check rotation
    if let Some(ua_str) = ua {
        if ua_str.is_empty() {
            // No User-Agent
            profile.add_score(8.0);
        } else {
            let ua_hash = hash_str(ua_str);
            add_hash(&mut profile.user_agents, ua_hash);

            if !profile.ua_rotation_flagged && profile.user_agents.len() > UA_ROTATION_THRESHOLD {
                profile.ua_rotation_flagged = true;
                profile.add_score(15.0);
                warn!(
                    client = client_addr,
                    uas = profile.user_agents.len(),
                    "Behavioral: UA rotation detected"
                );
            }
        }
    } else {
        // No User-Agent header at all
        profile.add_score(8.0);
    }

    // Small baseline score per request
    profile.score += 0.1;

    // Evaluate thresholds
    let score = profile.score;

    if score >= *SCORE_THRESHOLD_BLOCK {
        let ban_until = Instant::now() + std::time::Duration::from_secs(*BAN_DURATION_SECS);
        profile.banned_until = Some(ban_until);
        warn!(
            client = client_addr,
            score = score,
            ban_secs = *BAN_DURATION_SECS,
            "Behavioral: IP banned"
        );
        metrics::record_block_in(
            &identity.site,
            "behavioral_block",
            client_addr,
            uri,
            &format!("Behavioral ban, score: {:.1}", score),
        );
        return BehavioralVerdict::Block;
    }

    if score >= *SCORE_THRESHOLD_SLOW {
        warn!(
            client = client_addr,
            score = score,
            "Behavioral: throttling IP"
        );
        metrics::record_block_in(
            &identity.site,
            "behavioral_throttle",
            client_addr,
            uri,
            &format!("Behavioral throttle, score: {:.1}", score),
        );
        return BehavioralVerdict::Throttle;
    }

    BehavioralVerdict::Allow
}

/// Record a WAF block event — adds significant score.
pub fn record_waf_block(identity: &RiskIdentity) {
    if !*BEHAVIORAL_ENABLED {
        return;
    }
    let mut entry = PROFILES
        .entry(identity.network_key())
        .or_insert_with(IpProfile::new);
    let profile = entry.value_mut();
    profile.last_seen = Instant::now();
    profile.waf_blocks = profile.waf_blocks.saturating_add(1);
    profile.add_score(20.0);
}

/// Record upstream response status — feeds scoring for scan/brute-force detection.
pub fn record_response(identity: &RiskIdentity, status: u16) {
    if !*BEHAVIORAL_ENABLED {
        return;
    }
    let mut entry = PROFILES
        .entry(identity.network_key())
        .or_insert_with(IpProfile::new);
    let profile = entry.value_mut();
    profile.last_seen = Instant::now();

    match status {
        404 => {
            profile.not_found = profile.not_found.saturating_add(1);
            profile.add_score(3.0);
        }
        401 => {
            profile.auth_failures = profile.auth_failures.saturating_add(1);
            profile.add_score(5.0);
        }
        403 => {
            profile.auth_failures = profile.auth_failures.saturating_add(1);
            profile.add_score(3.0);
        }
        _ => {}
    }
}

/// Remove stale entries to bound memory usage.
fn cleanup_stale() {
    let len = PROFILES.len();
    if len <= *MAX_TRACKED_IPS {
        return;
    }

    // Phase 1: remove entries with score 0 and idle > 5 minutes
    let stale_threshold = std::time::Duration::from_secs(300);
    PROFILES.retain(|_, profile| {
        profile.apply_decay();
        !profile.is_stale(stale_threshold)
    });

    // Phase 2: if still over limit, remove lowest-score entries
    if PROFILES.len() > *MAX_TRACKED_IPS {
        let to_remove = PROFILES.len() - *MAX_TRACKED_IPS;
        let mut entries: Vec<(SiteClientKey, f32)> = PROFILES
            .iter()
            .map(|e| (e.key().clone(), e.value().score))
            .collect();
        entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        for (key, _) in entries.into_iter().take(to_remove) {
            PROFILES.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    fn identity(ip: IpAddr, site: &str, uri: &str) -> RiskIdentity {
        RiskIdentity::new(site, ip, uri, None, None)
    }

    #[test]
    fn test_normal_traffic_stays_low() {
        let ip = test_ip(1);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        for _ in 0..10 {
            let verdict = check_and_record(
                &identity(ip, "site-a", "/index.html"),
                "/index.html",
                Some("Mozilla/5.0"),
                "10.0.0.1",
            );
            assert!(matches!(verdict, BehavioralVerdict::Allow));
        }
        let profile = PROFILES.get(&key).unwrap();
        assert!(
            profile.score < 5.0,
            "Normal traffic score should be low, got {}",
            profile.score
        );
    }

    #[test]
    fn test_waf_blocks_raise_score() {
        let ip = test_ip(2);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        let identity = identity(ip, "site-a", "/test");
        check_and_record(&identity, "/test", Some("Mozilla/5.0"), "10.0.0.2");
        for _ in 0..3 {
            record_waf_block(&identity);
        }
        let profile = PROFILES.get(&key).unwrap();
        assert!(
            profile.score >= 50.0,
            "3 WAF blocks should raise score significantly, got {}",
            profile.score
        );
    }

    #[test]
    fn test_decay_reduces_score() {
        let ip = test_ip(3);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        {
            let mut entry = PROFILES.entry(key.clone()).or_insert_with(IpProfile::new);
            let profile = entry.value_mut();
            profile.score = 40.0;
            // Simulate time passing by backdating last_decay
            profile.last_decay = Instant::now() - std::time::Duration::from_secs(5);
        }
        // Next check_and_record triggers decay
        let verdict = check_and_record(
            &identity(ip, "site-a", "/test"),
            "/test",
            Some("Mozilla/5.0"),
            "10.0.0.3",
        );
        assert!(matches!(verdict, BehavioralVerdict::Allow));
        let profile = PROFILES.get(&key).unwrap();
        // 40 - (5 * 5.0) = 15, plus small additions from check_and_record
        assert!(
            profile.score < 20.0,
            "Score should have decayed, got {}",
            profile.score
        );
    }

    #[test]
    fn test_ban_blocks_requests() {
        let ip = test_ip(4);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        {
            let mut entry = PROFILES.entry(key).or_insert_with(IpProfile::new);
            let profile = entry.value_mut();
            profile.banned_until = Some(Instant::now() + std::time::Duration::from_secs(60));
        }
        let verdict = check_and_record(
            &identity(ip, "site-a", "/test"),
            "/test",
            Some("Mozilla/5.0"),
            "10.0.0.4",
        );
        assert!(matches!(verdict, BehavioralVerdict::Block));
    }

    #[test]
    fn test_no_ua_adds_score() {
        let ip = test_ip(5);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        for _ in 0..5 {
            check_and_record(&identity(ip, "site-a", "/test"), "/test", None, "10.0.0.5");
        }
        let profile = PROFILES.get(&key).unwrap();
        // 5 requests with no UA: 5 * 8.0 + 5 * 0.1 = 40.5 (minus decay)
        assert!(
            profile.score > 30.0,
            "No-UA requests should raise score, got {}",
            profile.score
        );
    }

    #[test]
    fn test_404_scanning_raises_score() {
        let ip = test_ip(6);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        let identity = identity(ip, "site-a", "/test");
        check_and_record(&identity, "/test", Some("Mozilla/5.0"), "10.0.0.6");
        for _ in 0..15 {
            record_response(&identity, 404);
        }
        let profile = PROFILES.get(&key).unwrap();
        // 15 * 3.0 = 45 points (minus decay)
        assert!(
            profile.score > 35.0,
            "404 scanning should raise score, got {}",
            profile.score
        );
    }

    #[test]
    fn sites_have_independent_behavior_profiles() {
        let ip = test_ip(7);
        let site_a = SiteClientKey::new("site-a", ip);
        let site_b = SiteClientKey::new("site-b", ip);
        PROFILES.remove(&site_a);
        PROFILES.remove(&site_b);
        record_waf_block(&identity(ip, "site-a", "/"));
        assert!(PROFILES.contains_key(&site_a));
        assert!(!PROFILES.contains_key(&site_b));
    }

    #[test]
    fn path_scan_detection_uses_rolling_windows_for_old_profiles() {
        let ip = test_ip(8);
        let key = SiteClientKey::new("site-a", ip);
        PROFILES.remove(&key);
        {
            let mut entry = PROFILES.entry(key.clone()).or_insert_with(IpProfile::new);
            entry.path_window_started =
                Instant::now() - std::time::Duration::from_secs(PATH_DIVERSITY_WINDOW_SECS + 1);
        }
        for index in 0..=PATH_DIVERSITY_THRESHOLD {
            let uri = format!("/scan/{index}");
            check_and_record(
                &identity(ip, "site-a", &uri),
                &uri,
                Some("Mozilla/5.0"),
                "10.0.0.8",
            );
        }
        let profile = PROFILES.get(&key).unwrap();
        assert!(profile.path_diversity_flagged);
        assert!(profile.score >= 20.0);
    }

    #[test]
    fn score_decay_does_not_hide_idle_profiles_from_cleanup() {
        let mut profile = IpProfile::new();
        profile.last_seen = Instant::now() - std::time::Duration::from_secs(301);
        profile.last_decay = Instant::now() - std::time::Duration::from_secs(301);
        profile.apply_decay();
        assert!(profile.is_stale(std::time::Duration::from_secs(300)));
    }
}
