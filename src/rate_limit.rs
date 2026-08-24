use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::metrics;

const DEFAULT_MAX: u64 = 100;
const DEFAULT_WINDOW: u64 = 60;
const DEFAULT_MAX_IPS: usize = 50_000;
const SWEEP_EVERY: u64 = 256;

pub struct RateLimiter {
    requests: DashMap<IpAddr, Vec<Instant>>,
    max_requests: u64,
    window_secs: u64,
    max_ips: usize,
    hits: AtomicU64,
}

impl RateLimiter {
    pub fn from_env() -> Self {
        let max_requests = std::env::var("RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX);

        let window_secs = std::env::var("RATE_LIMIT_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_WINDOW);

        let max_ips = std::env::var("RATE_LIMIT_MAX_IPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_IPS);

        tracing::info!(max_requests, window_secs, max_ips, "Rate limiter initialized");

        Self::new(max_requests, window_secs, max_ips)
    }

    pub fn new(max_requests: u64, window_secs: u64, max_ips: usize) -> Self {
        Self {
            requests: DashMap::new(),
            max_requests,
            window_secs,
            max_ips: max_ips.max(1),
            hits: AtomicU64::new(0),
        }
    }

    /// Returns true if request is allowed, false if rate limited.
    pub fn check(&self, ip: IpAddr, uri: &str) -> bool {
        self.maybe_sweep();

        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        let mut entry = self.requests.entry(ip).or_insert_with(Vec::new);
        let timestamps = entry.value_mut();

        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() as u64 >= self.max_requests {
            warn!(
                client = %ip,
                uri = uri,
                requests = timestamps.len(),
                window = self.window_secs,
                "Rate limit exceeded"
            );
            metrics::record_block("rate_limit", &ip.to_string(), uri, "Rate limit exceeded");
            return false;
        }

        timestamps.push(now);
        drop(entry);

        self.enforce_cap(ip);
        true
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    pub fn tracked_ips(&self) -> usize {
        self.requests.len()
    }

    /// Drop IPs whose entire window has expired. Called on a sample of requests
    /// so a flood of unique IPs cannot grow the map forever after they go quiet.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        self.requests.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < window);
            !timestamps.is_empty()
        });
    }

    fn maybe_sweep(&self) {
        let n = self.hits.fetch_add(1, Ordering::Relaxed);
        if n % SWEEP_EVERY == 0 {
            self.evict_expired();
            if self.requests.len() > self.max_ips {
                self.shrink_to_cap(None);
            }
        }
    }

    fn enforce_cap(&self, keep: IpAddr) {
        if self.requests.len() > self.max_ips {
            self.evict_expired();
            if self.requests.len() > self.max_ips {
                self.shrink_to_cap(Some(keep));
            }
        }
    }

    fn shrink_to_cap(&self, keep: Option<IpAddr>) {
        let overflow = self.requests.len().saturating_sub(self.max_ips);
        if overflow == 0 {
            return;
        }
        let mut entries: Vec<(IpAddr, Instant)> = self
            .requests
            .iter()
            .filter_map(|e| {
                let ip = *e.key();
                if keep == Some(ip) {
                    return None;
                }
                e.value().last().copied().map(|t| (ip, t))
            })
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        for (ip, _) in entries.into_iter().take(overflow) {
            self.requests.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn allows_under_limit() {
        let rl = RateLimiter::new(3, 60, 100);
        assert!(rl.check(ip(1), "/"));
        assert!(rl.check(ip(1), "/"));
        assert!(rl.check(ip(1), "/"));
        assert!(!rl.check(ip(1), "/"));
    }

    #[test]
    fn evict_expired_drops_quiet_ips() {
        let rl = RateLimiter::new(10, 0, 100);
        assert!(rl.check(ip(1), "/"));
        assert_eq!(rl.tracked_ips(), 1);
        rl.evict_expired();
        assert_eq!(
            rl.tracked_ips(),
            0,
            "IPs whose window has elapsed must leave the map"
        );
    }

    #[test]
    fn cap_drops_oldest_when_full() {
        let rl = RateLimiter::new(10, 60, 2);
        assert!(rl.check(ip(1), "/"));
        assert!(rl.check(ip(2), "/"));
        assert_eq!(rl.tracked_ips(), 2);
        assert!(rl.check(ip(3), "/"));
        assert!(
            rl.tracked_ips() <= 2,
            "map must not grow past max_ips, got {}",
            rl.tracked_ips()
        );
        assert!(
            rl.requests.contains_key(&ip(3)),
            "the IP just seen must be kept"
        );
    }

    #[test]
    fn independent_ips_do_not_share_budget() {
        let rl = RateLimiter::new(1, 60, 100);
        assert!(rl.check(ip(1), "/"));
        assert!(!rl.check(ip(1), "/"));
        assert!(rl.check(ip(2), "/"));
    }
}
