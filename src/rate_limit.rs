use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::client_ip::{RiskIdentity, SiteClientKey};
use crate::metrics;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum RateKey {
    Network(SiteClientKey),
    Route {
        network: SiteClientKey,
        route: String,
    },
    Session {
        site: String,
        hash: u64,
    },
    ApiKey {
        site: String,
        hash: u64,
    },
}

const DEFAULT_MAX: u64 = 100;
const DEFAULT_WINDOW: u64 = 60;
const DEFAULT_MAX_IPS: usize = 50_000;
const SWEEP_EVERY: u64 = 256;

pub struct RateLimiter {
    requests: DashMap<RateKey, Vec<Instant>>,
    max_requests: u64,
    window_secs: u64,
    max_ips: usize,
    hits: AtomicU64,
}

impl RateLimiter {
    pub fn from_env() -> Self {
        let configured_max_requests = std::env::var("RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX);
        let replica_count = std::env::var("REPLICA_COUNT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        let max_requests = (configured_max_requests / replica_count).max(1);

        let window_secs = std::env::var("RATE_LIMIT_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_WINDOW);

        let max_ips = std::env::var("RATE_LIMIT_MAX_IPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_IPS);

        tracing::info!(
            max_requests,
            configured_max_requests,
            replica_count,
            window_secs,
            max_ips,
            "Rate limiter initialized"
        );

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
    pub fn check(&self, identity: &RiskIdentity, uri: &str) -> bool {
        self.maybe_sweep();

        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        let network = identity.network_key();
        let mut keys = vec![
            RateKey::Network(network.clone()),
            RateKey::Route {
                network,
                route: identity.route.clone(),
            },
        ];
        if let Some(hash) = identity.session_hash {
            keys.push(RateKey::Session {
                site: identity.site.clone(),
                hash,
            });
        }
        if let Some(hash) = identity.api_key_hash {
            keys.push(RateKey::ApiKey {
                site: identity.site.clone(),
                hash,
            });
        }

        for key in &keys {
            let mut entry = self.requests.entry(key.clone()).or_default();
            entry.retain(|timestamp| now.duration_since(*timestamp) < window);
            if entry.len() as u64 >= self.max_requests {
                warn!(
                    client = %identity.network,
                    uri,
                    requests = entry.len(),
                    window = self.window_secs,
                    "Rate limit exceeded"
                );
                metrics::record_block_in(
                    &identity.site,
                    "rate_limit",
                    &identity.network.to_string(),
                    uri,
                    "Rate limit exceeded",
                );
                return false;
            }
            entry.push(now);
        }
        self.enforce_cap(&keys);
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
        if n.is_multiple_of(SWEEP_EVERY) {
            self.evict_expired();
            if self.requests.len() > self.max_ips {
                self.shrink_to_cap(&[]);
            }
        }
    }

    fn enforce_cap(&self, keep: &[RateKey]) {
        if self.requests.len() > self.max_ips {
            self.evict_expired();
            if self.requests.len() > self.max_ips {
                self.shrink_to_cap(keep);
            }
        }
    }

    fn shrink_to_cap(&self, keep: &[RateKey]) {
        let overflow = self.requests.len().saturating_sub(self.max_ips);
        if overflow == 0 {
            return;
        }
        let mut entries: Vec<(RateKey, Instant)> = self
            .requests
            .iter()
            .filter_map(|e| {
                let key = e.key().clone();
                if keep.contains(&key) {
                    return None;
                }
                e.value().last().copied().map(|t| (key, t))
            })
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        for (key, _) in entries.into_iter().take(overflow) {
            self.requests.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn identity(ip: IpAddr, site: &str, uri: &str) -> RiskIdentity {
        RiskIdentity::new(site, ip, uri, None, None)
    }

    #[test]
    fn allows_under_limit() {
        let rl = RateLimiter::new(3, 60, 100);
        let identity = identity(ip(1), "site-a", "/");
        assert!(rl.check(&identity, "/"));
        assert!(rl.check(&identity, "/"));
        assert!(rl.check(&identity, "/"));
        assert!(!rl.check(&identity, "/"));
    }

    #[test]
    fn evict_expired_drops_quiet_ips() {
        let rl = RateLimiter::new(10, 0, 100);
        assert!(rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert_eq!(rl.tracked_ips(), 2);
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
        assert!(rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert!(rl.check(&identity(ip(2), "site-a", "/"), "/"));
        assert_eq!(rl.tracked_ips(), 2);
        assert!(rl.check(&identity(ip(3), "site-a", "/"), "/"));
        assert!(
            rl.tracked_ips() <= 2,
            "map must not grow past max_ips, got {}",
            rl.tracked_ips()
        );
        assert!(
            rl.requests
                .contains_key(&RateKey::Network(SiteClientKey::new("site-a", ip(3)))),
            "the IP just seen must be kept"
        );
    }

    #[test]
    fn independent_ips_do_not_share_budget() {
        let rl = RateLimiter::new(1, 60, 100);
        assert!(rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert!(!rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert!(rl.check(&identity(ip(2), "site-a", "/"), "/"));
    }

    #[test]
    fn sites_have_independent_budgets() {
        let rl = RateLimiter::new(1, 60, 100);
        assert!(rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert!(!rl.check(&identity(ip(1), "site-a", "/"), "/"));
        assert!(rl.check(&identity(ip(1), "site-b", "/"), "/"));
    }

    #[test]
    fn api_key_budget_is_shared_across_networks() {
        let rl = RateLimiter::new(1, 60, 100);
        let first = RiskIdentity::new("site-a", ip(1), "/api", None, Some("same-key"));
        let second = RiskIdentity::new("site-a", ip(2), "/api", None, Some("same-key"));
        assert!(rl.check(&first, "/api"));
        assert!(!rl.check(&second, "/api"));
    }
}
