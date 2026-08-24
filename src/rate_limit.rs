use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::time::Instant;
use tracing::warn;

use crate::metrics;

pub struct RateLimiter {
    requests: DashMap<IpAddr, Vec<Instant>>,
    max_requests: u64,
    window_secs: u64,
}

static DEFAULT_MAX: u64 = 100;
static DEFAULT_WINDOW: u64 = 60;

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

        tracing::info!(max_requests, window_secs, "Rate limiter initialized");

        Self {
            requests: DashMap::new(),
            max_requests,
            window_secs,
        }
    }

    /// Returns true if request is allowed, false if rate limited.
    pub fn check(&self, ip: IpAddr, uri: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entry = self.requests.entry(ip).or_insert_with(Vec::new);
        let timestamps = entry.value_mut();

        // Remove expired entries
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
        true
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
}
