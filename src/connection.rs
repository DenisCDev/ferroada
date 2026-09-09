use async_trait::async_trait;
use dashmap::DashMap;
use pingora::apps::{HttpServerApp, ServerApp};
use pingora::listeners::ConnectionFilter;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::metrics;
use crate::proxy_protocol::PreTlsProcess;
use pingora::tls::ssl::SslAcceptor;

#[derive(Debug)]
pub struct ConnectionRateFilter {
    attempts: DashMap<IpAddr, VecDeque<Instant>>,
    max_attempts: usize,
    window: Duration,
    max_ips: usize,
    checks: AtomicU64,
    global_attempts: Mutex<VecDeque<Instant>>,
    max_global_attempts: usize,
    connections: Arc<ActiveConnectionState>,
}

impl ConnectionRateFilter {
    pub fn from_env() -> Self {
        Self::new_with_connection_limit(
            env_usize("CONNECTION_RATE_MAX", 60),
            Duration::from_secs(env_u64("CONNECTION_RATE_WINDOW", 1)),
            env_usize("CONNECTION_RATE_MAX_IPS", 50_000),
            env_usize("GLOBAL_CONNECTION_RATE_MAX", 10_000),
            env_usize("MAX_ACTIVE_CONNECTIONS", 10_000),
        )
    }

    pub fn wrap<A>(
        &self,
        inner: A,
        proxy_protocol: bool,
        tls_acceptor: Option<SslAcceptor>,
    ) -> BoundedHttpApp<A> {
        BoundedHttpApp {
            inner: Arc::new(inner),
            connections: Arc::clone(&self.connections),
            proxy_protocol,
            tls_acceptor: tls_acceptor.map(Arc::new),
        }
    }

    #[cfg(test)]
    pub fn for_test(max_active: usize) -> Self {
        Self::new_with_connection_limit(60, Duration::from_secs(1), 50_000, 10_000, max_active)
    }

    #[cfg(test)]
    fn new(
        max_attempts: usize,
        window: Duration,
        max_ips: usize,
        max_global_attempts: usize,
    ) -> Self {
        Self::new_with_connection_limit(
            max_attempts,
            window,
            max_ips,
            max_global_attempts,
            usize::MAX,
        )
    }

    fn new_with_connection_limit(
        max_attempts: usize,
        window: Duration,
        max_ips: usize,
        max_global_attempts: usize,
        max_active_connections: usize,
    ) -> Self {
        Self {
            attempts: DashMap::new(),
            max_attempts: max_attempts.max(1),
            window,
            max_ips: max_ips.max(1),
            checks: AtomicU64::new(0),
            global_attempts: Mutex::new(VecDeque::new()),
            max_global_attempts: max_global_attempts.max(1),
            connections: Arc::new(ActiveConnectionState::new(max_active_connections)),
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let Ok(mut global_attempts) = self.global_attempts.lock() else {
            return false;
        };
        while global_attempts
            .front()
            .is_some_and(|accepted| now.duration_since(*accepted) >= self.window)
        {
            global_attempts.pop_front();
        }
        if global_attempts.len() >= self.max_global_attempts {
            return false;
        }

        if self
            .checks
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(256)
        {
            self.evict_expired();
        }
        if !self.attempts.contains_key(&ip) && self.attempts.len() >= self.max_ips {
            return false;
        }

        let mut attempts = self.attempts.entry(ip).or_default();
        while attempts
            .front()
            .map(|attempt| now.duration_since(*attempt) >= self.window)
            .unwrap_or(false)
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_attempts {
            return false;
        }
        attempts.push_back(now);
        global_attempts.push_back(now);
        true
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            while attempts
                .front()
                .map(|attempt| now.duration_since(*attempt) >= self.window)
                .unwrap_or(false)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
    }
}

#[derive(Debug)]
struct ActiveConnectionState {
    current: AtomicUsize,
    max: usize,
    pending: DashMap<SocketAddr, Instant>,
    pending_ttl: Duration,
}

struct ActiveConnectionGuard {
    state: Arc<ActiveConnectionState>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.state.current.fetch_sub(1, Ordering::Release);
    }
}

impl ActiveConnectionState {
    fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max: max.max(1),
            pending: DashMap::new(),
            // Pingora 0.8 terminates downstream handshakes after 60 seconds.
            pending_ttl: Duration::from_secs(65),
        }
    }

    fn increment(&self) -> bool {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.max).then_some(current + 1)
            })
            .is_ok()
    }

    fn acquire(self: &Arc<Self>) -> Option<ActiveConnectionGuard> {
        self.increment().then(|| ActiveConnectionGuard {
            state: Arc::clone(self),
        })
    }

    fn reserve_pending(self: &Arc<Self>, addr: SocketAddr) -> bool {
        self.evict_expired_pending();
        if !self.increment() {
            return false;
        }
        if self.pending.insert(addr, Instant::now()).is_some() {
            self.current.fetch_sub(1, Ordering::AcqRel);
        }
        true
    }

    fn activate(self: &Arc<Self>, addr: Option<SocketAddr>) -> Option<ActiveConnectionGuard> {
        self.evict_expired_pending();
        if addr.is_some_and(|addr| self.pending.remove(&addr).is_some()) {
            return Some(ActiveConnectionGuard {
                state: Arc::clone(self),
            });
        }
        self.acquire()
    }

    fn evict_expired_pending(&self) {
        let now = Instant::now();
        self.pending.retain(|_, accepted| {
            let keep = now.duration_since(*accepted) < self.pending_ttl;
            if !keep {
                self.current.fetch_sub(1, Ordering::AcqRel);
            }
            keep
        });
    }
}

pub struct BoundedHttpApp<A> {
    inner: Arc<A>,
    connections: Arc<ActiveConnectionState>,
    proxy_protocol: bool,
    /// When set, PROXY v2 is consumed first ([`PreTlsProcess`]) and then we
    /// handshake. Pingora 0.8.1 `add_tls` handshakes before `process_new`.
    tls_acceptor: Option<Arc<SslAcceptor>>,
}

#[async_trait]
impl<A> ServerApp for BoundedHttpApp<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        mut stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // Pending reservation is keyed by the TCP peer from should_accept.
        // PROXY rewrite must not run before activate, or the slot is leaked
        // and MAX_ACTIVE_CONNECTIONS=1 drops the happy path.
        let tcp_peer = stream
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().cloned());
        let tcp_inet = tcp_peer.as_ref().and_then(|addr| addr.as_inet().copied());
        let tcp_peer_label = tcp_peer
            .as_ref()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let Some(_guard) = self.connections.activate(tcp_inet) else {
            metrics::record_block(
                "connection_limit",
                &tcp_peer_label,
                "/",
                "Maximum active downstream connections reached",
            );
            return None;
        };
        if self.proxy_protocol {
            if let Err(error) = PreTlsProcess.process(&mut stream).await {
                metrics::record_block("proxy_protocol", &tcp_peer_label, "/", error.as_str());
                tracing::warn!(peer = %tcp_peer_label, reason = error.as_str(), "conexão recusada: PROXY protocol v2");
                return None;
            }
        }
        if let Some(acceptor) = self.tls_acceptor.as_ref() {
            let l4 = match pingora::protocols::IO::into_any(stream)
                .downcast::<pingora::protocols::l4::stream::Stream>()
            {
                Ok(l4) => *l4,
                Err(_) => {
                    tracing::warn!("PreTlsProcess: stream não é TCP claro");
                    return None;
                }
            };
            match tokio::time::timeout(
                Duration::from_secs(60),
                pingora::protocols::tls::server::handshake(acceptor.as_ref(), l4),
            )
            .await
            {
                Ok(Ok(tls)) => stream = Box::new(tls),
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "TLS handshake falhou após PROXY v2");
                    return None;
                }
                Err(_) => {
                    tracing::warn!("TLS handshake esgotou 60s após PROXY v2");
                    return None;
                }
            }
        }
        ServerApp::process_new(&self.inner, stream, shutdown).await
    }

    async fn cleanup(&self) {
        ServerApp::cleanup(self.inner.as_ref()).await;
    }
}

#[async_trait]
impl ConnectionFilter for ConnectionRateFilter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        let Some(addr) = addr else {
            return false;
        };
        let ip = addr.ip();
        if !self.check(ip) {
            metrics::record_block(
                "connection_limit",
                &ip.to_string(),
                "/",
                "Connection attempt rate exceeded",
            );
            return false;
        }
        if !self.connections.reserve_pending(*addr) {
            metrics::record_block(
                "connection_limit",
                &ip.to_string(),
                "/",
                "Maximum active downstream connections reached",
            );
            return false;
        }
        true
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_attempts_are_limited_before_http_parsing() {
        let filter = ConnectionRateFilter::new(2, Duration::from_secs(60), 10, 100);
        let ip = "203.0.113.10".parse().unwrap();
        assert!(filter.check(ip));
        assert!(filter.check(ip));
        assert!(!filter.check(ip));
    }

    #[test]
    fn identity_map_is_bounded() {
        let filter = ConnectionRateFilter::new(2, Duration::from_secs(60), 1, 100);
        assert!(filter.check("203.0.113.10".parse().unwrap()));
        assert!(!filter.check("203.0.113.11".parse().unwrap()));
    }

    #[test]
    fn connection_attempt_window_has_a_global_cap() {
        let filter = ConnectionRateFilter::new(10, Duration::from_secs(60), 10, 2);
        assert!(filter.check("203.0.113.10".parse().unwrap()));
        assert!(filter.check("203.0.113.11".parse().unwrap()));
        assert!(!filter.check("203.0.113.12".parse().unwrap()));
    }

    #[test]
    fn active_connection_limit_covers_handshake_and_releases_on_close() {
        let state = Arc::new(ActiveConnectionState::new(1));
        let first = "203.0.113.10:1234".parse().unwrap();
        let second = "203.0.113.11:1234".parse().unwrap();
        assert!(state.reserve_pending(first));
        assert!(!state.reserve_pending(second));
        let guard = state.activate(Some(first)).expect("handshake is activated");
        assert!(!state.reserve_pending(second));
        drop(guard);
        assert!(state.reserve_pending(second));
    }
}
