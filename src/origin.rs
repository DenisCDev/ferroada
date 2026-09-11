//! Origin pool: Pingora load balancing, active/passive health, circuit breaker.
//!
//! A site with one backend keeps the historical `HttpPeer` path (no discovery,
//! no round-robin). Several backends share a `LoadBalancer<RoundRobin>` from
//! `pingora-load-balancing`. Overload sheds 503 after WAF/DLP have already run.

use crate::config::{Backend, Config, OriginEndpoint};
use crate::policy::PolicyStore;
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::http::RequestHeader;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::utils::tls::CertKey;
use pingora_load_balancing::health_check::{HealthCheck, HttpHealthCheck};
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{Backend as LbBackend, LoadBalancer};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const HEALTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const CIRCUIT_OPEN_FOR: Duration = Duration::from_secs(5);
const FAILURES_TO_OPEN: u32 = 1;
const FIRST_HEALTH_WAIT: Duration = Duration::from_secs(5);

pub struct PickedOrigin {
    pub addr: SocketAddr,
    pub host: String,
    pub tls: bool,
    pub mtls: Option<Arc<CertKey>>,
}

impl PickedOrigin {
    pub fn http_peer(&self, connect: Duration, read: Duration, write: Duration) -> HttpPeer {
        let mut peer = HttpPeer::new(self.addr, self.tls, self.host.clone());
        peer.client_cert_key = self.mtls.clone();
        peer.options.connection_timeout = Some(connect);
        peer.options.read_timeout = Some(read);
        peer.options.write_timeout = Some(write);
        peer
    }

    fn from_backend(backend: &Backend) -> Self {
        Self {
            addr: backend.addr,
            host: backend.host.clone(),
            tls: backend.tls,
            mtls: backend.origin_mtls.clone(),
        }
    }

    fn from_endpoint(endpoint: &OriginEndpoint, mtls: Option<Arc<CertKey>>) -> Self {
        Self {
            addr: endpoint.addr,
            host: endpoint.host.clone(),
            tls: endpoint.tls,
            mtls,
        }
    }
}

pub fn method_is_idempotent(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

pub fn extra_retry_budget(configured: u32, balanced: bool) -> u32 {
    let capped = configured.min(3);
    if balanced {
        capped.max(1)
    } else {
        capped
    }
}

pub fn configured_extra_retries() -> u32 {
    std::env::var("MAX_UPSTREAM_RETRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
        .min(3)
}

#[derive(Clone)]
pub struct OriginPools {
    version: Arc<Mutex<String>>,
    sites: Arc<DashMap<String, Arc<SitePool>>>,
}

struct SitePool {
    #[allow(dead_code)]
    lb: Arc<LoadBalancer<RoundRobin>>,
    circuits: Arc<DashMap<SocketAddr, CircuitBreaker>>,
    down: Arc<DashMap<SocketAddr, ()>>,
    cursor: AtomicUsize,
    mtls: Option<Arc<CertKey>>,
    stop: Arc<AtomicBool>,
}

struct TrackingHealth {
    inner: HttpHealthCheck,
    down: Arc<DashMap<SocketAddr, ()>>,
    circuits: Arc<DashMap<SocketAddr, CircuitBreaker>>,
}

#[async_trait]
impl HealthCheck for TrackingHealth {
    async fn check(&self, target: &LbBackend) -> Result<()> {
        let result = self.inner.check(target).await;
        if let Some(addr) = inet_addr(target) {
            let key = canonical_addr(addr);
            if result.is_ok() {
                self.down.remove(&key);
                self.circuits
                    .entry(key)
                    .or_insert_with(CircuitBreaker::new)
                    .on_success();
            } else {
                self.down.insert(key, ());
            }
        }
        result
    }

    fn health_threshold(&self, success: bool) -> usize {
        self.inner.health_threshold(success)
    }
}

impl Drop for SitePool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct CircuitBreaker {
    consecutive_failures: AtomicU32,
    opened_at: Mutex<Option<Instant>>,
    probing: AtomicBool,
    open_for: Duration,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self::with_open_for(CIRCUIT_OPEN_FOR)
    }

    fn with_open_for(open_for: Duration) -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            opened_at: Mutex::new(None),
            probing: AtomicBool::new(false),
            open_for,
        }
    }

    fn allows_traffic(&self) -> bool {
        let opened = self
            .opened_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match *opened {
            None => true,
            Some(at) => at.elapsed() >= self.open_for,
        }
    }

    fn can_send(&self) -> bool {
        let opened = self
            .opened_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match *opened {
            None => true,
            Some(at) if at.elapsed() >= self.open_for => self
                .probing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            Some(_) => false,
        }
    }

    fn on_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.probing.store(false, Ordering::Release);
        *self
            .opened_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = None;
    }

    fn on_failure(&self) {
        self.probing.store(false, Ordering::Release);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= FAILURES_TO_OPEN {
            *self
                .opened_at
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(Instant::now());
        }
    }
}

impl OriginPools {
    pub fn from_policy(policy: &PolicyStore) -> Self {
        let pools = Self {
            version: Arc::new(Mutex::new(String::new())),
            sites: Arc::new(DashMap::new()),
        };
        pools.rebuild(&policy.config(), true);
        if let Ok(mut version) = pools.version.lock() {
            *version = policy.snapshot().policy_version;
        }
        pools
    }

    pub fn sync(&self, policy: &PolicyStore) {
        let next = policy.snapshot().policy_version;
        let mut current = self
            .version
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if *current == next {
            return;
        }
        self.rebuild(&policy.config(), false);
        *current = next;
    }

    fn rebuild(&self, config: &Config, wait_first_health: bool) {
        let mut next = Vec::new();
        for backend in config.all_backends() {
            if !backend.is_balanced() {
                continue;
            }
            match build_pool(backend, wait_first_health) {
                Ok(pool) => {
                    info!(
                        site = %backend.site_scope,
                        origins = backend.origins.len(),
                        health_path = %backend.health_path,
                        "origin pool with health checks"
                    );
                    next.push((backend.site_scope.clone(), pool));
                }
                Err(error) => panic!(
                    "falha a montar o pool de origin para {}: {error}",
                    backend.site_scope
                ),
            }
        }
        self.sites.clear();
        for (scope, pool) in next {
            self.sites.insert(scope, pool);
        }
    }

    pub fn pick(&self, backend: &Backend, tried: &[SocketAddr]) -> Option<PickedOrigin> {
        if !backend.is_balanced() {
            return Some(PickedOrigin::from_backend(backend));
        }
        let pool = self.sites.get(&backend.site_scope)?;
        let n = backend.origins.len();
        if n == 0 {
            return None;
        }
        let start = pool.cursor.fetch_add(1, Ordering::Relaxed);
        for offset in 0..n {
            let origin = &backend.origins[(start + offset) % n];
            if tried
                .iter()
                .any(|addr| canonical_addr(*addr) == canonical_addr(origin.addr))
            {
                continue;
            }
            if pool.is_down(origin.addr) {
                continue;
            }
            if !pool.can_send(origin.addr) {
                continue;
            }
            return Some(PickedOrigin::from_endpoint(origin, pool.mtls.clone()));
        }
        None
    }

    pub fn has_ready(&self, backend: &Backend) -> bool {
        if !backend.is_balanced() {
            return true;
        }
        let Some(pool) = self.sites.get(&backend.site_scope) else {
            return false;
        };
        backend
            .origins
            .iter()
            .any(|origin| !pool.is_down(origin.addr) && pool.circuit_allows(origin.addr))
    }

    pub fn record_success(&self, backend: &Backend, addr: SocketAddr) {
        if let Some(pool) = self.sites.get(&backend.site_scope) {
            pool.circuit_mut(addr).on_success();
        }
    }

    pub fn record_failure(&self, backend: &Backend, addr: SocketAddr) {
        if let Some(pool) = self.sites.get(&backend.site_scope) {
            pool.circuit_mut(addr).on_failure();
            pool.down.insert(canonical_addr(addr), ());
        }
    }
}

impl SitePool {
    fn is_down(&self, addr: SocketAddr) -> bool {
        self.down.contains_key(&canonical_addr(addr))
    }

    fn circuit_allows(&self, addr: SocketAddr) -> bool {
        self.circuits
            .get(&canonical_addr(addr))
            .map(|circuit| circuit.allows_traffic())
            .unwrap_or(true)
    }

    fn can_send(&self, addr: SocketAddr) -> bool {
        self.circuits
            .entry(canonical_addr(addr))
            .or_insert_with(CircuitBreaker::new)
            .can_send()
    }

    fn circuit_mut(
        &self,
        addr: SocketAddr,
    ) -> dashmap::mapref::one::RefMut<'_, SocketAddr, CircuitBreaker> {
        self.circuits
            .entry(canonical_addr(addr))
            .or_insert_with(CircuitBreaker::new)
    }
}

fn build_pool(backend: &Backend, wait_first_health: bool) -> Result<Arc<SitePool>, String> {
    let addrs: Vec<SocketAddr> = backend.origins.iter().map(|origin| origin.addr).collect();
    let down = Arc::new(DashMap::new());
    let circuits = Arc::new(DashMap::new());
    let mut lb = LoadBalancer::<RoundRobin>::try_from_iter(addrs.iter().copied())
        .map_err(|error| format!("load balancer: {error}"))?;
    lb.set_health_check(Box::new(TrackingHealth {
        inner: http_health(backend)?,
        down: Arc::clone(&down),
        circuits: Arc::clone(&circuits),
    }));
    lb.health_check_frequency = Some(HEALTH_INTERVAL);
    let lb = Arc::new(lb);
    let stop = Arc::new(AtomicBool::new(false));
    spawn_health_loop(Arc::clone(&lb), Arc::clone(&stop), wait_first_health);
    Ok(Arc::new(SitePool {
        lb,
        circuits,
        down,
        cursor: AtomicUsize::new(0),
        mtls: backend.origin_mtls.clone(),
        stop,
    }))
}

fn http_health(backend: &Backend) -> Result<HttpHealthCheck, String> {
    let first = backend
        .origins
        .first()
        .ok_or_else(|| "site sem origin".to_string())?;
    let mut hc = HttpHealthCheck::new(&first.host, first.tls);
    let mut req = RequestHeader::build("GET", backend.health_path.as_bytes(), None)
        .map_err(|error| format!("health_path: {error}"))?;
    req.insert_header("Host", &first.host)
        .map_err(|error| format!("health Host: {error}"))?;
    req.insert_header("Connection", "close")
        .map_err(|error| format!("health Connection: {error}"))?;
    hc.req = req;
    hc.peer_template.options.connection_timeout = Some(HEALTH_CONNECT_TIMEOUT);
    hc.peer_template.options.read_timeout = Some(HEALTH_CONNECT_TIMEOUT);
    hc.consecutive_success = 1;
    hc.consecutive_failure = 1;
    hc.reuse_connection = false;
    hc.validator = Some(Box::new(|resp| {
        let status = resp.status.as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Error::e_explain(
                ErrorType::CustomCode("origin health", status),
                "health check",
            )
        }
    }));
    if let Some(mtls) = &backend.origin_mtls {
        hc.peer_template.client_cert_key = Some(Arc::clone(mtls));
    }
    Ok(hc)
}

fn spawn_health_loop(lb: Arc<LoadBalancer<RoundRobin>>, stop: Arc<AtomicBool>, wait_first: bool) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let thread_lb = Arc::clone(&lb);
    let started = std::thread::Builder::new()
        .name("ferroada-origin-health".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    warn!(error = %error, "runtime de health do origin");
                    let _ = ready_tx.send(());
                    return;
                }
            };
            runtime.block_on(async {
                thread_lb.backends().run_health_check(false).await;
                let _ = ready_tx.send(());
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(HEALTH_INTERVAL).await;
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    thread_lb.backends().run_health_check(false).await;
                }
            });
        });
    if let Err(error) = started {
        warn!(error = %error, "thread de health do origin");
        return;
    }
    if wait_first {
        match ready_rx.recv_timeout(FIRST_HEALTH_WAIT) {
            Ok(()) => {}
            Err(_) => warn!("primeiro health check do origin excedeu o prazo"),
        }
    }
}

fn inet_addr(backend: &LbBackend) -> Option<SocketAddr> {
    backend
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(canonical_addr)
}

fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_idempotent_methods_retry() {
        assert!(method_is_idempotent("GET"));
        assert!(method_is_idempotent("HEAD"));
        assert!(method_is_idempotent("OPTIONS"));
        assert!(!method_is_idempotent("POST"));
        assert!(!method_is_idempotent("PATCH"));
        assert!(!method_is_idempotent("PUT"));
        assert!(!method_is_idempotent("DELETE"));
    }

    #[test]
    fn extra_retries_cap_at_three_and_multi_origin_gets_one() {
        assert_eq!(extra_retry_budget(0, false), 0);
        assert_eq!(extra_retry_budget(0, true), 1);
        assert_eq!(extra_retry_budget(9, true), 3);
        assert_eq!(extra_retry_budget(2, false), 2);
    }

    #[test]
    fn circuit_opens_on_failure_and_closes_on_success() {
        let circuit = CircuitBreaker::with_open_for(Duration::from_secs(30));
        assert!(circuit.can_send());
        circuit.on_failure();
        assert!(!circuit.can_send());
        circuit.on_success();
        assert!(circuit.can_send());
    }

    #[test]
    fn circuit_half_open_allows_one_probe() {
        let circuit = CircuitBreaker::with_open_for(Duration::from_millis(1));
        circuit.on_failure();
        std::thread::sleep(Duration::from_millis(5));
        assert!(circuit.can_send());
        assert!(!circuit.can_send());
    }
}
