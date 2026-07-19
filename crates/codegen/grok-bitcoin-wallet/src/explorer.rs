//! Rate-limited explorer client (mempool.space shaped).
//!
//! Unit-testable without network: inject clock + record of fetches.
//! Optional real HTTP via feature `explorer-http` (reqwest blocking).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::address_ux::{BitcoinNetwork, mempool_address_url, mempool_base_url, mempool_txid_url};

#[cfg(feature = "explorer-http")]
use crate::error::{Result, WalletError};

/// Default minimum interval between outbound explorer requests.
pub const DEFAULT_MIN_INTERVAL: Duration = Duration::from_millis(350);

/// Default cache TTL for address/tx JSON bodies.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

/// Initial backoff after HTTP 429.
pub const DEFAULT_429_BACKOFF: Duration = Duration::from_secs(5);

/// Configuration for [`RateLimitedExplorer`].
#[derive(Debug, Clone)]
pub struct ExplorerConfig {
    pub min_interval: Duration,
    pub cache_ttl: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        Self {
            min_interval: DEFAULT_MIN_INTERVAL,
            cache_ttl: DEFAULT_CACHE_TTL,
            initial_backoff: DEFAULT_429_BACKOFF,
            max_backoff: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    body: String,
    stored_at: Instant,
}

/// In-memory rate-limited fetcher. Does not perform real HTTP by default;
/// callers supply a `fetch_fn` or use [`RateLimitedExplorer::get_or_fetch`].
/// With feature `explorer-http`, see [`MempoolHttpClient`].
#[derive(Debug)]
pub struct RateLimitedExplorer {
    cfg: ExplorerConfig,
    last_request: Option<Instant>,
    backoff_until: Option<Instant>,
    current_backoff: Duration,
    cache: HashMap<String, CacheEntry>,
    /// Outbound attempt count (for tests).
    pub attempt_count: u64,
}

impl RateLimitedExplorer {
    pub fn new(cfg: ExplorerConfig) -> Self {
        Self {
            current_backoff: cfg.initial_backoff,
            cfg,
            last_request: None,
            backoff_until: None,
            cache: HashMap::new(),
            attempt_count: 0,
        }
    }

    /// Whether a live fetch is allowed at `now` (respects min interval + backoff).
    pub fn can_fetch(&self, now: Instant) -> bool {
        if let Some(until) = self.backoff_until
            && now < until
        {
            return false;
        }
        if let Some(last) = self.last_request
            && now.duration_since(last) < self.cfg.min_interval
        {
            return false;
        }
        true
    }

    /// Time until next allowed fetch, if currently blocked.
    pub fn wait_hint(&self, now: Instant) -> Option<Duration> {
        let mut wait = Duration::ZERO;
        if let Some(until) = self.backoff_until
            && now < until
        {
            wait = wait.max(until.saturating_duration_since(now));
        }
        if let Some(last) = self.last_request {
            let elapsed = now.duration_since(last);
            if elapsed < self.cfg.min_interval {
                wait = wait.max(self.cfg.min_interval - elapsed);
            }
        }
        if wait.is_zero() { None } else { Some(wait) }
    }

    /// Cached body if present and fresh.
    pub fn get_cached(&self, key: &str, now: Instant) -> Option<&str> {
        let e = self.cache.get(key)?;
        if now.duration_since(e.stored_at) > self.cfg.cache_ttl {
            return None;
        }
        Some(e.body.as_str())
    }

    /// Insert/replace cache entry (e.g. after successful HTTP).
    pub fn put_cache(&mut self, key: impl Into<String>, body: impl Into<String>, now: Instant) {
        self.cache.insert(
            key.into(),
            CacheEntry {
                body: body.into(),
                stored_at: now,
            },
        );
    }

    /// Record a successful fetch timing (marks interval).
    pub fn mark_request(&mut self, now: Instant) {
        self.attempt_count += 1;
        self.last_request = Some(now);
        // Successful traffic shrinks backoff toward initial.
        self.current_backoff = self.cfg.initial_backoff;
        self.backoff_until = None;
    }

    /// Record HTTP 429 and apply exponential backoff.
    pub fn mark_429(&mut self, now: Instant) {
        self.attempt_count += 1;
        self.last_request = Some(now);
        self.backoff_until = Some(now + self.current_backoff);
        self.current_backoff = (self.current_backoff * 2).min(self.cfg.max_backoff);
    }

    /// Fetch-or-cache helper: uses `producer` only when allowed and miss.
    ///
    /// Never bypasses rate limits: when blocked, returns `None` without calling
    /// `producer`.
    pub fn get_or_fetch(
        &mut self,
        key: &str,
        now: Instant,
        producer: impl FnOnce() -> FetchResult,
    ) -> Option<String> {
        if let Some(c) = self.get_cached(key, now) {
            return Some(c.to_owned());
        }
        if !self.can_fetch(now) {
            return None;
        }
        match producer() {
            FetchResult::Ok(body) => {
                self.mark_request(now);
                self.put_cache(key, body.clone(), now);
                Some(body)
            }
            FetchResult::RateLimited => {
                self.mark_429(now);
                None
            }
            FetchResult::Error => {
                self.mark_request(now);
                None
            }
        }
    }

    /// Block until [`Self::can_fetch`] (sleeps `wait_hint`), then
    /// [`Self::get_or_fetch`]. Still returns `None` on 429 / error.
    pub fn get_or_fetch_blocking(
        &mut self,
        key: &str,
        producer: impl FnOnce() -> FetchResult,
    ) -> Option<String> {
        loop {
            let now = Instant::now();
            if let Some(c) = self.get_cached(key, now) {
                return Some(c.to_owned());
            }
            if let Some(wait) = self.wait_hint(now) {
                std::thread::sleep(wait);
                continue;
            }
            return self.get_or_fetch(key, Instant::now(), producer);
        }
    }
}

/// Simulated / mapped HTTP outcome (no network required for unit tests).
#[derive(Debug, Clone)]
pub enum FetchResult {
    Ok(String),
    RateLimited,
    Error,
}

/// Build mempool.space REST paths (JSON APIs under the same base as browser URLs).
pub fn mempool_api_address_url(network: BitcoinNetwork, address: &str) -> String {
    // Browser helper is `/address/{addr}`; REST is `/api/address/{addr}`.
    let page = mempool_address_url(network, address);
    page.replacen("/address/", "/api/address/", 1)
}

/// REST tx endpoint.
pub fn mempool_api_tx_url(network: BitcoinNetwork, txid: &str) -> String {
    let page = mempool_txid_url(network, txid);
    page.replacen("/tx/", "/api/tx/", 1)
}

/// REST tip height (cheap health probe).
pub fn mempool_api_tip_height_url(network: BitcoinNetwork) -> String {
    format!("{}/api/blocks/tip/height", mempool_base_url(network))
}

/// Map HTTP status + body into a [`FetchResult`] (shared by real client + tests).
pub fn fetch_result_from_http(status: u16, body: String) -> FetchResult {
    if status == 429 {
        return FetchResult::RateLimited;
    }
    if (200..300).contains(&status) {
        return FetchResult::Ok(body);
    }
    FetchResult::Error
}

/// HTTP client that always goes through [`RateLimitedExplorer`] gates.
///
/// Enabled with feature `explorer-http`. Default CI builds stay offline-safe.
#[cfg(feature = "explorer-http")]
#[derive(Debug)]
pub struct MempoolHttpClient {
    explorer: RateLimitedExplorer,
    network: BitcoinNetwork,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "explorer-http")]
impl MempoolHttpClient {
    pub fn new(network: BitcoinNetwork, cfg: ExplorerConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!(
                "grok-bitcoin-wallet/",
                env!("CARGO_PKG_VERSION"),
                " (Routstr; +https://github.com/SurmountSystems/grok-oss)"
            ))
            .build()
            .map_err(|e| WalletError::Explorer(format!("http client: {e}")))?;
        Ok(Self {
            explorer: RateLimitedExplorer::new(cfg),
            network,
            client,
        })
    }

    pub fn with_defaults(network: BitcoinNetwork) -> Result<Self> {
        Self::new(network, ExplorerConfig::default())
    }

    pub fn explorer(&self) -> &RateLimitedExplorer {
        &self.explorer
    }

    pub fn explorer_mut(&mut self) -> &mut RateLimitedExplorer {
        &mut self.explorer
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// GET `url` through rate-limit / cache gates. Cache key is the full URL.
    pub fn get_text(&mut self, url: &str) -> Option<String> {
        let client = &self.client;
        self.explorer
            .get_or_fetch_blocking(url, || match client.get(url).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    fetch_result_from_http(status, body)
                }
                Err(_) => FetchResult::Error,
            })
    }

    /// Address UTXO / chain stats JSON from mempool.space.
    pub fn fetch_address(&mut self, address: &str) -> Option<String> {
        let url = mempool_api_address_url(self.network, address);
        self.get_text(&url)
    }

    /// Transaction JSON from mempool.space.
    pub fn fetch_tx(&mut self, txid: &str) -> Option<String> {
        let url = mempool_api_tx_url(self.network, txid);
        self.get_text(&url)
    }

    /// Tip height (string body, decimal).
    pub fn fetch_tip_height(&mut self) -> Option<String> {
        let url = mempool_api_tip_height_url(self.network);
        self.get_text(&url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_interval_blocks_rapid_fetches() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_millis(100),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        let body = ex
            .get_or_fetch("addr", t0, || FetchResult::Ok("{}".into()))
            .unwrap();
        assert_eq!(body, "{}");
        assert_eq!(ex.attempt_count, 1);
        // Immediate retry blocked.
        assert!(
            ex.get_or_fetch("other", t0, || FetchResult::Ok("x".into()))
                .is_none()
        );
        assert_eq!(ex.attempt_count, 1);
        // After interval, allowed.
        let t1 = t0 + Duration::from_millis(100);
        assert!(
            ex.get_or_fetch("other", t1, || FetchResult::Ok("x".into()))
                .is_some()
        );
        assert_eq!(ex.attempt_count, 2);
    }

    #[test]
    fn cache_ttl_serves_without_fetch() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_secs(0),
            cache_ttl: Duration::from_secs(10),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        ex.get_or_fetch("k", t0, || FetchResult::Ok("cached".into()))
            .unwrap();
        let t1 = t0 + Duration::from_millis(1);
        let again = ex
            .get_or_fetch("k", t1, || panic!("must not fetch"))
            .unwrap();
        assert_eq!(again, "cached");
        assert_eq!(ex.attempt_count, 1);
    }

    #[test]
    fn backoff_on_429() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(8),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        assert!(
            ex.get_or_fetch("k", t0, || FetchResult::RateLimited)
                .is_none()
        );
        assert!(!ex.can_fetch(t0 + Duration::from_secs(1)));
        assert!(ex.can_fetch(t0 + Duration::from_secs(2)));
        // Second 429 doubles backoff.
        ex.get_or_fetch("k", t0 + Duration::from_secs(2), || {
            FetchResult::RateLimited
        });
        assert!(!ex.can_fetch(t0 + Duration::from_secs(5))); // still in 4s backoff from t+2
        assert!(ex.can_fetch(t0 + Duration::from_secs(6)));
    }

    #[test]
    fn wait_hint_reports_remaining() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_millis(50),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        ex.mark_request(t0);
        let hint = ex.wait_hint(t0).unwrap();
        assert!(hint <= Duration::from_millis(50));
        assert!(hint > Duration::ZERO);
    }

    #[test]
    fn fetch_result_from_http_maps_status() {
        assert!(matches!(
            fetch_result_from_http(200, "ok".into()),
            FetchResult::Ok(b) if b == "ok"
        ));
        assert!(matches!(
            fetch_result_from_http(429, "slow".into()),
            FetchResult::RateLimited
        ));
        assert!(matches!(
            fetch_result_from_http(500, "err".into()),
            FetchResult::Error
        ));
    }

    #[test]
    fn api_urls_use_mempool_api_prefix() {
        let a = mempool_api_address_url(BitcoinNetwork::Mainnet, "bc1qxyz");
        assert_eq!(a, "https://mempool.space/api/address/bc1qxyz");
        let t = mempool_api_tx_url(BitcoinNetwork::Signet, "abcd");
        assert_eq!(t, "https://mempool.space/signet/api/tx/abcd");
        let h = mempool_api_tip_height_url(BitcoinNetwork::Mainnet);
        assert_eq!(h, "https://mempool.space/api/blocks/tip/height");
    }

    #[test]
    fn get_or_fetch_never_calls_producer_while_rate_limited() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_secs(10),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        ex.mark_request(t0);
        let mut called = false;
        assert!(
            ex.get_or_fetch("k", t0, || {
                called = true;
                FetchResult::Ok("nope".into())
            })
            .is_none()
        );
        assert!(!called);
    }

    /// Live mempool.space tip-height probe. Offline CI must not run this.
    #[test]
    #[ignore = "network: live mempool.space GET"]
    #[cfg(feature = "explorer-http")]
    fn live_mempool_tip_height() {
        let mut client = MempoolHttpClient::with_defaults(BitcoinNetwork::Mainnet).unwrap();
        let body = client
            .fetch_tip_height()
            .expect("tip height body from mempool.space");
        let height: u64 = body.trim().parse().expect("decimal tip height");
        assert!(
            height > 800_000,
            "mainnet tip should be past 800k, got {height}"
        );
        // Second call within cache TTL must not bump attempt if cached...
        // tip height URL is cached after first success.
        let attempts_after = client.explorer().attempt_count;
        let again = client.fetch_tip_height().expect("cached tip");
        assert_eq!(again, body);
        assert_eq!(
            client.explorer().attempt_count,
            attempts_after,
            "cache hit must not mark another request"
        );
    }
}
