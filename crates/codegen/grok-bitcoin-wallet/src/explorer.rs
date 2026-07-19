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
        mut producer: impl FnMut() -> FetchResult,
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

    /// Max HTTP 429 responses to absorb in [`Self::get_or_fetch_blocking`]
    /// (sleeps `wait_hint` / backoff between attempts). After this many 429s,
    /// returns `None` (fail closed). Does not bypass rate gates.
    pub const BLOCKING_MAX_429_RETRIES: u32 = 3;

    /// Block until [`Self::can_fetch`] (sleeps `wait_hint`), then
    /// [`Self::get_or_fetch`]. On HTTP 429, waits out backoff and retries up to
    /// [`Self::BLOCKING_MAX_429_RETRIES`] additional times. Still returns
    /// `None` on hard error or exhausted 429 retries. Never bypasses gates.
    pub fn get_or_fetch_blocking(
        &mut self,
        key: &str,
        mut producer: impl FnMut() -> FetchResult,
    ) -> Option<String> {
        let mut rate_limit_hits = 0u32;
        loop {
            let now = Instant::now();
            if let Some(c) = self.get_cached(key, now) {
                return Some(c.to_owned());
            }
            if let Some(wait) = self.wait_hint(now) {
                std::thread::sleep(wait);
                continue;
            }
            // Snapshot attempt count so we can tell 429 (mark_429) from Error
            // (mark_request) when both return None.
            let attempts_before = self.attempt_count;
            let backoff_before = self.backoff_until;
            match self.get_or_fetch(key, Instant::now(), &mut producer) {
                Some(body) => return Some(body),
                None => {
                    let now = Instant::now();
                    // Cache may have been filled by a concurrent path; re-check.
                    if let Some(c) = self.get_cached(key, now) {
                        return Some(c.to_owned());
                    }
                    let was_429 = self.backoff_until.is_some()
                        && self.backoff_until != backoff_before
                        && self.attempt_count > attempts_before;
                    if was_429 {
                        rate_limit_hits += 1;
                        if rate_limit_hits > Self::BLOCKING_MAX_429_RETRIES {
                            return None;
                        }
                        // Loop: wait_hint will sleep until backoff_until.
                        continue;
                    }
                    // Hard error or still gated without progress — fail closed.
                    return None;
                }
            }
        }
    }

    /// POST-style fetch: respects min-interval + 429 backoff, **never caches**.
    ///
    /// Used for broadcast (`POST /api/tx`) so a prior body is never replayed as
    /// success. When rate-gated, returns `None` without calling `producer`.
    pub fn post_no_cache(
        &mut self,
        now: Instant,
        mut producer: impl FnMut() -> FetchResult,
    ) -> Option<String> {
        if !self.can_fetch(now) {
            return None;
        }
        match producer() {
            FetchResult::Ok(body) => {
                self.mark_request(now);
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

    /// Blocking POST helper with 429 retries (no cache). Same 429 budget as GET.
    pub fn post_no_cache_blocking(
        &mut self,
        mut producer: impl FnMut() -> FetchResult,
    ) -> Option<String> {
        let mut rate_limit_hits = 0u32;
        loop {
            let now = Instant::now();
            if let Some(wait) = self.wait_hint(now) {
                std::thread::sleep(wait);
                continue;
            }
            let attempts_before = self.attempt_count;
            let backoff_before = self.backoff_until;
            match self.post_no_cache(Instant::now(), &mut producer) {
                Some(body) => return Some(body),
                None => {
                    let was_429 = self.backoff_until.is_some()
                        && self.backoff_until != backoff_before
                        && self.attempt_count > attempts_before;
                    if was_429 {
                        rate_limit_hits += 1;
                        if rate_limit_hits > Self::BLOCKING_MAX_429_RETRIES {
                            return None;
                        }
                        continue;
                    }
                    return None;
                }
            }
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

/// REST address UTXO list: `GET /api/address/{addr}/utxo`.
pub fn mempool_api_address_utxo_url(network: BitcoinNetwork, address: &str) -> String {
    format!("{}/utxo", mempool_api_address_url(network, address))
}

/// REST broadcast endpoint: `POST /api/tx` with raw transaction hex body.
///
/// mempool.space returns the txid (64 hex) as plain text on success.
pub fn mempool_api_broadcast_tx_url(network: BitcoinNetwork) -> String {
    format!("{}/api/tx", mempool_base_url(network))
}

/// REST recommended fee rates: `GET /api/v1/fees/recommended` (sat/vB integers).
pub fn mempool_api_fees_recommended_url(network: BitcoinNetwork) -> String {
    format!("{}/api/v1/fees/recommended", mempool_base_url(network))
}

/// mempool.space-shaped recommended fee ladder (all values sat/vB).
///
/// Pure data; product maps a [`FeePriority`] via [`FeeEstimates::rate_sat_vb`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeEstimates {
    pub fastest_sat_vb: u64,
    pub half_hour_sat_vb: u64,
    pub hour_sat_vb: u64,
    pub economy_sat_vb: u64,
    pub minimum_sat_vb: u64,
}

/// Which ladder rung to use when selecting a spend fee rate from estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeePriority {
    /// Next-block target (`fastestFee`).
    Fastest,
    /// ~3 block / half-hour target. Product default when estimates are live.
    #[default]
    HalfHour,
    /// ~6 block / hour target.
    Hour,
    /// Economy / low-priority.
    Economy,
    /// Mempool minimum relay-ish floor from the explorer.
    Minimum,
}

impl FeeEstimates {
    /// Rate for `priority` in sat/vB (may be 0 if the explorer returned 0).
    pub fn rate_sat_vb(&self, priority: FeePriority) -> u64 {
        match priority {
            FeePriority::Fastest => self.fastest_sat_vb,
            FeePriority::HalfHour => self.half_hour_sat_vb,
            FeePriority::Hour => self.hour_sat_vb,
            FeePriority::Economy => self.economy_sat_vb,
            FeePriority::Minimum => self.minimum_sat_vb,
        }
    }
}

/// Parse mempool.space `GET /api/v1/fees/recommended` JSON (offline-testable).
///
/// Expected shape:
/// `{"fastestFee":N,"halfHourFee":N,"hourFee":N,"economyFee":N,"minimumFee":N}`
///
/// All five fields required; non-negative integers. Rejects missing keys and
/// non-object bodies. Does **not** require network.
pub fn parse_mempool_fee_estimates(body: &str) -> std::result::Result<FeeEstimates, String> {
    let v: serde_json::Value = serde_json::from_str(body.trim())
        .map_err(|e| format!("fee estimates JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "fee estimates JSON: expected object".to_owned())?;
    let field = |key: &str| -> std::result::Result<u64, String> {
        let raw = obj
            .get(key)
            .ok_or_else(|| format!("fee estimates JSON: missing {key}"))?;
        if let Some(n) = raw.as_u64() {
            return Ok(n);
        }
        if let Some(n) = raw.as_i64() {
            if n < 0 {
                return Err(format!("fee estimates JSON: {key} must be >= 0"));
            }
            return Ok(n as u64);
        }
        if let Some(s) = raw.as_str() {
            return s
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("fee estimates JSON: {key} not an integer"));
        }
        Err(format!("fee estimates JSON: {key} not an integer"))
    };
    Ok(FeeEstimates {
        fastest_sat_vb: field("fastestFee")?,
        half_hour_sat_vb: field("halfHourFee")?,
        hour_sat_vb: field("hourFee")?,
        economy_sat_vb: field("economyFee")?,
        minimum_sat_vb: field("minimumFee")?,
    })
}

/// Resolve a spend fee rate (sat/vB): user override → estimates → fallback.
///
/// - `user_override` of `Some(0)` is treated as unset (invalid zero rate).
/// - Estimates rate of 0 is ignored (fall through).
/// - Final value is always ≥ 1 (fallback forced to at least 1).
pub fn resolve_spend_fee_rate_sat_vb(
    user_override: Option<u64>,
    estimates: Option<&FeeEstimates>,
    priority: FeePriority,
    fallback_sat_vb: u64,
) -> u64 {
    if let Some(n) = user_override
        && n > 0
    {
        return n;
    }
    if let Some(est) = estimates {
        let r = est.rate_sat_vb(priority);
        if r > 0 {
            return r;
        }
    }
    fallback_sat_vb.max(1)
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

/// Outcome of mapping an HTTP broadcast response (pure; no network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastHttpOutcome {
    /// Explorer accepted the tx; body is a 64-hex txid.
    Accepted { txid: String },
    /// HTTP 429 — retry after rate-limit backoff.
    RateLimited,
    /// Non-success status or unparseable body. Never treat as broadcast success.
    Rejected { status: u16, message: String },
}

/// Bitcoin txid: exactly 64 ASCII hex characters (no `0x` prefix).
pub fn is_valid_txid_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse mempool.space-shaped broadcast response body (plain 64-hex txid).
///
/// Trims whitespace; accepts mixed-case hex and normalizes to lowercase.
pub fn parse_broadcast_txid_body(body: &str) -> std::result::Result<String, String> {
    let t = body.trim();
    if !is_valid_txid_hex(t) {
        let preview: String = t.chars().take(80).collect();
        return Err(format!(
            "broadcast response is not a 64-hex txid (len {}); body starts: {preview:?}",
            t.len()
        ));
    }
    Ok(t.to_ascii_lowercase())
}

/// Map HTTP status + body for `POST /api/tx` (offline-testable).
///
/// Success requires 2xx **and** a parseable txid body. Never claims acceptance
/// from a bare 200 with garbage body.
pub fn broadcast_outcome_from_http(status: u16, body: String) -> BroadcastHttpOutcome {
    if status == 429 {
        return BroadcastHttpOutcome::RateLimited;
    }
    if !(200..300).contains(&status) {
        let preview: String = body.trim().chars().take(120).collect();
        return BroadcastHttpOutcome::Rejected {
            status,
            message: if preview.is_empty() {
                format!("HTTP {status}")
            } else {
                format!("HTTP {status}: {preview}")
            },
        };
    }
    match parse_broadcast_txid_body(&body) {
        Ok(txid) => BroadcastHttpOutcome::Accepted { txid },
        Err(message) => BroadcastHttpOutcome::Rejected { status, message },
    }
}

/// Successful network broadcast result (txid as returned by the explorer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastResult {
    pub txid: String,
}

/// Injectable transaction broadcaster (mempool.space / electrum push / mock).
///
/// Product code must not claim broadcast success without a successful
/// [`BroadcastResult`] from this trait.
pub trait TxBroadcaster {
    /// Submit raw transaction hex (no `0x` prefix). Returns explorer txid.
    fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> crate::error::Result<BroadcastResult>;
}

/// Trim and validate raw transaction hex before any network POST.
///
/// Shared by [`crate::descriptor_wallet::broadcast_raw_tx`] and live
/// [`MempoolHttpClient`] so neither path can bypass empty / non-hex gates.
/// Returns the trimmed hex slice on success.
pub fn validate_raw_tx_hex(raw_tx_hex: &str) -> crate::error::Result<&str> {
    let trimmed = raw_tx_hex.trim();
    if trimmed.is_empty() {
        return Err(crate::error::WalletError::Onchain(
            "cannot broadcast empty transaction hex".into(),
        ));
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) || !trimmed.len().is_multiple_of(2) {
        return Err(crate::error::WalletError::Onchain(
            "transaction hex must be even-length ASCII hex".into(),
        ));
    }
    Ok(trimmed)
}

/// In-memory broadcaster for unit tests (records hex; scripted outcomes).
#[derive(Debug, Default)]
pub struct MockTxBroadcaster {
    /// Scripted results (pop front). Empty → error "mock broadcaster exhausted".
    pub scripted: std::collections::VecDeque<crate::error::Result<BroadcastResult>>,
    /// Last submitted raw hex (for request-construction assertions).
    pub last_raw_hex: Option<String>,
    /// All submitted hex bodies (in order).
    pub submitted: Vec<String>,
}

impl MockTxBroadcaster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Always accept and echo a fixed txid (or derive from a placeholder).
    pub fn always_accept(txid: impl Into<String>) -> Self {
        let mut m = Self::new();
        m.scripted
            .push_back(Ok(BroadcastResult { txid: txid.into() }));
        m
    }

    pub fn push_ok(&mut self, txid: impl Into<String>) {
        self.scripted
            .push_back(Ok(BroadcastResult { txid: txid.into() }));
    }

    pub fn push_err(&mut self, msg: impl Into<String>) {
        self.scripted
            .push_back(Err(crate::error::WalletError::Explorer(msg.into())));
    }
}

impl TxBroadcaster for MockTxBroadcaster {
    fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> crate::error::Result<BroadcastResult> {
        self.last_raw_hex = Some(raw_tx_hex.to_owned());
        self.submitted.push(raw_tx_hex.to_owned());
        self.scripted.pop_front().unwrap_or_else(|| {
            Err(crate::error::WalletError::Explorer(
                "mock broadcaster exhausted (no scripted response)".into(),
            ))
        })
    }
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

    /// Address UTXO list JSON from mempool.space (`/api/address/{addr}/utxo`).
    ///
    /// Always goes through [`RateLimitedExplorer`] gates (no bypass).
    pub fn fetch_address_utxos(&mut self, address: &str) -> Option<String> {
        let url = mempool_api_address_utxo_url(self.network, address);
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

    /// Recommended fee ladder JSON from mempool.space (`/api/v1/fees/recommended`).
    ///
    /// Always goes through [`RateLimitedExplorer`] gates (no bypass). Returns
    /// `None` when gated, rate-limited, or network error — never invents rates.
    pub fn fetch_fees_recommended_json(&mut self) -> Option<String> {
        let url = mempool_api_fees_recommended_url(self.network);
        self.get_text(&url)
    }

    /// Parsed [`FeeEstimates`] from live explorer (or `None` on any failure).
    pub fn fetch_fee_estimates(&mut self) -> Option<FeeEstimates> {
        let body = self.fetch_fees_recommended_json()?;
        parse_mempool_fee_estimates(&body).ok()
    }

    /// Broadcast raw transaction hex via `POST /api/tx`.
    ///
    /// Always goes through [`RateLimitedExplorer`] gates (no cache, no bypass).
    /// Rejects empty / non-hex bodies **before** POST (same gate as
    /// [`crate::descriptor_wallet::broadcast_raw_tx`]).
    /// Returns [`WalletError::Explorer`] on rate-limit exhaustion, network
    /// error, or rejected body — never a success without a parseable txid.
    pub fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> Result<BroadcastResult> {
        let trimmed = validate_raw_tx_hex(raw_tx_hex)?;
        let url = mempool_api_broadcast_tx_url(self.network);
        let client = &self.client;
        let hex_body = trimmed.to_owned();
        // Capture HTTP status for honest error mapping after the rate-limited
        // call (producer only returns FetchResult; stash last status/body).
        let last_status = std::cell::Cell::new(0u16);
        let last_body = std::cell::RefCell::new(String::new());
        let maybe = self.explorer.post_no_cache_blocking(|| {
            match client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .body(hex_body.clone())
                .send()
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    last_status.set(status);
                    *last_body.borrow_mut() = body.clone();
                    fetch_result_from_http(status, body)
                }
                Err(e) => {
                    last_status.set(0);
                    *last_body.borrow_mut() = e.to_string();
                    FetchResult::Error
                }
            }
        });
        match maybe {
            Some(body) => match broadcast_outcome_from_http(200, body) {
                BroadcastHttpOutcome::Accepted { txid } => Ok(BroadcastResult { txid }),
                BroadcastHttpOutcome::Rejected { message, .. } => Err(WalletError::Explorer(
                    format!("broadcast rejected: {message}"),
                )),
                BroadcastHttpOutcome::RateLimited => Err(WalletError::Explorer(
                    "broadcast rate-limited after retries".into(),
                )),
            },
            None => {
                let status = last_status.get();
                let body = last_body.into_inner();
                match broadcast_outcome_from_http(if status == 0 { 503 } else { status }, body) {
                    BroadcastHttpOutcome::RateLimited => Err(WalletError::Explorer(
                        "broadcast rate-limited (or gated) after retries".into(),
                    )),
                    BroadcastHttpOutcome::Rejected { message, .. } => Err(WalletError::Explorer(
                        format!("broadcast failed: {message}"),
                    )),
                    BroadcastHttpOutcome::Accepted { .. } => Err(WalletError::Explorer(
                        "broadcast returned empty after rate-limit gate".into(),
                    )),
                }
            }
        }
    }
}

#[cfg(feature = "explorer-http")]
impl TxBroadcaster for MempoolHttpClient {
    fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> Result<BroadcastResult> {
        MempoolHttpClient::broadcast_raw_tx_hex(self, raw_tx_hex)
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
        let u = mempool_api_address_utxo_url(BitcoinNetwork::Mainnet, "bc1qxyz");
        assert_eq!(u, "https://mempool.space/api/address/bc1qxyz/utxo");
        let u_s = mempool_api_address_utxo_url(BitcoinNetwork::Signet, "tb1qxyz");
        assert_eq!(u_s, "https://mempool.space/signet/api/address/tb1qxyz/utxo");
        let b = mempool_api_broadcast_tx_url(BitcoinNetwork::Mainnet);
        assert_eq!(b, "https://mempool.space/api/tx");
        let b_s = mempool_api_broadcast_tx_url(BitcoinNetwork::Signet);
        assert_eq!(b_s, "https://mempool.space/signet/api/tx");
        let f = mempool_api_fees_recommended_url(BitcoinNetwork::Mainnet);
        assert_eq!(f, "https://mempool.space/api/v1/fees/recommended");
        let f_s = mempool_api_fees_recommended_url(BitcoinNetwork::Signet);
        assert_eq!(f_s, "https://mempool.space/signet/api/v1/fees/recommended");
    }

    #[test]
    fn parse_mempool_fee_estimates_happy_path() {
        let body = r#"{
            "fastestFee": 20,
            "halfHourFee": 15,
            "hourFee": 10,
            "economyFee": 5,
            "minimumFee": 1
        }"#;
        let est = parse_mempool_fee_estimates(body).unwrap();
        assert_eq!(est.fastest_sat_vb, 20);
        assert_eq!(est.half_hour_sat_vb, 15);
        assert_eq!(est.hour_sat_vb, 10);
        assert_eq!(est.economy_sat_vb, 5);
        assert_eq!(est.minimum_sat_vb, 1);
        assert_eq!(est.rate_sat_vb(FeePriority::Fastest), 20);
        assert_eq!(est.rate_sat_vb(FeePriority::HalfHour), 15);
        assert_eq!(est.rate_sat_vb(FeePriority::Hour), 10);
        assert_eq!(est.rate_sat_vb(FeePriority::Economy), 5);
        assert_eq!(est.rate_sat_vb(FeePriority::Minimum), 1);
        assert_eq!(FeePriority::default(), FeePriority::HalfHour);
    }

    #[test]
    fn parse_mempool_fee_estimates_accepts_string_integers() {
        let body = r#"{"fastestFee":"8","halfHourFee":"6","hourFee":"4","economyFee":"2","minimumFee":"1"}"#;
        let est = parse_mempool_fee_estimates(body).unwrap();
        assert_eq!(est.hour_sat_vb, 4);
    }

    #[test]
    fn parse_mempool_fee_estimates_rejects_missing_and_bad_shape() {
        assert!(parse_mempool_fee_estimates("[]").is_err());
        assert!(parse_mempool_fee_estimates("not-json").is_err());
        assert!(
            parse_mempool_fee_estimates(r#"{"fastestFee":1}"#)
                .unwrap_err()
                .contains("missing")
        );
        assert!(
            parse_mempool_fee_estimates(
                r#"{"fastestFee":-1,"halfHourFee":1,"hourFee":1,"economyFee":1,"minimumFee":1}"#
            )
            .is_err()
        );
        assert!(
            parse_mempool_fee_estimates(
                r#"{"fastestFee":"x","halfHourFee":1,"hourFee":1,"economyFee":1,"minimumFee":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_spend_fee_rate_prefers_override_then_estimates_then_fallback() {
        let est = FeeEstimates {
            fastest_sat_vb: 20,
            half_hour_sat_vb: 15,
            hour_sat_vb: 10,
            economy_sat_vb: 5,
            minimum_sat_vb: 1,
        };
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(Some(12), Some(&est), FeePriority::Fastest, 5),
            12
        );
        // Zero override is unset.
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(Some(0), Some(&est), FeePriority::HalfHour, 5),
            15
        );
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(None, Some(&est), FeePriority::Economy, 5),
            5
        );
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(None, None, FeePriority::HalfHour, 7),
            7
        );
        // Fallback of 0 still yields 1.
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(None, None, FeePriority::HalfHour, 0),
            1
        );
        // Zero estimate rate falls through.
        let zero = FeeEstimates {
            fastest_sat_vb: 0,
            half_hour_sat_vb: 0,
            hour_sat_vb: 0,
            economy_sat_vb: 0,
            minimum_sat_vb: 0,
        };
        assert_eq!(
            resolve_spend_fee_rate_sat_vb(None, Some(&zero), FeePriority::Fastest, 9),
            9
        );
    }

    #[test]
    fn validate_raw_tx_hex_rejects_empty_odd_and_non_hex() {
        assert!(
            validate_raw_tx_hex("")
                .unwrap_err()
                .to_string()
                .contains("empty")
        );
        assert!(
            validate_raw_tx_hex("   ")
                .unwrap_err()
                .to_string()
                .contains("empty")
        );
        assert!(
            validate_raw_tx_hex("abc")
                .unwrap_err()
                .to_string()
                .contains("even-length")
        );
        assert!(
            validate_raw_tx_hex("zz")
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase()
                .contains("hex")
        );
        assert_eq!(validate_raw_tx_hex("  deadbeef\n").unwrap(), "deadbeef");
    }

    #[test]
    fn parse_broadcast_txid_body_accepts_hex() {
        let id = "a".repeat(64);
        assert_eq!(parse_broadcast_txid_body(&id).unwrap(), id);
        let upper = "AB".repeat(32);
        assert_eq!(
            parse_broadcast_txid_body(&format!("  {upper}\n")).unwrap(),
            upper.to_ascii_lowercase()
        );
        assert!(parse_broadcast_txid_body("too-short").is_err());
        assert!(parse_broadcast_txid_body(&"g".repeat(64)).is_err());
    }

    #[test]
    fn broadcast_outcome_from_http_maps_status() {
        let id = "b".repeat(64);
        assert_eq!(
            broadcast_outcome_from_http(200, id.clone()),
            BroadcastHttpOutcome::Accepted { txid: id.clone() }
        );
        assert!(matches!(
            broadcast_outcome_from_http(429, "slow".into()),
            BroadcastHttpOutcome::RateLimited
        ));
        assert!(matches!(
            broadcast_outcome_from_http(400, "bad-tx".into()),
            BroadcastHttpOutcome::Rejected { status: 400, .. }
        ));
        // 200 with garbage body must not be Accepted.
        assert!(matches!(
            broadcast_outcome_from_http(200, "not-a-txid".into()),
            BroadcastHttpOutcome::Rejected { status: 200, .. }
        ));
    }

    #[test]
    fn mock_tx_broadcaster_records_hex_and_returns_scripted() {
        let mut mock = MockTxBroadcaster::new();
        mock.push_ok("c".repeat(64));
        let res = mock.broadcast_raw_tx_hex("deadbeef").unwrap();
        assert_eq!(res.txid, "c".repeat(64));
        assert_eq!(mock.last_raw_hex.as_deref(), Some("deadbeef"));
        assert_eq!(mock.submitted, vec!["deadbeef".to_owned()]);
        // Exhausted → error (never silent success).
        let err = mock.broadcast_raw_tx_hex("aa").unwrap_err();
        assert!(err.to_string().contains("exhausted"));
    }

    #[test]
    fn post_no_cache_never_serves_cache_and_respects_rate_limit() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_millis(100),
            cache_ttl: Duration::from_secs(60),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        // Seed a GET cache entry that must not be used by post.
        ex.put_cache("https://mempool.space/api/tx", "cached-wrong", t0);
        let body = ex
            .post_no_cache(t0, || FetchResult::Ok("d".repeat(64)))
            .unwrap();
        assert_eq!(body, "d".repeat(64));
        assert_eq!(ex.attempt_count, 1);
        // Immediate second post blocked by min_interval.
        let mut called = false;
        assert!(
            ex.post_no_cache(t0, || {
                called = true;
                FetchResult::Ok("nope".into())
            })
            .is_none()
        );
        assert!(!called);
    }

    #[test]
    fn post_no_cache_blocking_retries_429() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            cache_ttl: Duration::from_secs(30),
        });
        let mut calls = 0u32;
        let body = ex.post_no_cache_blocking(|| {
            calls += 1;
            if calls == 1 {
                FetchResult::RateLimited
            } else {
                FetchResult::Ok("e".repeat(64))
            }
        });
        assert_eq!(body, Some("e".repeat(64)));
        assert_eq!(calls, 2);
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

    #[test]
    fn get_or_fetch_blocking_retries_after_429() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            cache_ttl: Duration::from_secs(30),
        });
        let mut calls = 0u32;
        let body = ex.get_or_fetch_blocking("retry-key", || {
            calls += 1;
            if calls == 1 {
                FetchResult::RateLimited
            } else {
                FetchResult::Ok(r#"{"ok":true}"#.into())
            }
        });
        assert_eq!(body.as_deref(), Some(r#"{"ok":true}"#));
        assert_eq!(calls, 2, "first 429 then success");
    }

    #[test]
    fn get_or_fetch_blocking_gives_up_after_max_429_retries() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            initial_backoff: Duration::from_millis(2),
            max_backoff: Duration::from_millis(8),
            cache_ttl: Duration::from_secs(30),
        });
        let mut calls = 0u32;
        let body = ex.get_or_fetch_blocking("always-429", || {
            calls += 1;
            FetchResult::RateLimited
        });
        assert!(body.is_none());
        // 1 initial + BLOCKING_MAX_429_RETRIES retries, then give up.
        assert_eq!(
            calls,
            RateLimitedExplorer::BLOCKING_MAX_429_RETRIES + 1,
            "exhausted 429 budget"
        );
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

    /// Live broadcast path shape check: invalid hex must not yield Accepted.
    /// Does not broadcast a real payment. Offline CI must not run this.
    #[test]
    #[ignore = "network: live mempool.space POST /api/tx reject path"]
    #[cfg(feature = "explorer-http")]
    fn live_mempool_broadcast_rejects_invalid_hex() {
        let mut client = MempoolHttpClient::with_defaults(BitcoinNetwork::Signet).unwrap();
        let err = client
            .broadcast_raw_tx_hex("00")
            .expect_err("invalid tx must not be accepted");
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("broadcast") || msg.contains("reject") || msg.contains("fail"),
            "expected honest reject wording: {msg}"
        );
    }
}
