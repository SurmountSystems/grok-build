//! Address / tx watcher that feeds [`crate::cashu::FundingWizard`] confirmations.
//!
//! Default builds stay offline-safe: callers inject a `producer` (or use a
//! pre-seeded [`crate::explorer::RateLimitedExplorer`]). Real HTTP is only via
//! [`crate::explorer::MempoolHttpClient`] behind feature `explorer-http`.
//!
//! **Never** bypasses [`crate::explorer::RateLimitedExplorer`] gates.
//!
//! Multi-URL polls advance the clock (or sleep) between gated fetches so a
//! single logical poll can complete address → tx → tip under default
//! `min_interval` without under-reporting confirmations.

use std::time::{Duration, Instant};

use crate::address_ux::{BitcoinNetwork, mempool_txid_url};
use crate::cashu::{FundingStep, FundingWizard};
use crate::error::Result;
use crate::explorer::{
    FetchResult, RateLimitedExplorer, mempool_api_address_url, mempool_api_tip_height_url,
    mempool_api_tx_url,
};

/// Outcome of one watcher poll (no network implied).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherUpdate {
    /// Address being watched.
    pub address: String,
    /// First seen funding txid, if any.
    pub txid: Option<String>,
    /// Confirmations for `txid` (0 = in mempool / unconfirmed).
    pub confirmations: u32,
    /// Whether tip height was available for confirmed txs.
    pub tip_height: Option<u64>,
    /// Explorer URL for the tx when known.
    pub explorer_tx_url: Option<String>,
    /// True when a needed body was missing because the explorer was still gated
    /// (caller should retry after `wait_hint`). Distinct from "no txs yet".
    pub incomplete: bool,
}

/// Poll target: receive address (+ optional known txid).
#[derive(Debug)]
pub struct AddressWatcher {
    address: String,
    network: BitcoinNetwork,
    /// Known funding txid (set after first detection or by caller).
    txid: Option<String>,
    explorer: RateLimitedExplorer,
}

impl AddressWatcher {
    /// Watch `address` on `network` using a fresh default-rate explorer.
    pub fn new(address: impl Into<String>, network: BitcoinNetwork) -> Self {
        Self::with_explorer(
            address,
            network,
            RateLimitedExplorer::new(crate::explorer::ExplorerConfig::default()),
        )
    }

    /// Inject explorer (tests: short intervals; product: shared client gates).
    pub fn with_explorer(
        address: impl Into<String>,
        network: BitcoinNetwork,
        explorer: RateLimitedExplorer,
    ) -> Self {
        Self {
            address: address.into(),
            network,
            txid: None,
            explorer,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    pub fn txid(&self) -> Option<&str> {
        self.txid.as_deref()
    }

    /// Seed a known txid (e.g. user pasted from wallet broadcast).
    pub fn set_txid(&mut self, txid: impl Into<String>) {
        self.txid = Some(txid.into());
    }

    pub fn explorer(&self) -> &RateLimitedExplorer {
        &self.explorer
    }

    pub fn explorer_mut(&mut self) -> &mut RateLimitedExplorer {
        &mut self.explorer
    }

    /// One poll cycle through rate-limit / cache gates.
    ///
    /// Between distinct URL fetches, advances `now` by at least the explorer
    /// `min_interval` (via `clock_advance`) so a multi-URL cycle can complete
    /// under non-zero product defaults. Unit tests pass `|d| { /* virtual */ }`
    /// without sleeping; product uses [`Self::poll_once_blocking`].
    ///
    /// `producer` receives the full REST URL and must return a [`FetchResult`].
    /// When rate-limited or on error after waits, returns a partial update with
    /// `incomplete: true` rather than under-reporting confirmations as `1`.
    pub fn poll_once_with_clock(
        &mut self,
        mut now: Instant,
        mut clock_advance: impl FnMut(Duration) -> Instant,
        mut producer: impl FnMut(&str) -> FetchResult,
    ) -> WatcherUpdate {
        let mut update = WatcherUpdate {
            address: self.address.clone(),
            txid: self.txid.clone(),
            confirmations: 0,
            tip_height: None,
            explorer_tx_url: self
                .txid
                .as_ref()
                .map(|t| mempool_txid_url(self.network, t)),
            incomplete: false,
        };

        // Discover funding txid from address txs if unknown.
        if self.txid.is_none() {
            let addr_url = format!(
                "{}/txs",
                mempool_api_address_url(self.network, &self.address)
            );
            match self.fetch_url(&addr_url, &mut now, &mut clock_advance, &mut producer) {
                FetchOutcome::Body(body) => {
                    if let Some(txid) = parse_first_txid_from_address_txs(&body) {
                        self.txid = Some(txid.clone());
                        update.txid = Some(txid.clone());
                        update.explorer_tx_url = Some(mempool_txid_url(self.network, &txid));
                    }
                    // Empty txs list is complete "no payment yet".
                }
                FetchOutcome::Gated | FetchOutcome::Failed => {
                    update.incomplete = true;
                    return update;
                }
            }
        }

        let Some(txid) = self.txid.clone() else {
            return update;
        };
        update.txid = Some(txid.clone());
        update.explorer_tx_url = Some(mempool_txid_url(self.network, &txid));

        let tx_url = mempool_api_tx_url(self.network, &txid);
        let tx_body = match self.fetch_url(&tx_url, &mut now, &mut clock_advance, &mut producer) {
            FetchOutcome::Body(body) => body,
            FetchOutcome::Gated | FetchOutcome::Failed => {
                update.incomplete = true;
                return update;
            }
        };

        let status = parse_tx_status(&tx_body);
        if !status.confirmed {
            update.confirmations = 0;
            return update;
        }

        let block_height = match status.block_height {
            Some(h) => h,
            None => {
                // Confirmed without height: treat as at least 1 (complete).
                update.confirmations = 1;
                return update;
            }
        };

        let tip_url = mempool_api_tip_height_url(self.network);
        match self.fetch_url(&tip_url, &mut now, &mut clock_advance, &mut producer) {
            FetchOutcome::Body(body) => match parse_tip_height(&body) {
                Some(tip_h) => {
                    update.tip_height = Some(tip_h);
                    update.confirmations = confirmations_from_heights(tip_h, block_height);
                }
                None => {
                    // Body unusable: do not invent confirmations.
                    update.incomplete = true;
                }
            },
            FetchOutcome::Gated | FetchOutcome::Failed => {
                // Tip missing: leave confirmations at 0 and mark incomplete so
                // callers do not treat "1" as authoritative.
                update.incomplete = true;
            }
        }
        update
    }

    /// Convenience: [`Self::poll_once_with_clock`] with wall-clock sleep.
    pub fn poll_once_blocking(
        &mut self,
        producer: impl FnMut(&str) -> FetchResult,
    ) -> WatcherUpdate {
        self.poll_once_with_clock(
            Instant::now(),
            |d| {
                if !d.is_zero() {
                    std::thread::sleep(d);
                }
                Instant::now()
            },
            producer,
        )
    }

    /// Backward-compatible entry: single `now`, virtual advance by exact wait
    /// (no sleep). Prefer [`Self::poll_once_blocking`] in product code so
    /// multi-URL cycles complete under default `min_interval`.
    pub fn poll_once(
        &mut self,
        now: Instant,
        producer: impl FnMut(&str) -> FetchResult,
    ) -> WatcherUpdate {
        let mut cursor = now;
        self.poll_once_with_clock(
            now,
            |d| {
                cursor += d;
                cursor
            },
            producer,
        )
    }

    /// Fetch one URL: honor cache, wait out interval/backoff via `clock_advance`,
    /// then call producer at most once.
    fn fetch_url(
        &mut self,
        url: &str,
        now: &mut Instant,
        clock_advance: &mut impl FnMut(Duration) -> Instant,
        producer: &mut impl FnMut(&str) -> FetchResult,
    ) -> FetchOutcome {
        // Cache hit needs no network / interval.
        if let Some(c) = self.explorer.get_cached(url, *now) {
            return FetchOutcome::Body(c.to_owned());
        }
        // Wait out min_interval / 429 backoff (virtual or real).
        if let Some(wait) = self.explorer.wait_hint(*now) {
            *now = clock_advance(wait);
        }
        // Re-check cache after wait (another task may have filled it; rare).
        if let Some(c) = self.explorer.get_cached(url, *now) {
            return FetchOutcome::Body(c.to_owned());
        }
        if !self.explorer.can_fetch(*now) {
            // Still gated after wait (e.g. zero advance in a stuck test clock).
            return FetchOutcome::Gated;
        }
        match producer(url) {
            FetchResult::Ok(body) => {
                self.explorer.mark_request(*now);
                self.explorer.put_cache(url, body.clone(), *now);
                FetchOutcome::Body(body)
            }
            FetchResult::RateLimited => {
                self.explorer.mark_429(*now);
                FetchOutcome::Gated
            }
            FetchResult::Error => {
                self.explorer.mark_request(*now);
                FetchOutcome::Failed
            }
        }
    }

    /// Apply a poll result to the funding wizard.
    ///
    /// Incomplete updates (tip gated, etc.) still register a known txid on
    /// `ShowAddress` but do **not** bump confirmations with a guess.
    ///
    /// - `ShowAddress` + txid → [`FundingWizard::watch_tx`] (+ confirmations if complete)
    /// - `WatchingTx` → [`FundingWizard::set_confirmations`] when complete
    /// - Other steps: no-op `Ok(())`
    pub fn apply_to_wizard(update: &WatcherUpdate, wizard: &mut FundingWizard) -> Result<()> {
        match wizard.step {
            FundingStep::ShowAddress => {
                let Some(txid) = update.txid.as_deref() else {
                    return Ok(());
                };
                wizard.watch_tx(txid)?;
                if !update.incomplete {
                    wizard.set_confirmations(update.confirmations)?;
                }
                Ok(())
            }
            FundingStep::WatchingTx => {
                if let Some(txid) = update.txid.as_deref() {
                    if wizard.watched_txid.as_deref() != Some(txid) {
                        return Ok(());
                    }
                }
                if update.incomplete {
                    return Ok(());
                }
                wizard.set_confirmations(update.confirmations)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

enum FetchOutcome {
    Body(String),
    Gated,
    Failed,
}

/// Confirmations given chain tip and the block that included the tx.
///
/// `tip == block_height` → 1 confirmation.
pub fn confirmations_from_heights(tip_height: u64, block_height: u64) -> u32 {
    if tip_height < block_height {
        return 0;
    }
    let c = tip_height - block_height + 1;
    u32::try_from(c).unwrap_or(u32::MAX)
}

/// Parse tip height body (`"840000"` or JSON number).
pub fn parse_tip_height(body: &str) -> Option<u64> {
    let t = body.trim();
    if let Ok(n) = t.parse::<u64>() {
        return Some(n);
    }
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| v.as_str()?.parse().ok())
}

/// mempool.space `/api/tx/{txid}` status slice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

/// Parse confirmations-related fields from a mempool.space tx JSON body.
pub fn parse_tx_status(body: &str) -> TxStatus {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return TxStatus::default();
    };
    let status = v.get("status").unwrap_or(&v);
    let confirmed = status
        .get("confirmed")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let block_height = status.get("block_height").and_then(|h| {
        h.as_u64()
            .or_else(|| h.as_i64().and_then(|i| u64::try_from(i).ok()))
            .or_else(|| h.as_str()?.parse().ok())
    });
    TxStatus {
        confirmed,
        block_height,
    }
}

/// Confirmations from tx JSON + tip height (0 if unconfirmed).
pub fn parse_tx_confirmations(tx_body: &str, tip_height: Option<u64>) -> u32 {
    let status = parse_tx_status(tx_body);
    if !status.confirmed {
        return 0;
    }
    match (status.block_height, tip_height) {
        (Some(bh), Some(tip)) => confirmations_from_heights(tip, bh),
        (Some(_), None) | (None, _) => 1,
    }
}

/// First txid from mempool.space `/api/address/{addr}/txs` JSON array.
pub fn parse_first_txid_from_address_txs(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let arr = v.as_array()?;
    for item in arr {
        if let Some(txid) = item.get("txid").and_then(|t| t.as_str()) {
            let t = txid.trim();
            if !t.is_empty() {
                return Some(t.to_owned());
            }
        }
    }
    None
}

/// Feature-gated helper: one poll using [`crate::explorer::MempoolHttpClient`].
///
/// Uses **only** the client's explorer (single gate). The watcher's explorer is
/// replaced with a zero-interval pass-through so multi-URL orchestration does
/// not double-apply rate limits; real spacing/cache/429 live on the client.
#[cfg(feature = "explorer-http")]
pub fn poll_with_http_client(
    watcher: &mut AddressWatcher,
    client: &mut crate::explorer::MempoolHttpClient,
) -> WatcherUpdate {
    // Pass-through explorer on the watcher: producer (client.get_text) is the
    // sole RateLimitedExplorer. Cache on the client still applies per URL.
    let passthrough = RateLimitedExplorer::new(crate::explorer::ExplorerConfig {
        min_interval: Duration::ZERO,
        cache_ttl: Duration::ZERO,
        ..crate::explorer::ExplorerConfig::default()
    });
    // Swap explorer for this poll so dual gates cannot desync.
    let previous = std::mem::replace(watcher.explorer_mut(), passthrough);
    let update = watcher.poll_once_blocking(|url| match client.get_text(url) {
        Some(body) => FetchResult::Ok(body),
        // Client already applied gates; miss is not a second 429 on watcher.
        None => FetchResult::Error,
    });
    *watcher.explorer_mut() = previous;
    update
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cashu::FundingWizard;
    use crate::explorer::ExplorerConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const ADDR: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fast_explorer() -> RateLimitedExplorer {
        RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            cache_ttl: Duration::from_secs(60),
            ..ExplorerConfig::default()
        })
    }

    fn default_interval_explorer() -> RateLimitedExplorer {
        RateLimitedExplorer::new(ExplorerConfig::default())
    }

    fn producer_full_path(url: &str) -> FetchResult {
        if url.contains("/txs") {
            FetchResult::Ok(format!(
                r#"[{{"txid":"{TXID}","status":{{"confirmed":true,"block_height":100}}}}]"#
            ))
        } else if url.contains(&format!("/tx/{TXID}")) {
            FetchResult::Ok(r#"{"status":{"confirmed":true,"block_height":100}}"#.into())
        } else if url.contains("tip/height") {
            FetchResult::Ok("102".into())
        } else {
            FetchResult::Error
        }
    }

    #[test]
    fn confirmations_math() {
        assert_eq!(confirmations_from_heights(100, 100), 1);
        assert_eq!(confirmations_from_heights(102, 100), 3);
        assert_eq!(confirmations_from_heights(99, 100), 0);
    }

    #[test]
    fn parse_tip_height_plain_and_json() {
        assert_eq!(parse_tip_height("840001\n"), Some(840001));
        assert_eq!(parse_tip_height(" 42 "), Some(42));
        assert_eq!(parse_tip_height("not-a-number"), None);
    }

    #[test]
    fn parse_tx_unconfirmed() {
        let body = r#"{"txid":"aa","status":{"confirmed":false}}"#;
        let s = parse_tx_status(body);
        assert!(!s.confirmed);
        assert_eq!(parse_tx_confirmations(body, Some(100)), 0);
    }

    #[test]
    fn parse_tx_confirmed_with_height() {
        let body = r#"{"status":{"confirmed":true,"block_height":100}}"#;
        assert_eq!(parse_tx_confirmations(body, Some(102)), 3);
        assert_eq!(parse_tx_confirmations(body, None), 1);
    }

    #[test]
    fn parse_address_txs_first_txid() {
        let body =
            format!(r#"[{{"txid":"{TXID}","status":{{"confirmed":false}}}},{{"txid":"bbbb"}}]"#);
        assert_eq!(
            parse_first_txid_from_address_txs(&body).as_deref(),
            Some(TXID)
        );
        assert!(parse_first_txid_from_address_txs("[]").is_none());
        assert!(parse_first_txid_from_address_txs("{}").is_none());
    }

    #[test]
    fn poll_discovers_txid_and_confirmations_via_injected_producer() {
        let mut w = AddressWatcher::with_explorer(ADDR, BitcoinNetwork::Mainnet, fast_explorer());
        let t0 = Instant::now();
        let update = w.poll_once(t0, producer_full_path);
        assert_eq!(update.txid.as_deref(), Some(TXID));
        assert_eq!(update.confirmations, 3);
        assert_eq!(update.tip_height, Some(102));
        assert!(!update.incomplete);
        assert!(
            update
                .explorer_tx_url
                .as_deref()
                .is_some_and(|u| u.contains(TXID))
        );
        assert_eq!(w.txid(), Some(TXID));
        // Cache: second poll must not call producer for same URLs.
        let update2 = w.poll_once(t0 + Duration::from_millis(1), |_url| {
            panic!("cache hit must not call producer");
        });
        assert_eq!(update2.confirmations, 3);
        assert!(!update2.incomplete);
    }

    #[test]
    fn poll_with_default_min_interval_completes_multi_url_via_clock_advance() {
        // Regression for same-Instant multi-fetch under DEFAULT_MIN_INTERVAL.
        let mut w = AddressWatcher::with_explorer(
            ADDR,
            BitcoinNetwork::Mainnet,
            default_interval_explorer(),
        );
        let t0 = Instant::now();
        let mut cursor = t0;
        let calls = AtomicUsize::new(0);
        let update = w.poll_once_with_clock(
            t0,
            |d| {
                // Virtual time: advance from last cursor (not always from t0).
                cursor += d + Duration::from_millis(1);
                cursor
            },
            |url| {
                calls.fetch_add(1, Ordering::SeqCst);
                producer_full_path(url)
            },
        );
        assert_eq!(update.txid.as_deref(), Some(TXID));
        assert_eq!(
            update.confirmations, 3,
            "must not under-report when tip fetch needs a later Instant"
        );
        assert_eq!(update.tip_height, Some(102));
        assert!(!update.incomplete);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "addr + tx + tip");
    }

    #[test]
    fn poll_tip_gated_marks_incomplete_not_fake_one_conf() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_secs(60),
            cache_ttl: Duration::ZERO,
            ..ExplorerConfig::default()
        });
        // Pre-seed address + tx so only tip is needed; then force gate.
        let t0 = Instant::now();
        let addr_url = format!(
            "{}/txs",
            mempool_api_address_url(BitcoinNetwork::Mainnet, ADDR)
        );
        let tx_url = mempool_api_tx_url(BitcoinNetwork::Mainnet, TXID);
        ex.put_cache(&addr_url, format!(r#"[{{"txid":"{TXID}"}}]"#), t0);
        ex.put_cache(
            &tx_url,
            r#"{"status":{"confirmed":true,"block_height":100}}"#,
            t0,
        );
        ex.mark_request(t0); // start interval so tip is gated if clock stuck

        let mut w = AddressWatcher::with_explorer(ADDR, BitcoinNetwork::Mainnet, ex);
        w.set_txid(TXID);
        // Clock that never advances: tip stays gated.
        let update = w.poll_once_with_clock(
            t0,
            |_| t0,
            |_url| {
                panic!("tip producer must not run while gated with stuck clock");
            },
        );
        assert!(update.incomplete);
        assert_eq!(
            update.confirmations, 0,
            "must not report 1 conf when tip is unknown/gated"
        );
        assert!(update.tip_height.is_none());
    }

    #[test]
    fn poll_respects_rate_limit_without_calling_producer_when_clock_stuck() {
        let mut ex = RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::from_secs(10),
            cache_ttl: Duration::from_secs(0),
            ..ExplorerConfig::default()
        });
        let t0 = Instant::now();
        ex.mark_request(t0);
        let mut w = AddressWatcher::with_explorer(ADDR, BitcoinNetwork::Mainnet, ex);
        let mut called = false;
        // Stuck clock: wait_hint asks for advance but we return same Instant.
        let update = w.poll_once_with_clock(
            t0,
            |_| t0,
            |_url| {
                called = true;
                FetchResult::Ok("[]".into())
            },
        );
        assert!(!called);
        assert!(update.incomplete);
        assert!(update.txid.is_none());
        assert_eq!(update.confirmations, 0);
    }

    #[test]
    fn apply_to_wizard_show_address_then_confirmations() {
        let mut wizard = FundingWizard::new();
        wizard.mark_backup_confirmed_for_test();
        wizard.show_address(ADDR).unwrap();

        let update = WatcherUpdate {
            address: ADDR.into(),
            txid: Some(TXID.into()),
            confirmations: 1,
            tip_height: Some(100),
            explorer_tx_url: Some(mempool_txid_url(BitcoinNetwork::Mainnet, TXID)),
            incomplete: false,
        };
        AddressWatcher::apply_to_wizard(&update, &mut wizard).unwrap();
        assert_eq!(wizard.step, FundingStep::WatchingTx);
        assert_eq!(wizard.watched_txid.as_deref(), Some(TXID));
        assert_eq!(wizard.confirmations, 1);

        let update2 = WatcherUpdate {
            confirmations: 3,
            ..update.clone()
        };
        AddressWatcher::apply_to_wizard(&update2, &mut wizard).unwrap();
        assert_eq!(wizard.step, FundingStep::OpenChannel);
        assert_eq!(wizard.confirmations, 3);
    }

    #[test]
    fn apply_incomplete_registers_txid_without_fake_confirmations() {
        let mut wizard = FundingWizard::new();
        wizard.mark_backup_confirmed_for_test();
        wizard.show_address(ADDR).unwrap();
        let update = WatcherUpdate {
            address: ADDR.into(),
            txid: Some(TXID.into()),
            confirmations: 0,
            tip_height: None,
            explorer_tx_url: None,
            incomplete: true,
        };
        AddressWatcher::apply_to_wizard(&update, &mut wizard).unwrap();
        assert_eq!(wizard.step, FundingStep::WatchingTx);
        assert_eq!(wizard.confirmations, 0);
    }

    #[test]
    fn apply_noop_on_need_wallet() {
        let mut wizard = FundingWizard::new();
        let update = WatcherUpdate {
            address: ADDR.into(),
            txid: Some(TXID.into()),
            confirmations: 5,
            tip_height: None,
            explorer_tx_url: None,
            incomplete: false,
        };
        AddressWatcher::apply_to_wizard(&update, &mut wizard).unwrap();
        assert_eq!(wizard.step, FundingStep::NeedWallet);
    }
}

// ── Multi-poll session (pager / long-running product) ───────────────────────

/// How often product UIs should schedule the next poll after a complete tick.
///
/// Respects mempool.space politeness together with [`RateLimitedExplorer`];
/// callers must not spin tighter than this without a user-triggered refresh.
pub const DEFAULT_WATCH_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// One logical watch session: address watcher + funding wizard transitions.
///
/// Designed for pager / TUI background tasks: call [`WatchSession::poll_tick`]
/// with an injected `producer` (tests) or a rate-limited HTTP producer
/// (`explorer-http`). Never bypasses explorer gates.
#[derive(Debug)]
pub struct WatchSession {
    watcher: AddressWatcher,
    wizard: FundingWizard,
    /// Generation / epoch so UI can drop stale ticks after stop/restart.
    generation: u64,
    last_update: Option<WatcherUpdate>,
}

impl WatchSession {
    /// Start watching `address` after backup has already been confirmed and
    /// the receive address is known (CLI fund path already printed it).
    ///
    /// Does **not** touch SeedVault or BIP-39. Callers must only start a
    /// session for an address obtained via the gated fund path.
    pub fn start(
        address: impl Into<String>,
        network: BitcoinNetwork,
        required_confirmations: u32,
    ) -> Self {
        let address = address.into();
        // Watch sessions begin only after fund CLI already enforced backup gates.
        let wizard = FundingWizard::for_watch_after_fund(address.clone(), required_confirmations);
        Self {
            watcher: AddressWatcher::new(address, network),
            wizard,
            generation: 1,
            last_update: None,
        }
    }

    /// Inject explorer (tests: zero interval).
    pub fn start_with_explorer(
        address: impl Into<String>,
        network: BitcoinNetwork,
        explorer: RateLimitedExplorer,
        required_confirmations: u32,
    ) -> Self {
        let address = address.into();
        let wizard = FundingWizard::for_watch_after_fund(address.clone(), required_confirmations);
        Self {
            watcher: AddressWatcher::with_explorer(address, network, explorer),
            wizard,
            generation: 1,
            last_update: None,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Bump generation so in-flight ticks become stale.
    pub fn stop(&mut self) {
        self.generation = self.generation.saturating_add(1);
    }

    pub fn address(&self) -> &str {
        self.watcher.address()
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.watcher.network()
    }

    pub fn wizard(&self) -> &FundingWizard {
        &self.wizard
    }

    pub fn wizard_mut(&mut self) -> &mut FundingWizard {
        &mut self.wizard
    }

    pub fn watcher(&self) -> &AddressWatcher {
        &self.watcher
    }

    pub fn watcher_mut(&mut self) -> &mut AddressWatcher {
        &mut self.watcher
    }

    pub fn last_update(&self) -> Option<&WatcherUpdate> {
        self.last_update.as_ref()
    }

    /// Whether the funding wizard has enough confirmations to leave WatchingTx.
    pub fn is_confirmed_enough(&self) -> bool {
        matches!(
            self.wizard.step,
            FundingStep::OpenChannel
                | FundingStep::AcquireCashu
                | FundingStep::ReadyForInference
                | FundingStep::RefundOptional
        )
    }

    /// One poll tick: fetch via `producer`, apply to wizard, return snapshot.
    pub fn poll_tick(
        &mut self,
        now: Instant,
        producer: impl FnMut(&str) -> FetchResult,
    ) -> Result<WatchTick> {
        let update = self.watcher.poll_once(now, producer);
        AddressWatcher::apply_to_wizard(&update, &mut self.wizard)?;
        self.last_update = Some(update.clone());
        Ok(WatchTick {
            generation: self.generation,
            update,
            step: self.wizard.step,
            required_confirmations: self.wizard.required_confirmations,
            status_line: format_watch_status_line(
                self.wizard.step,
                self.last_update.as_ref().expect("just set"),
                self.wizard.required_confirmations,
            ),
        })
    }

    /// Blocking wall-clock poll (product path with sleep between URLs).
    pub fn poll_tick_blocking(
        &mut self,
        producer: impl FnMut(&str) -> FetchResult,
    ) -> Result<WatchTick> {
        let update = self.watcher.poll_once_blocking(producer);
        AddressWatcher::apply_to_wizard(&update, &mut self.wizard)?;
        self.last_update = Some(update.clone());
        Ok(WatchTick {
            generation: self.generation,
            update,
            step: self.wizard.step,
            required_confirmations: self.wizard.required_confirmations,
            status_line: format_watch_status_line(
                self.wizard.step,
                self.last_update.as_ref().expect("just set"),
                self.wizard.required_confirmations,
            ),
        })
    }
}

/// Snapshot returned after one [`WatchSession`] poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTick {
    pub generation: u64,
    pub update: WatcherUpdate,
    pub step: FundingStep,
    pub required_confirmations: u32,
    /// Short user-facing status (no em dash; "top up" spelling not needed here).
    pub status_line: String,
}

/// Format a single-line watch status for pager footer / system message.
///
/// Incomplete polls never invent confirmation counts.
pub fn format_watch_status_line(
    step: FundingStep,
    update: &WatcherUpdate,
    required: u32,
) -> String {
    let addr_short = shorten_address(&update.address);
    match step {
        FundingStep::ShowAddress => {
            if update.incomplete {
                format!("Watching {addr_short}: explorer busy, retrying")
            } else {
                format!("Watching {addr_short}: waiting for payment")
            }
        }
        FundingStep::WatchingTx => {
            let tx = update
                .txid
                .as_deref()
                .map(shorten_txid)
                .unwrap_or_else(|| "txid?".into());
            if update.incomplete {
                format!("Watching {addr_short}: tx {tx}, confirmations pending (explorer)")
            } else if update.confirmations == 0 {
                format!("Watching {addr_short}: tx {tx} in mempool (0/{required} conf)")
            } else {
                format!(
                    "Watching {addr_short}: tx {tx} {}/{required} confirmations",
                    update.confirmations
                )
            }
        }
        FundingStep::OpenChannel => {
            let tx = update
                .txid
                .as_deref()
                .map(shorten_txid)
                .unwrap_or_else(|| "txid".into());
            format!(
                "Deposit confirmed ({}/{required}). Next: open channel / external top up. tx {tx}",
                update.confirmations.max(required)
            )
        }
        other => format!("Funding: {}", other.user_label()),
    }
}

fn shorten_address(addr: &str) -> String {
    let a = addr.trim();
    if a.chars().count() <= 16 {
        return a.to_owned();
    }
    let prefix: String = a.chars().take(8).collect();
    let suffix: String = a.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{prefix}…{suffix}")
}

fn shorten_txid(txid: &str) -> String {
    let t = txid.trim();
    if t.chars().count() <= 12 {
        return t.to_owned();
    }
    let prefix: String = t.chars().take(6).collect();
    let suffix: String = t.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{prefix}…{suffix}")
}

#[cfg(test)]
mod watch_session_tests {
    use super::*;
    use crate::explorer::ExplorerConfig;

    const ADDR: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fast_ex() -> RateLimitedExplorer {
        RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            cache_ttl: Duration::from_secs(60),
            ..ExplorerConfig::default()
        })
    }

    #[test]
    fn session_waits_then_confirms_with_injected_producer() {
        let mut session =
            WatchSession::start_with_explorer(ADDR, BitcoinNetwork::Mainnet, fast_ex(), 3);
        assert_eq!(session.wizard().step, FundingStep::ShowAddress);

        let t0 = Instant::now();
        // No txs yet.
        let tick = session
            .poll_tick(t0, |url| {
                if url.contains("/txs") {
                    FetchResult::Ok("[]".into())
                } else {
                    FetchResult::Error
                }
            })
            .unwrap();
        assert_eq!(tick.step, FundingStep::ShowAddress);
        assert!(tick.status_line.contains("waiting for payment"));
        assert!(!tick.update.incomplete);

        // Payment appears, unconfirmed.
        let txs = format!(r#"[{{"txid":"{TXID}"}}]"#);
        let tick = session
            .poll_tick(t0 + Duration::from_secs(1), |url| {
                if url.contains("/txs") {
                    FetchResult::Ok(txs.clone())
                } else if url.contains("/tx/") {
                    FetchResult::Ok(r#"{"status":{"confirmed":false}}"#.into())
                } else {
                    FetchResult::Error
                }
            })
            .unwrap();
        assert_eq!(tick.step, FundingStep::WatchingTx);
        assert!(tick.status_line.contains("mempool"));
        assert_eq!(tick.update.confirmations, 0);

        // Confirmed with tip.
        let tick = session
            .poll_tick(t0 + Duration::from_secs(2), |url| {
                if url.contains("/tx/") && !url.contains("/txs") {
                    FetchResult::Ok(
                        r#"{"status":{"confirmed":true,"block_height":100}}"#.into(),
                    )
                } else if url.contains("tip") {
                    FetchResult::Ok("102".into())
                } else {
                    FetchResult::Error
                }
            })
            .unwrap();
        assert_eq!(tick.update.confirmations, 3);
        assert_eq!(tick.step, FundingStep::OpenChannel);
        assert!(session.is_confirmed_enough());
        assert!(tick.status_line.contains("confirmed") || tick.status_line.contains("Deposit"));
    }

    #[test]
    fn incomplete_tick_does_not_fake_confirmations() {
        let mut session =
            WatchSession::start_with_explorer(ADDR, BitcoinNetwork::Mainnet, fast_ex(), 3);
        session.watcher_mut().set_txid(TXID);
        let t0 = Instant::now();
        let tick = session
            .poll_tick(t0, |_url| FetchResult::RateLimited)
            .unwrap();
        assert!(tick.update.incomplete);
        assert_eq!(tick.update.confirmations, 0);
        // Still ShowAddress (txid known on watcher but apply needs non-incomplete
        // path carefully — ShowAddress + txid registers watch even if incomplete).
        assert!(
            tick.step == FundingStep::ShowAddress || tick.step == FundingStep::WatchingTx,
            "step={:?}",
            tick.step
        );
        if tick.step == FundingStep::WatchingTx {
            assert_eq!(session.wizard().confirmations, 0);
        }
    }

    #[test]
    fn stop_bumps_generation() {
        let mut session = WatchSession::start(ADDR, BitcoinNetwork::Mainnet, 3);
        let g = session.generation();
        session.stop();
        assert_eq!(session.generation(), g + 1);
    }

    #[test]
    fn status_line_shortens_ids() {
        let update = WatcherUpdate {
            address: ADDR.into(),
            txid: Some(TXID.into()),
            confirmations: 1,
            tip_height: Some(100),
            explorer_tx_url: None,
            incomplete: false,
        };
        let line = format_watch_status_line(FundingStep::WatchingTx, &update, 3);
        assert!(line.contains("1/3"));
        assert!(!line.contains(TXID), "full txid should be shortened");
        assert!(!line.contains('—'), "no em dash");
    }

    #[test]
    fn default_poll_interval_is_polite() {
        assert!(DEFAULT_WATCH_POLL_INTERVAL >= Duration::from_secs(15));
    }
}
