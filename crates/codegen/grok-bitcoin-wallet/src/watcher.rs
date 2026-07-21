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
//!
//! ## Persistence
//!
//! [`WatchSessionState`] can be serialized to disk so a deposit watch survives
//! pager process restarts. The file holds **only** address / network / txid /
//! confirmation progress — **never** BIP-39 mnemonic, BIP-39 passphrase, or
//! other seed material. SeedVault must not use this path
//! ([`crate::seed_vault::assert_allowed_seed_storage_path`]).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::address_ux::{BitcoinNetwork, mempool_txid_url};
use crate::cashu::{FundingStep, FundingWizard};
use crate::error::{Result, WalletError};
use crate::explorer::{
    FetchResult, RateLimitedExplorer, mempool_api_address_url, mempool_api_tip_height_url,
    mempool_api_tx_url,
};

/// On-disk format version for [`WatchSessionState`].
pub const WATCH_SESSION_FORMAT_VERSION: u32 = 1;

/// Relative path under grok home: `bitcoin/watch_session.json`.
pub const WATCH_SESSION_REL_PATH: &str = "bitcoin/watch_session.json";

/// Default durable path: `{grok_home}/bitcoin/watch_session.json`.
///
/// No BIP-39 — only watch progress (address / txid / confirmations).
pub fn default_watch_session_path(grok_home: impl AsRef<Path>) -> PathBuf {
    grok_home.as_ref().join(WATCH_SESSION_REL_PATH)
}

/// Durable watch progress for resume after process restart.
///
/// **Invariant:** never contains seed material, recovery phrases, or vault
/// secrets. Safe to write as world-unreadable JSON under grok home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchSessionState {
    /// Format version ([`WATCH_SESSION_FORMAT_VERSION`]).
    pub version: u32,
    /// Receive address being watched (no secrets).
    pub address: String,
    /// Canonical network wire string (`mainnet`, `signet`, …).
    pub network: String,
    /// Confirmations required to leave WatchingTx.
    pub required_confirmations: u32,
    /// Known funding txid when discovered.
    pub watched_txid: Option<String>,
    /// Last observed confirmation count for `watched_txid`.
    pub confirmations: u32,
    /// Funding wizard step wire name ([`FundingStep::as_wire_str`]).
    pub step: String,
    /// Session generation at last persist (product may re-bump on reload).
    pub generation: u64,
    /// Whether the watch is considered running (false after stop / confirmed).
    pub running: bool,
    /// Unix seconds when last written (informational).
    pub updated_unix_secs: u64,
}

impl WatchSessionState {
    /// Validate wire fields and reject seed-looking payloads.
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 || self.version > WATCH_SESSION_FORMAT_VERSION {
            return Err(WalletError::Onchain(format!(
                "unsupported watch session version {}",
                self.version
            )));
        }
        let address = self.address.trim();
        if address.is_empty() {
            return Err(WalletError::Onchain(
                "watch session address is empty".into(),
            ));
        }
        // Hard reject: never persist / load BIP-39-shaped blobs here.
        if looks_like_bip39_phrase(address) {
            return Err(WalletError::Onchain(
                "watch session must not contain BIP-39 material".into(),
            ));
        }
        if BitcoinNetwork::from_env_str(&self.network).is_none() {
            return Err(WalletError::Onchain(format!(
                "watch session unknown network {:?}",
                self.network
            )));
        }
        if FundingStep::from_wire_str(&self.step).is_none() {
            return Err(WalletError::Onchain(format!(
                "watch session unknown step {:?}",
                self.step
            )));
        }
        if let Some(txid) = self.watched_txid.as_deref() {
            let t = txid.trim();
            if t.is_empty() || looks_like_bip39_phrase(t) {
                return Err(WalletError::Onchain(
                    "watch session txid invalid or looks like seed material".into(),
                ));
            }
        }
        Ok(())
    }

    /// True when a process restart should re-arm the watch loop.
    pub fn should_resume(&self) -> bool {
        self.running
            && !self.address.trim().is_empty()
            && FundingStep::from_wire_str(&self.step)
                .is_some_and(|s| matches!(s, FundingStep::ShowAddress | FundingStep::WatchingTx))
    }
}

fn looks_like_bip39_phrase(s: &str) -> bool {
    let words: Vec<&str> = s.split_whitespace().collect();
    (words.len() == 12 || words.len() == 24)
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_lowercase()))
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load watch session state from `path`. Missing file → `Ok(None)`.
pub fn load_watch_session_state(path: &Path) -> Result<Option<WatchSessionState>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)
        .map_err(|e| WalletError::Onchain(format!("read watch session {}: {e}", path.display())))?;
    let state: WatchSessionState = serde_json::from_slice(&bytes).map_err(|e| {
        WalletError::Onchain(format!("parse watch session {}: {e}", path.display()))
    })?;
    state.validate()?;
    // Defense in depth: reject if any string field looks like BIP-39.
    if looks_like_bip39_phrase(&state.address)
        || state
            .watched_txid
            .as_deref()
            .is_some_and(looks_like_bip39_phrase)
    {
        return Err(WalletError::Onchain(
            "watch session rejected: BIP-39-shaped field".into(),
        ));
    }
    Ok(Some(state))
}

/// Atomically write watch session state (mode 0600 on Unix).
pub fn save_watch_session_state(path: &Path, state: &WatchSessionState) -> Result<()> {
    state.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            WalletError::Onchain(format!(
                "create watch session dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    let mut to_write = state.clone();
    to_write.updated_unix_secs = unix_secs_now();
    let json = serde_json::to_vec_pretty(&to_write)
        .map_err(|e| WalletError::Onchain(format!("serialize watch session: {e}")))?;
    write_watch_file_atomic(path, &json)
}

/// Remove persisted watch session if present (stop / confirmed).
pub fn clear_watch_session_state(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| {
            WalletError::Onchain(format!("remove watch session {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

/// Stop a durable watch so it will not resume after process restart.
///
/// Prefer unlinking the file. If remove fails (permissions, busy FS, etc.),
/// fall back to writing `running: false` so [`WatchSessionState::should_resume`]
/// is false and the next pager start cannot re-arm a user-stopped watch.
pub fn stop_watch_session_state(path: &Path) -> Result<()> {
    match clear_watch_session_state(path) {
        Ok(()) => Ok(()),
        Err(clear_err) => match load_watch_session_state(path) {
            Ok(Some(mut state)) => {
                state.running = false;
                save_watch_session_state(path, &state).map_err(|save_err| {
                    WalletError::Onchain(format!(
                        "stop watch session: clear failed ({clear_err}); \
                         write running=false also failed: {save_err}"
                    ))
                })
            }
            Ok(None) => Ok(()), // already gone
            Err(load_err) => Err(WalletError::Onchain(format!(
                "stop watch session: clear failed ({clear_err}); \
                 load for running=false also failed: {load_err}"
            ))),
        },
    }
}

fn write_watch_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "watch_session.json".into());
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| WalletError::Onchain(format!("create watch temp: {e}")))?
        };
        #[cfg(not(unix))]
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| WalletError::Onchain(format!("create watch temp: {e}")))?;

        file.write_all(bytes)
            .map_err(|e| WalletError::Onchain(format!("write watch temp: {e}")))?;
        file.sync_all()
            .map_err(|e| WalletError::Onchain(format!("fsync watch temp: {e}")))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        WalletError::Onchain(format!("rename watch session: {e}"))
    })?;
    Ok(())
}

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

/// Pure lifecycle for a pager / TUI background watch task.
///
/// Holds no explorer handles; product code owns a [`WatchSession`] and uses this
/// to decide whether an async poll result is still current after stop/restart.
///
/// **Product wiring:** the pager currently mirrors these generation/running/
/// address rules on `AppView` fields (`routstr_watch_generation`,
/// `routstr_watch_address`, …) via `dispatch/routstr.rs` helpers
/// (`start_routstr_watch_for_agent`, `watch_tick_accepts`). Keep those in sync
/// with [`WatchTaskLifecycle::start`] / [`stop`] / [`accepts`] when changing
/// semantics. Full embed of this type on `AppView` remains optional residual.
///
/// **Singleton:** one watch per process is intentional today; concurrent
/// per-agent watches would need a map of lifecycles keyed by agent id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTaskLifecycle {
    generation: u64,
    running: bool,
    address: Option<String>,
}

impl Default for WatchTaskLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchTaskLifecycle {
    pub fn new() -> Self {
        Self {
            generation: 0,
            running: false,
            address: None,
        }
    }

    /// Start (or restart) watching `address`. Bumps generation so in-flight
    /// ticks from a previous run are rejected via [`Self::accepts`].
    pub fn start(&mut self, address: impl Into<String>) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.running = true;
        self.address = Some(address.into());
        self.generation
    }

    /// Stop watching. Further ticks with the old generation must be dropped.
    pub fn stop(&mut self) {
        if self.running {
            self.generation = self.generation.saturating_add(1);
        }
        self.running = false;
        self.address = None;
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Whether a completed poll with `tick_generation` should update UI state.
    pub fn accepts(&self, tick_generation: u64) -> bool {
        self.running && tick_generation == self.generation && self.generation > 0
    }
}

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

    /// Snapshot durable fields (no seed material). `running` false when stopped
    /// or already confirmed enough for next funding steps.
    pub fn to_state(&self, running: bool) -> WatchSessionState {
        let effective_running = running && !self.is_confirmed_enough();
        WatchSessionState {
            version: WATCH_SESSION_FORMAT_VERSION,
            address: self.address().to_owned(),
            network: self.network().as_str().to_owned(),
            required_confirmations: self.wizard.required_confirmations,
            watched_txid: self
                .wizard
                .watched_txid
                .clone()
                .or_else(|| self.watcher.txid().map(str::to_owned)),
            confirmations: self.wizard.confirmations,
            step: self.wizard.step.as_wire_str().to_owned(),
            generation: self.generation,
            running: effective_running,
            updated_unix_secs: unix_secs_now(),
        }
    }

    /// Rebuild a session from durable state (pager process restart).
    ///
    /// Does **not** load BIP-39. Restores address / network / txid / wizard
    /// progress only. Generation is taken from state (product may re-bump).
    pub fn resume_from_state(state: &WatchSessionState) -> Result<Self> {
        state.validate()?;
        let network = BitcoinNetwork::from_env_str(&state.network).ok_or_else(|| {
            WalletError::Onchain(format!("resume watch: bad network {}", state.network))
        })?;
        let step = FundingStep::from_wire_str(&state.step).ok_or_else(|| {
            WalletError::Onchain(format!("resume watch: bad step {}", state.step))
        })?;
        let address = state.address.trim().to_owned();
        let wizard = FundingWizard::resume_watch(
            address.clone(),
            state.required_confirmations,
            step,
            state.watched_txid.clone(),
            state.confirmations,
        )?;
        let mut watcher = AddressWatcher::new(address, network);
        if let Some(txid) = state.watched_txid.as_deref() {
            let t = txid.trim();
            if !t.is_empty() {
                watcher.set_txid(t);
            }
        }
        Ok(Self {
            watcher,
            wizard,
            generation: state.generation.max(1),
            last_update: None,
        })
    }

    /// Like [`Self::resume_from_state`] but injects a custom explorer (tests).
    pub fn resume_from_state_with_explorer(
        state: &WatchSessionState,
        explorer: RateLimitedExplorer,
    ) -> Result<Self> {
        let mut session = Self::resume_from_state(state)?;
        session.watcher = AddressWatcher::with_explorer(
            session.watcher.address().to_owned(),
            session.watcher.network(),
            explorer,
        );
        if let Some(txid) = state.watched_txid.as_deref() {
            let t = txid.trim();
            if !t.is_empty() {
                session.watcher.set_txid(t);
            }
        }
        Ok(session)
    }

    /// Persist [`Self::to_state`] to `path` (atomic, mode 0600 on Unix).
    pub fn save_to_path(&self, path: &Path, running: bool) -> Result<()> {
        save_watch_session_state(path, &self.to_state(running))
    }

    /// Load + resume from `path`. Missing file → `Ok(None)`.
    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        match load_watch_session_state(path)? {
            Some(state) if state.should_resume() => Ok(Some(Self::resume_from_state(&state)?)),
            Some(_) => Ok(None), // present but not resumable (stopped / confirmed)
            None => Ok(None),
        }
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
    let suffix: String = a
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}…{suffix}")
}

fn shorten_txid(txid: &str) -> String {
    let t = txid.trim();
    if t.chars().count() <= 12 {
        return t.to_owned();
    }
    let prefix: String = t.chars().take(6).collect();
    let suffix: String = t
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}…{suffix}")
}

#[cfg(test)]
mod watch_session_tests {
    use super::*;
    use crate::explorer::ExplorerConfig;

    const ADDR: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fast_ex() -> RateLimitedExplorer {
        // Zero cache so progressive multi-poll tests can change producer bodies.
        RateLimitedExplorer::new(ExplorerConfig {
            min_interval: Duration::ZERO,
            cache_ttl: Duration::ZERO,
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
                    FetchResult::Ok(r#"{"status":{"confirmed":true,"block_height":100}}"#.into())
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

    #[test]
    fn watch_task_lifecycle_rejects_stale_generation() {
        let mut life = WatchTaskLifecycle::new();
        assert!(!life.accepts(0));
        let g1 = life.start(ADDR);
        assert!(life.is_running());
        assert!(life.accepts(g1));
        assert!(!life.accepts(g1.saturating_sub(1)));
        life.stop();
        assert!(!life.is_running());
        assert!(!life.accepts(g1), "stopped task must drop prior generation");
        let g2 = life.start(ADDR);
        assert_ne!(g1, g2);
        assert!(life.accepts(g2));
        assert!(!life.accepts(g1));
    }

    #[test]
    fn watch_session_state_roundtrip_json() {
        let session = WatchSession::start(ADDR, BitcoinNetwork::Mainnet, 3);
        let state = session.to_state(true);
        assert_eq!(state.version, WATCH_SESSION_FORMAT_VERSION);
        assert_eq!(state.address, ADDR);
        assert_eq!(state.network, "mainnet");
        assert!(state.running);
        assert!(state.should_resume());
        state.validate().unwrap();

        let json = serde_json::to_string_pretty(&state).unwrap();
        let lower = json.to_ascii_lowercase();
        // Dual residual: never seed / passphrase fields on watch session disk.
        assert!(!lower.contains("mnemonic"));
        assert!(!lower.contains("passphrase"));
        assert!(!lower.contains("bip39"));
        assert!(!lower.contains("seed"));
        assert!(!json.contains("leader"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().expect("watch session object");
        for forbidden_key in ["mnemonic", "passphrase", "bip39_passphrase", "seed", "nsec"] {
            assert!(
                !obj.contains_key(forbidden_key),
                "watch session must not serialize key {forbidden_key}"
            );
        }
        let back: WatchSessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, state.address);
        assert_eq!(back.network, state.network);
        assert_eq!(back.step, FundingStep::ShowAddress.as_wire_str());
        assert_eq!(back.required_confirmations, 3);
    }

    #[test]
    fn watch_session_persist_load_resume_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_watch_session_path(dir.path());
        assert!(load_watch_session_state(&path).unwrap().is_none());

        let mut session =
            WatchSession::start_with_explorer(ADDR, BitcoinNetwork::Signet, fast_ex(), 3);
        // Progress: payment in mempool.
        let t0 = Instant::now();
        let txs = format!(r#"[{{"txid":"{TXID}"}}]"#);
        let tick = session
            .poll_tick(t0, |url| {
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
        assert_eq!(session.wizard().watched_txid.as_deref(), Some(TXID));

        session.save_to_path(&path, true).unwrap();
        assert!(path.exists());
        // Atomic write must leave the final path mode 0600 (secrets-adjacent).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "watch_session.json must be mode 0600, got {:o}",
                mode & 0o777
            );
        }

        // Simulate pager process restart: load durable state, resume session.
        let loaded = load_watch_session_state(&path).unwrap().expect("file");
        assert!(loaded.should_resume());
        assert_eq!(loaded.watched_txid.as_deref(), Some(TXID));
        assert_eq!(loaded.step, FundingStep::WatchingTx.as_wire_str());
        assert_eq!(loaded.network, "signet");

        let mut resumed =
            WatchSession::resume_from_state_with_explorer(&loaded, fast_ex()).unwrap();
        assert_eq!(resumed.address(), ADDR);
        assert_eq!(resumed.network(), BitcoinNetwork::Signet);
        assert_eq!(resumed.wizard().step, FundingStep::WatchingTx);
        assert_eq!(resumed.wizard().watched_txid.as_deref(), Some(TXID));
        assert_eq!(resumed.watcher().txid(), Some(TXID));

        // Continue poll from resumed state → confirmations advance.
        let tick = resumed
            .poll_tick(t0 + Duration::from_secs(2), |url| {
                if url.contains("/tx/") && !url.contains("/txs") {
                    FetchResult::Ok(r#"{"status":{"confirmed":true,"block_height":100}}"#.into())
                } else if url.contains("tip") {
                    FetchResult::Ok("102".into())
                } else {
                    FetchResult::Error
                }
            })
            .unwrap();
        assert_eq!(tick.update.confirmations, 3);
        assert!(resumed.is_confirmed_enough());

        // Confirmed → to_state(running=true) still marks running=false.
        let done = resumed.to_state(true);
        assert!(!done.running);
        assert!(!done.should_resume());
        save_watch_session_state(&path, &done).unwrap();
        assert!(WatchSession::load_from_path(&path).unwrap().is_none());

        clear_watch_session_state(&path).unwrap();
        assert!(!path.exists());
        assert!(load_watch_session_state(&path).unwrap().is_none());
    }

    #[test]
    fn watch_session_stop_persists_not_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.json");
        let mut session = WatchSession::start(ADDR, BitcoinNetwork::Mainnet, 3);
        session.save_to_path(&path, true).unwrap();
        assert!(WatchSession::load_from_path(&path).unwrap().is_some());

        session.stop();
        // Product path: save running=false on stop (or clear file).
        session.save_to_path(&path, false).unwrap();
        let state = load_watch_session_state(&path).unwrap().unwrap();
        assert!(!state.running);
        assert!(!state.should_resume());
        assert!(WatchSession::load_from_path(&path).unwrap().is_none());
    }

    #[test]
    fn stop_watch_session_state_unlinks_when_possible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.json");
        WatchSession::start(ADDR, BitcoinNetwork::Signet, 3)
            .save_to_path(&path, true)
            .unwrap();
        assert!(path.exists());
        stop_watch_session_state(&path).unwrap();
        assert!(!path.exists());
        assert!(load_watch_session_state(&path).unwrap().is_none());
    }

    #[test]
    fn stop_watch_session_state_running_false_fallback() {
        // Simulate clear-failure path by writing running=false via the same
        // fallback branch logic (direct exercise of non-resumable save).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.json");
        let mut state = WatchSession::start(ADDR, BitcoinNetwork::Testnet, 3).to_state(true);
        state.watched_txid = Some(TXID.into());
        state.step = FundingStep::WatchingTx.as_wire_str().into();
        save_watch_session_state(&path, &state).unwrap();
        assert!(
            load_watch_session_state(&path)
                .unwrap()
                .unwrap()
                .should_resume()
        );

        // Best-effort stop when unlink is not the only option: mark stopped.
        let mut stopped = load_watch_session_state(&path).unwrap().unwrap();
        stopped.running = false;
        save_watch_session_state(&path, &stopped).unwrap();
        let loaded = load_watch_session_state(&path).unwrap().unwrap();
        assert!(!loaded.running);
        assert!(!loaded.should_resume());
        assert_eq!(loaded.network, "testnet");
        assert!(WatchSession::load_from_path(&path).unwrap().is_none());
    }

    #[test]
    fn watch_session_rejects_bip39_in_state() {
        let mut state = WatchSession::start(ADDR, BitcoinNetwork::Mainnet, 3).to_state(true);
        state.address =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .into();
        let err = state.validate().unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("bip-39")
                || err.to_string().to_ascii_lowercase().contains("bip39"),
            "{err}"
        );

        // File with BIP-39-shaped address must not load.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        let evil = serde_json::json!({
            "version": 1,
            "address": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "network": "mainnet",
            "required_confirmations": 3,
            "watched_txid": null,
            "confirmations": 0,
            "step": "show_address",
            "generation": 1,
            "running": true,
            "updated_unix_secs": 0,
        });
        fs::write(&path, serde_json::to_vec(&evil).unwrap()).unwrap();
        let err = load_watch_session_state(&path).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("bip"),
            "{err}"
        );
    }

    #[test]
    fn watch_session_resume_preserves_generation_and_rejects_need_wallet() {
        let mut state = WatchSession::start(ADDR, BitcoinNetwork::Testnet, 5).to_state(true);
        state.generation = 42;
        let session = WatchSession::resume_from_state(&state).unwrap();
        assert_eq!(session.generation(), 42);
        assert_eq!(session.network(), BitcoinNetwork::Testnet);
        assert_eq!(session.wizard().required_confirmations, 5);

        state.step = FundingStep::NeedWallet.as_wire_str().into();
        let err = WatchSession::resume_from_state(&state).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("need_wallet")
                || err.to_string().to_ascii_lowercase().contains("backup"),
            "{err}"
        );
    }

    #[test]
    fn default_watch_session_path_under_bitcoin() {
        let p = default_watch_session_path("/tmp/grok-home-test");
        assert!(p.ends_with("bitcoin/watch_session.json"));
    }

    #[test]
    fn funding_step_wire_roundtrip() {
        for step in [
            FundingStep::ShowAddress,
            FundingStep::WatchingTx,
            FundingStep::OpenChannel,
            FundingStep::AcquireCashu,
            FundingStep::ReadyForInference,
            FundingStep::RefundOptional,
            FundingStep::NeedWallet,
        ] {
            let w = step.as_wire_str();
            assert_eq!(FundingStep::from_wire_str(w), Some(step));
        }
        assert_eq!(FundingStep::from_wire_str("nope"), None);
    }
}
