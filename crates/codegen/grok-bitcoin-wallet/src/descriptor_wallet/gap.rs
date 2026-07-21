//! Gap-limit constants and pure window-extend helpers.
//!
//! Gap-limit ChainSource sync (default product path). Real BDK auto-sync:
//! feature-gated [`crate::bdk_sync`].

use std::collections::HashSet;

use super::types::{WalletBalance, WalletUtxo};

/// Max receive addresses derived when building a wallet gap window.
pub const DEFAULT_RECEIVE_GAP: u32 = 20;

/// Hard cap on receive **or** change address window length.
///
/// Applies to both [`DescriptorWallet::from_mnemonic`] construction and
/// gap-extend paths. Never raised by options: [`GapExtendOptions::max_gap`]
/// is clamped to this. Prevents unbounded address growth (gap-limit
/// ChainSource sync only — not full BDK auto-sync).
pub const MAX_ADDRESS_GAP: u32 = 200;

/// BIP84 **signing** scan for product explicit-prevout paths (RBF/CPFP).
///
/// Equal to [`MAX_ADDRESS_GAP`] so same-input RBF / CPFP can sign any receive
/// or change index that product gap-sync spend may have recovered. Does **not**
/// open a [`ChainSource`], list UTXOs, or re-extend wallet windows — only widens
/// the `bip84_script_lookup` / sign scan (`0..gap`). Product shell RBF/CPFP
/// must pass this (not [`DEFAULT_RECEIVE_GAP`]) after gap-sync spend can select
/// deep indices.
pub const PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP: u32 = MAX_ADDRESS_GAP;

/// Default number of addresses appended per extend step (receive and change
/// independently).
pub const DEFAULT_GAP_EXTEND_STEP: u32 = 20;

/// Default look-ahead for gap extend (BIP44/BDK-style stop-gap).
///
/// Extend while `highest_used >= window_len.saturating_sub(lookahead)` — i.e.
/// while fewer than `lookahead` addresses remain after the highest used index
/// (including the case where mid-window activity must keep scanning). Equal to
/// [`DEFAULT_RECEIVE_GAP`] (20) so default options match common wallet recovery
/// stop-gap, **not** tip-of-window-only (`lookahead = 1`).
///
/// Callers who want tip-hot-only behaviour should set `lookahead: 1` explicitly.
/// This is still UTXO-list gap (no spent-tx history); not full `bdk_wallet` sync.
pub const DEFAULT_GAP_LOOKAHEAD: u32 = DEFAULT_RECEIVE_GAP;

/// Options for bounded gap-window extend during [`DescriptorWallet::sync_with_gap_extend`].
///
/// All growth is capped by [`MAX_ADDRESS_GAP`] regardless of `max_gap`.
/// Default `lookahead` is BIP44/BDK-style stop-gap ([`DEFAULT_GAP_LOOKAHEAD`]),
/// not tip-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapExtendOptions {
    /// Stop-gap / look-ahead: extend when
    /// `highest_used >= window_len.saturating_sub(lookahead)`.
    /// `0` is treated as `1` (tip-of-window activity). Default is 20
    /// ([`DEFAULT_GAP_LOOKAHEAD`]).
    pub lookahead: u32,
    /// Addresses to append per extend step (receive/change independently).
    pub extend_step: u32,
    /// Soft max gap for this sync; clamped to [`MAX_ADDRESS_GAP`].
    pub max_gap: u32,
}

impl Default for GapExtendOptions {
    fn default() -> Self {
        Self {
            lookahead: DEFAULT_GAP_LOOKAHEAD,
            extend_step: DEFAULT_GAP_EXTEND_STEP,
            max_gap: MAX_ADDRESS_GAP,
        }
    }
}

impl GapExtendOptions {
    /// `max_gap` clamped into `1..=MAX_ADDRESS_GAP`.
    pub fn effective_max_gap(self) -> u32 {
        self.max_gap.clamp(1, MAX_ADDRESS_GAP)
    }

    /// Look-ahead of at least 1 (`0` → tip-of-window).
    pub fn effective_lookahead(self) -> u32 {
        self.lookahead.max(1)
    }

    /// Extend step of at least 1.
    pub fn effective_extend_step(self) -> u32 {
        self.extend_step.max(1)
    }
}

/// Snapshot of UTXOs + balance + gap meta after a ChainSource sync.
///
/// Only contains UTXOs the [`ChainSource`] returned for the watched window —
/// never invents coins. Gap fields describe the **current** derived window
/// (which may have grown during [`DescriptorWallet::sync_with_gap_extend`]).
///
/// This is **gap-limit ChainSource sync**, not full `bdk_wallet` auto-sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSyncSnapshot {
    pub utxos: Vec<WalletUtxo>,
    pub balance: WalletBalance,
    /// Receive address window length after sync.
    pub receive_gap: u32,
    /// Change address window length after sync.
    pub change_gap: u32,
    /// Highest receive index (0-based) that has ≥1 UTXO in `utxos`, if any.
    pub highest_used_receive: Option<u32>,
    /// Highest change index with ≥1 UTXO, if any.
    pub highest_used_change: Option<u32>,
    /// Addresses appended to the receive window during this sync (0 for fixed
    /// [`DescriptorWallet::sync_utxos`]).
    pub extended_receive_by: u32,
    /// Addresses appended to the change window during this sync.
    pub extended_change_by: u32,
    /// True when further extend was warranted but hard/soft max gap blocked growth.
    pub hit_max_gap: bool,
}

/// Result of a single [`DescriptorWallet::extend_gap_if_needed`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapExtendReport {
    pub receive_before: u32,
    pub receive_after: u32,
    pub change_before: u32,
    pub change_after: u32,
    pub receive_extended: bool,
    pub change_extended: bool,
    pub hit_max_gap: bool,
}

impl GapExtendReport {
    pub fn grew(self) -> bool {
        self.receive_extended || self.change_extended
    }
}

/// Whether a gap window should grow given the highest used index and look-ahead.
///
/// - No used addresses → `false`
/// - Empty window → `false`
/// - Extend when `highest_used >= window_len.saturating_sub(lookahead.max(1))`
///   (with `lookahead` 0 treated as 1: last index of the window is “hot”)
///
/// With `lookahead == window_len` (default stop-gap 20 on a 20-address window),
/// **any** used index keeps extending until at least `lookahead` slots sit after
/// the highest used index — BIP44/BDK-style recovery, not tip-only.
///
/// Pure helper: offline-testable without a wallet or chain.
pub fn address_window_needs_extend(
    highest_used: Option<u32>,
    window_len: u32,
    lookahead: u32,
) -> bool {
    let Some(hi) = highest_used else {
        return false;
    };
    if window_len == 0 {
        return false;
    }
    let la = lookahead.max(1);
    let threshold = window_len.saturating_sub(la);
    hi >= threshold
}

/// Next window length after one extend step, or `None` when already at `max_gap`.
///
/// Pure helper: never returns a value larger than `max_gap`, and never returns
/// `Some` equal to `current_gap` (so callers can detect “no growth”).
pub fn next_gap_after_extend(current_gap: u32, extend_step: u32, max_gap: u32) -> Option<u32> {
    let max_gap = max_gap.clamp(1, MAX_ADDRESS_GAP);
    if current_gap >= max_gap {
        return None;
    }
    let step = extend_step.max(1);
    let next = current_gap.saturating_add(step).min(max_gap);
    if next > current_gap { Some(next) } else { None }
}

/// Highest 0-based index in `addresses` that appears on at least one UTXO.
///
/// Pure: only matches exact address strings returned by the chain source.
/// Builds a set of UTXO addresses once, then reverse-scans the window so the
/// first hit is the highest index (`O(window + utxos)`).
pub fn highest_used_address_index(addresses: &[String], utxos: &[WalletUtxo]) -> Option<u32> {
    if addresses.is_empty() || utxos.is_empty() {
        return None;
    }
    let used: HashSet<&str> = utxos.iter().map(|u| u.address.as_str()).collect();
    for (i, addr) in addresses.iter().enumerate().rev() {
        if used.contains(addr.as_str()) {
            return Some(i as u32);
        }
    }
    None
}
