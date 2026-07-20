//! Descriptor-shaped BIP84 wallet surface: list UTXOs + coin selection + PSBT.
//!
//! Full `bdk_wallet` auto-sync remains residual. This module ships a **lightweight
//! gap-limit** UTXO sync over injectable [`ChainSource`] (list + optional
//! bounded window extend) — **not** a full BDK wallet engine. Injectable
//! electrum/esplora backends live in [`crate::electrum`] / [`crate::esplora`]
//! (mock always; live HTTP/TCP feature-gated). Product env selection is
//! [`crate::chain_select`] (default mempool). This module provides:
//! - BIP84 external/internal descriptor **strings** (wpkh account xpub)
//! - injectable [`ChainSource`] (mock for tests; live mempool UTXO behind
//!   `explorer-http`; electrum/esplora via sibling modules)
//! - [`list_unspent`], balance, gap-limit [`DescriptorWallet::sync_utxos`] /
//!   [`DescriptorWallet::sync_with_gap_extend`], product
//!   [`list_bip84_utxos_with_gap_sync`] (snapshot-authoritative list/balance —
//!   no extra list) + [`select_and_prepare_bip84_spend_with_gap_sync`]
//!   (select-from-snapshot after sync — no extra list; [`GapSyncSpendFailure`]
//!   AfterSync keeps hit-max notices on select/prepare Err),
//!   [`select_and_prepare_bip84_spend_from_utxos`], and fee-aware
//!   [`select_coins`] APIs
//! - unsigned PSBT build from [`CoinSelection`] ([`build_unsigned_psbt`])
//! - BIP84 P2WPKH sign + offline finalize ([`finalize_psbt`]) for completeable
//!   single-key paths, bare m-of-n CHECKMULTISIG P2WSH when enough
//!   `partial_sigs` are present, **Taproot key-path** when `tap_key_sig` is
//!   already present, and **Taproot script-path** bare single-key x-only
//!   CHECKSIG, bare multi_a (`CHECKSIG`/`CHECKSIGADD`/`NUMEQUAL`), bare
//!   thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL`), bare
//!   and_v CHECKSIGVERIFY…CHECKSIG chains, bare or_i IF/ELSE dual CHECKSIG,
//!   bare or_d CHECKSIG IFDUP NOTIF dual CHECKSIG, bare and_n CHECKSIG
//!   NOTIF 0 ELSE CHECKSIG, bare andor CHECKSIG NOTIF CHECKSIG ELSE
//!   CHECKSIG, bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest
//!   EQUAL`) when matching PSBT preimage maps are present, or
//!   `and_v(v:pk, hash)` when both matching `tap_script_sigs` + preimage are
//!   present, or **older/CSV** forms
//!   (`and_v(v:pk, older(n))` / `and_v(v:older(n), pk)` / bare `older(n)`)
//!   when matching sigs (if any) and the **already-present** unsigned-tx
//!   nSequence satisfies BIP-112 CSV, or **after/CLTV** forms
//!   (`and_v(v:pk, after(n))` / `and_v(v:after(n), pk)` / bare `after(n)`)
//!   when matching sigs (if any) and the **already-present** unsigned-tx
//!   nLockTime + nSequence satisfy BIP-65 CLTV (never invents missing
//!   signatures, control blocks, leaves, preimages, or nSequence/nLockTime)
//! - extract + raw-hex helpers; network broadcast via [`crate::explorer::TxBroadcaster`]
//! - pure RBF / CPFP fee planners ([`plan_rbf_fee_bump`], [`plan_cpfp_child_fee`])
//! - same-input RBF replacement ([`prepare_rbf_replacement`],
//!   [`prepare_rbf_replacement_from_selection`], [`selection_with_rbf_fee`])
//! - CPFP child prepare ([`prepare_cpfp_child`], [`coin_selection_for_cpfp`])
//!
//! Seed material stays in [`crate::mnemonic::MnemonicSecret`] / SeedVault only;
//! this module never persists BIP-39. Signing zeroizes intermediate seed bytes
//! and never `Debug`-prints key material.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpriv, Xpub};
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, transaction,
};
use zeroize::Zeroize;

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;
use crate::onchain::{derive_bip84_receive_address_with_passphrase, network_from_str};

#[cfg(feature = "explorer-http")]
use std::cell::RefCell;

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

/// On-chain outpoint (txid + vout).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPointRef {
    pub txid: String,
    pub vout: u32,
}

impl OutPointRef {
    pub fn new(txid: impl Into<String>, vout: u32) -> Self {
        Self {
            txid: txid.into(),
            vout,
        }
    }
}

/// One spendable UTXO known to the wallet surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletUtxo {
    pub outpoint: OutPointRef,
    pub amount_sats: u64,
    pub address: String,
    pub confirmations: u32,
    /// True when the UTXO is on the internal (change) chain.
    pub is_change: bool,
}

/// Confirmed + unconfirmed sat balances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WalletBalance {
    pub confirmed_sats: u64,
    pub unconfirmed_sats: u64,
}

impl WalletBalance {
    pub fn total_sats(self) -> u64 {
        self.confirmed_sats.saturating_add(self.unconfirmed_sats)
    }
}

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

/// Strategy for picking coins to cover a target amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoinSelectStrategy {
    /// Prefer larger UTXOs first (fewer inputs; residual default).
    #[default]
    LargestFirst,
    /// Prefer smaller UTXOs first (UTXO consolidation-friendly).
    SmallestFirst,
}

/// Result of coin selection (feeds [`build_unsigned_psbt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinSelection {
    pub selected: Vec<WalletUtxo>,
    pub total_input_sats: u64,
    /// `total_input_sats - target_sats - fee_sats` (0 when change is dust-folded).
    pub change_sats: u64,
    pub target_sats: u64,
    /// Estimated network fee in sats (0 when fee rate not applied).
    pub fee_sats: u64,
}

/// Payment + change destinations for [`build_unsigned_psbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendParams {
    /// Destination address receiving [`CoinSelection::target_sats`].
    pub payment_address: String,
    /// Required when [`CoinSelection::change_sats`] `> 0`; ignored when zero.
    pub change_address: Option<String>,
    pub network: Network,
}

/// Unsigned PSBT built from a fee-aware (or zero-fee) [`CoinSelection`].
///
/// Does **not** claim network broadcast. Sign with
/// [`sign_psbt_bip84_p2wpkh`] when inputs are BIP84 P2WPKH owned by a mnemonic.
#[derive(Clone)]
pub struct BuiltPsbt {
    pub psbt: Psbt,
    pub fee_sats: u64,
    pub payment_sats: u64,
    pub change_sats: u64,
}

impl std::fmt::Debug for BuiltPsbt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltPsbt")
            .field("inputs", &self.psbt.inputs.len())
            .field("outputs", &self.psbt.unsigned_tx.output.len())
            .field("fee_sats", &self.fee_sats)
            .field("payment_sats", &self.payment_sats)
            .field("change_sats", &self.change_sats)
            .finish()
    }
}

impl BuiltPsbt {
    /// PSBT binary as lowercase hex (no secrets until signed).
    pub fn serialize_hex(&self) -> String {
        self.psbt.serialize_hex()
    }

    pub fn input_count(&self) -> usize {
        self.psbt.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.psbt.unsigned_tx.output.len()
    }
}

/// Outcome of BIP84 P2WPKH signing (honest about partial coverage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    /// Every input received a partial signature.
    AllSigned { signed_inputs: usize },
    /// Some inputs signed; others could not be resolved within the address gap.
    ///
    /// Not broadcast-ready. Callers must not treat this as a complete spend.
    Partial {
        signed_inputs: usize,
        unsigned_inputs: usize,
        detail: String,
    },
}

impl SignOutcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::AllSigned { .. })
    }

    /// True only when every input was signed — never true for multi-sig residual.
    pub fn is_broadcast_ready(&self) -> bool {
        self.is_complete()
    }

    pub fn signed_inputs(&self) -> usize {
        match self {
            Self::AllSigned { signed_inputs } => *signed_inputs,
            Self::Partial { signed_inputs, .. } => *signed_inputs,
        }
    }
}

/// Outcome of offline PSBT finalize (honest Complete vs Partial gates).
///
/// # Complete only when every input has real final material
///
/// [`Self::Complete`] requires every input to already carry (or receive from
/// offline finalize) **non-empty** [`PsbtInput::final_script_witness`] and/or
/// **non-empty** [`PsbtInput::final_script_sig`]. Empty witnesses / empty
/// script_sigs are never counted.
///
/// Offline finalize fills final material only for cases that need **no
/// invention**:
/// - already-present non-empty finals (preserved)
/// - single-key **P2WPKH** (`partial_sigs` + matching `witness_utxo`)
/// - single-key **P2SH-P2WPKH** (redeem_script is P2WPKH + matching sig)
/// - single-key **P2PKH** (legacy; matching `partial_sigs` → `final_script_sig`)
/// - single-key **P2WSH** whose `witness_script` is bare `<pubkey> OP_CHECKSIG`
/// - bare **m-of-n CHECKMULTISIG** P2WSH / nested P2SH-P2WSH when the PSBT
///   already has ≥ m matching `partial_sigs` for script pubkeys; the
///   assembler builds BIP147 NULLDUMMY + sigs in witness_script pubkey
///   order (never invents; callers need not pre-order `partial_sigs`)
/// - **Taproot key-path** P2TR when `tap_key_sig` is already present
///   ([`Witness::p2tr_key_spend`]; never invents a Schnorr sig)
/// - **Taproot script-path** P2TR when a present `tap_scripts` entry is bare
///   `<x-only pk> OP_CHECKSIG`, bare multi_a
///   (`<pk1> CHECKSIG <pk2> CHECKSIGADD … <k> NUMEQUAL`), bare thresh
///   (`<pk1> CHECKSIG (SWAP <pki> CHECKSIG ADD)+ <k> EQUAL` =
///   miniscript `thresh(k, pk, s:pk, …)` — distinct from multi_a), bare and_v
///   (`(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG`, all n sigs present), bare
///   or_i (`IF <pkA> CHECKSIG ELSE <pkB> CHECKSIG ENDIF` with a matching sig
///   for A and/or B — IF/A preferred when both; ELSE when only B; neither →
///   Partial), bare or_d
///   (`<pkA> CHECKSIG IFDUP NOTIF <pkB> CHECKSIG ENDIF` — A preferred when
///   both; empty BIP-342 dissatisfaction for A when only B), bare and_n
///   (`<pkA> CHECKSIG NOTIF 0 ELSE <pkB> CHECKSIG ENDIF` — both sigs
///   required), or bare andor
///   (`<pkA> CHECKSIG NOTIF <pkC> CHECKSIG ELSE <pkB> CHECKSIG ENDIF` —
///   AB preferred when both A+B present; else C with empty BIP-342
///   dissatisfaction of A), bare miniscript **hash**
///   (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL` for sha256/hash256/
///   ripemd160/hash160 when a matching 32-byte PSBT preimage is present),
///   or bare **and_v(v:pk, hash)** (`<A> CHECKSIGVERIFY` + hash fragment
///   when both matching `tap_script_sig` and preimage are present), or
///   **older/CSV** forms (`and_v(v:pk, older(n))` =
///   `<A> CHECKSIGVERIFY <n> CSV`; `and_v(v:older(n), pk)` =
///   `<n> CSV VERIFY <A> CHECKSIG`; bare `older(n)` = `<n> CSV`) when matching
///   `tap_script_sig` (if required) is present **and** the unsigned-tx input
///   nSequence already satisfies BIP-112 CSV for `n` (tx version ≥ 2; never
///   invents nSequence), or **after/CLTV** forms (`and_v(v:pk, after(n))` =
///   `<A> CHECKSIGVERIFY <n> CLTV`; `and_v(v:after(n), pk)` =
///   `<n> CLTV VERIFY <A> CHECKSIG`; bare `after(n)` = `<n> CLTV`) when matching
///   `tap_script_sig` (if required) is present **and** the unsigned-tx
///   nLockTime already satisfies BIP-65 for `n` with an nSequence that enables
///   absolute locktime (never invents nLockTime/nSequence), matching
///   `tap_script_sigs` / preimage maps cover the template (multi_a / thresh
///   unused keys get empty BIP-342 placeholders only), and the present control
///   block verifies against the prevout (never invents control blocks / leaves
///   / signatures / preimages / locktimes)
///
/// # Residual (Partial — not broadcast-ready)
///
/// Incomplete CHECKMULTISIG / multi_a / thresh / and_v / and_n thresholds,
/// or_i / or_d with neither branch sig, incomplete andor (neither AB nor C
/// completeable), missing hash preimage / incomplete and_v(v:pk, hash),
/// older/CSV with missing sig or nSequence that does not satisfy BIP-112,
/// after/CLTV with missing sig or nLockTime/nSequence that does not satisfy
/// BIP-65, Taproot **other complex script-path** / miniscript
/// (or_c/ non-s:pk thresh /…) / non-standard leaves, missing
/// UTXO/scripts/`tap_key_sig` / incomplete script-path maps, and unsigned
/// inputs stay [`Self::Partial`]. Product prepare still refuses Partial
/// before any broadcast claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// Every input has non-empty final spend material (witness and/or script_sig).
    Complete { finalized_inputs: usize },
    /// Some inputs finalized; others residual (unsigned, multi-sig, unsupported).
    ///
    /// Not broadcast-ready. Callers must not extract/broadcast as a success.
    Partial {
        finalized_inputs: usize,
        residual_inputs: usize,
        detail: String,
    },
}

impl FinalizeOutcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    /// Alias for product copy: only [`Self::Complete`] is broadcast-ready.
    pub fn is_broadcast_ready(&self) -> bool {
        self.is_complete()
    }

    pub fn finalized_inputs(&self) -> usize {
        match self {
            Self::Complete { finalized_inputs } => *finalized_inputs,
            Self::Partial {
                finalized_inputs, ..
            } => *finalized_inputs,
        }
    }
}

/// True when a single PSBT input has **non-empty** final spend material.
///
/// Accepts non-empty `final_script_witness` and/or non-empty `final_script_sig`.
/// Empty stacks are **not** final — multi-sig must not be marked complete without
/// real finals.
pub fn input_is_finalized(input: &PsbtInput) -> bool {
    let has_witness = input
        .final_script_witness
        .as_ref()
        .is_some_and(|w| !w.is_empty());
    let has_script_sig = input
        .final_script_sig
        .as_ref()
        .is_some_and(|s| !s.is_empty());
    has_witness || has_script_sig
}

/// True when every PSBT input has non-empty final spend material.
///
/// Empty witnesses, empty script_sigs, and missing finals are **not** complete.
/// Never use this alone to invent multi-sig success — only real
/// `final_script_witness` / `final_script_sig` count.
pub fn psbt_is_broadcast_ready(psbt: &Psbt) -> bool {
    !psbt.inputs.is_empty() && psbt.inputs.iter().all(input_is_finalized)
}

/// Options for coin selection (confirmed filter + optional fee model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinSelectOptions {
    pub strategy: CoinSelectStrategy,
    /// When true (product default), unconfirmed (0-conf) UTXOs are excluded.
    pub confirmed_only: bool,
    /// Fee rate in sat/vB. `None` or `Some(0)` skips fee modeling (legacy path).
    pub fee_rate_sat_vb: Option<u64>,
}

impl Default for CoinSelectOptions {
    fn default() -> Self {
        Self {
            strategy: CoinSelectStrategy::LargestFirst,
            confirmed_only: true,
            fee_rate_sat_vb: None,
        }
    }
}

/// Conservative P2WPKH size estimates used for fee-aware selection (vbytes).
///
/// Not a full weight calculator; good enough for selection before PSBT build.
pub const TX_OVERHEAD_VB: u64 = 11;
/// Typical signed P2WPKH input size in vbytes.
pub const P2WPKH_INPUT_VB: u64 = 68;
/// Typical P2WPKH output size in vbytes.
pub const P2WPKH_OUTPUT_VB: u64 = 31;
/// Dust threshold: change below this is folded into the fee (no change output).
pub const DUST_P2WPKH_SATS: u64 = 294;

/// Estimate transaction vbytes for `input_count` P2WPKH inputs and
/// `output_count` P2WPKH outputs (payment + optional change).
pub fn estimate_tx_vbytes(input_count: usize, output_count: usize) -> u64 {
    TX_OVERHEAD_VB
        .saturating_add((input_count as u64).saturating_mul(P2WPKH_INPUT_VB))
        .saturating_add((output_count as u64).saturating_mul(P2WPKH_OUTPUT_VB))
}

/// `estimate_tx_vbytes(...) * fee_rate_sat_vb`.
pub fn estimate_fee_sats(input_count: usize, output_count: usize, fee_rate_sat_vb: u64) -> u64 {
    estimate_tx_vbytes(input_count, output_count).saturating_mul(fee_rate_sat_vb)
}

/// Bitcoin Core default incremental relay fee (sat/vB) used for BIP-125 RBF
/// absolute fee floor guidance. Not network-fetched; product may override.
pub const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB: u64 = 1;

/// Floor division fee rate in sat/vB. Returns 0 when `vbytes == 0`.
pub fn effective_fee_rate_sat_vb(fee_sats: u64, vbytes: u64) -> u64 {
    if vbytes == 0 {
        return 0;
    }
    fee_sats / vbytes
}

/// Ceiling division (`num / den`, rounding up). Returns 0 when `den == 0`.
pub fn div_ceil_u64(num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    num.div_ceil(den)
}

/// Minimum absolute fee increase (sats) for a same-size BIP-125 replacement:
/// `replacement_vbytes * incremental_relay_sat_vb` (at least 1 sat when sizes > 0).
pub fn rbf_min_fee_increase_sats(replacement_vbytes: u64, incremental_relay_sat_vb: u64) -> u64 {
    let inc = if incremental_relay_sat_vb == 0 {
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB
    } else {
        incremental_relay_sat_vb
    };
    let raw = replacement_vbytes.saturating_mul(inc);
    if replacement_vbytes > 0 {
        raw.max(1)
    } else {
        0
    }
}

/// Errors from RBF / CPFP pure fee planners (offline; no network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeBumpPlanError {
    /// Transaction virtual size must be > 0.
    ZeroVbytes,
    /// Target fee rate must be > 0 sat/vB.
    ZeroTargetRate,
    /// Child vbytes must be > 0 for CPFP.
    ZeroChildVbytes,
}

impl std::fmt::Display for FeeBumpPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroVbytes => write!(f, "vbytes must be > 0"),
            Self::ZeroTargetRate => write!(f, "target fee rate must be > 0 sat/vB"),
            Self::ZeroChildVbytes => write!(f, "child vbytes must be > 0"),
        }
    }
}

impl std::error::Error for FeeBumpPlanError {}

/// BIP-125-style RBF fee bump plan for a **same-size** single-tx replacement.
///
/// Does not rebuild a PSBT. Product uses this to pick a higher fee rate / absolute
/// fee before re-selecting coins and rebuilding. Inputs already signal RBF via
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`] on [`build_unsigned_psbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbfFeePlan {
    pub original_fee_sats: u64,
    pub original_vbytes: u64,
    /// Floor sat/vB of the original tx.
    pub original_fee_rate_sat_vb: u64,
    /// Minimum absolute fee for a same-size replacement (increment + higher rate).
    pub min_replacement_fee_sats: u64,
    /// Floor sat/vB at [`Self::min_replacement_fee_sats`].
    pub min_replacement_fee_rate_sat_vb: u64,
    /// Recommended absolute fee meeting target rate and BIP-125 floors.
    pub recommended_fee_sats: u64,
    /// Floor sat/vB at [`Self::recommended_fee_sats`].
    pub recommended_fee_rate_sat_vb: u64,
    /// `recommended_fee_sats - original_fee_sats`.
    pub fee_delta_sats: u64,
    pub target_fee_rate_sat_vb: u64,
    pub incremental_relay_sat_vb: u64,
}

/// Plan a same-size RBF fee bump.
///
/// Ensures the recommended fee:
/// 1. Is strictly greater than `original_fee_sats`
/// 2. Pays at least `vbytes * incremental_relay` extra (BIP-125 bandwidth)
/// 3. Has a strictly higher floor fee rate than the original when possible
/// 4. Meets `target_fee_rate_sat_vb * vbytes`
///
/// `incremental_relay_sat_vb == 0` uses [`DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB`].
pub fn plan_rbf_fee_bump(
    original_fee_sats: u64,
    original_vbytes: u64,
    target_fee_rate_sat_vb: u64,
    incremental_relay_sat_vb: u64,
) -> std::result::Result<RbfFeePlan, FeeBumpPlanError> {
    if original_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroVbytes);
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(FeeBumpPlanError::ZeroTargetRate);
    }
    let incremental = if incremental_relay_sat_vb == 0 {
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB
    } else {
        incremental_relay_sat_vb
    };
    let original_fee_rate_sat_vb = effective_fee_rate_sat_vb(original_fee_sats, original_vbytes);
    let min_increase = rbf_min_fee_increase_sats(original_vbytes, incremental);
    let min_by_increment = original_fee_sats.saturating_add(min_increase);
    // Strictly higher absolute fee.
    let min_by_absolute = original_fee_sats.saturating_add(1);
    // Strictly higher floor feerate: (orig_rate + 1) * vb (at least 1 sat/vB).
    let higher_rate = original_fee_rate_sat_vb.saturating_add(1).max(1);
    let min_by_rate = higher_rate.saturating_mul(original_vbytes);
    let by_target = original_vbytes.saturating_mul(target_fee_rate_sat_vb);

    // BIP-125 floor (no target): increment bandwidth + absolute + higher rate.
    let min_replacement_fee_sats = min_by_increment.max(min_by_absolute).max(min_by_rate);
    // Recommended also meets the caller's target mempool rate.
    let mut recommended = by_target.max(min_replacement_fee_sats);
    // Defensive: never recommend ≤ original absolute fee.
    if recommended <= original_fee_sats {
        recommended = original_fee_sats.saturating_add(min_increase.max(1));
    }

    let recommended_fee_rate_sat_vb = effective_fee_rate_sat_vb(recommended, original_vbytes);
    let min_replacement_fee_rate_sat_vb =
        effective_fee_rate_sat_vb(min_replacement_fee_sats, original_vbytes);
    let fee_delta_sats = recommended.saturating_sub(original_fee_sats);

    Ok(RbfFeePlan {
        original_fee_sats,
        original_vbytes,
        original_fee_rate_sat_vb,
        min_replacement_fee_sats,
        min_replacement_fee_rate_sat_vb,
        recommended_fee_sats: recommended,
        recommended_fee_rate_sat_vb,
        fee_delta_sats,
        target_fee_rate_sat_vb,
        incremental_relay_sat_vb: incremental,
    })
}

/// CPFP child fee plan: child pays enough so parent+child package meets a target rate.
///
/// Pure guidance (does not build the child PSBT). Typical child is 1-in (parent
/// output) + 1–2 P2WPKH outs — use [`estimate_tx_vbytes`] / [`estimate_cpfp_child_vbytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpfpFeePlan {
    pub parent_fee_sats: u64,
    pub parent_vbytes: u64,
    pub child_vbytes: u64,
    pub target_fee_rate_sat_vb: u64,
    /// Minimum child absolute fee so package rate ≥ target (and child meets min relay).
    pub min_child_fee_sats: u64,
    /// Floor sat/vB of the child alone at [`Self::min_child_fee_sats`].
    pub min_child_fee_rate_sat_vb: u64,
    /// Package fee rate after paying [`Self::min_child_fee_sats`].
    pub package_fee_rate_sat_vb: u64,
    pub package_vbytes: u64,
    pub package_fee_sats: u64,
}

/// Estimate vbytes for a typical CPFP child spending one P2WPKH parent output
/// with `output_count` P2WPKH outputs (payment and/or change). `output_count`
/// of 0 is treated as 1.
pub fn estimate_cpfp_child_vbytes(output_count: usize) -> u64 {
    estimate_tx_vbytes(1, output_count.max(1))
}

/// Plan CPFP child fee so `(parent_fee + child_fee) / (parent_vb + child_vb) ≥ target`.
///
/// Also enforces a minimum child fee of `child_vbytes * 1` sat (min-relay style)
/// so a fully overpaying parent still yields a relayable child.
pub fn plan_cpfp_child_fee(
    parent_fee_sats: u64,
    parent_vbytes: u64,
    child_vbytes: u64,
    target_fee_rate_sat_vb: u64,
) -> std::result::Result<CpfpFeePlan, FeeBumpPlanError> {
    if parent_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroVbytes);
    }
    if child_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroChildVbytes);
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(FeeBumpPlanError::ZeroTargetRate);
    }
    let package_vbytes = parent_vbytes.saturating_add(child_vbytes);
    let needed_package_fee = package_vbytes.saturating_mul(target_fee_rate_sat_vb);
    let for_package = needed_package_fee.saturating_sub(parent_fee_sats);
    // Child must pay at least min-relay for its own size (1 sat/vB).
    let min_relay_child = child_vbytes
        .saturating_mul(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB)
        .max(1);
    let min_child_fee_sats = for_package.max(min_relay_child);
    let package_fee_sats = parent_fee_sats.saturating_add(min_child_fee_sats);
    let package_fee_rate_sat_vb = effective_fee_rate_sat_vb(package_fee_sats, package_vbytes);
    let min_child_fee_rate_sat_vb = effective_fee_rate_sat_vb(min_child_fee_sats, child_vbytes);

    Ok(CpfpFeePlan {
        parent_fee_sats,
        parent_vbytes,
        child_vbytes,
        target_fee_rate_sat_vb,
        min_child_fee_sats,
        min_child_fee_rate_sat_vb,
        package_fee_rate_sat_vb,
        package_vbytes,
        package_fee_sats,
    })
}

/// Injectable chain / explorer backend for UTXO discovery.
///
/// Built-in impls: [`MockChainSource`] (tests); [`MempoolChainSource`]
/// (`explorer-http`); [`crate::esplora::EsploraChainSource`] (mock always,
/// live HTTP behind `esplora`); [`crate::electrum::ElectrumChainSource`]
/// (mock always, live TCP behind `electrum`).
pub trait ChainSource {
    /// List UTXOs for the given addresses (any order).
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>>;
}

/// In-memory chain source for unit tests and offline demos.
#[derive(Debug, Clone, Default)]
pub struct MockChainSource {
    utxos: Vec<WalletUtxo>,
}

impl MockChainSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_utxos(utxos: Vec<WalletUtxo>) -> Self {
        Self { utxos }
    }

    pub fn push(&mut self, utxo: WalletUtxo) {
        self.utxos.push(utxo);
    }
}

impl ChainSource for MockChainSource {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        Ok(self
            .utxos
            .iter()
            .filter(|u| addresses.iter().any(|a| a == &u.address))
            .cloned()
            .collect())
    }
}

/// Live [`ChainSource`] backed by mempool.space address UTXO REST API.
///
/// Only available with feature `explorer-http`. All fetches go through
/// [`crate::explorer::MempoolHttpClient`] / [`crate::explorer::RateLimitedExplorer`]
/// gates (never bypassed). Default CI builds without the feature stay offline.
///
/// **Tip height:** one tip probe runs per `list_unspent_for_addresses` call.
/// If tip is missing (gated/error/unparseable), API-`confirmed:true` UTXOs still
/// get `confirmations = 1` via [`parse_mempool_address_utxos`] — they are
/// spend-eligible under the default `confirmed_only` filter, but confirmation
/// *depth* is untrusted (not the same as [`crate::watcher::AddressWatcher`],
/// which marks incomplete and leaves conf at 0 when tip is gated). Product
/// paths that require N>1 confs must not treat that `1` as authoritative depth.
#[cfg(feature = "explorer-http")]
#[derive(Debug)]
pub struct MempoolChainSource {
    client: RefCell<crate::explorer::MempoolHttpClient>,
}

#[cfg(feature = "explorer-http")]
impl MempoolChainSource {
    pub fn new(client: crate::explorer::MempoolHttpClient) -> Self {
        Self {
            client: RefCell::new(client),
        }
    }

    pub fn with_defaults(network: crate::address_ux::BitcoinNetwork) -> Result<Self> {
        Ok(Self::new(
            crate::explorer::MempoolHttpClient::with_defaults(network)?,
        ))
    }

    pub fn network(&self) -> crate::address_ux::BitcoinNetwork {
        self.client.borrow().network()
    }
}

#[cfg(feature = "explorer-http")]
impl ChainSource for MempoolChainSource {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        let mut client = self.client.borrow_mut();
        // One tip-height probe for confirmation math across all address UTXOs.
        let tip = client
            .fetch_tip_height()
            .and_then(|b| crate::watcher::parse_tip_height(&b));

        let mut out = Vec::new();
        for addr in addresses {
            let body = client.fetch_address_utxos(addr).ok_or_else(|| {
                WalletError::Explorer(
                    "failed to fetch UTXOs for address (rate-limited or network error)".into(),
                )
            })?;
            let parsed = parse_mempool_address_utxos(&body, addr, tip)?;
            out.extend(parsed);
        }
        Ok(out)
    }
}

/// BIP84 account descriptors + derived receive/change address windows.
///
/// UTXO discovery is via an injectable [`ChainSource`] (mock, mempool,
/// [`crate::esplora::EsploraChainSource`], or [`crate::electrum::ElectrumChainSource`]).
/// Gap-limit helpers ([`Self::sync_utxos`], [`Self::sync_with_gap_extend`]) list
/// UTXOs for the current window and optionally extend it when the tip is used,
/// bounded by [`MAX_ADDRESS_GAP`]. This is **not** full `bdk_wallet` auto-sync.
///
/// The struct never stores BIP-39 or passphrase; extend APIs take
/// [`MnemonicSecret`] ephemerally (same pattern as signing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorWallet {
    network: Network,
    /// `wpkh(<account_xpub>/0/*)` external.
    pub receive_descriptor: String,
    /// `wpkh(<account_xpub>/1/*)` internal/change.
    pub change_descriptor: String,
    /// Account-level xpub string (no origin fingerprint in this pass).
    pub account_xpub: String,
    receive_addresses: Vec<String>,
    change_addresses: Vec<String>,
}

impl DescriptorWallet {
    /// Build BIP84 descriptors and a receive/change address gap from mnemonic.
    pub fn from_mnemonic(
        mnemonic: &MnemonicSecret,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(mnemonic, "", network, receive_gap)
    }

    /// Same with BIP-39 passphrase.
    ///
    /// `receive_gap` is clamped to `1..=`[`MAX_ADDRESS_GAP`] (same hard cap as
    /// extend). Both receive and change windows use this length at construction.
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        let gap = receive_gap.clamp(1, MAX_ADDRESS_GAP);
        let (account_xpub, origin) = account_xpub_and_origin(mnemonic, passphrase, network)?;
        // BIP380-style origin `[fingerprint/84h/coin'h/0h]` so BDK importers
        // can resolve the account path. Wildcard children stay `/0/*` `/1/*`.
        let receive_descriptor = format!("wpkh([{origin}]{account_xpub}/0/*)");
        let change_descriptor = format!("wpkh([{origin}]{account_xpub}/1/*)");

        let mut receive_addresses = Vec::with_capacity(gap as usize);
        for i in 0..gap {
            receive_addresses.push(derive_bip84_receive_address_with_passphrase(
                mnemonic, passphrase, network, i,
            )?);
        }
        // Change chain: m/84'/coin'/0'/1/{i} — derive via same path helper style.
        let mut change_addresses = Vec::with_capacity(gap as usize);
        for i in 0..gap {
            change_addresses.push(derive_bip84_change_address_with_passphrase(
                mnemonic, passphrase, network, i,
            )?);
        }

        Ok(Self {
            network,
            receive_descriptor,
            change_descriptor,
            account_xpub,
            receive_addresses,
            change_addresses,
        })
    }

    /// Convenience: parse `GROK_BITCOIN_NETWORK` style string (empty → mainnet).
    ///
    /// Uses empty BIP-39 passphrase (default path). Prefer
    /// [`Self::from_mnemonic_env_network_with_passphrase`] for passphrase wallets.
    pub fn from_mnemonic_env_network(
        mnemonic: &MnemonicSecret,
        network_str: &str,
        receive_gap: u32,
    ) -> Result<Self> {
        Self::from_mnemonic_env_network_with_passphrase(mnemonic, "", network_str, receive_gap)
    }

    /// Same as [`Self::from_mnemonic_env_network`] with BIP-39 passphrase.
    ///
    /// Passphrase must match the one used at funding/signing. Never log it.
    pub fn from_mnemonic_env_network_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network_str: &str,
        receive_gap: u32,
    ) -> Result<Self> {
        let trimmed = network_str.trim();
        let network = if trimmed.is_empty() {
            Network::Bitcoin
        } else {
            network_from_str(trimmed).ok_or_else(|| {
                WalletError::Onchain(format!(
                    "unknown GROK_BITCOIN_NETWORK value {trimmed:?}; \
                     use mainnet, signet, testnet, testnet4, or regtest"
                ))
            })?
        };
        Self::from_mnemonic_with_passphrase(mnemonic, passphrase, network, receive_gap)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn receive_addresses(&self) -> &[String] {
        &self.receive_addresses
    }

    pub fn change_addresses(&self) -> &[String] {
        &self.change_addresses
    }

    /// Current receive address window length (gap).
    pub fn receive_gap(&self) -> u32 {
        self.receive_addresses.len() as u32
    }

    /// Current change address window length (gap).
    pub fn change_gap(&self) -> u32 {
        self.change_addresses.len() as u32
    }

    /// First receive address (index 0), if the gap window is non-empty.
    pub fn primary_receive_address(&self) -> Option<&str> {
        self.receive_addresses.first().map(String::as_str)
    }

    /// All watched addresses (receive then change).
    pub fn watched_addresses(&self) -> Vec<String> {
        let mut all = self.receive_addresses.clone();
        all.extend(self.change_addresses.iter().cloned());
        all
    }

    /// List UTXOs known to `chain` for this wallet's address window.
    pub fn list_unspent(&self, chain: &dyn ChainSource) -> Result<Vec<WalletUtxo>> {
        let addrs = self.watched_addresses();
        let mut utxos = chain.list_unspent_for_addresses(&addrs)?;
        // Annotate change vs receive when the chain source left is_change false
        // but the address is in our change set.
        for u in &mut utxos {
            if self.change_addresses.iter().any(|a| a == &u.address) {
                u.is_change = true;
            }
        }
        Ok(utxos)
    }

    /// Sum confirmed (confs ≥ 1) and unconfirmed balances from chain UTXOs.
    pub fn balance(&self, chain: &dyn ChainSource) -> Result<WalletBalance> {
        let utxos = self.list_unspent(chain)?;
        balance_from_utxos(&utxos)
    }

    /// Fixed-window UTXO sync: list + balance + gap meta (no address growth).
    ///
    /// Only returns UTXOs the chain source provides for the current receive +
    /// change windows. Does **not** extend the gap (even when the tip is hot);
    /// use [`Self::sync_with_gap_extend`] when stop-gap / look-ahead should grow
    /// the watched set (bounded by [`MAX_ADDRESS_GAP`]).
    ///
    /// Propagates [`ChainSource`] errors unchanged.
    pub fn sync_utxos(&self, chain: &dyn ChainSource) -> Result<WalletSyncSnapshot> {
        let utxos = self.list_unspent(chain)?;
        self.snapshot_from_utxos(utxos, 0, 0, false)
    }

    /// One pass: list current window; if receive and/or change needs look-ahead
    /// room, append one extend step (independent chains).
    ///
    /// Does not loop. Call [`Self::sync_with_gap_extend`] for re-list until
    /// stable. Derivation failures and wrong passphrase (mismatch vs stored
    /// index 0) surface as [`WalletError::Onchain`]. Propagates chain errors.
    /// Never stores `mnemonic` / passphrase on `self`.
    ///
    /// **Chain calls:** one `list_unspent` for this pass (no final re-list).
    pub fn extend_gap_if_needed(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        chain: &dyn ChainSource,
        opts: GapExtendOptions,
    ) -> Result<GapExtendReport> {
        let max_gap = opts.effective_max_gap();
        let step = opts.effective_extend_step();
        let lookahead = opts.effective_lookahead();

        let receive_before = self.receive_gap();
        let change_before = self.change_gap();
        let utxos = self.list_unspent(chain)?;
        let hi_recv = highest_used_address_index(&self.receive_addresses, &utxos);
        let hi_chg = highest_used_address_index(&self.change_addresses, &utxos);

        let need_recv = address_window_needs_extend(hi_recv, receive_before, lookahead);
        let need_chg = address_window_needs_extend(hi_chg, change_before, lookahead);

        let mut hit_max_gap = false;
        let mut receive_extended = false;
        let mut change_extended = false;

        if need_recv {
            match next_gap_after_extend(receive_before, step, max_gap) {
                Some(new_gap) => {
                    self.extend_receive_window_to(mnemonic, passphrase, new_gap)?;
                    receive_extended = self.receive_gap() > receive_before;
                }
                None => hit_max_gap = true,
            }
        }
        if need_chg {
            match next_gap_after_extend(change_before, step, max_gap) {
                Some(new_gap) => {
                    self.extend_change_window_to(mnemonic, passphrase, new_gap)?;
                    change_extended = self.change_gap() > change_before;
                }
                None => hit_max_gap = true,
            }
        }

        Ok(GapExtendReport {
            receive_before,
            receive_after: self.receive_gap(),
            change_before,
            change_after: self.change_gap(),
            receive_extended,
            change_extended,
            hit_max_gap,
        })
    }

    /// Gap-limit ChainSource sync with bounded auto-extend of receive/change windows.
    ///
    /// Algorithm:
    /// 1. List UTXOs for the current receive + change windows.
    /// 2. If highest used receive (or change) index is within `lookahead` of
    ///    the window end (default look-ahead is BIP44-style stop-gap 20), append
    ///    `extend_step` addresses (capped by `max_gap` and hard [`MAX_ADDRESS_GAP`]).
    /// 3. Re-list; repeat until stable or no further growth is possible.
    ///
    /// **Chain calls:** each extend step performs one list; after the loop a
    /// final list builds the snapshot (stable sync ≈ N+1 lists where N is the
    /// number of extend steps, including a terminal no-grow probe). Live
    /// Esplora/Electrum backends are rate-limited separately.
    ///
    /// **Honesty:** only UTXOs returned by `chain`; unconfirmed (0-conf) UTXOs
    /// count as activity for gap (they appear in the list). Not full
    /// `bdk_wallet` auto-sync (no script history / spent-tx gap, no SPV). BIP-39
    /// is not retained on the wallet. Wrong passphrase → hard error before
    /// mutate (see [`Self::extend_receive_window_to`]).
    pub fn sync_with_gap_extend(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        chain: &dyn ChainSource,
        opts: GapExtendOptions,
    ) -> Result<WalletSyncSnapshot> {
        let max_gap = opts.effective_max_gap();
        // Each successful step grows a window by ≥1; bound iterations tightly.
        let max_iters = (max_gap as usize).saturating_mul(2).saturating_add(2);

        let mut extended_receive_by = 0u32;
        let mut extended_change_by = 0u32;
        let mut hit_max_gap = false;

        for _ in 0..max_iters {
            let report = self.extend_gap_if_needed(mnemonic, passphrase, chain, opts)?;
            if report.hit_max_gap {
                hit_max_gap = true;
            }
            if report.receive_extended {
                extended_receive_by = extended_receive_by
                    .saturating_add(report.receive_after.saturating_sub(report.receive_before));
            }
            if report.change_extended {
                extended_change_by = extended_change_by
                    .saturating_add(report.change_after.saturating_sub(report.change_before));
            }
            if !report.grew() {
                break;
            }
        }

        // Final list for snapshot (see method docs: one extra round-trip after
        // the terminal no-grow extend_gap_if_needed list).
        let utxos = self.list_unspent(chain)?;
        // If look-ahead still hot after stop, surface max-gap honesty even if
        // last extend_gap_if_needed returned grew=false only because max blocked.
        if !hit_max_gap {
            let hi_recv = highest_used_address_index(&self.receive_addresses, &utxos);
            let hi_chg = highest_used_address_index(&self.change_addresses, &utxos);
            let la = opts.effective_lookahead();
            if (address_window_needs_extend(hi_recv, self.receive_gap(), la)
                && next_gap_after_extend(self.receive_gap(), opts.effective_extend_step(), max_gap)
                    .is_none())
                || (address_window_needs_extend(hi_chg, self.change_gap(), la)
                    && next_gap_after_extend(
                        self.change_gap(),
                        opts.effective_extend_step(),
                        max_gap,
                    )
                    .is_none())
            {
                hit_max_gap = true;
            }
        }

        self.snapshot_from_utxos(utxos, extended_receive_by, extended_change_by, hit_max_gap)
    }

    /// Append receive addresses until the window length is `new_gap` (no shrink).
    ///
    /// Errors if derivation fails or if `mnemonic`/`passphrase` do not re-derive
    /// the existing window (index 0 check) — wrong passphrase must not silently
    /// append foreign addresses. Caps at [`MAX_ADDRESS_GAP`].
    pub fn extend_receive_window_to(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        new_gap: u32,
    ) -> Result<()> {
        let target = new_gap.min(MAX_ADDRESS_GAP);
        let current = self.receive_gap();
        if target <= current {
            return Ok(());
        }
        self.verify_receive_material(mnemonic, passphrase)?;
        for i in current..target {
            self.receive_addresses
                .push(derive_bip84_receive_address_with_passphrase(
                    mnemonic,
                    passphrase,
                    self.network,
                    i,
                )?);
        }
        Ok(())
    }

    /// Append change addresses until the window length is `new_gap` (no shrink).
    ///
    /// Same passphrase/material check as [`Self::extend_receive_window_to`].
    pub fn extend_change_window_to(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        new_gap: u32,
    ) -> Result<()> {
        let target = new_gap.min(MAX_ADDRESS_GAP);
        let current = self.change_gap();
        if target <= current {
            return Ok(());
        }
        self.verify_change_material(mnemonic, passphrase)?;
        for i in current..target {
            self.change_addresses
                .push(derive_bip84_change_address_with_passphrase(
                    mnemonic,
                    passphrase,
                    self.network,
                    i,
                )?);
        }
        Ok(())
    }

    /// Re-derive receive index 0; fail closed if material does not match the wallet.
    fn verify_receive_material(&self, mnemonic: &MnemonicSecret, passphrase: &str) -> Result<()> {
        let Some(stored) = self.receive_addresses.first() else {
            return Ok(());
        };
        let derived =
            derive_bip84_receive_address_with_passphrase(mnemonic, passphrase, self.network, 0)?;
        if derived != *stored {
            return Err(WalletError::Onchain(
                "gap extend aborted: mnemonic/passphrase does not re-derive wallet receive \
                 address index 0 (wrong passphrase or seed?); window left unchanged"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Re-derive change index 0; fail closed if material does not match the wallet.
    fn verify_change_material(&self, mnemonic: &MnemonicSecret, passphrase: &str) -> Result<()> {
        let Some(stored) = self.change_addresses.first() else {
            return Ok(());
        };
        let derived =
            derive_bip84_change_address_with_passphrase(mnemonic, passphrase, self.network, 0)?;
        if derived != *stored {
            return Err(WalletError::Onchain(
                "gap extend aborted: mnemonic/passphrase does not re-derive wallet change \
                 address index 0 (wrong passphrase or seed?); window left unchanged"
                    .into(),
            ));
        }
        Ok(())
    }

    fn snapshot_from_utxos(
        &self,
        utxos: Vec<WalletUtxo>,
        extended_receive_by: u32,
        extended_change_by: u32,
        hit_max_gap: bool,
    ) -> Result<WalletSyncSnapshot> {
        let highest_used_receive = highest_used_address_index(&self.receive_addresses, &utxos);
        let highest_used_change = highest_used_address_index(&self.change_addresses, &utxos);
        let balance = balance_from_utxos(&utxos)?;
        Ok(WalletSyncSnapshot {
            utxos,
            balance,
            receive_gap: self.receive_gap(),
            change_gap: self.change_gap(),
            highest_used_receive,
            highest_used_change,
            extended_receive_by,
            extended_change_by,
            hit_max_gap,
        })
    }
}

/// Confirmed (≥1 conf) vs unconfirmed totals.
pub fn balance_from_utxos(utxos: &[WalletUtxo]) -> Result<WalletBalance> {
    let mut bal = WalletBalance::default();
    for u in utxos {
        if u.confirmations >= 1 {
            bal.confirmed_sats = bal.confirmed_sats.saturating_add(u.amount_sats);
        } else {
            bal.unconfirmed_sats = bal.unconfirmed_sats.saturating_add(u.amount_sats);
        }
    }
    Ok(bal)
}

/// Select coins to cover `target_sats` (no fee model).
///
/// **Spend-safe default:** only UTXOs with `confirmations >= 1` are considered
/// (`confirmed_only = true`). Pass `confirmed_only = false` only for explicit
/// zero-conf experiments; product spend paths should keep the default.
///
/// For fee-aware selection use [`select_coins_with_fee`] or
/// [`select_coins_ex`]. Returns [`WalletError::Onchain`] when funds are
/// insufficient.
///
/// Feed the result into [`build_unsigned_psbt`] for a spend path.
pub fn select_coins(
    utxos: &[WalletUtxo],
    target_sats: u64,
    strategy: CoinSelectStrategy,
) -> Result<CoinSelection> {
    select_coins_with_options(utxos, target_sats, strategy, /*confirmed_only*/ true)
}

/// Coin selection with explicit confirmed-only filter (no fee model).
///
/// When `confirmed_only` is true (product default), unconfirmed (0-conf) UTXOs
/// are excluded before ordering. When false, all provided UTXOs may be selected.
pub fn select_coins_with_options(
    utxos: &[WalletUtxo],
    target_sats: u64,
    strategy: CoinSelectStrategy,
    confirmed_only: bool,
) -> Result<CoinSelection> {
    select_coins_ex(
        utxos,
        target_sats,
        CoinSelectOptions {
            strategy,
            confirmed_only,
            fee_rate_sat_vb: None,
        },
    )
}

/// Fee-aware coin selection (confirmed-only, product default).
///
/// Ensures `total_input >= target_sats + estimated_fee` using P2WPKH size
/// heuristics. Change below [`DUST_P2WPKH_SATS`] is folded into the fee (no
/// change output in the fee estimate).
///
/// Feed the result into [`build_unsigned_psbt`] (fee already accounted).
pub fn select_coins_with_fee(
    utxos: &[WalletUtxo],
    target_sats: u64,
    fee_rate_sat_vb: u64,
    strategy: CoinSelectStrategy,
) -> Result<CoinSelection> {
    select_coins_ex(
        utxos,
        target_sats,
        CoinSelectOptions {
            strategy,
            confirmed_only: true,
            fee_rate_sat_vb: Some(fee_rate_sat_vb),
        },
    )
}

/// Full coin selection with confirmed filter and optional fee rate.
pub fn select_coins_ex(
    utxos: &[WalletUtxo],
    target_sats: u64,
    options: CoinSelectOptions,
) -> Result<CoinSelection> {
    if target_sats == 0 {
        return Err(WalletError::Onchain(
            "coin selection target must be > 0 sats".into(),
        ));
    }
    let mut ordered: Vec<WalletUtxo> = if options.confirmed_only {
        utxos
            .iter()
            .filter(|u| u.confirmations >= 1)
            .cloned()
            .collect()
    } else {
        utxos.to_vec()
    };
    match options.strategy {
        CoinSelectStrategy::LargestFirst => {
            ordered.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats));
        }
        CoinSelectStrategy::SmallestFirst => {
            ordered.sort_by(|a, b| a.amount_sats.cmp(&b.amount_sats));
        }
    }

    let fee_rate = options.fee_rate_sat_vb.unwrap_or(0);
    let mut selected = Vec::new();
    let mut total = 0u64;

    for u in ordered {
        total = total.saturating_add(u.amount_sats);
        selected.push(u);
        let n_in = selected.len();

        if fee_rate == 0 {
            if total >= target_sats {
                return Ok(CoinSelection {
                    selected,
                    total_input_sats: total,
                    change_sats: total.saturating_sub(target_sats),
                    target_sats,
                    fee_sats: 0,
                });
            }
            continue;
        }

        // Prefer payment + change (2 outputs) when change is non-dust.
        // When 2-out fee is unaffordable *or* change would be dust, fall through
        // to the payment-only (1-output) path so the window
        // `needed_1out <= total < needed_2out` is not a false shortfall.
        let fee_with_change = estimate_fee_sats(n_in, 2, fee_rate);
        let needed_with_change = target_sats.saturating_add(fee_with_change);
        if total >= needed_with_change {
            let change = total - needed_with_change;
            if change >= DUST_P2WPKH_SATS {
                return Ok(CoinSelection {
                    selected,
                    total_input_sats: total,
                    change_sats: change,
                    target_sats,
                    fee_sats: fee_with_change,
                });
            }
            // else: dust change — try 1-output below
        }
        let fee_no_change = estimate_fee_sats(n_in, 1, fee_rate);
        let needed_no_change = target_sats.saturating_add(fee_no_change);
        if total >= needed_no_change {
            let fee_sats = total.saturating_sub(target_sats);
            return Ok(CoinSelection {
                selected,
                total_input_sats: total,
                change_sats: 0,
                target_sats,
                fee_sats,
            });
        }
        // Need more inputs if available.
    }

    let fee_hint = if fee_rate == 0 {
        String::new()
    } else {
        let n = selected.len().max(1);
        let est = estimate_fee_sats(n, 2, fee_rate);
        format!(" (+~{est} sats fee at {fee_rate} sat/vB)")
    };
    Err(WalletError::Onchain(format!(
        "insufficient funds: need {target_sats} sats{fee_hint}, have {total} sats in {} UTXOs{}",
        selected.len(),
        if options.confirmed_only {
            " (confirmed only)"
        } else {
            ""
        }
    )))
}

/// Build an **unsigned** PSBT from a [`CoinSelection`].
///
/// # Inputs / outputs
/// - One PSBT input per selected UTXO (`witness_utxo` filled from the UTXO
///   address + value; outpoint must be a 64-hex txid).
/// - Payment output: `params.payment_address` for `selection.target_sats`.
/// - Change output when `selection.change_sats > 0` (requires
///   `params.change_address`).
/// - Fee is the residual `total_input - outputs` and must equal
///   `selection.fee_sats`.
///
/// # Residual
/// - Does not sign, finalize, extract, or broadcast.
/// - Non-P2WPKH UTXO script types are accepted at build time (script_pubkey
///   from the address) but only BIP84 P2WPKH is signed by
///   [`sign_psbt_bip84_p2wpkh`].
///
/// # Dust change
/// Rejects `0 < change_sats < `[`DUST_P2WPKH_SATS`] so callers cannot emit a
/// non-relayable change output. Fee-aware [`select_coins_with_fee`] already
/// folds dust into the fee; hand-built / zero-fee selections must do the same
/// before build (or set `change_sats = 0` and absorb dust into `fee_sats`).
pub fn build_unsigned_psbt(selection: &CoinSelection, params: &SpendParams) -> Result<BuiltPsbt> {
    if selection.selected.is_empty() {
        return Err(WalletError::Onchain(
            "coin selection has no inputs to spend".into(),
        ));
    }
    if selection.target_sats == 0 {
        return Err(WalletError::Onchain(
            "payment amount (target_sats) must be > 0".into(),
        ));
    }
    if selection.change_sats > 0 && selection.change_sats < DUST_P2WPKH_SATS {
        return Err(WalletError::Onchain(format!(
            "change_sats {} is below P2WPKH dust threshold {DUST_P2WPKH_SATS}; \
             fold dust into fee_sats (change_sats = 0) before PSBT build",
            selection.change_sats
        )));
    }

    let payment_addr = parse_network_address(&params.payment_address, params.network)?;
    let change_addr = if selection.change_sats > 0 {
        let s = params.change_address.as_deref().ok_or_else(|| {
            WalletError::Onchain(
                "change_sats > 0 but no change_address provided for PSBT build".into(),
            )
        })?;
        Some(parse_network_address(s, params.network)?)
    } else {
        None
    };

    let mut output_sum = selection.target_sats;
    if selection.change_sats > 0 {
        output_sum = output_sum.saturating_add(selection.change_sats);
    }
    if selection.total_input_sats < output_sum {
        return Err(WalletError::Onchain(format!(
            "selection imbalance: inputs {} sats < outputs {} sats",
            selection.total_input_sats, output_sum
        )));
    }
    let fee_from_balance = selection.total_input_sats - output_sum;
    if fee_from_balance != selection.fee_sats {
        return Err(WalletError::Onchain(format!(
            "selection fee mismatch: inputs {} - outputs {} = {} but fee_sats is {}",
            selection.total_input_sats, output_sum, fee_from_balance, selection.fee_sats
        )));
    }

    let mut tx_inputs = Vec::with_capacity(selection.selected.len());
    let mut psbt_inputs = Vec::with_capacity(selection.selected.len());
    let mut recomputed_input = 0u64;
    let mut seen_outpoints = HashSet::with_capacity(selection.selected.len());

    for utxo in &selection.selected {
        let outpoint = outpoint_from_ref(&utxo.outpoint)?;
        if !seen_outpoints.insert(outpoint) {
            return Err(WalletError::Onchain(format!(
                "duplicate outpoint in coin selection: {}:{}",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        let prev_addr = parse_network_address(&utxo.address, params.network)?;
        recomputed_input = recomputed_input.saturating_add(utxo.amount_sats);

        tx_inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });

        psbt_inputs.push(PsbtInput {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(utxo.amount_sats),
                script_pubkey: prev_addr.script_pubkey(),
            }),
            ..Default::default()
        });
    }

    if recomputed_input != selection.total_input_sats {
        return Err(WalletError::Onchain(format!(
            "selection total_input_sats {} != sum of selected UTXOs {}",
            selection.total_input_sats, recomputed_input
        )));
    }

    let mut tx_outputs = vec![TxOut {
        value: Amount::from_sat(selection.target_sats),
        script_pubkey: payment_addr.script_pubkey(),
    }];
    if let Some(change) = change_addr {
        tx_outputs.push(TxOut {
            value: Amount::from_sat(selection.change_sats),
            script_pubkey: change.script_pubkey(),
        });
    }

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| WalletError::Onchain(format!("PSBT from unsigned tx: {e}")))?;
    psbt.inputs = psbt_inputs;

    Ok(BuiltPsbt {
        psbt,
        fee_sats: selection.fee_sats,
        payment_sats: selection.target_sats,
        change_sats: selection.change_sats,
    })
}

/// Attach BIP84 derivation metadata and ECDSA-sign P2WPKH inputs owned by
/// `mnemonic` within `address_gap` receive + change indices.
///
/// Uses `bitcoin::psbt::Psbt::sign` with the master [`Xpriv`] (never logged).
/// Intermediate seed bytes are zeroized after master key creation.
///
/// # Residual
/// - Does **not** finalize witnesses or extract a transaction.
/// - Inputs whose script_pubkey is not a BIP84 P2WPKH address in the scanned
///   gap are left unsigned ([`SignOutcome::Partial`]) — not a complete spend.
/// - Network broadcast is not implemented in this crate.
pub fn sign_psbt_bip84_p2wpkh(
    psbt: &mut Psbt,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    address_gap: u32,
) -> Result<SignOutcome> {
    if psbt.inputs.is_empty() {
        return Err(WalletError::Onchain("PSBT has no inputs to sign".into()));
    }
    let gap = address_gap.max(1);
    let secp = Secp256k1::new();

    let mut seed = mnemonic.to_seed(passphrase);
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| WalletError::Onchain(format!("master for sign: {e}")))?;
    seed.zeroize();

    let fingerprint = master.fingerprint(&secp);
    let lookup = bip84_script_lookup(mnemonic, passphrase, network, gap)?;

    for input in &mut psbt.inputs {
        let Some(utxo) = input.witness_utxo.as_ref() else {
            continue;
        };
        if let Some((pubkey, path)) = lookup.get(&utxo.script_pubkey) {
            let key_source: KeySource = (fingerprint, path.clone());
            input.bip32_derivation.insert(*pubkey, key_source);
        }
    }

    // Sign with master xpriv; GetKey derives via bip32_derivation paths.
    // `Psbt::sign` may report an input as "used" even when bip32_derivation was
    // empty (no sigs written) — count real partial_sigs instead.
    // Note: `Xpriv` is `Copy` in bitcoin 0.32, so we cannot rely on Drop zeroize;
    // seed bytes above were already zeroized after master creation.
    let _ = psbt.sign(&master, &secp);
    let _ = master; // end of use; avoid lingering named binding past this point

    let signed = psbt
        .inputs
        .iter()
        .filter(|i| !i.partial_sigs.is_empty())
        .count();
    let total = psbt.inputs.len();
    let unsigned = total.saturating_sub(signed);

    if signed == total {
        Ok(SignOutcome::AllSigned {
            signed_inputs: signed,
        })
    } else if signed == 0 {
        // Prefer a clear residual over a hard error when keys simply don't cover
        // the inputs (foreign UTXO / gap miss) — callers decide whether to abort.
        Ok(SignOutcome::Partial {
            signed_inputs: 0,
            unsigned_inputs: unsigned,
            detail: format!(
                "signed 0/{total} inputs; no BIP84 P2WPKH keys matched within gap {gap} \
                 (not broadcast-ready)"
            ),
        })
    } else {
        Ok(SignOutcome::Partial {
            signed_inputs: signed,
            unsigned_inputs: unsigned,
            detail: format!(
                "signed {signed}/{total} inputs; unresolved inputs not in BIP84 gap {gap} \
                 (not broadcast-ready)"
            ),
        })
    }
}

/// Per-input offline finalize result (shared Complete vs Partial gate).
#[derive(Debug)]
enum FinalizeInputStep {
    /// Input already had or received non-empty final material.
    Finalized,
    /// Could not finalize offline without inventing material.
    Residual(String),
}

/// Clear empty final fields so residual partial_sigs can still produce real finals.
fn clear_empty_final_fields(input: &mut PsbtInput) {
    if input
        .final_script_witness
        .as_ref()
        .is_some_and(|w| w.is_empty())
    {
        input.final_script_witness = None;
    }
    if input
        .final_script_sig
        .as_ref()
        .is_some_and(|s| s.is_empty())
    {
        input.final_script_sig = None;
    }
}

/// Resolve prevout scriptPubKey from `witness_utxo` or `non_witness_utxo`.
fn input_prevout_script_pubkey(input: &PsbtInput, prevout: OutPoint) -> Option<ScriptBuf> {
    if let Some(utxo) = input.witness_utxo.as_ref() {
        return Some(utxo.script_pubkey.clone());
    }
    if let Some(tx) = input.non_witness_utxo.as_ref() {
        let vout = prevout.vout as usize;
        return tx.output.get(vout).map(|o| o.script_pubkey.clone());
    }
    None
}

/// Push bytes into a script builder helper (bounded by bitcoin push limits).
fn script_push_bytes(data: &[u8]) -> Result<bitcoin::script::PushBytesBuf> {
    bitcoin::script::PushBytesBuf::try_from(data.to_vec())
        .map_err(|e| WalletError::Onchain(format!("script data push rejected: {e}")))
}

/// Detect bare single-key `<pubkey> OP_CHECKSIG` witness/redeem scripts.
///
/// Returns the pubkey when the script is exactly that template; otherwise
/// `None` (CHECKMULTISIG is handled separately via
/// [`bare_checkmultisig_template`]).
fn single_checksig_pubkey(script: &bitcoin::Script) -> Option<bitcoin::PublicKey> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKSIG;

    let mut iter = script.instructions();
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    bitcoin::PublicKey::from_slice(push.as_bytes()).ok()
}

/// Detect bare Taproot leaf `<32-byte x-only pk> OP_CHECKSIG`.
///
/// Tapscript leaves use x-only (BIP-340) pubkeys, not compressed ECDSA.
/// Returns `None` for empty / multi-op / non-32-byte pushes / CHECKMULTISIG
/// or miniscript templates (those stay residual). multi_a leaves are handled
/// separately via [`bare_tapscript_checksigadd_multi_template`].
fn single_tapscript_checksig_xonly(
    script: &bitcoin::Script,
) -> Option<bitcoin::secp256k1::XOnlyPublicKey> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKSIG;

    let mut iter = script.instructions();
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()
}

/// Parse bare Taproot multi_a leaf (BIP-342 CHECKSIGADD k-of-n):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// <xonly2> OP_CHECKSIGADD
/// …
/// <xonlyn> OP_CHECKSIGADD
/// <k> OP_NUMEQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` when the script is exactly
/// that template with `n ≥ 2` and `k ∈ 1..=n` via `OP_1..=OP_16`. Otherwise
/// `None` (single-key CHECKSIG, other miniscript, non-standard stays residual).
///
/// Witness stack for this template is n elements in **reverse key order**
/// (sig for last key first), with empty vectors for unused keys when `k < n`.
fn bare_tapscript_checksigadd_multi_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];

    // Remaining: (<xonly> OP_CHECKSIGADD)+ then <k> OP_NUMEQUAL.
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let kb = b.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGADD => {
                        pubkeys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_NUMEQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // multi_a requires at least one CHECKSIGADD (n ≥ 2).
                if pubkeys.len() < 2 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Err(_) => return None,
        }
    }
}

/// Parse bare Taproot and_v n-of-n leaf (CHECKSIGVERIFY chain):
///
/// ```text
/// <xonly1> OP_CHECKSIGVERIFY
/// <xonly2> OP_CHECKSIGVERIFY
/// …
/// <xonly{n-1}> OP_CHECKSIGVERIFY
/// <xonlyn> OP_CHECKSIG
/// ```
///
/// Returns pubkeys in script order when the script is exactly that template
/// with `n ≥ 2`. Otherwise `None` (single-key CHECKSIG, multi_a, other
/// miniscript stays residual).
///
/// All n signatures are required (CHECKSIGVERIFY rejects empty placeholders).
/// Witness stack is n elements in **reverse key order** (sig for last key
/// first) — same order as multi_a full-threshold stacks.
fn bare_tapscript_and_v_checksigverify_template(
    script: &bitcoin::Script,
) -> Option<Vec<bitcoin::secp256k1::XOnlyPublicKey>> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // Require at least one CHECKSIGVERIFY then a final CHECKSIG (n ≥ 2).
    // Pattern: (<xonly> CHECKSIGVERIFY)+ <xonly> CHECKSIG
    loop {
        let push = match iter.next()? {
            Ok(Instruction::PushBytes(b)) => b,
            _ => return None,
        };
        let bytes = push.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                pubkeys.push(pk);
                // Continue for more CSV pairs or the final CHECKSIG key.
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                pubkeys.push(pk);
                if iter.next().is_some() {
                    return None;
                }
                // Need ≥ 1 CHECKSIGVERIFY before this final CHECKSIG ⇒ n ≥ 2.
                if pubkeys.len() < 2 {
                    return None;
                }
                return Some(pubkeys);
            }
            _ => return None,
        }
    }
}

/// Parse bare Taproot or_i dual-key leaf (miniscript `or_i(pk(A), pk(B))`):
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIG
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_if, pk_else)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Witness script inputs (before leaf + control block):
/// - IF branch (A): `<sigA> <0x01>`
/// - ELSE branch (B): `<sigB> <empty>`
///
/// Policy when both sigs present: prefer IF branch (A) — deterministic, no
/// invented branch selector beyond the standard OP_IF encoding of present
/// material.
fn bare_tapscript_or_i_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_IF};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b))
}

/// Parse bare Taproot or_c dual-key leaf (miniscript `or_c(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// **Honesty:** bare top-level `or_c` is **CLEANSTACK-invalid** as a spend leaf
/// (A path leaves an empty stack after CHECKSIG consumes the sig — no IFDUP to
/// re-push the result). Detection exists only so finalize can emit a distinct
/// residual reason; **never assemble** a final witness for this template.
/// Prefer nested CLEANSTACK-valid forms only when offline-proved (not invented).
fn bare_tapscript_or_c_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_NOTIF};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b))
}

/// Parse bare Taproot or_d dual-key leaf (miniscript `or_d(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_IFDUP
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (IFDUP keeps the CHECKSIG true for CLEANSTACK)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A;
///   never an invented Schnorr)
///
/// Policy when both sigs present: prefer A — deterministic, no invented
/// branch beyond present material. Bare `or_c` (CHECKSIG NOTIF … without
/// IFDUP) is **not** a valid top-level spend leaf under CLEANSTACK (A path
/// leaves empty stack) and stays residual.
fn bare_tapscript_or_d_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IFDUP, OP_NOTIF};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IFDUP => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b))
}

/// Parse bare Taproot and_n dual-key leaf (miniscript `and_n(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   OP_0
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Both signatures are required (when A is false the script pushes 0 and
/// never evaluates B). Witness script inputs: `<sigB> <sigA>` (B then A;
/// reverse of script evaluation order so A is top-of-stack first).
/// Never invents empty dissatisfaction slots for a partial and_n spend.
fn bare_tapscript_and_n_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_NOTIF};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    // OP_0 / OP_FALSE is encoded as empty PushBytes (OP_PUSHBYTES_0).
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes().is_empty() => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b))
}

/// Parse bare Taproot andor triple-key leaf
/// (miniscript `andor(pk(A), pk(B), pk(C))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyC> OP_CHECKSIG
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b, pk_c)` when the script is exactly that template.
/// Otherwise `None`. Distinct from [`bare_tapscript_and_n_checksig_template`]
/// (which pushes OP_0 in the NOTIF branch, not a third key).
///
/// Witness script inputs (before leaf + control block):
/// - AB path: `<sigB> <sigA>` (A true → ELSE evaluates B; both required)
/// - C path: `<sigC> <empty>` (empty = BIP-342 dissatisfaction of A;
///   never an invented Schnorr)
///
/// Policy when material allows both: prefer AB when A+B are present;
/// otherwise C when sigC is present. Never invents a third key, empty
/// dissatisfaction without a present C, or AB when either A or B is missing.
fn bare_tapscript_andor_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_NOTIF};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    // NOTIF branch: third key C (not OP_0 — that is and_n).
    let push_c = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_c = push_c.as_bytes();
    if bytes_c.len() != 32 {
        return None;
    }
    let pk_c = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_c).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c))
}

/// Parse bare Taproot thresh-of-pks leaf (miniscript
/// `thresh(k, pk(A), s:pk(B), …, s:pk(N))`):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// OP_SWAP <xonly2> OP_CHECKSIG OP_ADD
/// …
/// OP_SWAP <xonlyn> OP_CHECKSIG OP_ADD
/// <k> OP_EQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` when the script is exactly
/// that template with `n ≥ 2` and `k ∈ 1..=n` via `OP_1..=OP_16`. Otherwise
/// `None`.
///
/// Distinct from [`bare_tapscript_checksigadd_multi_template`] (`multi_a`
/// uses `CHECKSIGADD` + `NUMEQUAL`, no `SWAP`/`ADD`). Policy compilers often
/// emit multi_a for all-key thresholds on Taproot; this form is the explicit
/// miniscript `thresh` encoding with `s:` (SWAP) wrappers on subsequent keys.
///
/// Witness stack is n elements in **reverse key order** (sig for last key
/// first), with empty BIP-342 vectors for unused keys when `k < n` — same
/// policy as multi_a (first k keys **that already have** `tap_script_sigs`
/// in script order; never invents signatures).
fn bare_tapscript_thresh_checksig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_SWAP};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B; no SWAP).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];

    // Remaining: (OP_SWAP <xonly> OP_CHECKSIG OP_ADD)+ then <k> OP_EQUAL.
    // After the first CHECKSIG the next opcode is either SWAP (another key)
    // or a small pushnum k followed by EQUAL (end). multi_a would push a key
    // next (no SWAP) — rejected here.
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_SWAP => {
                let push_i = match iter.next()? {
                    Ok(Instruction::PushBytes(b)) => b,
                    _ => return None,
                };
                let kb = push_i.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op3)) if op3 == OP_ADD => {
                        pubkeys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // thresh-of-pks requires at least one SWAP arm (n ≥ 2).
                if pubkeys.len() < 2 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// Miniscript hash fragment kind (sha256 / hash256 / ripemd160 / hash160).
///
/// All four encode as `SIZE <32> EQUALVERIFY <HASHOP> <digest> EQUAL` with a
/// **32-byte** preimage (SIZE check is always 32, even for 20-byte digests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TapscriptHashKind {
    Sha256,
    Hash256,
    Ripemd160,
    Hash160,
}

impl TapscriptHashKind {
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Hash256 => "hash256",
            Self::Ripemd160 => "ripemd160",
            Self::Hash160 => "hash160",
        }
    }

    fn from_hash_op(op: bitcoin::opcodes::Opcode) -> Option<Self> {
        use bitcoin::opcodes::all::{OP_HASH160, OP_HASH256, OP_RIPEMD160, OP_SHA256};
        if op == OP_SHA256 {
            Some(Self::Sha256)
        } else if op == OP_HASH256 {
            Some(Self::Hash256)
        } else if op == OP_RIPEMD160 {
            Some(Self::Ripemd160)
        } else if op == OP_HASH160 {
            Some(Self::Hash160)
        } else {
            None
        }
    }

    fn expected_digest_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Hash256 => 32,
            Self::Ripemd160 | Self::Hash160 => 20,
        }
    }
}

/// Parse bare Taproot miniscript hash leaf:
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(kind, digest bytes)` when the script is exactly that template.
/// Witness: single 32-byte preimage already present in the matching PSBT
/// preimage map (never invented).
fn bare_tapscript_hash_preimage_template(
    script: &bitcoin::Script,
) -> Option<(TapscriptHashKind, Vec<u8>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        _ => return None,
    }
    // Miniscript always SIZE-checks 32 (even for 20-byte digests).
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest = digest_push.as_bytes();
    if digest.len() != kind.expected_digest_len() {
        return None;
    }
    let digest = digest.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((kind, digest))
}

/// Parse bare Taproot `and_v(v:pk(A), hash(H))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, kind, digest)` when the script is exactly that template.
/// Witness script inputs: `<preimage> <sigA>` (sig on top so CHECKSIGVERIFY
/// runs first; preimage deeper for the hash fragment). Never invents sigs or
/// preimages — both must already be present on the PSBT.
fn bare_tapscript_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    // Remainder must be the bare hash fragment.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest = digest_push.as_bytes();
    if digest.len() != kind.expected_digest_len() {
        return None;
    }
    let digest = digest.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, kind, digest))
}

/// Parse a miniscript `older(n)` / BIP-112 CSV argument from a script instruction.
///
/// Accepts OP_1..=OP_16 and minimal scriptnum pushes. Rejects 0, negatives,
/// and values with the relative-locktime **disable** flag set (bit 31).
/// Returns the consensus `u32` used as both the script push and the BIP-68
/// relative locktime encoding (height or time-interval bits).
fn parse_csv_older_n(instr: bitcoin::blockdata::script::Instruction<'_>) -> Option<u32> {
    let n = instr.script_num()?;
    if n <= 0 || n > i64::from(u32::MAX) {
        return None;
    }
    let n = n as u32;
    // BIP-112 disable flag on the stack item → relative locktime not enforced.
    if n & 0x8000_0000 != 0 {
        return None;
    }
    let seq = Sequence::from_consensus(n);
    if !seq.is_relative_lock_time() {
        return None;
    }
    // Miniscript older requires non-zero value bits (height or 512s intervals).
    if n & 0xffff == 0 {
        return None;
    }
    // Must decode as a relative::LockTime (type bits consistent).
    let _ = seq.to_relative_lock_time()?;
    Some(n)
}

/// True when BIP-112 `CHECKSEQUENCEVERIFY` for miniscript `older(n)` would pass
/// given the **already-present** tx version and input nSequence.
///
/// Does **not** check chain age (BIP-68 mempool/consensus finality) — only that
/// the unsigned tx already encodes a compatible nSequence ≥ required. Never
/// invents or mutates nSequence / nLockTime / version.
fn sequence_satisfies_csv_older(
    tx_version: transaction::Version,
    sequence: Sequence,
    older_n: u32,
) -> bool {
    // BIP-112: when the stack item's disable flag is unset, tx version must be ≥ 2.
    if tx_version.0 < 2 {
        return false;
    }
    let Some(required) = Sequence::from_consensus(older_n).to_relative_lock_time() else {
        return false;
    };
    required.is_implied_by_sequence(sequence)
}

/// Parse bare Taproot `and_v(v:pk(A), older(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, older_n)` when the script is exactly that template.
/// Witness script inputs: `<sigA>` (sig alone; CSV uses nSequence, not the
/// witness). Requires matching `tap_script_sig` **and** unsigned-tx nSequence
/// that satisfies BIP-112 for `n` — never invents either.
fn bare_tapscript_and_v_pk_older_template(
    script: &bitcoin::Script,
) -> Option<(bitcoin::secp256k1::XOnlyPublicKey, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, older_n))
}

/// Parse bare Taproot `and_v(v:older(n), pk(A))` leaf:
///
/// ```text
/// <n> OP_CSV OP_VERIFY
/// <xonlyA> OP_CHECKSIG
/// ```
///
/// (`v:older` encodes as CSV + OP_VERIFY — CSV is not a combined VERIFY opcode.)
/// Returns `(older_n, pk_a)` when the script is exactly that template.
/// Witness: `<sigA>`. Requires matching sig + satisfying nSequence.
fn bare_tapscript_and_v_older_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, bitcoin::secp256k1::XOnlyPublicKey)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_VERIFY};

    let mut iter = script.instructions();
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((older_n, pk_a))
}

/// Parse bare Taproot miniscript `older(n)` leaf:
///
/// ```text
/// <n> OP_CSV
/// ```
///
/// Returns `older_n` when the script is exactly that template. Witness script
/// inputs are empty (CSV uses nSequence only). Completes only when unsigned-tx
/// nSequence already satisfies BIP-112 for `n`.
fn bare_tapscript_older_template(script: &bitcoin::Script) -> Option<u32> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CSV;

    let mut iter = script.instructions();
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some(older_n)
}

/// Parse a miniscript `after(n)` / BIP-65 CLTV argument from a script instruction.
///
/// Accepts OP_1..=OP_16 and minimal scriptnum pushes. Rejects 0, negatives, and
/// values above miniscript's absolute-locktime max (`0x7FFF_FFFF`). Returns the
/// consensus `u32` used as both the script push and the BIP-65 absolute
/// locktime encoding (height if `< LOCK_TIME_THRESHOLD`, else UNIX time).
fn parse_cltv_after_n(instr: bitcoin::blockdata::script::Instruction<'_>) -> Option<u32> {
    let n = instr.script_num()?;
    // Miniscript AbsLockTime: 1..=0x7FFF_FFFF (0 is boolean-abused; high bit
    // would be negative as a CScriptNum / is outside miniscript after range).
    if n < 1 || n > i64::from(0x7FFF_FFFFu32) {
        return None;
    }
    Some(n as u32)
}

/// True when BIP-65 `CHECKLOCKTIMEVERIFY` for miniscript `after(n)` would pass
/// given the **already-present** tx nLockTime and input nSequence.
///
/// Does **not** check chain height/time (mempool/consensus finality) — only that
/// the unsigned tx already encodes a compatible nLockTime ≥ required with the
/// same unit, and that nSequence enables absolute locktime
/// (`!= Sequence::MAX`). Never invents or mutates nLockTime / nSequence.
fn locktime_satisfies_cltv_after(lock_time: LockTime, sequence: Sequence, after_n: u32) -> bool {
    // BIP-65: final sequence (0xffffffff) disables nLockTime for this input → CLTV fails.
    if !sequence.enables_absolute_lock_time() {
        return false;
    }
    let required = LockTime::from_consensus(after_n);
    // required.is_implied_by(lock_time) ⇔ same unit and required ≤ lock_time.
    required.is_implied_by(lock_time)
}

/// Parse bare Taproot `and_v(v:pk(A), after(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, after_n)` when the script is exactly that template.
/// Witness script inputs: `<sigA>` (sig alone; CLTV uses nLockTime, not the
/// witness). Requires matching `tap_script_sig` **and** unsigned-tx nLockTime
/// that satisfies BIP-65 for `n` with a non-final nSequence — never invents either.
fn bare_tapscript_and_v_pk_after_template(
    script: &bitcoin::Script,
) -> Option<(bitcoin::secp256k1::XOnlyPublicKey, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV};

    let mut iter = script.instructions();
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, after_n))
}

/// Parse bare Taproot `and_v(v:after(n), pk(A))` leaf:
///
/// ```text
/// <n> OP_CLTV OP_VERIFY
/// <xonlyA> OP_CHECKSIG
/// ```
///
/// (`v:after` encodes as CLTV + OP_VERIFY — CLTV is not a combined VERIFY opcode.)
/// Returns `(after_n, pk_a)` when the script is exactly that template.
/// Witness: `<sigA>`. Requires matching sig + satisfying nLockTime/nSequence.
fn bare_tapscript_and_v_after_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, bitcoin::secp256k1::XOnlyPublicKey)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_VERIFY};

    let mut iter = script.instructions();
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((after_n, pk_a))
}

/// Parse bare Taproot miniscript `after(n)` leaf:
///
/// ```text
/// <n> OP_CLTV
/// ```
///
/// Returns `after_n` when the script is exactly that template. Witness script
/// inputs are empty (CLTV uses nLockTime only). Completes only when unsigned-tx
/// nLockTime already satisfies BIP-65 for `n` with a non-final nSequence.
fn bare_tapscript_after_template(script: &bitcoin::Script) -> Option<u32> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CLTV;

    let mut iter = script.instructions();
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some(after_n)
}

/// Look up a miniscript hash preimage already present on the PSBT input map.
///
/// Returns:
/// - `Ok(Some(preimage))` when the matching map has a **32-byte** preimage
///   whose hash equals `digest` (BIP-174 key consistency)
/// - `Ok(None)` when the preimage is absent (honest Partial residual)
/// - `Err` when a map entry is present but corrupt (wrong hash / not 32 bytes
///   for miniscript SIZE) — tamper/corrupt, not silent finalize
fn lookup_miniscript_hash_preimage(
    idx: usize,
    input: &PsbtInput,
    kind: TapscriptHashKind,
    digest: &[u8],
) -> Result<Option<Vec<u8>>> {
    use bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};

    let preimage = match kind {
        TapscriptHashKind::Sha256 => {
            let key = sha256::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: sha256 digest in leaf is not 32 bytes: {e}"
                ))
            })?;
            input.sha256_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Hash256 => {
            let key = sha256d::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: hash256 digest in leaf is not 32 bytes: {e}"
                ))
            })?;
            input.hash256_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Ripemd160 => {
            let key = ripemd160::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: ripemd160 digest in leaf is not 20 bytes: {e}"
                ))
            })?;
            input.ripemd160_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Hash160 => {
            let key = hash160::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: hash160 digest in leaf is not 20 bytes: {e}"
                ))
            })?;
            input.hash160_preimages.get(&key).cloned()
        }
    };

    let Some(preimage) = preimage else {
        return Ok(None);
    };

    // Miniscript SIZE <32> EQUALVERIFY — preimage must be exactly 32 bytes.
    if preimage.len() != 32 {
        return Err(WalletError::Onchain(format!(
            "input {idx}: {} preimage present but length {} (miniscript requires 32; \
             corrupt/tamper; not broadcast-ready)",
            kind.name(),
            preimage.len()
        )));
    }

    // BIP-174: map key must be the hash of the preimage value.
    let computed: Vec<u8> = match kind {
        TapscriptHashKind::Sha256 => sha256::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Hash256 => sha256d::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Ripemd160 => ripemd160::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Hash160 => hash160::Hash::hash(&preimage).to_byte_array().to_vec(),
    };
    if computed.as_slice() != digest {
        return Err(WalletError::Onchain(format!(
            "input {idx}: {} preimage does not hash to leaf digest (tamper/corrupt; \
             not broadcast-ready)",
            kind.name()
        )));
    }
    Ok(Some(preimage))
}

/// Extract the 32-byte output key from a native P2TR scriptPubKey.
fn p2tr_output_key(spk: &bitcoin::Script) -> Option<bitcoin::secp256k1::XOnlyPublicKey> {
    if !spk.is_p2tr() {
        return None;
    }
    // P2TR: OP_PUSHNUM_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32-byte key.
    let bytes = spk.as_bytes();
    if bytes.len() != 34 {
        return None;
    }
    bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes[2..34]).ok()
}

/// Decode OP_1..=OP_16 small integer push (standard bare multisig m/n).
fn small_pushnum(op: bitcoin::opcodes::Opcode) -> Option<u8> {
    use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16};
    let code = op.to_u8();
    let start = OP_PUSHNUM_1.to_u8();
    let end = OP_PUSHNUM_16.to_u8();
    if (start..=end).contains(&code) {
        Some(code - start + 1)
    } else {
        None
    }
}

/// Parse bare standard `OP_m <pk1>…<pkn> OP_n OP_CHECKMULTISIG` (m,n ∈ 1..=16).
///
/// Returns `(threshold m, pubkeys in script order)` when the script is exactly
/// that template; otherwise `None` (non-standard / miniscript stay residual).
fn bare_checkmultisig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::PublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;

    let mut iter = script.instructions();
    let m = match iter.next()? {
        Ok(Instruction::Op(op)) => small_pushnum(op)?,
        _ => return None,
    };
    if m == 0 {
        return None;
    }

    let mut pubkeys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let pk = bitcoin::PublicKey::from_slice(b.as_bytes()).ok()?;
                pubkeys.push(pk);
            }
            Ok(Instruction::Op(op)) => {
                let n = small_pushnum(op)?;
                if n as usize != pubkeys.len() {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKMULTISIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    if pubkeys.is_empty() || (m as usize) > pubkeys.len() {
        return None;
    }
    Some((m as usize, pubkeys))
}

/// Try to finalize one input offline without inventing witnesses.
///
/// # Completeable offline
/// - Already-present non-empty finals (preserved)
/// - Single-key P2WPKH
/// - Single-key P2SH-P2WPKH (redeem_script is P2WPKH)
/// - Single-key P2PKH → `final_script_sig`
/// - Single-key P2WSH with bare CHECKSIG `witness_script`
/// - Bare m-of-n CHECKMULTISIG P2WSH / nested P2SH-P2WSH when ≥ m matching
///   `partial_sigs` for script pubkeys are present (assembler adds BIP147
///   NULLDUMMY + script-order sigs; never invents)
/// - Taproot **key-path** P2TR when `tap_key_sig` is already present
/// - Taproot **script-path** P2TR when present `tap_scripts` + matching
///   `tap_script_sigs` / PSBT preimage maps cover a bare x-only CHECKSIG leaf,
///   bare multi_a CHECKSIGADD k-of-n leaf, bare thresh (SWAP/CHECKSIG/ADD + k
///   EQUAL) k-of-n leaf, bare and_v CHECKSIGVERIFY chain, bare or_i IF/ELSE
///   dual CHECKSIG, bare or_d IFDUP NOTIF dual CHECKSIG, bare and_n NOTIF 0
///   ELSE dual CHECKSIG, bare andor NOTIF/ELSE triple CHECKSIG, bare
///   miniscript hash leaf, and_v(v:pk, hash), older/CSV forms
///   (`and_v(v:pk, older)` / `and_v(v:older, pk)` / bare `older` when
///   nSequence on the unsigned tx already satisfies BIP-112; never invented),
///   or after/CLTV forms (`and_v(v:pk, after)` / `and_v(v:after, pk)` /
///   bare `after` when nLockTime on the unsigned tx already satisfies BIP-65
///   with a non-final nSequence; never invented)
///
/// # Residual
/// - CHECKMULTISIG / multi_a / thresh / and_v / and_n with fewer than threshold matching sigs
/// - or_i / or_d with neither branch matching `tap_script_sig`
/// - andor with neither AB nor C completeable from present sigs
/// - bare hash / and_v(v:pk, hash) missing preimage or missing pk sig
/// - older/CSV with missing sig or nSequence that does not satisfy BIP-112
/// - after/CLTV with missing sig or nLockTime/nSequence that does not satisfy BIP-65
/// - Taproot other complex script-path / miniscript (or_c/…)
///   / bare legacy P2SH multi-sig / non-standard templates / incomplete maps
/// - Missing UTXO / scripts / partial_sigs / `tap_key_sig` / control block
///
/// Hard errors: pubkey HASH160 / witness_script hash mismatch against a
/// matching template; Taproot `tap_internal_key` (+ optional merkle root)
/// mismatch against P2TR scriptPubKey; control block that fails taproot
/// commitment verify (tamper/corrupt), not silent skip.
fn try_finalize_input(
    idx: usize,
    input: &mut PsbtInput,
    prevout: OutPoint,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    clear_empty_final_fields(input);
    if input_is_finalized(input) {
        return Ok(FinalizeInputStep::Finalized);
    }

    let Some(spk) = input_prevout_script_pubkey(input, prevout) else {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: missing witness_utxo / non_witness_utxo (not broadcast-ready)"
        )));
    };

    // --- Taproot key-path (uses tap_key_sig, not ECDSA partial_sigs) ---
    if spk.is_p2tr() {
        return finalize_taproot_key_path(idx, input, &spk, sequence, tx_version, lock_time);
    }

    if input.partial_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: no partial_sigs (unsigned residual; not broadcast-ready)"
        )));
    }

    // --- Single-key P2WPKH ---
    if spk.is_p2wpkh() {
        if input.partial_sigs.len() != 1 {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: multi-sig / multi-key residual ({} partial_sigs on P2WPKH; \
                 not broadcast-ready)",
                input.partial_sigs.len()
            )));
        }
        let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
        let wpkh = match pk.wpubkey_hash() {
            Ok(h) => h,
            Err(e) => {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: partial_sig pubkey is not compressed P2WPKH: {e}"
                )));
            }
        };
        let expected = ScriptBuf::new_p2wpkh(&wpkh);
        if spk != expected {
            return Err(WalletError::Onchain(format!(
                "input {idx}: partial_sig pubkey HASH160 does not match witness_utxo P2WPKH script"
            )));
        }
        input.final_script_witness = Some(Witness::from_slice(&[sig.to_vec(), pk.to_bytes()]));
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- Single-key P2PKH (legacy) ---
    if spk.is_p2pkh() {
        if input.partial_sigs.len() != 1 {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: multi-sig / multi-key residual ({} partial_sigs on P2PKH; \
                 not broadcast-ready)",
                input.partial_sigs.len()
            )));
        }
        let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
        let expected = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        if spk != expected {
            return Err(WalletError::Onchain(format!(
                "input {idx}: partial_sig pubkey HASH160 does not match P2PKH script"
            )));
        }
        let sig_pb = script_push_bytes(&sig.to_vec())?;
        let pk_pb = script_push_bytes(&pk.to_bytes())?;
        input.final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(sig_pb)
                .push_slice(pk_pb)
                .into_script(),
        );
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- P2SH: nested P2WPKH only when redeem_script is present and matches ---
    if spk.is_p2sh() {
        let Some(redeem) = input.redeem_script.clone() else {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: P2SH residual missing redeem_script (not broadcast-ready)"
            )));
        };
        if redeem.to_p2sh() != spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: redeem_script HASH160 does not match P2SH scriptPubKey"
            )));
        }
        if redeem.is_p2wpkh() {
            if input.partial_sigs.len() != 1 {
                return Ok(FinalizeInputStep::Residual(format!(
                    "input {idx}: multi-sig / multi-key residual ({} partial_sigs on \
                     P2SH-P2WPKH; not broadcast-ready)",
                    input.partial_sigs.len()
                )));
            }
            let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
            let wpkh = match pk.wpubkey_hash() {
                Ok(h) => h,
                Err(e) => {
                    return Err(WalletError::Onchain(format!(
                        "input {idx}: partial_sig pubkey is not compressed P2WPKH: {e}"
                    )));
                }
            };
            let expected_redeem = ScriptBuf::new_p2wpkh(&wpkh);
            if redeem != expected_redeem {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: partial_sig pubkey HASH160 does not match P2SH-P2WPKH redeem_script"
                )));
            }
            // Clone sig/pk bytes before mutating input (partial_sigs borrow).
            let sig_bytes = sig.to_vec();
            let pk_bytes = pk.to_bytes();
            let redeem_pb = script_push_bytes(redeem.as_bytes())?;
            input.final_script_sig = Some(
                bitcoin::script::Builder::new()
                    .push_slice(redeem_pb)
                    .into_script(),
            );
            input.final_script_witness = Some(Witness::from_slice(&[sig_bytes, pk_bytes.to_vec()]));
            return Ok(FinalizeInputStep::Finalized);
        }
        // Nested P2WSH: bare CHECKSIG or bare CHECKMULTISIG witness_script.
        if redeem.is_p2wsh() {
            let Some(wscript) = input.witness_script.clone() else {
                return Ok(FinalizeInputStep::Residual(format!(
                    "input {idx}: P2SH-P2WSH residual missing witness_script \
                     (not broadcast-ready)"
                )));
            };
            if wscript.to_p2wsh() != redeem {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: witness_script hash does not match P2SH-P2WSH redeem_script"
                )));
            }
            return finalize_p2wsh_witness_script(
                idx,
                input,
                &wscript,
                /* also set script_sig with redeem push */ Some(redeem),
            );
        }
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: P2SH non-P2WPKH / multi-sig residual (not broadcast-ready)"
        )));
    }

    // --- Native P2WSH: bare CHECKSIG or bare CHECKMULTISIG witness_script ---
    if spk.is_p2wsh() {
        let Some(wscript) = input.witness_script.clone() else {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: non-P2WPKH P2WSH residual missing witness_script \
                 (not broadcast-ready)"
            )));
        };
        if wscript.to_p2wsh() != spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: witness_script hash does not match P2WSH scriptPubKey"
            )));
        }
        return finalize_p2wsh_witness_script(idx, input, &wscript, None);
    }

    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: unsupported script residual (only single-key P2WPKH / P2PKH / \
         P2SH-P2WPKH / single-CHECKSIG or bare CHECKMULTISIG P2WSH / Taproot key-path \
         or bare script-path CHECKSIG / multi_a / thresh / and_v / or_i / or_d / and_n / \
         andor / hash / older / after finalize; not broadcast-ready)"
    )))
}

/// Finalize native P2TR: key-path first, then bare script-path subset.
///
/// # Key-path
/// Uses [`Witness::p2tr_key_spend`] when `tap_key_sig` is already present —
/// never invents a Schnorr signature.
///
/// # Script-path (subset)
/// When key-path is absent, assembles a script-path witness **only** when a
/// present `tap_scripts` entry is:
/// - bare `<x-only pk> OP_CHECKSIG` with a matching `tap_script_sig`, or
/// - bare multi_a (`CHECKSIG`/`CHECKSIGADD`/`NUMEQUAL`) with ≥ k matching
///   `tap_script_sigs` (empty BIP-342 placeholders for unused keys only), or
/// - bare thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL`) with ≥ k
///   matching `tap_script_sigs` (empty BIP-342 placeholders for unused keys),
///   or
/// - bare and_v (`CHECKSIGVERIFY`…`CHECKSIG`) with **all** n matching
///   `tap_script_sigs` (no empty placeholders — CHECKSIGVERIFY rejects empty), or
/// - bare or_i (`IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF`) with a matching
///   sig for A (IF) and/or B (ELSE); when both present, IF/A wins, or
/// - bare or_d (`<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF`) with a matching
///   sig for A and/or B; when both present, A wins; only-B uses empty A
///   dissatisfaction (BIP-342), or
/// - bare and_n (`<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF`) with **both**
///   matching sigs (A false short-circuits to 0 — no partial B-only path), or
/// - bare andor (`<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF`)
///   with A+B (AB preferred) or C alone (empty BIP-342 dissatisfaction of A),
/// - bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL`) with a
///   matching 32-byte PSBT preimage (sha256/hash256/ripemd160/hash160 maps),
/// - bare and_v(v:pk, hash) (`<A> CHECKSIGVERIFY` + hash fragment) with both
///   matching `tap_script_sig` and PSBT preimage,
/// - older/CSV forms (`and_v(v:pk, older)` / `and_v(v:older, pk)` / bare
///   `older`) with matching sig (if any) **and** present nSequence that
///   satisfies BIP-112 for `n` (never invents nSequence),
/// - after/CLTV forms (`and_v(v:pk, after)` / `and_v(v:after, pk)` / bare
///   `after`) with matching sig (if any) **and** present nLockTime that
///   satisfies BIP-65 for `n` with non-final nSequence (never invents
///   nLockTime/nSequence),
/// and the **already-present** control block verifies against the prevout P2TR.
///
/// Never invents control blocks, leaves, signatures, preimages, or
/// nSequence/nLockTime. Other miniscript / incomplete maps stay Partial.
///
/// When `tap_internal_key` is set, verifies it (+ optional `tap_merkle_root`)
/// reproduces the prevout P2TR scriptPubKey (tamper/corrupt → hard error).
/// Control-block commitment failure is also a hard error (tamper).
fn finalize_taproot_key_path(
    idx: usize,
    input: &mut PsbtInput,
    spk: &ScriptBuf,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    debug_assert!(spk.is_p2tr());

    if let Some(internal) = input.tap_internal_key {
        let secp = Secp256k1::verification_only();
        let expected = ScriptBuf::new_p2tr(&secp, internal, input.tap_merkle_root);
        if expected != *spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: tap_internal_key (+ merkle root) does not match P2TR \
                 scriptPubKey (tamper/corrupt; not broadcast-ready)"
            )));
        }
    }

    if let Some(sig) = input.tap_key_sig {
        // Key-path witness is a single Schnorr sig element (BIP-341).
        // Prefer key-path even when script-path maps are also present.
        input.final_script_witness = Some(Witness::p2tr_key_spend(&sig));
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- Script-path: bare CHECKSIG / multi_a / and_v / or_i / or_d / and_n / andor / older / after ---
    if !input.tap_scripts.is_empty() {
        return finalize_taproot_script_path(idx, input, spk, sequence, tx_version, lock_time);
    }

    // Script-path sigs without any leaf/control-block map → residual (no invent).
    if !input.tap_script_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: Taproot script-path residual missing tap_scripts \
             (control block + leaf; not broadcast-ready)"
        )));
    }

    // ECDSA partial_sigs alone cannot finalize P2TR (BIP-341 needs Schnorr
    // tap_key_sig for key-path). Acknowledge alternate material when present.
    if !input.partial_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: Taproot key-path residual: ECDSA partial_sigs are insufficient \
             for P2TR (key-path requires tap_key_sig; not broadcast-ready)"
        )));
    }

    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: Taproot key-path residual missing tap_key_sig \
         (not broadcast-ready)"
    )))
}

/// Assemble Taproot script-path witness from present PSBT fields only.
///
/// Completes when a `tap_scripts` entry is:
/// - bare `<x-only pk> OP_CHECKSIG` with matching `tap_script_sigs`, or
/// - bare multi_a CHECKSIGADD k-of-n with ≥ k matching `tap_script_sigs`
///   (exactly k keys contribute present sigs in script order; remaining
///   keys get empty BIP-342 placeholders — not invented signatures), or
/// - bare thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL`) with ≥ k
///   matching `tap_script_sigs` (same reverse-key + empty-placeholder policy
///   as multi_a; distinct opcode template), or
/// - bare and_v CHECKSIGVERIFY…CHECKSIG n-of-n with **all** n matching
///   `tap_script_sigs` (no empty placeholders — CHECKSIGVERIFY rejects empty), or
/// - bare or_i IF/ELSE dual CHECKSIG with a matching sig for A and/or B
///   (IF/A preferred when both; branch selector is standard OP_IF encoding,
///   not an invented control path), or
/// - bare or_d IFDUP NOTIF dual CHECKSIG with a matching sig for A and/or B
///   (A preferred when both; only-B uses empty BIP-342 dissatisfaction of A),
///   or
/// - bare and_n NOTIF 0 ELSE dual CHECKSIG with **both** matching sigs
///   (`<sigB> <sigA>`; never invents a B-only path — and_n short-circuits),
///   or
/// - bare andor NOTIF/ELSE triple CHECKSIG with A+B (AB preferred) or C
///   (`<sigC> <empty>`; empty = BIP-342 dissatisfaction of A only),
/// - bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL`) with a
///   matching 32-byte PSBT preimage (never invents preimages),
/// - bare and_v(v:pk, hash) with both matching `tap_script_sig` and preimage
///   (`<preimage> <sigA>`),
/// - older/CSV: `and_v(v:pk, older(n))` / `and_v(v:older(n), pk)` /
///   bare `older(n)` when matching sig (if required) is present **and**
///   `sequence` on the unsigned tx already satisfies BIP-112 for `n`
///   (never invents nSequence),
/// - after/CLTV: `and_v(v:pk, after(n))` / `and_v(v:after(n), pk)` /
///   bare `after(n)` when matching sig (if required) is present **and**
///   `lock_time` on the unsigned tx already satisfies BIP-65 for `n` with
///   non-final `sequence` (never invents nLockTime/nSequence),
/// and the present control block verifies against the prevout output key.
///
/// # Selection / failure policy
/// - First **completeable** entry in `tap_scripts` [`BTreeMap`](std::collections::BTreeMap)
///   order (`ControlBlock` `Ord`) wins (deterministic; skips incomplete earlier
///   entries; never invents a preference among incomplete leaves).
/// - If an entry is completeable (known template + enough material) but its control
///   block fails commitment verify, that is **hard error for the whole input**
///   — later map entries are **not** tried. Tamper must not be silently
///   skipped even when another leaf would verify.
/// - Complex / non-template leaves and incomplete maps stay residual (Partial).
/// - Multi-leaf residual detail joins unique incompleteness reasons (not
///   first-only), so multi-path PSBTs do not mis-attribute the dominant gap.
fn finalize_taproot_script_path(
    idx: usize,
    input: &mut PsbtInput,
    spk: &ScriptBuf,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    use bitcoin::taproot::TapLeafHash;

    let Some(output_key) = p2tr_output_key(spk) else {
        return Err(WalletError::Onchain(format!(
            "input {idx}: P2TR scriptPubKey is malformed (cannot extract output key)"
        )));
    };

    let secp = Secp256k1::verification_only();
    // Unique residual reasons in encounter order (multi-leaf honesty).
    let mut residual_reasons: Vec<&'static str> = Vec::new();
    let mut push_reason = |r: &'static str| {
        if !residual_reasons.contains(&r) {
            residual_reasons.push(r);
        }
    };
    // Script-input stack items + leaf + control block (owned; no input borrow).
    let mut chosen: Option<(Vec<Vec<u8>>, ScriptBuf, Vec<u8>)> = None;

    for (control_block, (leaf_script, leaf_ver)) in &input.tap_scripts {
        if *leaf_ver != control_block.leaf_version {
            push_reason("leaf_version mismatch between control block and tap_scripts value");
            continue;
        }

        let leaf_hash = TapLeafHash::from_script(leaf_script, *leaf_ver);

        // --- Bare single-key x-only CHECKSIG ---
        if let Some(xonly) = single_tapscript_checksig_xonly(leaf_script) {
            let Some(sig) = input.tap_script_sigs.get(&(xonly, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for bare CHECKSIG leaf");
                continue;
            };

            // Present control block must commit to this leaf + output key.
            // Failure is tamper/corrupt — hard error for the whole input.
            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare multi_a: CHECKSIG + CHECKSIGADD… + k NUMEQUAL ---
        if let Some((threshold, pubkeys)) = bare_tapscript_checksigadd_multi_template(leaf_script) {
            // Collect present sigs; take first `threshold` keys in script order
            // that already have tap_script_sigs (never invent signatures).
            // Empty Vec = BIP-342 unused-key placeholder (not an invented Schnorr).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                // Unused key slot (or past threshold): empty BIP-342 placeholder.
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for multi_a CHECKSIGADD threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare thresh: CHECKSIG + (SWAP CHECKSIG ADD)+ + k EQUAL ---
        // miniscript thresh(k, pk, s:pk, …) — distinct from multi_a.
        if let Some((threshold, pubkeys)) = bare_tapscript_thresh_checksig_template(leaf_script) {
            // Same selection policy as multi_a: first `threshold` keys in
            // script order that already have tap_script_sigs; empty BIP-342
            // placeholders for the rest (never invent signatures).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for thresh k-of-n threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            // SWAP arms need later keys' material deeper so earlier keys run first.
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare and_v: (<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG (n-of-n) ---
        if let Some(pubkeys) = bare_tapscript_and_v_checksigverify_template(leaf_script) {
            // All n keys require present sigs — no empty placeholders
            // (CHECKSIGVERIFY fails on empty BIP-342 unused-key vectors).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Reverse key order: last key's sig is first witness element (bottom).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare or_i: IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_or_i_checksig_template(leaf_script) {
            // Prefer IF/A when both present; else ELSE/B. Never invent a branch
            // when neither sig is present.
            let script_inputs =
                if let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() {
                    // OP_IF true: non-empty branch selector (standard 0x01).
                    vec![sig_a.to_vec(), vec![1u8]]
                } else if let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() {
                    // OP_IF false: empty branch selector.
                    vec![sig_b.to_vec(), Vec::new()]
                } else {
                    push_reason("missing tap_script_sig for both or_i IF/ELSE branches");
                    continue;
                };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare or_d: <A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_or_d_checksig_template(leaf_script) {
            // Prefer A when both present; else B with empty BIP-342 dissatisfaction
            // of A. Never invent a branch when neither sig is present.
            let script_inputs =
                if let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() {
                    // A path: single sig; IFDUP keeps CHECKSIG true for CLEANSTACK.
                    vec![sig_a.to_vec()]
                } else if let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() {
                    // B path: <sigB> <empty> — empty is BIP-342 CHECKSIG dissatisfaction
                    // of A (not an invented Schnorr).
                    vec![sig_b.to_vec(), Vec::new()]
                } else {
                    push_reason("missing tap_script_sig for both or_d A/B branches");
                    continue;
                };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare and_n: <A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_and_n_checksig_template(leaf_script) {
            // Both keys required — and_n short-circuits to 0 when A is false,
            // so a B-only path cannot complete (never invent empty A + sigB).
            // Distinct residual reasons so multi-leaf join can name which key
            // was absent (not a single shared "both required" string).
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_n (missing A)");
                continue;
            };
            let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_n (missing B)");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigB> <sigA> — A is top-of-stack first (executed first).
            chosen = Some((
                vec![sig_b.to_vec(), sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare andor: <A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b, pk_c)) = bare_tapscript_andor_checksig_template(leaf_script) {
            // Prefer AB when both A+B present; else C with empty BIP-342
            // dissatisfaction of A. Never invent empty A without present C,
            // never invent B when only A is present, never invent A for C path.
            let script_inputs = if let (Some(sig_a), Some(sig_b)) = (
                input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied(),
                input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied(),
            ) {
                // AB path: <sigB> <sigA> — A top-of-stack first (executed first).
                vec![sig_b.to_vec(), sig_a.to_vec()]
            } else if let Some(sig_c) = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied() {
                // C path: <sigC> <empty> — empty = BIP-342 dissat of A only.
                vec![sig_c.to_vec(), Vec::new()]
            } else {
                // Neither AB nor C completeable — name the gap distinctly.
                let has_a = input.tap_script_sigs.contains_key(&(pk_a, leaf_hash));
                let has_b = input.tap_script_sigs.contains_key(&(pk_b, leaf_hash));
                if has_a && !has_b {
                    push_reason(
                        "insufficient tap_script_sigs for andor (missing B for AB; missing C)",
                    );
                } else if has_b && !has_a {
                    push_reason(
                        "insufficient tap_script_sigs for andor (missing A for AB; missing C)",
                    );
                } else {
                    push_reason("missing tap_script_sig for andor A/B/C paths");
                }
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare miniscript hash: SIZE 32 EQUALVERIFY HASHOP digest EQUAL ---
        if let Some((kind, digest)) = bare_tapscript_hash_preimage_template(leaf_script) {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason("missing matching PSBT preimage for bare hash leaf");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: single preimage (SIZE 32 already enforced in lookup).
            chosen = Some((
                vec![preimage],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:pk(A), hash(H)): <A> CHECKSIGVERIFY + hash fragment ---
        if let Some((pk_a, kind, digest)) = bare_tapscript_and_v_pk_hash_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_v(v:pk, hash) (missing A)");
                continue;
            };
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason("missing matching PSBT preimage for and_v(v:pk, hash) leaf");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <preimage> <sigA> — A/sig is top-of-stack (CHECKSIGVERIFY first).
            chosen = Some((
                vec![preimage, sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:pk(A), older(n)): <A> CHECKSIGVERIFY <n> CSV ---
        if let Some((pk_a, older_n)) = bare_tapscript_and_v_pk_older_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:pk, older) leaf");
                continue;
            };
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                // Never invent nSequence — residual when present sequence is
                // disabled / type-mismatch / below required / tx version < 2.
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigA> only (CSV reads nSequence, not the witness).
            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:older(n), pk(A)): <n> CSV VERIFY <A> CHECKSIG ---
        if let Some((older_n, pk_a)) = bare_tapscript_and_v_older_pk_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:older, pk) leaf");
                continue;
            };
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- bare older(n): <n> CSV (empty script-input stack) ---
        if let Some(older_n) = bare_tapscript_older_template(leaf_script) {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: empty script inputs — only leaf + control block.
            chosen = Some((Vec::new(), leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- and_v(v:pk(A), after(n)): <A> CHECKSIGVERIFY <n> CLTV ---
        if let Some((pk_a, after_n)) = bare_tapscript_and_v_pk_after_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:pk, after) leaf");
                continue;
            };
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                // Never invent nLockTime/nSequence — residual when present
                // locktime is below required / type-mismatch / sequence final.
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigA> only (CLTV reads nLockTime, not the witness).
            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:after(n), pk(A)): <n> CLTV VERIFY <A> CHECKSIG ---
        if let Some((after_n, pk_a)) = bare_tapscript_and_v_after_pk_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:after, pk) leaf");
                continue;
            };
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- bare after(n): <n> CLTV (empty script-input stack) ---
        if let Some(after_n) = bare_tapscript_after_template(leaf_script) {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: empty script inputs — only leaf + control block.
            chosen = Some((Vec::new(), leaf_script.clone(), control_block.serialize()));
            break;
        }

        // Bare or_c (no IFDUP / no ELSE): detect for a distinct residual reason.
        // Never assemble — CLEANSTACK-invalid as a top-level leaf.
        if bare_tapscript_or_c_checksig_template(leaf_script).is_some() {
            push_reason(
                "bare or_c leaf (CHECKSIG NOTIF … CHECKSIG ENDIF without IFDUP) \
                 is CLEANSTACK-invalid as top-level spend; not assembled offline",
            );
            continue;
        }

        push_reason(
            "leaf is not bare x-only CHECKSIG / multi_a CHECKSIGADD / thresh \
             SWAP-CHECKSIG-ADD / and_v CHECKSIGVERIFY / or_i IF-ELSE / or_d \
             IFDUP-NOTIF / and_n NOTIF-0 / andor NOTIF-ELSE / bare hash / \
             and_v(v:pk, hash) / and_v(v:pk, older) / and_v(v:older, pk) / \
             bare older / and_v(v:pk, after) / and_v(v:after, pk) / bare after \
             (complex/miniscript not assembled offline)",
        );
    }

    if let Some((script_inputs, leaf_script, cb_bytes)) = chosen {
        // BIP-341 script-path witness: <script inputs...> <script> <control block>
        let mut witness_parts: Vec<&[u8]> = script_inputs.iter().map(|s| s.as_slice()).collect();
        witness_parts.push(leaf_script.as_bytes());
        witness_parts.push(cb_bytes.as_slice());
        input.final_script_witness = Some(Witness::from_slice(&witness_parts));
        return Ok(FinalizeInputStep::Finalized);
    }

    let detail = if residual_reasons.is_empty() {
        format!(
            "input {idx}: Taproot script-path residual (no completeable bare \
             CHECKSIG / multi_a / thresh / and_v / or_i / or_d / and_n / andor / \
             hash / and_v(v:pk, hash) / older/CSV / after/CLTV leaf with present \
             control block + material; not broadcast-ready)"
        )
    } else {
        format!(
            "input {idx}: Taproot script-path residual: {}; not broadcast-ready",
            residual_reasons.join("; ")
        )
    };
    Ok(FinalizeInputStep::Residual(detail))
}

/// Finalize P2WSH when `witness_script` is bare CHECKSIG or bare CHECKMULTISIG.
///
/// Optional nested P2SH redeem push sets `final_script_sig`. Never invents
/// signatures that are not already present in `partial_sigs`.
fn finalize_p2wsh_witness_script(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
) -> Result<FinalizeInputStep> {
    if let Some(expected_pk) = single_checksig_pubkey(wscript) {
        return finalize_single_checksig_p2wsh(idx, input, wscript, nested_redeem, expected_pk);
    }
    if let Some((threshold, pubkeys)) = bare_checkmultisig_template(wscript) {
        return finalize_checkmultisig_p2wsh(
            idx,
            input,
            wscript,
            nested_redeem,
            threshold,
            &pubkeys,
        );
    }
    // Complex miniscript / Taproot leaves / non-standard templates.
    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: script-path P2WSH residual (witness_script is not bare single-key \
         CHECKSIG or standard bare CHECKMULTISIG; not broadcast-ready)"
    )))
}

/// Finalize bare single-key CHECKSIG P2WSH (optional nested P2SH redeem push).
fn finalize_single_checksig_p2wsh(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
    expected_pk: bitcoin::PublicKey,
) -> Result<FinalizeInputStep> {
    if input.partial_sigs.len() != 1 {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: multi-sig / multi-key residual ({} partial_sigs; single-key \
             CHECKSIG P2WSH needs exactly one; not broadcast-ready)",
            input.partial_sigs.len()
        )));
    }
    let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
    if *pk != expected_pk {
        return Err(WalletError::Onchain(format!(
            "input {idx}: partial_sig pubkey does not match single-CHECKSIG witness_script"
        )));
    }
    // Clone before mutating input (partial_sigs borrow).
    let sig_bytes = sig.to_vec();
    apply_nested_redeem_script_sig(input, nested_redeem)?;
    // Witness: <sig> <witnessScript> (pubkey lives in the script).
    input.final_script_witness = Some(Witness::from_slice(&[sig_bytes, wscript.to_bytes()]));
    Ok(FinalizeInputStep::Finalized)
}

/// Finalize bare m-of-n CHECKMULTISIG P2WSH when enough matching `partial_sigs`
/// exist.
///
/// Builds witness stack as BIP147 **NULLDUMMY** (empty element) + up to
/// `threshold` sigs selected in **witness_script pubkey order** + witnessScript.
/// Callers need not pre-order `partial_sigs`. Never invents missing signatures:
/// fewer than `threshold` matching keys → [`FinalizeInputStep::Residual`].
/// Extra unrelated `partial_sigs` are ignored.
fn finalize_checkmultisig_p2wsh(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
    threshold: usize,
    pubkeys: &[bitcoin::PublicKey],
) -> Result<FinalizeInputStep> {
    // Collect up to `threshold` signatures in witness_script pubkey order.
    // CHECKMULTISIG requires sigs ordered relative to the key list; we never
    // reorder or invent.
    let mut ordered_sig_bytes: Vec<Vec<u8>> = Vec::with_capacity(threshold);
    for pk in pubkeys {
        if let Some(sig) = input.partial_sigs.get(pk) {
            ordered_sig_bytes.push(sig.to_vec());
            if ordered_sig_bytes.len() == threshold {
                break;
            }
        }
    }
    if ordered_sig_bytes.len() < threshold {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: CHECKMULTISIG threshold residual \
             ({}/{} matching partial_sigs for {}-of-{}; not broadcast-ready)",
            ordered_sig_bytes.len(),
            threshold,
            threshold,
            pubkeys.len()
        )));
    }

    apply_nested_redeem_script_sig(input, nested_redeem)?;

    // BIP147 witness stack: OP_0 dummy, then m sigs (script order), then script.
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(threshold + 2);
    stack.push(Vec::new());
    stack.append(&mut ordered_sig_bytes);
    stack.push(wscript.to_bytes());
    input.final_script_witness = Some(Witness::from_slice(&stack));
    Ok(FinalizeInputStep::Finalized)
}

/// Optional nested P2SH-P2WSH: push redeem_script as final_script_sig.
fn apply_nested_redeem_script_sig(
    input: &mut PsbtInput,
    nested_redeem: Option<ScriptBuf>,
) -> Result<()> {
    if let Some(redeem) = nested_redeem {
        let redeem_pb = script_push_bytes(redeem.as_bytes())?;
        input.final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(redeem_pb)
                .into_script(),
        );
    }
    Ok(())
}

/// Offline PSBT finalize with shared Complete vs Partial gates.
///
/// Expands beyond bare P2WPKH where material already present on the PSBT is
/// enough — never invents multi-sig witnesses. See [`FinalizeOutcome`].
///
/// Product paths must require [`FinalizeOutcome::is_complete`] before extract
/// or broadcast.
pub fn finalize_psbt(psbt: &mut Psbt) -> Result<FinalizeOutcome> {
    let total = psbt.inputs.len();
    if total == 0 {
        return Err(WalletError::Onchain(
            "PSBT has no inputs to finalize".into(),
        ));
    }
    if total != psbt.unsigned_tx.input.len() {
        return Err(WalletError::Onchain(format!(
            "PSBT input map length ({total}) does not match unsigned_tx.input length ({}); \
             corrupt or malformed PSBT",
            psbt.unsigned_tx.input.len()
        )));
    }
    let mut finalized = 0usize;
    let mut residual_reasons: Vec<String> = Vec::new();

    let tx_version = psbt.unsigned_tx.version;
    let lock_time = psbt.unsigned_tx.lock_time;
    for idx in 0..total {
        let prevout = psbt.unsigned_tx.input[idx].previous_output;
        let sequence = psbt.unsigned_tx.input[idx].sequence;
        match try_finalize_input(
            idx,
            &mut psbt.inputs[idx],
            prevout,
            sequence,
            tx_version,
            lock_time,
        )? {
            FinalizeInputStep::Finalized => {
                debug_assert!(input_is_finalized(&psbt.inputs[idx]));
                finalized += 1;
            }
            FinalizeInputStep::Residual(reason) => residual_reasons.push(reason),
        }
    }

    let residual = total.saturating_sub(finalized);
    if residual == 0 {
        debug_assert!(psbt_is_broadcast_ready(psbt));
        Ok(FinalizeOutcome::Complete {
            finalized_inputs: finalized,
        })
    } else {
        let detail = if residual_reasons.is_empty() {
            format!("finalized {finalized}/{total} inputs; residual not broadcast-ready")
        } else {
            format!(
                "finalized {finalized}/{total} inputs (not broadcast-ready): {}",
                residual_reasons.join("; ")
            )
        };
        Ok(FinalizeOutcome::Partial {
            finalized_inputs: finalized,
            residual_inputs: residual,
            detail,
        })
    }
}

/// Convert ECDSA `partial_sigs` into final spend material where offline-safe.
///
/// Alias of [`finalize_psbt`] (historical name; still used by product BIP84
/// prepare). Supports single-key P2WPKH plus additional completeable cases
/// documented on [`FinalizeOutcome`] — incomplete CHECKMULTISIG / multi_a
/// thresholds, complex Taproot script-path, and other unsupported scripts
/// stay [`FinalizeOutcome::Partial`].
pub fn finalize_p2wpkh_psbt(psbt: &mut Psbt) -> Result<FinalizeOutcome> {
    finalize_psbt(psbt)
}

/// Extract a transaction when **every** input has non-empty final spend material.
///
/// Empty witnesses / empty script_sigs are rejected (never treated as complete).
/// Multi-sig residual PSBTs fail here if finalize left them partial.
///
/// Diagnostics prefer `!input_is_finalized` so a finalized input that still
/// carries an empty companion field (`Some(empty)` on the unused final slot)
/// is not blamed ahead of a truly residual input.
///
/// Uses fee-rate-unchecked extract so dust-folded / test fees are not rejected.
/// **Does not broadcast.** Submit via [`broadcast_raw_tx`] / [`TxBroadcaster`].
pub fn extract_finalized_tx(psbt: Psbt) -> Result<Transaction> {
    if psbt.inputs.is_empty() {
        return Err(WalletError::Onchain("cannot extract empty PSBT".into()));
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(WalletError::Onchain(format!(
            "PSBT input map length ({}) does not match unsigned_tx.input length ({}); \
             corrupt or malformed PSBT",
            psbt.inputs.len(),
            psbt.unsigned_tx.input.len()
        )));
    }
    if !psbt_is_broadcast_ready(&psbt) {
        for (idx, input) in psbt.inputs.iter().enumerate() {
            if input_is_finalized(input) {
                // Finalized via non-empty witness and/or script_sig; ignore any
                // empty companion field on the unused slot.
                continue;
            }
            let wit_empty = input
                .final_script_witness
                .as_ref()
                .is_some_and(|w| w.is_empty());
            let sig_empty = input
                .final_script_sig
                .as_ref()
                .is_some_and(|s| s.is_empty());
            if wit_empty || sig_empty {
                return Err(WalletError::Onchain(format!(
                    "input {idx} has empty final_script_witness / final_script_sig \
                     (not complete; multi-sig residual or unsigned)"
                )));
            }
            // Not finalized and no present-but-empty fields → missing finals.
            return Err(WalletError::Onchain(format!(
                "input {idx} missing final_script_witness and final_script_sig; \
                 finalize before extract (partial / multi-sig residual is not \
                 broadcast-ready)"
            )));
        }
        // Defensive: should not reach if loop found a residual input.
        return Err(WalletError::Onchain(
            "PSBT not broadcast-ready (missing or empty final spend material)".into(),
        ));
    }
    Ok(psbt.extract_tx_unchecked_fee_rate())
}

/// Consensus-encode a transaction as lowercase hex (mempool.space `POST /api/tx` body).
pub fn transaction_to_raw_hex(tx: &Transaction) -> String {
    bitcoin::consensus::encode::serialize_hex(tx)
}

/// Compute the txid hex (lowercase) for a transaction.
pub fn transaction_txid_hex(tx: &Transaction) -> String {
    tx.compute_txid().to_string()
}

/// Broadcast raw transaction hex through an injected [`crate::explorer::TxBroadcaster`].
///
/// Never claims success without a successful broadcaster response. Empty /
/// non-hex bodies are rejected via [`crate::explorer::validate_raw_tx_hex`]
/// before calling the broadcaster.
pub fn broadcast_raw_tx(
    broadcaster: &mut dyn crate::explorer::TxBroadcaster,
    raw_tx_hex: &str,
) -> Result<crate::explorer::BroadcastResult> {
    let trimmed = crate::explorer::validate_raw_tx_hex(raw_tx_hex)?;
    broadcaster.broadcast_raw_tx_hex(trimmed)
}

/// Extract then broadcast a fully finalized PSBT. Fails closed if extract or
/// broadcast fails (no partial success claim).
pub fn extract_and_broadcast(
    psbt: Psbt,
    broadcaster: &mut dyn crate::explorer::TxBroadcaster,
) -> Result<crate::explorer::BroadcastResult> {
    let tx = extract_finalized_tx(psbt)?;
    let hex = transaction_to_raw_hex(&tx);
    broadcast_raw_tx(broadcaster, &hex)
}

/// Local build → sign → finalize → extract for BIP84 P2WPKH (no network).
#[derive(Clone)]
pub struct PreparedSpend {
    pub tx: Transaction,
    pub fee_sats: u64,
    pub payment_sats: u64,
    pub change_sats: u64,
    pub input_count: usize,
    pub output_count: usize,
    /// Prevouts used for this spend (for same-input RBF). Not secret material.
    pub selected_inputs: Vec<WalletUtxo>,
}

impl std::fmt::Debug for PreparedSpend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSpend")
            .field("txid", &self.txid_hex())
            .field("fee_sats", &self.fee_sats)
            .field("payment_sats", &self.payment_sats)
            .field("change_sats", &self.change_sats)
            .field("input_count", &self.input_count)
            .field("output_count", &self.output_count)
            .field("selected_inputs", &self.selected_inputs.len())
            .finish()
    }
}

impl PreparedSpend {
    pub fn raw_hex(&self) -> String {
        transaction_to_raw_hex(&self.tx)
    }

    pub fn txid_hex(&self) -> String {
        transaction_txid_hex(&self.tx)
    }

    /// Consensus weight converted to virtual bytes (ceil). Prefer this over the
    /// P2WPKH heuristic when the signed tx is already in hand.
    pub fn weight_vbytes(&self) -> u64 {
        transaction_vbytes(&self.tx)
    }

    /// Floor effective fee rate (sat/vB) from actual weight and recorded fee.
    pub fn effective_fee_rate_sat_vb(&self) -> u64 {
        effective_fee_rate_sat_vb(self.fee_sats, self.weight_vbytes())
    }

    /// P2WPKH heuristic vbytes from input/output counts (matches coin select).
    pub fn estimated_vbytes(&self) -> u64 {
        estimate_tx_vbytes(self.input_count, self.output_count)
    }
}

/// Virtual size of a transaction: `weight.to_vbytes_ceil()`.
pub fn transaction_vbytes(tx: &Transaction) -> u64 {
    tx.weight().to_vbytes_ceil()
}

/// Build → BIP84 P2WPKH sign → finalize → extract for a complete local spend path.
///
/// Returns [`WalletError::Onchain`] if signing is partial (not broadcast-ready).
/// **Does not broadcast** — call [`broadcast_raw_tx`] with the returned hex.
pub fn build_sign_extract_bip84_p2wpkh(
    selection: &CoinSelection,
    params: &SpendParams,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    address_gap: u32,
) -> Result<Transaction> {
    Ok(prepare_bip84_p2wpkh_spend(selection, params, mnemonic, passphrase, address_gap)?.tx)
}

/// Same as [`build_sign_extract_bip84_p2wpkh`] but keeps fee/payment metadata.
pub fn prepare_bip84_p2wpkh_spend(
    selection: &CoinSelection,
    params: &SpendParams,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    address_gap: u32,
) -> Result<PreparedSpend> {
    let mut built = build_unsigned_psbt(selection, params)?;
    let fee_sats = built.fee_sats;
    let payment_sats = built.payment_sats;
    let change_sats = built.change_sats;
    let outcome = sign_psbt_bip84_p2wpkh(
        &mut built.psbt,
        mnemonic,
        passphrase,
        params.network,
        address_gap,
    )?;
    if !outcome.is_broadcast_ready() {
        return Err(WalletError::Onchain(format!(
            "incomplete BIP84 P2WPKH sign (not broadcast-ready): {}",
            match &outcome {
                SignOutcome::Partial { detail, .. } => detail.clone(),
                SignOutcome::AllSigned { .. } => unreachable!(),
            }
        )));
    }
    let fin = finalize_p2wpkh_psbt(&mut built.psbt)?;
    if !fin.is_broadcast_ready() {
        return Err(WalletError::Onchain(format!(
            "incomplete offline finalize (not broadcast-ready): {}",
            match &fin {
                FinalizeOutcome::Partial { detail, .. } => detail.clone(),
                FinalizeOutcome::Complete { .. } => unreachable!(),
            }
        )));
    }
    if !psbt_is_broadcast_ready(&built.psbt) {
        return Err(WalletError::Onchain(
            "PSBT not broadcast-ready after finalize (empty or missing final spend material)"
                .into(),
        ));
    }
    let tx = extract_finalized_tx(built.psbt)?;
    let input_count = tx.input.len();
    let output_count = tx.output.len();
    Ok(PreparedSpend {
        tx,
        fee_sats,
        payment_sats,
        change_sats,
        input_count,
        output_count,
        selected_inputs: selection.selected.clone(),
    })
}

/// Fee-aware select + BIP84 prepare from an **already-listed** UTXO slice.
///
/// Does **not** call [`ChainSource`] / [`DescriptorWallet::list_unspent`].
/// Callers that already hold authoritative UTXOs (e.g. product gap-sync after
/// [`DescriptorWallet::sync_with_gap_extend`], or a one-shot fixed-window list)
/// use this to avoid a redundant full-window round-trip.
///
/// **Honesty:** only the provided `utxos` are considered — never invents
/// balance or coins. Empty slice → same "no UTXOs" error as the list path.
/// `fee_rate_sat_vb` of 0 is rejected. Change goes to the wallet's first
/// change address when needed.
///
/// `passphrase` is the BIP-39 passphrase (empty = default path). Must match the
/// passphrase used to build `wallet` and to fund its addresses. Never log it.
pub fn select_and_prepare_bip84_spend_from_utxos(
    wallet: &DescriptorWallet,
    utxos: &[WalletUtxo],
    mnemonic: &MnemonicSecret,
    payment_address: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    passphrase: &str,
    address_gap: u32,
) -> Result<PreparedSpend> {
    if fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "fee rate must be > 0 sat/vB for product spend".into(),
        ));
    }
    if utxos.is_empty() {
        return Err(WalletError::Onchain(
            "no UTXOs found for wallet address gap (fund the receive address first)".into(),
        ));
    }
    let selection = select_coins_with_fee(
        utxos,
        amount_sats,
        fee_rate_sat_vb,
        CoinSelectStrategy::LargestFirst,
    )?;
    let change_address = if selection.change_sats > 0 {
        Some(
            wallet
                .change_addresses()
                .first()
                .cloned()
                .ok_or_else(|| WalletError::Onchain("wallet has no change address".into()))?,
        )
    } else {
        None
    };
    let params = SpendParams {
        payment_address: payment_address.to_owned(),
        change_address,
        network: wallet.network(),
    };
    prepare_bip84_p2wpkh_spend(
        &selection,
        &params,
        mnemonic,
        passphrase,
        address_gap.max(1),
    )
}

/// Fee-aware select + BIP84 prepare for a payment from wallet UTXOs.
///
/// Uses the wallet's **current** fixed receive/change windows only
/// ([`DescriptorWallet::list_unspent`]) — does **not** gap-extend. Prefer
/// [`select_and_prepare_bip84_spend_with_gap_sync`] for product spend so deep
/// indices near the look-ahead tip are recovered. Keep this path for callers
/// that already extended, or for RBF/CPFP with explicit prevouts.
///
/// Internally lists once then delegates to
/// [`select_and_prepare_bip84_spend_from_utxos`].
///
/// `fee_rate_sat_vb` of 0 is rejected (product paths must pass a positive rate).
/// Change goes to the wallet's first change address when needed.
///
/// `passphrase` is the BIP-39 passphrase (empty = default path). Must match the
/// passphrase used to build `wallet` and to fund its addresses. Never log it.
pub fn select_and_prepare_bip84_spend(
    wallet: &DescriptorWallet,
    chain: &dyn ChainSource,
    mnemonic: &MnemonicSecret,
    payment_address: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    passphrase: &str,
    address_gap: u32,
) -> Result<PreparedSpend> {
    // Reject zero fee before listing (avoids a needless chain round-trip).
    // from_utxos also rejects fee 0 for callers that skip this wrapper.
    if fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "fee rate must be > 0 sat/vB for product spend".into(),
        ));
    }
    let utxos = wallet.list_unspent(chain)?;
    select_and_prepare_bip84_spend_from_utxos(
        wallet,
        &utxos,
        mnemonic,
        payment_address,
        amount_sats,
        fee_rate_sat_vb,
        passphrase,
        address_gap,
    )
}

/// Result of product spend after gap-limit ChainSource sync + prepare.
///
/// `sync` describes the (possibly grown) window; `prepared` is the signed
/// local spend. Never invents UTXOs — empty chain → error, not success.
#[derive(Clone)]
pub struct GapSyncedPreparedSpend {
    pub prepared: PreparedSpend,
    pub sync: WalletSyncSnapshot,
}

impl std::fmt::Debug for GapSyncedPreparedSpend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GapSyncedPreparedSpend")
            .field("txid", &self.prepared.txid_hex())
            .field("fee_sats", &self.prepared.fee_sats)
            .field("payment_sats", &self.prepared.payment_sats)
            .field("receive_gap", &self.sync.receive_gap)
            .field("change_gap", &self.sync.change_gap)
            .field("extended_receive_by", &self.sync.extended_receive_by)
            .field("extended_change_by", &self.sync.extended_change_by)
            .field("hit_max_gap", &self.sync.hit_max_gap)
            .finish()
    }
}

/// Failure of product [`select_and_prepare_bip84_spend_with_gap_sync`].
///
/// Dual-arm so callers can distinguish:
/// - [`Self::Sync`]: failed **before** a usable snapshot (fee rate 0 pre-check,
///   wrong passphrase, chain list error, …). No notices — there is no honest
///   extend/`hit_max_gap` meta to surface.
/// - [`Self::AfterSync`]: sync **succeeded** (windows may have grown; wallet
///   still holds the grown gap) but coin select / prepare failed (insufficient
///   funds, no UTXOs, …). Carries the real [`WalletSyncSnapshot`] so hit-max /
///   extend notices are available on the error path — not success-only.
///
/// Kept **out of** [`WalletError`] to avoid error.rs circularity and accidental
/// secret-bearing Debug dumps via a catch-all variant. Snapshot `Debug` remains
/// address/UTXO-safe (no BIP-39 / seed).
pub enum GapSyncSpendFailure {
    /// Sync stage failed; no post-extend snapshot.
    Sync(WalletError),
    /// Sync produced a snapshot; select/prepare failed afterward.
    AfterSync {
        sync: WalletSyncSnapshot,
        cause: WalletError,
    },
}

impl GapSyncSpendFailure {
    /// Underlying [`WalletError`] (sync or select/prepare cause).
    pub fn cause(&self) -> &WalletError {
        match self {
            Self::Sync(e) | Self::AfterSync { cause: e, .. } => e,
        }
    }

    /// Snapshot when sync completed; `None` for [`Self::Sync`].
    pub fn sync_snapshot(&self) -> Option<&WalletSyncSnapshot> {
        match self {
            Self::Sync(_) => None,
            Self::AfterSync { sync, .. } => Some(sync),
        }
    }

    /// Honest gap-extend notice lines (empty for [`Self::Sync`] or quiet AfterSync).
    ///
    /// Reuses [`gap_sync_spend_notice_lines`] — never invents balance/UTXO counts.
    pub fn notice_lines(&self) -> Vec<String> {
        match self {
            Self::Sync(_) => Vec::new(),
            Self::AfterSync { sync, .. } => gap_sync_spend_notice_lines(sync),
        }
    }

    /// Cause message, then any gap-extend notice lines (multi-line UX).
    pub fn display_lines(&self) -> Vec<String> {
        let mut lines = vec![self.cause().to_string()];
        lines.extend(self.notice_lines());
        lines
    }

    /// `true` when select/prepare failed after a successful gap-sync.
    pub fn is_after_sync(&self) -> bool {
        matches!(self, Self::AfterSync { .. })
    }

    /// Consume into the underlying [`WalletError`], **dropping** any
    /// AfterSync snapshot (and therefore hit-max / extend notices).
    ///
    /// Prefer matching on [`Self`] and calling [`Self::notice_lines`] /
    /// [`Self::display_lines`] for product UX. There is intentionally **no**
    /// `From<GapSyncSpendFailure> for WalletError` so `?` cannot silently
    /// reintroduce success-path-only notices.
    pub fn into_cause(self) -> WalletError {
        match self {
            Self::Sync(e) | Self::AfterSync { cause: e, .. } => e,
        }
    }
}

impl std::fmt::Display for GapSyncSpendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Cause-only so `.to_string()` matches WalletError wording; use
        // [`Self::display_lines`] when notices must ride along.
        write!(f, "{}", self.cause())
    }
}

impl std::error::Error for GapSyncSpendFailure {
    // Cause is already the Display text; returning it as `source` would
    // double-print with printers that walk the chain.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Debug for GapSyncSpendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(e) => f.debug_tuple("Sync").field(e).finish(),
            Self::AfterSync { sync, cause } => f
                .debug_struct("AfterSync")
                .field("cause", cause)
                .field("receive_gap", &sync.receive_gap)
                .field("change_gap", &sync.change_gap)
                .field("extended_receive_by", &sync.extended_receive_by)
                .field("extended_change_by", &sync.extended_change_by)
                .field("hit_max_gap", &sync.hit_max_gap)
                .field("utxo_count", &sync.utxos.len())
                .finish(),
        }
    }
}

/// Gap-limit sync then fee-aware select + BIP84 prepare (product spend path).
///
/// 1. [`DescriptorWallet::sync_with_gap_extend`] with `opts` (default
///    [`GapExtendOptions`] = BIP44-style look-ahead 20; hard [`MAX_ADDRESS_GAP`]).
/// 2. Select/prepare from the sync snapshot's UTXOs via
///    [`select_and_prepare_bip84_spend_from_utxos`]; sign with
///    `max(receive_gap, change_gap)` so deep indices are covered.
///
/// **Chain calls:** only the N+1 list rounds inside `sync_with_gap_extend`
/// (extend steps + final snapshot list). Coin select uses `sync.utxos`
/// (authoritative as of that final sync list) — **no** extra
/// `list_unspent` after sync. Live backends therefore pay sync lists only
/// per product spend attempt. Accept minor race vs chain tip after the
/// final sync list (same honesty as treating the snapshot as the spend
/// attempt's UTXO set).
///
/// **Errors:** returns [`GapSyncSpendFailure`] (not bare [`WalletError`]):
/// - Fee rate 0 (pre-sync validation) or sync failure (wrong passphrase, chain
///   list error, …) → [`GapSyncSpendFailure::Sync`] — **no** snapshot /
///   notices (fail-closed; never fabricates AfterSync success meta; fee 0
///   skips the expensive N+1 sync lists, matching the fixed-window early check).
/// - Select/prepare failure after successful sync →
///   [`GapSyncSpendFailure::AfterSync`] with the real snapshot so
///   [`gap_sync_spend_notice_lines`] / [`GapSyncSpendFailure::notice_lines`]
///   surface hit-max / extended-window meta on insufficient funds / no UTXOs
///   (not success-path only). Wallet windows remain grown on AfterSync
///   (caller still holds `&mut wallet`).
///
/// Wrong passphrase fail-closed on extend (library verify before mutate).
/// Does **not** invent balance or UTXOs. RBF/CPFP should keep explicit-prevout
/// helpers with [`PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP`] for signing — no re-extend.
///
/// `passphrase` must match wallet construction; never log it.
pub fn select_and_prepare_bip84_spend_with_gap_sync(
    wallet: &mut DescriptorWallet,
    chain: &dyn ChainSource,
    mnemonic: &MnemonicSecret,
    payment_address: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    passphrase: &str,
    opts: GapExtendOptions,
) -> std::result::Result<GapSyncedPreparedSpend, GapSyncSpendFailure> {
    // Reject zero fee before gap-sync (avoids N+1 list rounds on live backends).
    // Same wording as fixed-window / from_utxos; Sync arm so no fake snapshot.
    if fee_rate_sat_vb == 0 {
        return Err(GapSyncSpendFailure::Sync(WalletError::Onchain(
            "fee rate must be > 0 sat/vB for product spend".into(),
        )));
    }
    let sync = wallet
        .sync_with_gap_extend(mnemonic, passphrase, chain, opts)
        .map_err(GapSyncSpendFailure::Sync)?;
    // Cover both chains after independent extend (sign lookup scans 0..gap).
    let address_gap = wallet.receive_gap().max(wallet.change_gap()).max(1);
    // Select from the final sync snapshot only — no post-sync list_unspent.
    match select_and_prepare_bip84_spend_from_utxos(
        wallet,
        &sync.utxos,
        mnemonic,
        payment_address,
        amount_sats,
        fee_rate_sat_vb,
        passphrase,
        address_gap,
    ) {
        Ok(prepared) => Ok(GapSyncedPreparedSpend { prepared, sync }),
        Err(cause) => Err(GapSyncSpendFailure::AfterSync { sync, cause }),
    }
}

/// Honest product notice lines after gap-extend spend sync.
///
/// Empty when the window did not grow and max gap was not hit (quiet default).
/// Never invents balance or UTXO counts — only reports window meta from `snap`.
///
/// Usable on both the success path ([`GapSyncedPreparedSpend::sync`]) and the
/// select/prepare error path ([`GapSyncSpendFailure::AfterSync`]).
/// Also reused by product UTXO list ([`list_bip84_utxos_with_gap_sync`]).
pub fn gap_sync_spend_notice_lines(snap: &WalletSyncSnapshot) -> Vec<String> {
    let mut lines = Vec::new();
    if snap.extended_receive_by > 0 || snap.extended_change_by > 0 {
        lines.push(format!(
            "Address gap extended during UTXO sync (receive +{}, change +{}; \
             windows receive={}, change={}). Gap-limit ChainSource sync only — \
             not full bdk_wallet auto-sync.",
            snap.extended_receive_by, snap.extended_change_by, snap.receive_gap, snap.change_gap
        ));
    }
    if snap.hit_max_gap {
        lines.push(format!(
            "Gap extend stopped at max address window (receive={}, change={}); \
             deeper UTXOs beyond this window were not scanned.",
            snap.receive_gap, snap.change_gap
        ));
    }
    lines
}

/// Product UTXO list / on-chain balance via gap-limit ChainSource sync.
///
/// Runs [`DescriptorWallet::sync_with_gap_extend`] with `opts` (default
/// [`GapExtendOptions`] = BIP44-style look-ahead 20; hard [`MAX_ADDRESS_GAP`])
/// and returns the [`WalletSyncSnapshot`] as-is.
///
/// **Chain calls:** only the N+1 list rounds inside `sync_with_gap_extend`.
/// Callers must treat `snapshot.utxos` / `snapshot.balance` as authoritative —
/// **do not** re-list after this helper (same honesty as
/// [`select_and_prepare_bip84_spend_with_gap_sync`] select-from-snapshot).
///
/// **Wrong passphrase:** fail-closed on extend (library verify before mutate) —
/// same Sync-stage behaviour as product gap-sync spend.
///
/// **Empty chain:** returns a successful snapshot with empty `utxos` and zero
/// balance (list is observational — unlike spend, which errors on no UTXOs).
/// Never invents coins. Not full `bdk_wallet` auto-sync.
///
/// `passphrase` must match wallet construction; never log it.
pub fn list_bip84_utxos_with_gap_sync(
    wallet: &mut DescriptorWallet,
    chain: &dyn ChainSource,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    opts: GapExtendOptions,
) -> Result<WalletSyncSnapshot> {
    wallet.sync_with_gap_extend(mnemonic, passphrase, chain, opts)
}

/// Result of an RBF replacement rebuild (local prepare only; no broadcast claim).
#[derive(Clone)]
pub struct RbfReplacementSpend {
    pub prepared: PreparedSpend,
    pub plan: RbfFeePlan,
    /// Target fee rate used when sizing the plan (sat/vB).
    pub fee_rate_sat_vb: u64,
    pub original_fee_sats: u64,
    pub original_vbytes: u64,
}

impl std::fmt::Debug for RbfReplacementSpend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbfReplacementSpend")
            .field("txid", &self.prepared.txid_hex())
            .field("fee_sats", &self.prepared.fee_sats)
            .field("original_fee_sats", &self.original_fee_sats)
            .field("fee_rate_sat_vb", &self.fee_rate_sat_vb)
            .field("fee_delta_sats", &self.fee_delta_sats())
            .finish()
    }
}

impl RbfReplacementSpend {
    /// `prepared.fee_sats - original_fee_sats` (always > 0 on success).
    pub fn fee_delta_sats(&self) -> u64 {
        self.prepared
            .fee_sats
            .saturating_sub(self.original_fee_sats)
    }
}

/// Minimum absolute replacement fee for BIP-125 bandwidth on the **replacement**
/// size: `original_fee + max(1, replacement_vbytes * incremental)`.
///
/// Does not encode higher-feerate or target-rate floors — use [`plan_rbf_fee_bump`]
/// for full same-size guidance, then re-check with this after prepare if size changed.
pub fn bip125_min_replacement_fee_sats(
    original_fee_sats: u64,
    replacement_vbytes: u64,
    incremental_relay_sat_vb: u64,
) -> u64 {
    let inc = rbf_min_fee_increase_sats(replacement_vbytes, incremental_relay_sat_vb);
    original_fee_sats
        .saturating_add(inc)
        .max(original_fee_sats.saturating_add(1))
}

/// Fail closed if `replacement_fee_sats` does not satisfy BIP-125 absolute +
/// incremental-bandwidth floors for the actual replacement size.
///
/// Also requires `replacement_fee_sats >= plan_min_fee_sats` when that floor is
/// provided (typically [`RbfFeePlan::min_replacement_fee_sats`] or recommended).
pub fn validate_rbf_replacement_fee(
    original_fee_sats: u64,
    replacement_fee_sats: u64,
    replacement_vbytes: u64,
    incremental_relay_sat_vb: u64,
    plan_min_fee_sats: u64,
) -> Result<()> {
    if replacement_vbytes == 0 {
        return Err(WalletError::Onchain(
            "replacement vbytes must be > 0 for BIP-125 fee check".into(),
        ));
    }
    if replacement_fee_sats <= original_fee_sats {
        return Err(WalletError::Onchain(format!(
            "RBF replacement fee {replacement_fee_sats} sats is not greater than original \
             {original_fee_sats} sats (BIP-125 absolute fee must increase)"
        )));
    }
    let min_by_bandwidth = bip125_min_replacement_fee_sats(
        original_fee_sats,
        replacement_vbytes,
        incremental_relay_sat_vb,
    );
    let required = min_by_bandwidth
        .max(plan_min_fee_sats)
        .max(original_fee_sats.saturating_add(1));
    if replacement_fee_sats < required {
        return Err(WalletError::Onchain(format!(
            "RBF replacement fee {replacement_fee_sats} sats is below BIP-125 floor {required} sats \
             (original {original_fee_sats} + bandwidth on {replacement_vbytes} vB; plan min \
             {plan_min_fee_sats}). Raise --fee-rate or free more change"
        )));
    }
    Ok(())
}

/// Rebuild a [`CoinSelection`] from the original stuck spend's inputs + fee.
///
/// Used for same-input RBF (product CLI `--input` specs). Folds dust change into
/// fee when reconstructing so PSBT build stays valid.
pub fn coin_selection_from_rbf_inputs(
    inputs: &[WalletUtxo],
    payment_sats: u64,
    original_fee_sats: u64,
) -> Result<CoinSelection> {
    if inputs.is_empty() {
        return Err(WalletError::Onchain(
            "RBF requires at least one original input (--input txid:vout:amount:address)".into(),
        ));
    }
    if payment_sats == 0 {
        return Err(WalletError::Onchain(
            "RBF payment amount must be > 0 sats".into(),
        ));
    }
    let mut seen = HashSet::with_capacity(inputs.len());
    let mut total = 0u64;
    for utxo in inputs {
        if utxo.amount_sats == 0 {
            return Err(WalletError::Onchain(format!(
                "RBF input {}:{} has zero amount",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        if utxo.address.trim().is_empty() {
            return Err(WalletError::Onchain(format!(
                "RBF input {}:{} has empty address",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        if !seen.insert((utxo.outpoint.txid.clone(), utxo.outpoint.vout)) {
            return Err(WalletError::Onchain(format!(
                "duplicate RBF input {}:{}",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        total = total.saturating_add(utxo.amount_sats);
    }
    let needed = payment_sats.saturating_add(original_fee_sats);
    if total < needed {
        return Err(WalletError::Onchain(format!(
            "insufficient value in original inputs for RBF: need {needed} sats \
             (payment {payment_sats} + original fee {original_fee_sats}), have {total}"
        )));
    }
    let mut change = total - needed;
    let mut fee = original_fee_sats;
    if change > 0 && change < DUST_P2WPKH_SATS {
        fee = fee.saturating_add(change);
        change = 0;
    }
    Ok(CoinSelection {
        selected: inputs.to_vec(),
        total_input_sats: total,
        change_sats: change,
        target_sats: payment_sats,
        fee_sats: fee,
    })
}

/// Raise absolute fee on a prior selection while keeping the **same inputs** and
/// **same payment amount** (true same-size RBF when output count stays equal).
///
/// Reduces change to fund the higher fee; folds dust change into fee. Fails when
/// `new_fee_sats` is not strictly greater than the original fee, or when inputs
/// cannot cover payment + new fee.
pub fn selection_with_rbf_fee(
    selection: &CoinSelection,
    new_fee_sats: u64,
) -> Result<CoinSelection> {
    if selection.selected.is_empty() {
        return Err(WalletError::Onchain("RBF selection has no inputs".into()));
    }
    if selection.target_sats == 0 {
        return Err(WalletError::Onchain(
            "RBF payment amount (target_sats) must be > 0".into(),
        ));
    }
    if new_fee_sats <= selection.fee_sats {
        return Err(WalletError::Onchain(format!(
            "RBF replacement fee {new_fee_sats} sats must be greater than original fee {} sats",
            selection.fee_sats
        )));
    }
    let needed = selection.target_sats.saturating_add(new_fee_sats);
    if selection.total_input_sats < needed {
        return Err(WalletError::Onchain(format!(
            "insufficient funds for RBF fee bump: need {needed} sats (payment {} + fee {new_fee_sats}), have {} sats in inputs",
            selection.target_sats, selection.total_input_sats
        )));
    }
    let mut change = selection.total_input_sats - needed;
    let mut fee = new_fee_sats;
    if change > 0 && change < DUST_P2WPKH_SATS {
        fee = fee.saturating_add(change);
        change = 0;
    }
    // Dust fold can only increase fee further; still require strictly greater.
    if fee <= selection.fee_sats {
        return Err(WalletError::Onchain(format!(
            "RBF fee after dust fold ({fee}) is not greater than original {}",
            selection.fee_sats
        )));
    }
    Ok(CoinSelection {
        selected: selection.selected.clone(),
        total_input_sats: selection.total_input_sats,
        change_sats: change,
        target_sats: selection.target_sats,
        fee_sats: fee,
    })
}

/// Same-size RBF rebuild from a prior selection: bump absolute fee via
/// [`selection_with_rbf_fee`], then BIP84 sign/finalize/extract.
///
/// `new_fee_sats` should come from [`plan_rbf_fee_bump`] recommended (or higher).
/// **Does not broadcast.**
pub fn prepare_rbf_replacement_from_selection(
    original: &CoinSelection,
    params: &SpendParams,
    new_fee_sats: u64,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    address_gap: u32,
) -> Result<PreparedSpend> {
    let bumped = selection_with_rbf_fee(original, new_fee_sats)?;
    prepare_bip84_p2wpkh_spend(&bumped, params, mnemonic, passphrase, address_gap.max(1))
}

/// Product BIP-125 RBF: **same original inputs**, absolute fee from
/// [`plan_rbf_fee_bump`], sign/finalize/extract.
///
/// Does **not** re-select from a chain source (confirmed UTXOs after broadcast of
/// the stuck tx are gone / not the conflicting set). Caller must pass the original
/// prevouts (`--input txid:vout:amount:address` from spend dry-run meta).
///
/// Enforces absolute fee increase and incremental bandwidth on the **actual**
/// replacement weight, not only a floor(rate) re-select. Inputs signal RBF via
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`].
///
/// `passphrase` is the BIP-39 passphrase (empty = default path). Must match the
/// passphrase used to build `wallet` and to fund its inputs. Never log it.
///
/// `address_gap` is the BIP84 **signing** scan only (not a chain re-list).
/// Product RBF after gap-sync spend must pass
/// [`PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP`] so deep recovered indices still sign;
/// [`DEFAULT_RECEIVE_GAP`] is too small once product spend can select index ≥ 20.
///
/// **Does not broadcast.**
pub fn prepare_rbf_replacement(
    wallet: &DescriptorWallet,
    mnemonic: &MnemonicSecret,
    original_inputs: &[WalletUtxo],
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    target_fee_rate_sat_vb: u64,
    passphrase: &str,
    address_gap: u32,
) -> Result<RbfReplacementSpend> {
    if amount_sats == 0 {
        return Err(WalletError::Onchain(
            "RBF payment amount must be > 0 sats".into(),
        ));
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "RBF target fee rate must be > 0 sat/vB".into(),
        ));
    }
    if original_vbytes == 0 {
        return Err(WalletError::Onchain(
            "original vbytes must be > 0 for RBF plan".into(),
        ));
    }
    if original_inputs.is_empty() {
        return Err(WalletError::Onchain(
            "RBF requires original inputs (--input); re-select from chain is not a stuck-tx replacement"
                .into(),
        ));
    }

    let plan = plan_rbf_fee_bump(
        original_fee_sats,
        original_vbytes,
        target_fee_rate_sat_vb,
        0,
    )
    .map_err(|e| WalletError::Onchain(format!("RBF fee plan: {e}")))?;

    let original_sel =
        coin_selection_from_rbf_inputs(original_inputs, amount_sats, original_fee_sats)?;

    // Absolute recommended fee from the plan (not floor(rate) * vb, which can underpay).
    let mut target_fee = plan.recommended_fee_sats;
    // If dust fold raised reconstructed original fee above plan input, still bump past it.
    if target_fee <= original_sel.fee_sats {
        target_fee = original_sel.fee_sats.saturating_add(
            rbf_min_fee_increase_sats(original_vbytes, plan.incremental_relay_sat_vb).max(1),
        );
    }

    let change_address_for = |change_sats: u64| -> Result<Option<String>> {
        if change_sats == 0 {
            return Ok(None);
        }
        Ok(Some(
            wallet
                .change_addresses()
                .first()
                .cloned()
                .ok_or_else(|| WalletError::Onchain("wallet has no change address".into()))?,
        ))
    };

    let params_for = |change_sats: u64| -> Result<SpendParams> {
        Ok(SpendParams {
            payment_address: payment_address.to_owned(),
            change_address: change_address_for(change_sats)?,
            network: wallet.network(),
        })
    };

    let bumped = selection_with_rbf_fee(&original_sel, target_fee)?;
    let params = params_for(bumped.change_sats)?;
    let mut prepared =
        prepare_bip84_p2wpkh_spend(&bumped, &params, mnemonic, passphrase, address_gap.max(1))?;

    // Re-check BIP-125 against actual replacement weight; retry once with higher fee if needed.
    let plan_floor = plan.min_replacement_fee_sats.max(plan.recommended_fee_sats);
    if let Err(e) = validate_rbf_replacement_fee(
        original_fee_sats,
        prepared.fee_sats,
        prepared.weight_vbytes(),
        plan.incremental_relay_sat_vb,
        plan_floor,
    ) {
        let needed = bip125_min_replacement_fee_sats(
            original_fee_sats,
            prepared.weight_vbytes(),
            plan.incremental_relay_sat_vb,
        )
        .max(plan_floor)
        .max(prepared.fee_sats.saturating_add(1));
        let retry = selection_with_rbf_fee(&original_sel, needed).map_err(|_| e)?;
        let retry_params = params_for(retry.change_sats)?;
        prepared = prepare_bip84_p2wpkh_spend(
            &retry,
            &retry_params,
            mnemonic,
            passphrase,
            address_gap.max(1),
        )?;
        validate_rbf_replacement_fee(
            original_fee_sats,
            prepared.fee_sats,
            prepared.weight_vbytes(),
            plan.incremental_relay_sat_vb,
            plan_floor,
        )?;
    }

    // Same-input invariant: every original outpoint must appear in the replacement.
    for orig in original_inputs {
        let found = prepared.selected_inputs.iter().any(|u| {
            u.outpoint.txid == orig.outpoint.txid && u.outpoint.vout == orig.outpoint.vout
        });
        if !found {
            return Err(WalletError::Onchain(format!(
                "RBF replacement dropped original input {}:{} (internal error)",
                orig.outpoint.txid, orig.outpoint.vout
            )));
        }
    }
    if prepared.selected_inputs.len() != original_inputs.len() {
        return Err(WalletError::Onchain(
            "RBF replacement must use exactly the original input set (no extra inputs)".into(),
        ));
    }

    Ok(RbfReplacementSpend {
        prepared,
        plan,
        fee_rate_sat_vb: target_fee_rate_sat_vb,
        original_fee_sats,
        original_vbytes,
    })
}

/// Result of a CPFP **child** prepare (local only; does **not** replace the parent).
///
/// The child spends wallet-owned parent output(s) so the parent+child package fee
/// rate meets the target. Never claims the parent was cancelled or replaced.
#[derive(Clone)]
pub struct CpfpChildSpend {
    pub prepared: PreparedSpend,
    pub plan: CpfpFeePlan,
    /// Target package fee rate used when sizing the plan (sat/vB).
    pub fee_rate_sat_vb: u64,
    pub parent_fee_sats: u64,
    pub parent_vbytes: u64,
}

impl std::fmt::Debug for CpfpChildSpend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpfpChildSpend")
            .field("txid", &self.prepared.txid_hex())
            .field("child_fee_sats", &self.prepared.fee_sats)
            .field("parent_fee_sats", &self.parent_fee_sats)
            .field("fee_rate_sat_vb", &self.fee_rate_sat_vb)
            .field("package_fee_sats", &self.package_fee_sats())
            .finish()
    }
}

impl CpfpChildSpend {
    /// `parent_fee_sats + prepared.fee_sats`.
    pub fn package_fee_sats(&self) -> u64 {
        self.parent_fee_sats.saturating_add(self.prepared.fee_sats)
    }
}

/// Fail closed if `child_fee_sats` does not meet package-target + min-relay for
/// the **actual** child size (and optional plan floor).
///
/// Package: `(parent_fee + child_fee) >= (parent_vb + child_vb) * target`.
/// Child alone: `child_fee >= max(1, child_vb)` (min-relay style 1 sat/vB).
pub fn validate_cpfp_child_fee(
    parent_fee_sats: u64,
    parent_vbytes: u64,
    child_fee_sats: u64,
    child_vbytes: u64,
    target_fee_rate_sat_vb: u64,
    plan_min_child_fee_sats: u64,
) -> Result<()> {
    if parent_vbytes == 0 {
        return Err(WalletError::Onchain(
            "parent vbytes must be > 0 for CPFP package fee check".into(),
        ));
    }
    if child_vbytes == 0 {
        return Err(WalletError::Onchain(
            "child vbytes must be > 0 for CPFP fee check".into(),
        ));
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "CPFP target fee rate must be > 0 sat/vB".into(),
        ));
    }
    if child_fee_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP child fee must be > 0 sats".into(),
        ));
    }
    let min_relay_child = child_vbytes
        .saturating_mul(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB)
        .max(1);
    let package_vbytes = parent_vbytes.saturating_add(child_vbytes);
    let needed_package_fee = package_vbytes.saturating_mul(target_fee_rate_sat_vb);
    let for_package = needed_package_fee.saturating_sub(parent_fee_sats);
    let required = for_package
        .max(min_relay_child)
        .max(plan_min_child_fee_sats);
    if child_fee_sats < required {
        return Err(WalletError::Onchain(format!(
            "CPFP child fee {child_fee_sats} sats is below package floor {required} sats \
             (parent fee {parent_fee_sats} + child on {child_vbytes} vB; package {package_vbytes} vB \
             at {target_fee_rate_sat_vb} sat/vB; plan min {plan_min_child_fee_sats}). \
             Raise --fee-rate, reduce payment, or add --extra-input"
        )));
    }
    Ok(())
}

/// Rebuild a [`CoinSelection`] for a CPFP child from parent output(s) + optional
/// extra confirmed inputs and an absolute child fee.
///
/// Parent outputs are the unconfirmed (or confirmed) wallet-owned outs of the stuck
/// parent that the child must spend. Extra inputs fund the child fee when the
/// parent output alone cannot cover payment + fee. Folds dust change into fee.
///
/// Does **not** re-select from a chain source.
pub fn coin_selection_for_cpfp(
    parent_outputs: &[WalletUtxo],
    extra_inputs: &[WalletUtxo],
    payment_sats: u64,
    child_fee_sats: u64,
) -> Result<CoinSelection> {
    if parent_outputs.is_empty() {
        return Err(WalletError::Onchain(
            "CPFP requires at least one parent output (--parent txid:vout:amount:address)".into(),
        ));
    }
    if payment_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP payment amount must be > 0 sats".into(),
        ));
    }
    if child_fee_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP child fee must be > 0 sats".into(),
        ));
    }
    let mut seen = HashSet::with_capacity(parent_outputs.len() + extra_inputs.len());
    let mut selected = Vec::with_capacity(parent_outputs.len() + extra_inputs.len());
    let mut total = 0u64;
    for (label, utxo) in parent_outputs
        .iter()
        .map(|u| ("parent", u))
        .chain(extra_inputs.iter().map(|u| ("extra", u)))
    {
        if utxo.amount_sats == 0 {
            return Err(WalletError::Onchain(format!(
                "CPFP {label} {}:{} has zero amount",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        if utxo.address.trim().is_empty() {
            return Err(WalletError::Onchain(format!(
                "CPFP {label} {}:{} has empty address",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        if !seen.insert((utxo.outpoint.txid.clone(), utxo.outpoint.vout)) {
            return Err(WalletError::Onchain(format!(
                "duplicate CPFP input {}:{}",
                utxo.outpoint.txid, utxo.outpoint.vout
            )));
        }
        total = total.saturating_add(utxo.amount_sats);
        selected.push(utxo.clone());
    }
    let needed = payment_sats.saturating_add(child_fee_sats);
    if total < needed {
        return Err(WalletError::Onchain(format!(
            "insufficient value for CPFP child: need {needed} sats \
             (payment {payment_sats} + child fee {child_fee_sats}), have {total}. \
             Add --extra-input confirmed UTXOs or reduce payment"
        )));
    }
    let mut change = total - needed;
    let mut fee = child_fee_sats;
    if change > 0 && change < DUST_P2WPKH_SATS {
        fee = fee.saturating_add(change);
        change = 0;
    }
    Ok(CoinSelection {
        selected,
        total_input_sats: total,
        change_sats: change,
        target_sats: payment_sats,
        fee_sats: fee,
    })
}

/// CPFP child from a prior selection: apply absolute child fee then BIP84 sign/finalize.
///
/// `child_fee_sats` should come from [`plan_cpfp_child_fee`] min (or higher).
/// **Does not broadcast.** Does not claim the parent is replaced.
pub fn prepare_cpfp_child_from_selection(
    selection: &CoinSelection,
    params: &SpendParams,
    child_fee_sats: u64,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    address_gap: u32,
) -> Result<PreparedSpend> {
    if selection.selected.is_empty() {
        return Err(WalletError::Onchain("CPFP selection has no inputs".into()));
    }
    if selection.target_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP payment amount (target_sats) must be > 0".into(),
        ));
    }
    if child_fee_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP child fee must be > 0 sats".into(),
        ));
    }
    // Rebuild selection with the requested absolute fee (same inputs + payment).
    let needed = selection.target_sats.saturating_add(child_fee_sats);
    if selection.total_input_sats < needed {
        return Err(WalletError::Onchain(format!(
            "insufficient funds for CPFP child fee: need {needed} sats (payment {} + fee {child_fee_sats}), \
             have {} sats in inputs",
            selection.target_sats, selection.total_input_sats
        )));
    }
    let mut change = selection.total_input_sats - needed;
    let mut fee = child_fee_sats;
    if change > 0 && change < DUST_P2WPKH_SATS {
        fee = fee.saturating_add(change);
        change = 0;
    }
    if fee == 0 {
        return Err(WalletError::Onchain(
            "CPFP child fee after dust fold is 0 (rejected)".into(),
        ));
    }
    let sel = CoinSelection {
        selected: selection.selected.clone(),
        total_input_sats: selection.total_input_sats,
        change_sats: change,
        target_sats: selection.target_sats,
        fee_sats: fee,
    };
    prepare_bip84_p2wpkh_spend(&sel, params, mnemonic, passphrase, address_gap.max(1))
}

/// Product CPFP: spend parent output(s) (+ optional extras) with absolute child fee
/// from [`plan_cpfp_child_fee`] so package rate ≥ target.
///
/// Caller passes parent prevouts (`--parent txid:vout:amount:address` from the
/// unconfirmed parent) and optional `--extra-input` confirmed UTXOs when the parent
/// output alone cannot fund the child fee. Does **not** re-select from chain.
///
/// `passphrase` is the BIP-39 passphrase (empty = default path). Must match the
/// passphrase used to build `wallet` and to fund its parent/extra inputs. Never
/// log it. Same contract as [`prepare_rbf_replacement`] / product spend.
///
/// `address_gap` is the BIP84 **signing** scan only (not a chain re-list).
/// Product CPFP after gap-sync spend must pass
/// [`PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP`] (same reason as RBF: deep recovered
/// indices need a signing window larger than [`DEFAULT_RECEIVE_GAP`]).
///
/// **Does not broadcast.** Never claims the parent was replaced (CPFP is a child).
pub fn prepare_cpfp_child(
    wallet: &DescriptorWallet,
    mnemonic: &MnemonicSecret,
    parent_outputs: &[WalletUtxo],
    extra_inputs: &[WalletUtxo],
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    target_fee_rate_sat_vb: u64,
    passphrase: &str,
    address_gap: u32,
) -> Result<CpfpChildSpend> {
    if amount_sats == 0 {
        return Err(WalletError::Onchain(
            "CPFP payment amount must be > 0 sats".into(),
        ));
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "CPFP target fee rate must be > 0 sat/vB".into(),
        ));
    }
    if parent_vbytes == 0 {
        return Err(WalletError::Onchain(
            "parent vbytes must be > 0 for CPFP plan".into(),
        ));
    }
    if parent_outputs.is_empty() {
        return Err(WalletError::Onchain(
            "CPFP requires parent output(s) (--parent); child must spend the stuck parent".into(),
        ));
    }

    // Guaranteed ≥ 1 after parent_outputs non-empty check above.
    let n_in = parent_outputs.len().saturating_add(extra_inputs.len());

    // Size estimate: start with 2 outs (payment + change) so plan fee is not under;
    // if change folds to 0, try 1-out; if lowering fee reintroduces non-dust change,
    // re-expand to 2-out so plan vbytes and output count agree before first sign.
    let child_vb = estimate_tx_vbytes(n_in, 2);
    let mut plan = plan_cpfp_child_fee(
        parent_fee_sats,
        parent_vbytes,
        child_vb,
        target_fee_rate_sat_vb,
    )
    .map_err(|e| WalletError::Onchain(format!("CPFP fee plan: {e}")))?;

    let mut selection = coin_selection_for_cpfp(
        parent_outputs,
        extra_inputs,
        amount_sats,
        plan.min_child_fee_sats,
    )?;

    if selection.change_sats == 0 {
        let one_out_vb = estimate_tx_vbytes(n_in, 1);
        if one_out_vb != child_vb {
            let one_out_plan = plan_cpfp_child_fee(
                parent_fee_sats,
                parent_vbytes,
                one_out_vb,
                target_fee_rate_sat_vb,
            )
            .map_err(|e| WalletError::Onchain(format!("CPFP fee plan: {e}")))?;
            let one_out_sel = coin_selection_for_cpfp(
                parent_outputs,
                extra_inputs,
                amount_sats,
                one_out_plan.min_child_fee_sats,
            )?;
            if one_out_sel.change_sats == 0 {
                // Stable 1-out: plan and selection agree (child_vb only used for the
                // estimate comparison above; plan is refreshed from actual weight later).
                plan = one_out_plan;
                selection = one_out_sel;
            }
            // else: fee drop reintroduced non-dust change — keep 2-out plan/selection
            // (avoid building a 2-out child against a 1-out plan before first sign).
        }
    }

    let change_address_for = |change_sats: u64| -> Result<Option<String>> {
        if change_sats == 0 {
            return Ok(None);
        }
        Ok(Some(
            wallet
                .change_addresses()
                .first()
                .cloned()
                .ok_or_else(|| WalletError::Onchain("wallet has no change address".into()))?,
        ))
    };

    let params_for = |change_sats: u64| -> Result<SpendParams> {
        Ok(SpendParams {
            payment_address: payment_address.to_owned(),
            change_address: change_address_for(change_sats)?,
            network: wallet.network(),
        })
    };

    let params = params_for(selection.change_sats)?;
    let mut prepared = prepare_bip84_p2wpkh_spend(
        &selection,
        &params,
        mnemonic,
        passphrase,
        address_gap.max(1),
    )?;

    // Re-check package floor against actual child weight; retry once with higher fee.
    let plan_floor = plan.min_child_fee_sats;
    if let Err(package_err) = validate_cpfp_child_fee(
        parent_fee_sats,
        parent_vbytes,
        prepared.fee_sats,
        prepared.weight_vbytes(),
        target_fee_rate_sat_vb,
        plan_floor,
    ) {
        let actual_vb = prepared.weight_vbytes().max(1);
        let retry_plan = plan_cpfp_child_fee(
            parent_fee_sats,
            parent_vbytes,
            actual_vb,
            target_fee_rate_sat_vb,
        )
        .map_err(|pe| WalletError::Onchain(format!("CPFP fee re-plan: {pe}")))?;
        let needed = retry_plan
            .min_child_fee_sats
            .max(plan_floor)
            .max(prepared.fee_sats.saturating_add(1));
        let retry_sel =
            match coin_selection_for_cpfp(parent_outputs, extra_inputs, amount_sats, needed) {
                Ok(sel) => sel,
                Err(sel_err) => {
                    // Prefer insufficient-funds guidance (extra-input / lower payment)
                    // over "fee below package floor" which tempts raising --fee-rate.
                    let sel_msg = sel_err.to_string();
                    if sel_msg.to_ascii_lowercase().contains("insufficient") {
                        return Err(WalletError::Onchain(format!(
                            "{sel_msg} (also needed ≥ {needed} sats child fee for package floor \
                             after actual weight {actual_vb} vB; {package_err})"
                        )));
                    }
                    return Err(WalletError::Onchain(format!(
                        "{package_err}; retry selection failed: {sel_msg}"
                    )));
                }
            };
        let retry_params = params_for(retry_sel.change_sats)?;
        prepared = prepare_bip84_p2wpkh_spend(
            &retry_sel,
            &retry_params,
            mnemonic,
            passphrase,
            address_gap.max(1),
        )?;
        validate_cpfp_child_fee(
            parent_fee_sats,
            parent_vbytes,
            prepared.fee_sats,
            prepared.weight_vbytes(),
            target_fee_rate_sat_vb,
            retry_plan.min_child_fee_sats.max(plan_floor),
        )?;
    }

    // Parent outputs must all appear in the child (CPFP spends the stuck parent outs).
    for parent in parent_outputs {
        let found = prepared.selected_inputs.iter().any(|u| {
            u.outpoint.txid == parent.outpoint.txid && u.outpoint.vout == parent.outpoint.vout
        });
        if !found {
            return Err(WalletError::Onchain(format!(
                "CPFP child dropped parent output {}:{} (internal error)",
                parent.outpoint.txid, parent.outpoint.vout
            )));
        }
    }

    // Refresh plan from actual signed weight so product lines match prepared size
    // (heuristic estimate can drift). When dust fold raised the absolute child fee
    // above the package floor, surface the real package fee/rate on the plan.
    let actual_child_vb = prepared.weight_vbytes().max(1);
    let mut plan = plan_cpfp_child_fee(
        parent_fee_sats,
        parent_vbytes,
        actual_child_vb,
        target_fee_rate_sat_vb,
    )
    .map_err(|e| WalletError::Onchain(format!("CPFP fee plan refresh: {e}")))?;
    if prepared.fee_sats > plan.min_child_fee_sats {
        plan.package_fee_sats = parent_fee_sats.saturating_add(prepared.fee_sats);
        plan.package_fee_rate_sat_vb =
            effective_fee_rate_sat_vb(plan.package_fee_sats, plan.package_vbytes);
    }

    Ok(CpfpChildSpend {
        prepared,
        plan,
        fee_rate_sat_vb: target_fee_rate_sat_vb,
        parent_fee_sats,
        parent_vbytes,
    })
}

/// Parse a 64-hex [`OutPointRef`] into a bitcoin [`OutPoint`].
fn outpoint_from_ref(op: &OutPointRef) -> Result<OutPoint> {
    if !is_valid_txid_hex(&op.txid) {
        return Err(WalletError::Onchain(format!(
            "UTXO txid must be 64 hex characters, got len {}",
            op.txid.len()
        )));
    }
    let txid =
        Txid::from_str(&op.txid).map_err(|e| WalletError::Onchain(format!("invalid txid: {e}")))?;
    Ok(OutPoint {
        txid,
        vout: op.vout,
    })
}

/// Parse an address and require it for `network` (no silent cross-network spend).
fn parse_network_address(addr: &str, network: Network) -> Result<Address> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Onchain("empty bitcoin address".into()));
    }
    let unchecked = Address::from_str(trimmed)
        .map_err(|e| WalletError::Onchain(format!("invalid address: {e}")))?;
    unchecked
        .require_network(network)
        .map_err(|e| WalletError::Onchain(format!("address network mismatch: {e}")))
}

/// Map `script_pubkey → (secp pubkey, full BIP84 path from master)` for gap window.
fn bip84_script_lookup(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    gap: u32,
) -> Result<BTreeMap<ScriptBuf, (bitcoin::secp256k1::PublicKey, DerivationPath)>> {
    let mut seed = mnemonic.to_seed(passphrase);
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| WalletError::Onchain(format!("master for lookup: {e}")))?;
    seed.zeroize();

    let hrp = hrp_for_network(network);
    let mut map = BTreeMap::new();
    for is_change in [false, true] {
        for index in 0..gap {
            let path = bip84_full_path(network, is_change, index)?;
            let child = master
                .derive_priv(&secp, &path)
                .map_err(|e| WalletError::Onchain(format!("derive for lookup: {e}")))?;
            let pk = child.private_key.public_key(&secp);
            let compressed = CompressedPublicKey(pk);
            let addr = Address::p2wpkh(&compressed, hrp);
            map.insert(addr.script_pubkey(), (pk, path));
        }
    }
    Ok(map)
}

fn bip84_full_path(network: Network, is_change: bool, index: u32) -> Result<DerivationPath> {
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    let chain = if is_change { 1u32 } else { 0u32 };
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
        ChildNumber::from_normal_idx(chain).expect("chain"),
        ChildNumber::from_normal_idx(index)
            .map_err(|e| WalletError::Onchain(format!("index: {e}")))?,
    ]))
}

fn hrp_for_network(network: Network) -> bitcoin::KnownHrp {
    match network {
        Network::Bitcoin => bitcoin::KnownHrp::Mainnet,
        Network::Testnet | Network::Signet => bitcoin::KnownHrp::Testnets,
        Network::Regtest => bitcoin::KnownHrp::Regtest,
        _ => bitcoin::KnownHrp::Testnets,
    }
}

/// Parse mempool.space `GET /api/address/{addr}/utxo` JSON into [`WalletUtxo`]s.
///
/// Pure / offline-testable. `tip_height` (when known) yields accurate
/// confirmations via [`crate::watcher::confirmations_from_heights`]; when tip
/// is missing, API-confirmed UTXOs get `confirmations = 1` so they remain
/// spend-eligible under `confirmed_only`, but **depth is untrusted** (not a
/// claim of exactly one confirmation). Live mempool ChainSource documents the
/// same tip-miss policy.
///
/// Each `txid` must be 64 ASCII hex characters (fail-closed against empty /
/// truncated explorer bodies).
///
/// Expected item shape:
/// ```json
/// { "txid": "...", "vout": 0, "value": 12345,
///   "status": { "confirmed": true, "block_height": 800000 } }
/// ```
pub fn parse_mempool_address_utxos(
    body: &str,
    address: &str,
    tip_height: Option<u64>,
) -> Result<Vec<WalletUtxo>> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| WalletError::Explorer(format!("mempool address utxo JSON: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| WalletError::Explorer("mempool address utxo JSON: expected array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let txid = item
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::Explorer("utxo missing txid".into()))?;
        if !is_valid_txid_hex(txid) {
            return Err(WalletError::Explorer(format!(
                "utxo txid must be 64 hex chars, got len {} / non-hex",
                txid.len()
            )));
        }
        let txid = txid.to_owned();
        let vout = item
            .get("vout")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("utxo missing vout".into()))?;
        let vout = u32::try_from(vout)
            .map_err(|_| WalletError::Explorer("utxo vout out of range".into()))?;
        let amount_sats = item
            .get("value")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("utxo missing value".into()))?;

        let status = item.get("status");
        let confirmed = status
            .and_then(|s| s.get("confirmed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let block_height = status.and_then(|s| s.get("block_height")).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        });

        let confirmations = if !confirmed {
            0
        } else {
            match (block_height, tip_height) {
                (Some(bh), Some(tip)) => crate::watcher::confirmations_from_heights(tip, bh),
                // Confirmed without tip/height: spend-eligible conf=1; depth untrusted.
                _ => 1,
            }
        };

        out.push(WalletUtxo {
            outpoint: OutPointRef::new(txid, vout),
            amount_sats,
            address: address.to_owned(),
            confirmations,
            is_change: false,
        });
    }
    Ok(out)
}

/// Bitcoin txid: exactly 64 ASCII hex characters (no `0x` prefix).
fn is_valid_txid_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// BIP84 account path `m/84'/coin'/0'`.
fn account_path(network: Network) -> DerivationPath {
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
    ])
}

/// Account-level xpub and BIP380 origin body `fingerprint/84h/{coin}h/0h`
/// (without surrounding brackets).
fn account_xpub_and_origin(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
) -> Result<(String, String)> {
    let mut seed = mnemonic.to_seed(passphrase);
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| WalletError::Onchain(format!("master: {e}")))?;
    seed.zeroize();
    let fingerprint = master.fingerprint(&secp);
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    // BIP380 uses `h` for hardened; keep ASCII so descriptors stay portable.
    let origin = format!("{fingerprint}/84h/{coin}h/0h");
    let path = account_path(network);
    let account = master
        .derive_priv(&secp, &path)
        .map_err(|e| WalletError::Onchain(format!("account derive: {e}")))?;
    let xpub = Xpub::from_priv(&secp, &account);
    Ok((xpub.to_string(), origin))
}

/// BIP84 change address: `m/84'/coin'/0'/1/{index}`.
fn derive_bip84_change_address_with_passphrase(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    index: u32,
) -> Result<String> {
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::{Address, KnownHrp};

    let mut seed = mnemonic.to_seed(passphrase);
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| WalletError::Onchain(format!("master: {e}")))?;
    seed.zeroize();
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
        ChildNumber::from_normal_idx(1).expect("change"),
        ChildNumber::from_normal_idx(index)
            .map_err(|e| WalletError::Onchain(format!("index: {e}")))?,
    ]);
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| WalletError::Onchain(format!("derive: {e}")))?;
    let pubkey = child.private_key.public_key(&secp);
    let compressed = CompressedPublicKey(pubkey);
    let hrp = match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet | Network::Signet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        _ => KnownHrp::Testnets,
    };
    let addr = Address::p2wpkh(&compressed, hrp);
    Ok(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::import_mnemonic;
    use crate::onchain::{
        derive_bip84_receive_address, derive_bip84_receive_address_with_passphrase,
    };

    const VECTOR: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";

    fn wallet() -> DescriptorWallet {
        let m = import_mnemonic(VECTOR).unwrap();
        DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap()
    }

    #[test]
    fn descriptors_are_wpkh_account_wildcard() {
        let w = wallet();
        assert!(
            w.receive_descriptor.starts_with("wpkh(["),
            "expected BIP380 origin: {}",
            w.receive_descriptor
        );
        assert!(
            w.receive_descriptor.contains("/84h/0h/0h]"),
            "mainnet origin path: {}",
            w.receive_descriptor
        );
        assert!(
            w.receive_descriptor.ends_with("/0/*)"),
            "{}",
            w.receive_descriptor
        );
        assert!(
            w.change_descriptor.ends_with("/1/*)"),
            "{}",
            w.change_descriptor
        );
        assert!(!w.account_xpub.is_empty());
        // Descriptor must not embed the mnemonic.
        assert!(!w.receive_descriptor.contains("leader"));
        assert!(!w.account_xpub.contains("leader"));
    }

    #[test]
    fn primary_receive_matches_onchain_bip84_index0() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let expected = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        assert_eq!(w.primary_receive_address(), Some(expected.as_str()));
    }

    #[test]
    fn list_unspent_from_mock_chain_filters_by_wallet_addresses() {
        let w = wallet();
        let addr0 = w.primary_receive_address().unwrap().to_owned();
        let foreign = "bc1qforeign0000000000000000000000000000".to_owned();
        let mut chain = MockChainSource::new();
        chain.push(WalletUtxo {
            outpoint: OutPointRef::new("aa".repeat(32), 0),
            amount_sats: 50_000,
            address: addr0.clone(),
            confirmations: 3,
            is_change: false,
        });
        chain.push(WalletUtxo {
            outpoint: OutPointRef::new("bb".repeat(32), 1),
            amount_sats: 99_999,
            address: foreign,
            confirmations: 6,
            is_change: false,
        });

        let listed = w.list_unspent(&chain).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].amount_sats, 50_000);
        assert_eq!(listed[0].address, addr0);

        let bal = w.balance(&chain).unwrap();
        assert_eq!(bal.confirmed_sats, 50_000);
        assert_eq!(bal.unconfirmed_sats, 0);
        assert_eq!(bal.total_sats(), 50_000);
    }

    #[test]
    fn balance_splits_unconfirmed() {
        let w = wallet();
        let addr0 = w.primary_receive_address().unwrap().to_owned();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("cc".repeat(32), 0),
                amount_sats: 10_000,
                address: addr0.clone(),
                confirmations: 0,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("dd".repeat(32), 0),
                amount_sats: 20_000,
                address: addr0,
                confirmations: 2,
                is_change: false,
            },
        ]);
        let bal = w.balance(&chain).unwrap();
        assert_eq!(bal.confirmed_sats, 20_000);
        assert_eq!(bal.unconfirmed_sats, 10_000);
    }

    #[test]
    fn pure_gap_helpers_threshold_and_next() {
        // window 5 (indices 0..4); lookahead 1 → extend when hi >= 4
        assert!(!address_window_needs_extend(None, 5, 1));
        assert!(!address_window_needs_extend(Some(0), 5, 1));
        assert!(!address_window_needs_extend(Some(3), 5, 1));
        assert!(address_window_needs_extend(Some(4), 5, 1));
        // lookahead 0 treated as 1
        assert!(address_window_needs_extend(Some(4), 5, 0));
        // larger lookahead: extend when hi >= 5-3 = 2
        assert!(!address_window_needs_extend(Some(1), 5, 3));
        assert!(address_window_needs_extend(Some(2), 5, 3));
        assert!(!address_window_needs_extend(Some(0), 0, 1));

        assert_eq!(next_gap_after_extend(5, 20, 200), Some(25));
        assert_eq!(next_gap_after_extend(190, 20, 200), Some(200));
        assert_eq!(next_gap_after_extend(200, 20, 200), None);
        assert_eq!(next_gap_after_extend(5, 20, 5), None);
        // soft max cannot exceed hard MAX_ADDRESS_GAP
        assert_eq!(next_gap_after_extend(MAX_ADDRESS_GAP, 20, u32::MAX), None);
        assert_eq!(next_gap_after_extend(0, 0, 10), Some(1)); // step min 1
    }

    #[test]
    fn highest_used_index_from_utxo_addresses() {
        let addrs = vec!["a0".into(), "a1".into(), "a2".into()];
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new("aa".repeat(32), 0),
                amount_sats: 1,
                address: "a0".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("bb".repeat(32), 0),
                amount_sats: 1,
                address: "a2".into(),
                confirmations: 0,
                is_change: false,
            },
        ];
        assert_eq!(highest_used_address_index(&addrs, &utxos), Some(2));
        assert_eq!(highest_used_address_index(&addrs, &[]), None);
        assert_eq!(
            highest_used_address_index(
                &addrs,
                &[WalletUtxo {
                    outpoint: OutPointRef::new("cc".repeat(32), 0),
                    amount_sats: 1,
                    address: "foreign".into(),
                    confirmations: 1,
                    is_change: false,
                }]
            ),
            None
        );
    }

    #[test]
    fn sync_utxos_fixed_window_no_extend() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("ee".repeat(32), 0),
            amount_sats: 7_000,
            address: tip,
            confirmations: 1,
            is_change: false,
        }]);
        let snap = w.sync_utxos(&chain).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.balance.confirmed_sats, 7_000);
        assert_eq!(snap.receive_gap, 3);
        assert_eq!(snap.change_gap, 3);
        assert_eq!(snap.highest_used_receive, Some(2));
        assert_eq!(snap.highest_used_change, None);
        assert_eq!(snap.extended_receive_by, 0);
        assert_eq!(snap.extended_change_by, 0);
        assert!(!snap.hit_max_gap);
        // fixed sync never mutates the wallet
        assert_eq!(w.receive_gap(), 3);
    }

    #[test]
    fn sync_with_gap_extend_mid_window_no_extend_when_lookahead_is_tip_only() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 4).unwrap();
        // Activity only in the middle — not within tip-only lookahead of the end.
        let mid = w.receive_addresses()[1].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("11".repeat(32), 0),
            amount_sats: 3_000,
            address: mid,
            confirmations: 2,
            is_change: false,
        }]);
        let opts = GapExtendOptions {
            lookahead: 1, // tip-hot only (not default BIP44 stop-gap)
            extend_step: DEFAULT_GAP_EXTEND_STEP,
            max_gap: MAX_ADDRESS_GAP,
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert_eq!(snap.receive_gap, 4);
        assert_eq!(snap.extended_receive_by, 0);
        assert_eq!(snap.extended_change_by, 0);
        assert!(!snap.hit_max_gap);
        assert_eq!(snap.highest_used_receive, Some(1));
        assert_eq!(snap.balance.confirmed_sats, 3_000);
        assert_eq!(w.receive_gap(), 4);
    }

    #[test]
    fn sync_with_gap_extend_stop_gap_lookahead_finds_deep_mid_window_activity() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Initial window 5; used at index 1; deep UTXO at index 8 (beyond window).
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let mid = w.receive_addresses()[1].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 8).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("a1".repeat(32), 0),
                amount_sats: 2_000,
                address: mid,
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("a2".repeat(32), 0),
                amount_sats: 8_000,
                address: deep.clone(),
                confirmations: 1,
                is_change: false,
            },
        ]);

        // Tip-only look-ahead must NOT recover the deep UTXO.
        let tip_only = GapExtendOptions {
            lookahead: 1,
            extend_step: 5,
            max_gap: 40,
        };
        let mut w_tip = w.clone();
        let miss = w_tip
            .sync_with_gap_extend(&m, "", &chain, tip_only)
            .unwrap();
        assert_eq!(miss.receive_gap, 5);
        assert_eq!(miss.utxos.len(), 1);
        assert!(!w_tip.receive_addresses().contains(&deep));

        // BIP44-style stop-gap (default look-ahead 20) must extend and find index 8.
        let snap = w
            .sync_with_gap_extend(&m, "", &chain, GapExtendOptions::default())
            .unwrap();
        assert!(
            snap.receive_gap > 5,
            "stop-gap should grow window: {}",
            snap.receive_gap
        );
        assert!(snap.extended_receive_by >= 1);
        assert_eq!(snap.utxos.len(), 2);
        assert_eq!(snap.balance.confirmed_sats, 10_000);
        assert_eq!(snap.highest_used_receive, Some(8));
        assert!(w.receive_addresses().contains(&deep));
    }

    #[test]
    fn sync_with_gap_extend_tip_used_extends_and_sees_deeper_utxo() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Small window: indices 0..2. Tip (2) used → extend by step 2 to gap 4.
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        // Pre-derive deeper receive index that is outside the initial window.
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("22".repeat(32), 0),
                amount_sats: 1_000,
                address: tip,
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("33".repeat(32), 0),
                amount_sats: 9_000,
                address: deep.clone(),
                confirmations: 1,
                is_change: false,
            },
        ]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert!(snap.receive_gap >= 4, "gap grew: {}", snap.receive_gap);
        assert_eq!(snap.extended_receive_by, snap.receive_gap - 3);
        assert!(snap.extended_receive_by >= 1);
        assert_eq!(snap.extended_change_by, 0);
        assert!(!snap.hit_max_gap);
        // After extend, both tip and deeper UTXO are visible.
        assert_eq!(snap.utxos.len(), 2);
        assert_eq!(snap.balance.confirmed_sats, 10_000);
        assert_eq!(snap.highest_used_receive, Some(3));
        assert_eq!(w.receive_gap(), snap.receive_gap);
        // Deeper address must now be in the wallet window.
        assert!(w.receive_addresses().contains(&deep));
    }

    #[test]
    fn sync_with_gap_extend_stops_at_max_gap() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        // UTXO only on the tip of the *current* window; after each extend the new
        // tip also gets a fixture UTXO so growth would continue unbounded without cap.
        // We seed many indices so every tip after extend is "hot".
        let mut utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("44".repeat(32), 0),
            amount_sats: 100,
            address: tip,
            confirmations: 1,
            is_change: false,
        }];
        for i in 3..12u32 {
            let addr = derive_bip84_receive_address(&m, Network::Bitcoin, i).unwrap();
            utxos.push(WalletUtxo {
                outpoint: OutPointRef::new(format!("{i:064x}"), 0),
                amount_sats: 100,
                address: addr,
                confirmations: 1,
                is_change: false,
            });
        }
        let chain = MockChainSource::with_utxos(utxos);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 5, // soft max well below hard MAX_ADDRESS_GAP
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert_eq!(snap.receive_gap, 5);
        assert_eq!(w.receive_gap(), 5);
        assert!(
            snap.hit_max_gap,
            "must report max-gap stop while tip still hot"
        );
        assert!(snap.extended_receive_by >= 2);
        // Still only invents nothing: UTXOs come from mock for addresses in window.
        assert!(!snap.utxos.is_empty());
        assert_eq!(
            snap.balance.confirmed_sats,
            snap.utxos.iter().map(|u| u.amount_sats).sum::<u64>()
        );
    }

    #[test]
    fn sync_with_gap_extend_change_chain_independent() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let change_tip = w.change_addresses()[2].clone();
        let deep_change =
            derive_bip84_change_address_with_passphrase(&m, "", Network::Bitcoin, 3).unwrap();
        // Receive unused; only change tip used.
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("55".repeat(32), 0),
                amount_sats: 4_000,
                address: change_tip,
                confirmations: 3,
                is_change: true,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("66".repeat(32), 0),
                amount_sats: 6_000,
                address: deep_change.clone(),
                confirmations: 1,
                is_change: true,
            },
        ]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert_eq!(snap.receive_gap, 3);
        assert_eq!(snap.extended_receive_by, 0);
        assert!(snap.change_gap >= 4);
        assert!(snap.extended_change_by >= 1);
        assert_eq!(snap.highest_used_receive, None);
        assert_eq!(snap.highest_used_change, Some(3));
        assert_eq!(snap.balance.confirmed_sats, 10_000);
        assert!(w.change_addresses().contains(&deep_change));
        // list_unspent marks change
        assert!(snap.utxos.iter().all(|u| u.is_change));
    }

    #[test]
    fn extend_gap_if_needed_single_step_then_stable() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2).unwrap();
        let tip = w.receive_addresses()[1].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("77".repeat(32), 0),
            amount_sats: 500,
            address: tip,
            confirmations: 1,
            is_change: false,
        }]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 3,
            max_gap: 50,
        };
        let r1 = w.extend_gap_if_needed(&m, "", &chain, opts).unwrap();
        assert!(r1.receive_extended);
        assert!(!r1.change_extended);
        assert_eq!(r1.receive_before, 2);
        assert_eq!(r1.receive_after, 5);
        assert!(r1.grew());

        // New tip (index 4) has no UTXO → second pass does not extend.
        let r2 = w.extend_gap_if_needed(&m, "", &chain, opts).unwrap();
        assert!(!r2.grew());
        assert_eq!(r2.receive_after, 5);
        assert!(!r2.hit_max_gap);
    }

    #[test]
    fn gap_extend_options_clamp_to_hard_max() {
        let opts = GapExtendOptions {
            lookahead: 0,
            extend_step: 0,
            max_gap: u32::MAX,
        };
        assert_eq!(opts.effective_lookahead(), 1);
        assert_eq!(opts.effective_extend_step(), 1);
        assert_eq!(opts.effective_max_gap(), MAX_ADDRESS_GAP);
        // Default look-ahead is BIP44-style stop-gap, not tip-only.
        assert_eq!(DEFAULT_GAP_LOOKAHEAD, DEFAULT_RECEIVE_GAP);
        assert_eq!(GapExtendOptions::default().lookahead, DEFAULT_RECEIVE_GAP);
    }

    #[test]
    fn from_mnemonic_clamps_gap_to_max_address_gap() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w =
            DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, MAX_ADDRESS_GAP + 50).unwrap();
        assert_eq!(w.receive_gap(), MAX_ADDRESS_GAP);
        assert_eq!(w.change_gap(), MAX_ADDRESS_GAP);
        assert_eq!(w.receive_addresses().len(), MAX_ADDRESS_GAP as usize);
        // Zero request still yields at least one address.
        let w1 = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 0).unwrap();
        assert_eq!(w1.receive_gap(), 1);
        assert_eq!(w1.change_gap(), 1);
    }

    #[test]
    fn extend_with_wrong_passphrase_errors_and_leaves_gap_unchanged() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2).unwrap();
        let tip = w.receive_addresses()[1].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("wp".repeat(32), 0),
            amount_sats: 100,
            address: tip,
            confirmations: 1,
            is_change: false,
        }]);
        let before = w.receive_gap();
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 3,
            max_gap: 50,
        };
        let err = w
            .extend_gap_if_needed(&m, "wrong-passphrase", &chain, opts)
            .unwrap_err();
        assert!(
            matches!(err, WalletError::Onchain(ref s) if s.contains("passphrase") || s.contains("re-derive")),
            "expected material mismatch error, got {err:?}"
        );
        assert_eq!(
            w.receive_gap(),
            before,
            "window must not grow on bad material"
        );
        assert_eq!(w.change_gap(), before);

        // Direct extend API also refuses.
        let err2 = w
            .extend_receive_window_to(&m, "also-wrong", before + 5)
            .unwrap_err();
        assert!(matches!(err2, WalletError::Onchain(_)));
        assert_eq!(w.receive_gap(), before);
    }

    /// Failing chain source for error-propagation tests (no network).
    struct FailingChainSource;
    impl ChainSource for FailingChainSource {
        fn list_unspent_for_addresses(&self, _addresses: &[String]) -> Result<Vec<WalletUtxo>> {
            Err(WalletError::Explorer("mock chain list failure".into()))
        }
    }

    #[test]
    fn gap_sync_apis_propagate_chain_source_errors() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let chain = FailingChainSource;
        let opts = GapExtendOptions::default();

        let e1 = w.sync_utxos(&chain).unwrap_err();
        assert!(
            matches!(e1, WalletError::Explorer(ref s) if s.contains("mock chain")),
            "{e1:?}"
        );

        let e2 = w.extend_gap_if_needed(&m, "", &chain, opts).unwrap_err();
        assert!(matches!(e2, WalletError::Explorer(_)), "{e2:?}");
        assert_eq!(w.receive_gap(), 3, "failed list must not mutate gap");

        let e3 = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap_err();
        assert!(matches!(e3, WalletError::Explorer(_)), "{e3:?}");
        assert_eq!(w.receive_gap(), 3);
    }

    #[test]
    fn unconfirmed_tip_utxo_triggers_gap_extend() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("u0".repeat(32), 0),
                amount_sats: 500,
                address: tip,
                confirmations: 0, // 0-conf still counts as gap activity
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("u1".repeat(32), 0),
                amount_sats: 1_500,
                address: deep.clone(),
                confirmations: 0,
                is_change: false,
            },
        ]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert!(snap.receive_gap >= 4);
        assert_eq!(snap.utxos.len(), 2);
        assert_eq!(snap.balance.unconfirmed_sats, 2_000);
        assert_eq!(snap.balance.confirmed_sats, 0);
        assert!(w.receive_addresses().contains(&deep));
    }

    #[test]
    fn sync_with_gap_extend_stops_at_hard_max_address_gap() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Start near the hard cap so the test stays cheap.
        let start = MAX_ADDRESS_GAP - 3;
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, start).unwrap();
        // Seed UTXOs on every index through and past the hard cap tip so look-ahead
        // remains hot until growth is blocked.
        let mut utxos = Vec::new();
        for i in 0..=MAX_ADDRESS_GAP {
            let addr = derive_bip84_receive_address(&m, Network::Bitcoin, i).unwrap();
            utxos.push(WalletUtxo {
                outpoint: OutPointRef::new(format!("{i:064x}"), 0),
                amount_sats: 10,
                address: addr,
                confirmations: 1,
                is_change: false,
            });
        }
        let chain = MockChainSource::with_utxos(utxos);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 10,
            max_gap: u32::MAX, // soft max tries to exceed hard cap
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert_eq!(snap.receive_gap, MAX_ADDRESS_GAP);
        assert_eq!(w.receive_gap(), MAX_ADDRESS_GAP);
        assert!(
            snap.hit_max_gap,
            "must report hard MAX_ADDRESS_GAP stop while tip still hot"
        );
        assert!(snap.extended_receive_by >= 1);
        // Must not invent UTXOs beyond what the mock returned for the window.
        assert!(
            snap.utxos.len() as u32 <= MAX_ADDRESS_GAP,
            "only addresses in the capped window"
        );
    }

    #[test]
    fn sync_with_gap_extend_both_chains_hot_grow_independently() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv_tip = w.receive_addresses()[2].clone();
        let chg_tip = w.change_addresses()[2].clone();
        let deep_recv = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let deep_chg =
            derive_bip84_change_address_with_passphrase(&m, "", Network::Bitcoin, 3).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("br".repeat(32), 0),
                amount_sats: 1_000,
                address: recv_tip,
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("bc".repeat(32), 0),
                amount_sats: 2_000,
                address: chg_tip,
                confirmations: 1,
                is_change: true,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("dr".repeat(32), 0),
                amount_sats: 3_000,
                address: deep_recv.clone(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("dc".repeat(32), 0),
                amount_sats: 4_000,
                address: deep_chg.clone(),
                confirmations: 1,
                is_change: true,
            },
        ]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };
        let snap = w.sync_with_gap_extend(&m, "", &chain, opts).unwrap();
        assert!(snap.receive_gap >= 4);
        assert!(snap.change_gap >= 4);
        assert!(snap.extended_receive_by >= 1);
        assert!(snap.extended_change_by >= 1);
        assert_eq!(snap.utxos.len(), 4);
        assert_eq!(snap.balance.confirmed_sats, 10_000);
        assert!(w.receive_addresses().contains(&deep_recv));
        assert!(w.change_addresses().contains(&deep_chg));
    }

    #[test]
    fn sync_utxos_does_not_mutate_gap_when_tip_hot() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 5).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new("fh".repeat(32), 0),
                amount_sats: 100,
                address: tip,
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("fd".repeat(32), 0),
                amount_sats: 200,
                address: deep,
                confirmations: 1,
                is_change: false,
            },
        ]);
        let before_recv = w.receive_gap();
        let before_chg = w.change_gap();
        let snap = w.sync_utxos(&chain).unwrap();
        assert_eq!(snap.receive_gap, before_recv);
        assert_eq!(snap.change_gap, before_chg);
        assert_eq!(snap.extended_receive_by, 0);
        assert_eq!(w.receive_gap(), before_recv);
        // Deep UTXO outside window is invisible to fixed sync.
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.highest_used_receive, Some(2));
    }

    #[test]
    fn select_coins_largest_first_covers_target() {
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new("t1", 0),
                amount_sats: 10_000,
                address: "a".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("t2", 0),
                amount_sats: 40_000,
                address: "b".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("t3", 0),
                amount_sats: 15_000,
                address: "c".into(),
                confirmations: 1,
                is_change: false,
            },
        ];
        let sel = select_coins(&utxos, 45_000, CoinSelectStrategy::LargestFirst).unwrap();
        // 40k + 15k = 55k covers 45k with two largest-preferring picks.
        assert_eq!(sel.selected.len(), 2);
        assert_eq!(sel.selected[0].amount_sats, 40_000);
        assert_eq!(sel.total_input_sats, 55_000);
        assert_eq!(sel.change_sats, 10_000);
        assert_eq!(sel.target_sats, 45_000);
    }

    #[test]
    fn select_coins_smallest_first_covers_target() {
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new("t1", 0),
                amount_sats: 10_000,
                address: "a".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("t2", 0),
                amount_sats: 40_000,
                address: "b".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("t3", 0),
                amount_sats: 15_000,
                address: "c".into(),
                confirmations: 1,
                is_change: false,
            },
        ];
        // Target 20k: smallest-first should take 10k + 15k (not the single 40k).
        let sel = select_coins(&utxos, 20_000, CoinSelectStrategy::SmallestFirst).unwrap();
        assert_eq!(sel.selected.len(), 2);
        assert_eq!(sel.selected[0].amount_sats, 10_000);
        assert_eq!(sel.selected[1].amount_sats, 15_000);
        assert_eq!(sel.total_input_sats, 25_000);
        assert_eq!(sel.change_sats, 5_000);
    }

    #[test]
    fn select_coins_default_excludes_unconfirmed() {
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new("u0", 0),
                amount_sats: 100_000,
                address: "a".into(),
                confirmations: 0,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("c1", 0),
                amount_sats: 5_000,
                address: "b".into(),
                confirmations: 2,
                is_change: false,
            },
        ];
        // Default spend path: only the 5k confirmed UTXO counts → insufficient for 10k.
        let err = select_coins(&utxos, 10_000, CoinSelectStrategy::LargestFirst).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient"),
            "{err}"
        );
        // Explicit zero-conf allow: 100k unconfirmed covers target alone.
        let sel = select_coins_with_options(
            &utxos,
            10_000,
            CoinSelectStrategy::LargestFirst,
            /*confirmed_only*/ false,
        )
        .unwrap();
        assert_eq!(sel.selected[0].amount_sats, 100_000);
        assert_eq!(sel.selected[0].confirmations, 0);
    }

    #[test]
    fn select_coins_zero_conf_only_fails_when_confirmed_only() {
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("u0", 0),
            amount_sats: 50_000,
            address: "a".into(),
            confirmations: 0,
            is_change: false,
        }];
        let err = select_coins(&utxos, 1_000, CoinSelectStrategy::LargestFirst).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        assert!(err.to_string().contains("confirmed only"), "{err}");
    }

    #[test]
    fn select_coins_insufficient_funds_errors() {
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: 100,
            address: "a".into(),
            confirmations: 1,
            is_change: false,
        }];
        let err = select_coins(&utxos, 1_000, CoinSelectStrategy::LargestFirst).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("insufficient"), "{msg}");
    }

    #[test]
    fn select_coins_rejects_zero_target() {
        let err = select_coins(&[], 0, CoinSelectStrategy::LargestFirst).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
    }

    #[test]
    fn change_address_differs_from_receive() {
        let w = wallet();
        assert_ne!(
            w.receive_addresses.first(),
            w.change_addresses.first(),
            "external and change chains must differ"
        );
    }

    #[test]
    fn list_unspent_marks_change_utxos() {
        let w = wallet();
        let change0 = w.change_addresses[0].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("ee".repeat(32), 0),
            amount_sats: 1_000,
            address: change0,
            confirmations: 1,
            is_change: false, // chain did not annotate
        }]);
        let listed = w.list_unspent(&chain).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].is_change);
    }

    #[test]
    fn estimate_tx_vbytes_scales_with_inputs_and_outputs() {
        // 1-in 2-out: overhead + 68 + 2*31
        assert_eq!(estimate_tx_vbytes(1, 2), TX_OVERHEAD_VB + 68 + 62);
        assert_eq!(estimate_tx_vbytes(2, 1), TX_OVERHEAD_VB + 136 + 31);
        assert_eq!(estimate_fee_sats(1, 2, 10), estimate_tx_vbytes(1, 2) * 10);
    }

    #[test]
    fn effective_fee_rate_and_div_ceil_edge_cases() {
        assert_eq!(effective_fee_rate_sat_vb(1410, 141), 10);
        assert_eq!(effective_fee_rate_sat_vb(100, 0), 0);
        assert_eq!(effective_fee_rate_sat_vb(0, 100), 0);
        assert_eq!(div_ceil_u64(10, 3), 4);
        assert_eq!(div_ceil_u64(9, 3), 3);
        assert_eq!(div_ceil_u64(1, 0), 0);
        assert_eq!(div_ceil_u64(0, 5), 0);
    }

    #[test]
    fn rbf_min_fee_increase_uses_default_incremental() {
        assert_eq!(rbf_min_fee_increase_sats(141, 0), 141); // default 1 sat/vB
        assert_eq!(rbf_min_fee_increase_sats(141, 1), 141);
        assert_eq!(rbf_min_fee_increase_sats(141, 2), 282);
        assert_eq!(rbf_min_fee_increase_sats(0, 1), 0);
        assert_eq!(rbf_min_fee_increase_sats(1, 0), 1);
    }

    #[test]
    fn plan_rbf_fee_bump_meets_bip125_and_target() {
        // Original: 141 vb @ 5 sat/vB → 705 sats fee, floor rate 5.
        let orig_vb = 141u64;
        let orig_fee = 705u64;
        let plan = plan_rbf_fee_bump(orig_fee, orig_vb, 10, 0).unwrap();
        assert_eq!(plan.original_fee_rate_sat_vb, 5);
        assert_eq!(
            plan.incremental_relay_sat_vb,
            DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB
        );
        // Target 10 * 141 = 1410; increment floor = 705+141=846; higher rate 6*141=846.
        assert_eq!(plan.recommended_fee_sats, 1410);
        assert_eq!(plan.recommended_fee_rate_sat_vb, 10);
        assert_eq!(plan.fee_delta_sats, 1410 - 705);
        assert!(plan.min_replacement_fee_sats > orig_fee);
        assert!(plan.min_replacement_fee_sats >= orig_fee + orig_vb);
        assert!(plan.min_replacement_fee_rate_sat_vb > plan.original_fee_rate_sat_vb);
        assert!(plan.recommended_fee_sats >= plan.min_replacement_fee_sats);
    }

    #[test]
    fn plan_rbf_fee_bump_target_below_bip125_floor_still_bumps() {
        // Target equal to original rate must still raise absolute fee / rate.
        let plan = plan_rbf_fee_bump(705, 141, 5, 1).unwrap();
        assert!(plan.recommended_fee_sats > 705);
        assert!(plan.recommended_fee_rate_sat_vb >= 5);
        // At least +141 sats for 1 sat/vB incremental on same size.
        assert!(plan.recommended_fee_sats >= 705 + 141);
        assert_eq!(plan.min_replacement_fee_sats, plan.recommended_fee_sats);
    }

    #[test]
    fn plan_rbf_fee_bump_rejects_zero_vbytes_and_zero_target() {
        assert_eq!(
            plan_rbf_fee_bump(100, 0, 10, 1).unwrap_err(),
            FeeBumpPlanError::ZeroVbytes
        );
        assert_eq!(
            plan_rbf_fee_bump(100, 100, 0, 1).unwrap_err(),
            FeeBumpPlanError::ZeroTargetRate
        );
    }

    #[test]
    fn plan_rbf_fee_bump_zero_original_fee() {
        let plan = plan_rbf_fee_bump(0, 100, 5, 1).unwrap();
        assert_eq!(plan.original_fee_rate_sat_vb, 0);
        // higher_rate = 1 → min_by_rate = 100; increment = 100; absolute = 1 → min 100
        // target = 500 → recommended 500
        assert_eq!(plan.recommended_fee_sats, 500);
        assert!(plan.min_replacement_fee_sats >= 100);
        assert!(plan.recommended_fee_sats > 0);
    }

    #[test]
    fn plan_cpfp_child_fee_covers_underpaying_parent() {
        // Parent 200 vb, 200 sats fee → 1 sat/vB. Target 10. Child 110 vb (1-in 1-out).
        let child_vb = estimate_cpfp_child_vbytes(1);
        assert_eq!(child_vb, estimate_tx_vbytes(1, 1));
        let plan = plan_cpfp_child_fee(200, 200, child_vb, 10).unwrap();
        let package_vb = 200 + child_vb;
        let needed = package_vb * 10;
        assert_eq!(plan.min_child_fee_sats, needed - 200);
        assert_eq!(plan.package_fee_sats, needed);
        assert!(plan.package_fee_rate_sat_vb >= 10);
        assert_eq!(plan.package_vbytes, package_vb);
        assert!(plan.min_child_fee_rate_sat_vb >= 10);
    }

    #[test]
    fn plan_cpfp_child_fee_overpaying_parent_still_min_relay_child() {
        // Parent already at 50 sat/vB; child still needs min-relay for itself.
        let child_vb = 110u64;
        let parent_fee = 50 * 200;
        let plan = plan_cpfp_child_fee(parent_fee, 200, child_vb, 10).unwrap();
        assert_eq!(plan.min_child_fee_sats, child_vb); // 1 sat/vB min relay
        assert!(plan.package_fee_rate_sat_vb >= 10);
    }

    #[test]
    fn plan_cpfp_child_fee_rejects_bad_inputs() {
        assert_eq!(
            plan_cpfp_child_fee(10, 0, 100, 5).unwrap_err(),
            FeeBumpPlanError::ZeroVbytes
        );
        assert_eq!(
            plan_cpfp_child_fee(10, 100, 0, 5).unwrap_err(),
            FeeBumpPlanError::ZeroChildVbytes
        );
        assert_eq!(
            plan_cpfp_child_fee(10, 100, 50, 0).unwrap_err(),
            FeeBumpPlanError::ZeroTargetRate
        );
    }

    #[test]
    fn estimate_cpfp_child_vbytes_defaults_empty_outputs_to_one() {
        assert_eq!(estimate_cpfp_child_vbytes(0), estimate_tx_vbytes(1, 1));
        assert_eq!(estimate_cpfp_child_vbytes(2), estimate_tx_vbytes(1, 2));
    }

    #[test]
    fn prepared_spend_exposes_weight_and_fee_rate() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.receive_addresses[0].clone();
        let pay_to = w.receive_addresses[1].clone();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new("aa".repeat(32), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }]);
        let prep =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, "", 5).unwrap();
        assert!(prep.weight_vbytes() > 0);
        assert_eq!(
            prep.effective_fee_rate_sat_vb(),
            effective_fee_rate_sat_vb(prep.fee_sats, prep.weight_vbytes())
        );
        assert_eq!(
            prep.estimated_vbytes(),
            estimate_tx_vbytes(prep.input_count, prep.output_count)
        );
        // Weight vbytes should be in the same ballpark as the P2WPKH heuristic.
        let est = prep.estimated_vbytes();
        let actual = prep.weight_vbytes();
        assert!(
            actual.abs_diff(est) <= 20,
            "weight {actual} vs estimate {est}"
        );
    }

    #[test]
    fn select_coins_with_fee_covers_target_plus_fee() {
        // 1-in 2-out @ 10 sat/vB: fee = (11+68+62)*10 = 1410
        let fee = estimate_fee_sats(1, 2, 10);
        assert_eq!(fee, 1_410);
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: 50_000,
            address: "a".into(),
            confirmations: 3,
            is_change: false,
        }];
        let sel =
            select_coins_with_fee(&utxos, 20_000, 10, CoinSelectStrategy::LargestFirst).unwrap();
        assert_eq!(sel.selected.len(), 1);
        assert_eq!(sel.target_sats, 20_000);
        assert_eq!(sel.fee_sats, fee);
        assert_eq!(sel.total_input_sats, 50_000);
        assert_eq!(sel.change_sats, 50_000 - 20_000 - fee);
        assert!(sel.change_sats >= DUST_P2WPKH_SATS);
    }

    #[test]
    fn select_coins_fee_shortfall_when_target_fits_but_fee_does_not() {
        // Single 10k UTXO: target 9_500 — neither 2-out (need 10_910) nor 1-out
        // (need 10_600) is affordable at 10 sat/vB, even though target alone fits.
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: 10_000,
            address: "a".into(),
            confirmations: 1,
            is_change: false,
        }];
        // Without fee: 10k covers 9_500.
        let no_fee = select_coins(&utxos, 9_500, CoinSelectStrategy::LargestFirst).unwrap();
        assert_eq!(no_fee.change_sats, 500);
        assert_eq!(no_fee.fee_sats, 0);

        assert!(
            10_000 < estimate_fee_sats(1, 1, 10).saturating_add(9_500),
            "fixture must sit below 1-out needed"
        );
        let err =
            select_coins_with_fee(&utxos, 9_500, 10, CoinSelectStrategy::LargestFirst).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("insufficient"), "{msg}");
        assert!(msg.contains("fee") || msg.contains("sat/vb"), "{msg}");
    }

    #[test]
    fn select_coins_fee_one_output_when_two_output_fee_not_covered() {
        // Window: needed_1out <= total < needed_2out.
        // 1-in @ 10 sat/vB: fee_2out=1410 → needed 10_910; fee_1out=1100 → needed 10_600.
        // UTXO 10_600 covers 1-out exactly, not 2-out — must succeed (not false shortfall).
        let rate = 10u64;
        let target = 9_500u64;
        let total = 10_600u64;
        let fee_1 = estimate_fee_sats(1, 1, rate);
        let fee_2 = estimate_fee_sats(1, 2, rate);
        assert_eq!(fee_1, 1_100);
        assert_eq!(fee_2, 1_410);
        assert!(target + fee_1 <= total && total < target + fee_2);

        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: total,
            address: "a".into(),
            confirmations: 1,
            is_change: false,
        }];
        let sel =
            select_coins_with_fee(&utxos, target, rate, CoinSelectStrategy::LargestFirst).unwrap();
        assert_eq!(sel.selected.len(), 1);
        assert_eq!(sel.change_sats, 0);
        assert_eq!(sel.fee_sats, total - target);
        assert!(sel.fee_sats >= fee_1);
        assert_eq!(sel.total_input_sats, total);
        assert_eq!(sel.target_sats, target);
    }

    #[test]
    fn select_coins_fee_shortfall_adds_second_input_when_available() {
        // First coin alone: 15k target + 1410 fee = 16410 > 15k → need second.
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new("t1", 0),
                amount_sats: 15_000,
                address: "a".into(),
                confirmations: 1,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new("t2", 0),
                amount_sats: 15_000,
                address: "b".into(),
                confirmations: 1,
                is_change: false,
            },
        ];
        let fee_2in = estimate_fee_sats(2, 2, 10);
        let sel =
            select_coins_with_fee(&utxos, 15_000, 10, CoinSelectStrategy::LargestFirst).unwrap();
        assert_eq!(sel.selected.len(), 2);
        assert_eq!(sel.fee_sats, fee_2in);
        assert_eq!(sel.total_input_sats, 30_000);
        assert_eq!(sel.change_sats, 30_000 - 15_000 - fee_2in);
    }

    #[test]
    fn select_coins_fee_dust_change_folded_into_fee() {
        // Craft total so change under dust with 2-out, but 1-out still works.
        // 1-in 2-out fee @1 sat/vB = 141; 1-in 1-out fee = 11+68+31 = 110.
        // UTXO 10_400, target 10_200 → with change: need 10200+141=10341 > 10400
        // wait that's not enough. Use larger:
        // UTXO 10_500, target 10_200, rate 1:
        //   fee_2out=141 → change=10500-10200-141=159 < dust 294 → fold
        //   fee_1out=110 → need 10310, have 10500 → fee_sats = 300, change=0
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: 10_500,
            address: "a".into(),
            confirmations: 1,
            is_change: false,
        }];
        let sel =
            select_coins_with_fee(&utxos, 10_200, 1, CoinSelectStrategy::LargestFirst).unwrap();
        assert_eq!(sel.change_sats, 0);
        assert_eq!(sel.fee_sats, 300); // total - target
        assert!(sel.fee_sats >= estimate_fee_sats(1, 1, 1));
    }

    #[test]
    fn select_coins_ex_zero_fee_rate_matches_legacy() {
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new("t1", 0),
            amount_sats: 5_000,
            address: "a".into(),
            confirmations: 1,
            is_change: false,
        }];
        let a = select_coins(&utxos, 1_000, CoinSelectStrategy::LargestFirst).unwrap();
        let b = select_coins_ex(
            &utxos,
            1_000,
            CoinSelectOptions {
                strategy: CoinSelectStrategy::LargestFirst,
                confirmed_only: true,
                fee_rate_sat_vb: Some(0),
            },
        )
        .unwrap();
        assert_eq!(a.selected, b.selected);
        assert_eq!(a.change_sats, b.change_sats);
        assert_eq!(b.fee_sats, 0);
    }

    #[test]
    fn parse_mempool_utxo_confirmed_with_tip() {
        let body = r#"[
          {
            "txid": "12f96289f8f9cd51ccfe390879a46d7eeb0435d9e0af9297776e6bdf249414ff",
            "vout": 0,
            "status": {
              "confirmed": true,
              "block_height": 100,
              "block_hash": "00ab",
              "block_time": 1630561459
            },
            "value": 64495
          }
        ]"#;
        let utxos = parse_mempool_address_utxos(body, "bc1qtest", Some(102)).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(
            utxos[0].outpoint.txid,
            "12f96289f8f9cd51ccfe390879a46d7eeb0435d9e0af9297776e6bdf249414ff"
        );
        assert_eq!(utxos[0].outpoint.vout, 0);
        assert_eq!(utxos[0].amount_sats, 64_495);
        assert_eq!(utxos[0].address, "bc1qtest");
        assert_eq!(utxos[0].confirmations, 3); // tip 102, height 100 → 3
        assert!(!utxos[0].is_change);
    }

    #[test]
    fn parse_mempool_utxo_unconfirmed() {
        let txid = "ab".repeat(32);
        let body = format!(
            r#"[{{"txid":"{txid}","vout":1,"status":{{"confirmed":false}},"value":1000}}]"#
        );
        let utxos = parse_mempool_address_utxos(&body, "bc1qunconf", Some(900_000)).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].confirmations, 0);
        assert_eq!(utxos[0].amount_sats, 1_000);
        assert_eq!(utxos[0].outpoint.vout, 1);
        assert_eq!(utxos[0].outpoint.txid, txid);
    }

    #[test]
    fn parse_mempool_utxo_confirmed_without_tip_is_at_least_one() {
        let body = r#"[{
            "txid":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "vout":2,
            "status":{"confirmed":true,"block_height":800000},
            "value":42
        }]"#;
        let utxos = parse_mempool_address_utxos(body, "bc1qx", None).unwrap();
        assert_eq!(utxos[0].confirmations, 1);
        assert_eq!(utxos[0].amount_sats, 42);
    }

    #[test]
    fn parse_mempool_utxo_empty_array() {
        let utxos = parse_mempool_address_utxos("[]", "bc1qempty", Some(1)).unwrap();
        assert!(utxos.is_empty());
    }

    #[test]
    fn parse_mempool_utxo_rejects_non_array() {
        let err = parse_mempool_address_utxos("{}", "bc1q", None).unwrap_err();
        assert!(matches!(err, WalletError::Explorer(_)));
    }

    #[test]
    fn parse_mempool_utxo_rejects_missing_fields() {
        let err =
            parse_mempool_address_utxos(r#"[{"vout":0,"value":1}]"#, "bc1q", None).unwrap_err();
        assert!(matches!(err, WalletError::Explorer(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("txid"), "{msg}");
    }

    #[test]
    fn parse_mempool_utxo_multiple_items() {
        let tx_a = "aa".repeat(32);
        let tx_b = "bb".repeat(32);
        let body = format!(
            r#"[
          {{"txid":"{tx_a}","vout":0,"status":{{"confirmed":true,"block_height":10}},"value":100}},
          {{"txid":"{tx_b}","vout":3,"status":{{"confirmed":false}},"value":200}}
        ]"#
        );
        let utxos = parse_mempool_address_utxos(&body, "bc1qm", Some(12)).unwrap();
        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos[0].confirmations, 3);
        assert_eq!(utxos[1].confirmations, 0);
        assert_eq!(utxos[1].outpoint.vout, 3);
        assert_eq!(utxos[0].outpoint.txid, tx_a);
    }

    #[test]
    fn parse_mempool_utxo_rejects_empty_or_short_txid() {
        let empty = r#"[{"txid":"","vout":0,"status":{"confirmed":false},"value":1}]"#;
        let err = parse_mempool_address_utxos(empty, "bc1q", None).unwrap_err();
        assert!(matches!(err, WalletError::Explorer(_)));
        assert!(
            err.to_string().to_ascii_lowercase().contains("txid"),
            "{err}"
        );

        let short = r#"[{"txid":"deadbeef","vout":0,"status":{"confirmed":false},"value":1}]"#;
        let err = parse_mempool_address_utxos(short, "bc1q", None).unwrap_err();
        assert!(matches!(err, WalletError::Explorer(_)));

        let non_hex = format!(
            r#"[{{"txid":"{}","vout":0,"status":{{"confirmed":false}},"value":1}}]"#,
            "g".repeat(64)
        );
        let err = parse_mempool_address_utxos(&non_hex, "bc1q", None).unwrap_err();
        assert!(matches!(err, WalletError::Explorer(_)));
    }

    fn valid_txid(nibble: char) -> String {
        nibble.to_string().repeat(64)
    }

    fn selection_one_utxo(
        address: &str,
        amount_sats: u64,
        target_sats: u64,
        fee_sats: u64,
    ) -> CoinSelection {
        let change_sats = amount_sats
            .saturating_sub(target_sats)
            .saturating_sub(fee_sats);
        CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('a'), 0),
                amount_sats,
                address: address.to_owned(),
                confirmations: 3,
                is_change: false,
            }],
            total_input_sats: amount_sats,
            change_sats,
            target_sats,
            fee_sats,
        }
    }

    #[test]
    fn build_unsigned_psbt_payment_and_change_outputs() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        // Payment to a second receive address (same wallet / network).
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();

        let amount = 100_000u64;
        let target = 40_000u64;
        let fee = 500u64;
        let sel = selection_one_utxo(&recv, amount, target, fee);
        assert_eq!(sel.change_sats, 59_500);

        let built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to.clone(),
                change_address: Some(change.clone()),
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        assert_eq!(built.input_count(), 1);
        assert_eq!(built.output_count(), 2);
        assert_eq!(built.fee_sats, fee);
        assert_eq!(built.payment_sats, target);
        assert_eq!(built.change_sats, 59_500);

        let tx = &built.psbt.unsigned_tx;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), target);
        assert_eq!(tx.output[1].value.to_sat(), 59_500);
        // Fee residual: inputs - outputs
        let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(amount - out_sum, fee);

        let pay_spk = parse_network_address(&pay_to, Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        let change_spk = parse_network_address(&change, Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        assert_eq!(tx.output[0].script_pubkey, pay_spk);
        assert_eq!(tx.output[1].script_pubkey, change_spk);

        assert!(built.psbt.inputs[0].witness_utxo.is_some());
        assert_eq!(
            built.psbt.inputs[0]
                .witness_utxo
                .as_ref()
                .unwrap()
                .value
                .to_sat(),
            amount
        );
        // Still unsigned: no partial sigs / final witness.
        assert!(built.psbt.inputs[0].partial_sigs.is_empty());
        assert!(built.psbt.inputs[0].final_script_witness.is_none());
        assert!(!built.serialize_hex().is_empty());
    }

    #[test]
    fn build_unsigned_psbt_no_change_when_dust_folded() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        // total 10_000, target 9_500, fee 500 → change 0
        let sel = selection_one_utxo(&recv, 10_000, 9_500, 500);
        assert_eq!(sel.change_sats, 0);

        let built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        assert_eq!(built.output_count(), 1);
        assert_eq!(built.change_sats, 0);
        assert_eq!(built.psbt.unsigned_tx.output[0].value.to_sat(), 9_500);
    }

    #[test]
    fn build_unsigned_psbt_requires_change_address_when_change_positive() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 100_000, 40_000, 500);
        assert!(sel.change_sats > 0);

        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        assert!(
            err.to_string().to_ascii_lowercase().contains("change"),
            "{err}"
        );
    }

    #[test]
    fn build_unsigned_psbt_rejects_malformed_txid() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let mut sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        sel.selected[0].outpoint.txid = "not-a-txid".into();

        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        assert!(
            err.to_string().to_ascii_lowercase().contains("txid"),
            "{err}"
        );
    }

    #[test]
    fn build_unsigned_psbt_rejects_empty_selection() {
        let sel = CoinSelection {
            selected: vec![],
            total_input_sats: 0,
            change_sats: 0,
            target_sats: 1_000,
            fee_sats: 0,
        };
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
    }

    #[test]
    fn build_unsigned_psbt_rejects_fee_mismatch() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let mut sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        sel.fee_sats = 50; // lie about fee without adjusting totals

        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("fee"),
            "{err}"
        );
    }

    #[test]
    fn build_unsigned_psbt_rejects_empty_payment_address() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: "   ".into(),
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
    }

    #[test]
    fn sign_finalize_extract_bip84_p2wpkh_end_to_end() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();

        let amount = 50_000u64;
        let target = 20_000u64;
        let fee = 250u64;
        let sel = selection_one_utxo(&recv, amount, target, fee);

        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(change),
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(outcome.is_complete(), "{outcome:?}");
        assert_eq!(outcome.signed_inputs(), 1);
        assert_eq!(built.psbt.inputs[0].partial_sigs.len(), 1);

        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        assert!(psbt_is_broadcast_ready(&built.psbt));
        let witness = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        assert_eq!(witness.len(), 2, "P2WPKH witness: sig + pubkey");

        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), target);
        assert!(!tx.input[0].witness.is_empty());
        let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(amount - out_sum, fee);
    }

    #[test]
    fn build_sign_extract_convenience_matches_pipeline() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 80_000, 30_000, 400);

        let tx = build_sign_extract_bip84_p2wpkh(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(change),
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 30_000);
        assert!(!tx.input[0].witness.is_empty());
    }

    #[test]
    fn sign_psbt_partial_when_utxo_not_in_gap() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Foreign mainnet P2WPKH (Bitcoin wiki example) — not derived from VECTOR.
        let foreign = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let sel = selection_one_utxo(foreign, 10_000, 9_000, 1_000);

        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(!outcome.is_complete());
        match outcome {
            SignOutcome::Partial {
                signed_inputs,
                unsigned_inputs,
                ..
            } => {
                assert_eq!(signed_inputs, 0);
                assert_eq!(unsigned_inputs, 1);
            }
            other => panic!("expected Partial, got {other:?}"),
        }

        // Convenience path must refuse incomplete sign (honest residual).
        let err = build_sign_extract_bip84_p2wpkh(
            &sel,
            &SpendParams {
                payment_address: derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap(),
                change_address: None,
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("incomplete")
                || err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("not broadcast"),
            "{err}"
        );
    }

    #[test]
    fn transaction_hex_and_mock_broadcast_roundtrip() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 80_000, 30_000, 400);
        let prepared = prepare_bip84_p2wpkh_spend(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(change),
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap();
        let hex = prepared.raw_hex();
        assert!(!hex.is_empty());
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(hex.len() % 2, 0);
        assert_eq!(prepared.txid_hex().len(), 64);
        assert_eq!(prepared.payment_sats, 30_000);
        assert_eq!(prepared.fee_sats, 400);

        // Empty / non-hex never call through as success.
        let mut mock = crate::explorer::MockTxBroadcaster::new();
        let err = broadcast_raw_tx(&mut mock, "").unwrap_err();
        assert!(err.to_string().contains("empty"));
        assert!(mock.last_raw_hex.is_none());
        assert!(mock.submitted.is_empty());

        mock.push_ok(prepared.txid_hex());
        let res = broadcast_raw_tx(&mut mock, &hex).unwrap();
        assert_eq!(res.txid, prepared.txid_hex());
        assert_eq!(mock.last_raw_hex.as_deref(), Some(hex.as_str()));

        // Mock error must surface (never invent success).
        mock.push_err("rejected by policy");
        let err = broadcast_raw_tx(&mut mock, &hex).unwrap_err();
        assert!(err.to_string().contains("rejected"));
    }

    #[test]
    fn select_and_prepare_uses_fee_aware_coins() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('a'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }]);
        let prep =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, "", 5).unwrap();
        assert_eq!(prep.payment_sats, 25_000);
        assert!(prep.fee_sats > 0);
        assert_eq!(prep.input_count, 1);
        assert!(!prep.raw_hex().is_empty());
    }

    #[test]
    fn select_and_prepare_rejects_zero_fee_rate() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('a'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }]);
        let err =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 0, "", 5).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("fee rate") && (msg.contains("> 0") || msg.contains("must be")),
            "expected fee-rate rejection, got: {err}"
        );
    }

    /// Deep receive UTXO beyond the initial fixed window (activity near the
    /// look-ahead tip): fixed-window select misses the deep coin / cannot fund;
    /// gap-sync product path extends, lists it, and prepares a spend.
    #[test]
    fn gap_sync_spend_finds_deep_utxo_missed_by_fixed_window() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Initial window of 5; tip dust at index 4 pulls gap; real funds at index 8.
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let tip = w.receive_addresses()[4].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 8).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('1'), 0),
                // Dust-only in fixed window — cannot fund a 25k payment.
                amount_sats: 1_000,
                address: tip,
                confirmations: 6,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('2'), 0),
                amount_sats: 100_000,
                address: deep.clone(),
                confirmations: 6,
                is_change: false,
            },
        ]);

        // Fixed window only sees tip dust → shortfall (or no affordable selection).
        let fixed_err =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, "", 5).unwrap_err();
        let fixed_msg = fixed_err.to_string().to_ascii_lowercase();
        assert!(
            fixed_msg.contains("insufficient")
                || fixed_msg.contains("shortfall")
                || fixed_msg.contains("not enough")
                || fixed_msg.contains("no utxo")
                || fixed_msg.contains("fund")
                || fixed_msg.contains("cannot"),
            "fixed window must fail without deep UTXO, got: {fixed_err}"
        );
        assert_eq!(w.receive_gap(), 5, "fixed path must not mutate gap");

        // Product gap-sync path: default look-ahead 20 grows past index 8 and prepares.
        let synced = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            25_000,
            5,
            "",
            GapExtendOptions::default(),
        )
        .unwrap();
        assert!(
            synced.sync.receive_gap > 5,
            "gap must grow: {}",
            synced.sync.receive_gap
        );
        assert!(synced.sync.extended_receive_by >= 1);
        assert_eq!(synced.sync.utxos.len(), 2);
        assert_eq!(synced.sync.balance.confirmed_sats, 101_000);
        assert_eq!(synced.prepared.payment_sats, 25_000);
        assert!(synced.prepared.input_count >= 1);
        assert!(!synced.prepared.raw_hex().is_empty());
        assert!(w.receive_addresses().contains(&deep));
        assert_eq!(w.receive_gap(), synced.sync.receive_gap);

        let notice = gap_sync_spend_notice_lines(&synced.sync);
        assert!(!notice.is_empty(), "extend should emit honest gap notice");
        assert!(
            notice.join("\n").to_ascii_lowercase().contains("gap"),
            "{notice:?}"
        );
    }

    /// Wrong passphrase must fail closed on gap-extend spend (no silent foreign append).
    /// Sync-stage failure → [`GapSyncSpendFailure::Sync`] only (no fake AfterSync snapshot).
    #[test]
    fn gap_sync_spend_wrong_passphrase_fail_closed() {
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = "correct-product-pass";
        let mut w =
            DescriptorWallet::from_mnemonic_with_passphrase(&m, pass, Network::Bitcoin, 3).unwrap();
        // Tip activity so extend is attempted (and material verified).
        let tip = w.receive_addresses()[2].clone();
        let deep =
            derive_bip84_receive_address_with_passphrase(&m, pass, Network::Bitcoin, 3).unwrap();
        let pay_to =
            derive_bip84_receive_address_with_passphrase(&m, pass, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('2'), 0),
                amount_sats: 50_000,
                address: tip,
                confirmations: 3,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('3'), 0),
                amount_sats: 50_000,
                address: deep,
                confirmations: 3,
                is_change: false,
            },
        ]);
        let before = w.receive_gap();
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            25_000,
            5,
            "wrong-passphrase",
            GapExtendOptions {
                lookahead: 1,
                extend_step: 2,
                max_gap: 20,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, GapSyncSpendFailure::Sync(WalletError::Onchain(_))),
            "wrong pass must be Sync-stage hard-error, got: {err:?}"
        );
        assert!(
            !err.is_after_sync(),
            "must not fabricate AfterSync success snapshot on sync failure"
        );
        assert!(err.sync_snapshot().is_none());
        assert!(
            err.notice_lines().is_empty(),
            "Sync failures carry no gap notices"
        );
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("passphrase")
                || msg.contains("re-derive")
                || msg.contains("mnemonic")
                || msg.contains("gap extend"),
            "expected material mismatch wording, got: {err}"
        );
        assert_eq!(
            w.receive_gap(),
            before,
            "wrong passphrase must not grow the window"
        );
    }

    /// Empty chain → AfterSync hard error (sync quiet-succeeded); never invent spend success.
    #[test]
    fn gap_sync_spend_empty_chain_is_error_not_success() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![]);
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            25_000,
            5,
            "",
            GapExtendOptions::default(),
        )
        .unwrap_err();
        let GapSyncSpendFailure::AfterSync { sync, cause } = &err else {
            panic!("empty chain must be AfterSync (sync quiet-ok), got: {err:?}");
        };
        let msg = cause.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no utxo") || msg.contains("fund"),
            "empty chain must not invent spend success, got: {cause}"
        );
        // No activity → window unchanged; quiet notices.
        assert_eq!(w.receive_gap(), 5);
        assert_eq!(sync.receive_gap, 5);
        assert_eq!(sync.extended_receive_by, 0);
        assert!(!sync.hit_max_gap);
        assert!(err.notice_lines().is_empty(), "quiet AfterSync: no notices");
        assert!(
            gap_sync_spend_notice_lines(&WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 5,
                change_gap: 5,
                highest_used_receive: None,
                highest_used_change: None,
                extended_receive_by: 0,
                extended_change_by: 0,
                hit_max_gap: false,
            })
            .is_empty()
        );
    }

    /// Gap-extend hits max window, then select fails → AfterSync carries hit_max + notices.
    #[test]
    fn gap_sync_spend_hit_max_then_insufficient_carries_sync_notices() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Soft max equals start window: tip activity wants extend but is blocked.
        let start = 4u32;
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, start).unwrap();
        let tip = w.receive_addresses()[(start - 1) as usize].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('7'), 0),
            // Tiny balance so coin select fails after successful sync.
            amount_sats: 1_000,
            address: tip,
            confirmations: 3,
            is_change: false,
        }]);
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: start, // already at soft max; tip hot → hit_max_gap
        };
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w, &chain, &m, &pay_to, 50_000, // far above available
            5, "", opts,
        )
        .unwrap_err();
        let GapSyncSpendFailure::AfterSync { sync, cause } = &err else {
            panic!("select fail after sync must be AfterSync, got: {err:?}");
        };
        assert!(
            sync.hit_max_gap,
            "tip activity at soft max must set hit_max_gap"
        );
        assert_eq!(sync.receive_gap, start);
        assert_eq!(w.receive_gap(), start, "window stays at soft max");
        let cause_l = cause.to_string().to_ascii_lowercase();
        assert!(
            cause_l.contains("insufficient")
                || cause_l.contains("shortfall")
                || cause_l.contains("not enough")
                || cause_l.contains("fund"),
            "expected insufficient-funds cause, got: {cause}"
        );
        let notices = err.notice_lines();
        assert!(
            !notices.is_empty(),
            "hit_max AfterSync must surface notice lines"
        );
        let joined = notices.join("\n").to_ascii_lowercase();
        assert!(
            joined.contains("max") || joined.contains("gap"),
            "notice must mention max-gap stop, got: {notices:?}"
        );
        let display = err.display_lines().join("\n");
        assert!(
            display.contains(cause.to_string().as_str()) || display.contains("insufficient"),
            "display_lines must include cause"
        );
        assert!(
            display.to_ascii_lowercase().contains("gap")
                || display.to_ascii_lowercase().contains("max"),
            "display_lines must include max-gap notice"
        );
    }

    /// Quiet extend (no grow, no max) + insufficient funds → AfterSync with empty notices.
    #[test]
    fn gap_sync_spend_insufficient_after_quiet_sync_has_empty_notices() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        // Mid-window UTXO far from tip → look-ahead 1 does not extend; no hit_max.
        let mid = w.receive_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('8'), 0),
            amount_sats: 2_000,
            address: mid,
            confirmations: 6,
            is_change: false,
        }]);
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            100_000,
            5,
            "",
            GapExtendOptions {
                lookahead: 1,
                extend_step: 2,
                max_gap: 50,
            },
        )
        .unwrap_err();
        let GapSyncSpendFailure::AfterSync { sync, cause } = &err else {
            panic!("insufficient after quiet sync must be AfterSync, got: {err:?}");
        };
        assert_eq!(sync.extended_receive_by, 0);
        assert_eq!(sync.extended_change_by, 0);
        assert!(!sync.hit_max_gap);
        assert_eq!(w.receive_gap(), 5);
        assert!(
            err.notice_lines().is_empty(),
            "quiet AfterSync notices must be empty, got: {:?}",
            err.notice_lines()
        );
        let cause_l = cause.to_string().to_ascii_lowercase();
        assert!(
            cause_l.contains("insufficient")
                || cause_l.contains("shortfall")
                || cause_l.contains("not enough")
                || cause_l.contains("fund"),
            "expected insufficient cause, got: {cause}"
        );
        // display_lines is cause-only when quiet.
        assert_eq!(err.display_lines().len(), 1);
    }

    /// Extend grows the window, then select fails → AfterSync carries extend notices.
    #[test]
    fn gap_sync_spend_extended_then_insufficient_carries_extend_notices() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('9'), 0),
                amount_sats: 500,
                address: tip,
                confirmations: 3,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('a'), 0),
                amount_sats: 500,
                address: deep,
                confirmations: 3,
                is_change: false,
            },
        ]);
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            100_000,
            5,
            "",
            GapExtendOptions {
                lookahead: 1,
                extend_step: 2,
                max_gap: 20,
            },
        )
        .unwrap_err();
        let GapSyncSpendFailure::AfterSync { sync, cause } = &err else {
            panic!("expected AfterSync, got: {err:?}");
        };
        assert!(
            sync.extended_receive_by >= 1,
            "must have grown receive window"
        );
        assert!(w.receive_gap() > 3);
        assert!(
            cause
                .to_string()
                .to_ascii_lowercase()
                .contains("insufficient")
                || cause.to_string().to_ascii_lowercase().contains("fund"),
            "got: {cause}"
        );
        let notices = err.notice_lines();
        assert!(!notices.is_empty());
        assert!(
            notices.join("\n").to_ascii_lowercase().contains("extended")
                || notices.join("\n").to_ascii_lowercase().contains("gap"),
            "{notices:?}"
        );
    }

    /// RBF explicit-prevout path must not depend on gap-extend (sibling regression).
    #[test]
    fn rbf_prepare_stays_on_explicit_prevouts_without_gap_sync() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let inputs = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('4'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let original_fee = 705u64;
        let original_vbytes = 141u64;
        let rbf = prepare_rbf_replacement(
            &w,
            &m,
            &inputs,
            &pay_to,
            25_000,
            original_fee,
            original_vbytes,
            15,
            "",
            3,
        )
        .unwrap();
        assert!(rbf.prepared.fee_sats > original_fee);
        assert_eq!(rbf.prepared.payment_sats, 25_000);
        assert_eq!(rbf.prepared.input_count, 1);
        // Wallet gap unchanged (RBF never lists/extends chain).
        assert_eq!(w.receive_gap(), 3);
    }

    /// Product gap-sync can select a deep receive index; same-input RBF must
    /// still sign when callers use [`PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP`]
    /// (DEFAULT_RECEIVE_GAP alone leaves deep keys out of the sign lookup).
    #[test]
    fn rbf_after_gap_sync_deep_spend_signs_with_product_explicit_prevout_gap() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Start at product default window (20). Mid-window activity + funds at
        // index 22 (> DEFAULT_RECEIVE_GAP) so stop-gap look-ahead extends past 20
        // and product spend selects a deep coin. RBF with DEFAULT_RECEIVE_GAP
        // then fails incomplete-sign; PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP succeeds.
        let mut w =
            DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, DEFAULT_RECEIVE_GAP).unwrap();
        let mid = w.receive_addresses()[1].clone();
        let deep_idx = DEFAULT_RECEIVE_GAP + 2; // 22 — beyond product construction gap
        assert!(deep_idx > DEFAULT_RECEIVE_GAP);
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, deep_idx).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('5'), 0),
                // Dust only inside the initial default window.
                amount_sats: 1_000,
                address: mid,
                confirmations: 6,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('6'), 0),
                amount_sats: 100_000,
                address: deep.clone(),
                confirmations: 6,
                is_change: false,
            },
        ]);

        let synced = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            25_000,
            5,
            "",
            GapExtendOptions::default(),
        )
        .unwrap();
        assert!(
            synced.sync.receive_gap > deep_idx,
            "gap-sync must cover deep index {deep_idx}: gap={}",
            synced.sync.receive_gap
        );
        assert!(
            synced
                .prepared
                .selected_inputs
                .iter()
                .any(|u| u.address == deep),
            "spend must select deep UTXO for RBF regression"
        );
        let prep = &synced.prepared;
        let gap_before_rbf = w.receive_gap();

        // Product policy: sign with hard max (no re-list / re-extend).
        let rbf_ok = prepare_rbf_replacement(
            &w,
            &m,
            &prep.selected_inputs,
            &pay_to,
            prep.payment_sats,
            prep.fee_sats,
            prep.weight_vbytes(),
            15,
            "",
            PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP,
        )
        .unwrap();
        assert!(rbf_ok.prepared.fee_sats > prep.fee_sats);
        assert_eq!(rbf_ok.prepared.payment_sats, prep.payment_sats);
        assert!(!rbf_ok.prepared.raw_hex().is_empty());
        assert_eq!(
            w.receive_gap(),
            gap_before_rbf,
            "RBF must not re-extend wallet gap"
        );

        // DEFAULT_RECEIVE_GAP alone cannot sign deep recovered prevouts.
        let rbf_shallow = prepare_rbf_replacement(
            &w,
            &m,
            &prep.selected_inputs,
            &pay_to,
            prep.payment_sats,
            prep.fee_sats,
            prep.weight_vbytes(),
            15,
            "",
            DEFAULT_RECEIVE_GAP,
        );
        assert!(
            rbf_shallow.is_err(),
            "DEFAULT_RECEIVE_GAP must fail incomplete-sign for deep index {deep_idx}"
        );
        let msg = rbf_shallow.unwrap_err().to_string().to_ascii_lowercase();
        assert!(
            msg.contains("incomplete")
                || msg.contains("gap")
                || msg.contains("bip84")
                || msg.contains("sign")
                || msg.contains("not broadcast"),
            "expected incomplete-sign wording for shallow gap, got: {msg}"
        );
        assert_eq!(PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, MAX_ADDRESS_GAP);
    }

    /// Spy chain that counts `list_unspent_for_addresses` calls (no invent).
    struct CountingChainSource {
        inner: MockChainSource,
        lists: std::cell::Cell<usize>,
    }

    impl CountingChainSource {
        fn new(utxos: Vec<WalletUtxo>) -> Self {
            Self {
                inner: MockChainSource::with_utxos(utxos),
                lists: std::cell::Cell::new(0),
            }
        }

        fn list_count(&self) -> usize {
            self.lists.get()
        }
    }

    impl ChainSource for CountingChainSource {
        fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
            self.lists.set(self.lists.get().saturating_add(1));
            self.inner.list_unspent_for_addresses(addresses)
        }
    }

    /// Product gap-sync spend must not list again after `sync_with_gap_extend`
    /// finishes — select-from-snapshot uses `sync.utxos` only.
    #[test]
    fn gap_sync_spend_select_from_snapshot_no_extra_list() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('c'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let chain = CountingChainSource::new(utxos.clone());
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 50,
        };

        // Baseline: how many lists does sync alone perform on this quiet window?
        let mut w_sync = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let chain_sync = CountingChainSource::new(utxos);
        let snap = w_sync
            .sync_with_gap_extend(&m, "", &chain_sync, opts)
            .unwrap();
        let sync_only_lists = chain_sync.list_count();
        assert!(
            sync_only_lists >= 2,
            "quiet sync is terminal no-grow list + final snapshot list, got {sync_only_lists}"
        );
        assert_eq!(snap.utxos.len(), 1);

        // Product path must match sync-only list count (no +1 select list).
        let synced = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w, &chain, &m, &pay_to, 25_000, 5, "", opts,
        )
        .unwrap();
        assert_eq!(
            chain.list_count(),
            sync_only_lists,
            "product gap-sync spend must not list after sync (sync-only={sync_only_lists}, product={})",
            chain.list_count()
        );
        assert_eq!(synced.prepared.payment_sats, 25_000);
        assert_eq!(synced.sync.utxos.len(), 1);
        assert!(!synced.prepared.raw_hex().is_empty());
    }

    /// Extend path also must not add a post-sync select list.
    #[test]
    fn gap_sync_spend_with_extend_list_count_matches_sync_only() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('d'), 0),
                amount_sats: 1_000,
                address: tip,
                confirmations: 3,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('e'), 0),
                amount_sats: 100_000,
                address: deep,
                confirmations: 3,
                is_change: false,
            },
        ];
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };

        let mut w_sync = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let chain_sync = CountingChainSource::new(utxos.clone());
        let _ = w_sync
            .sync_with_gap_extend(&m, "", &chain_sync, opts)
            .unwrap();
        let sync_only_lists = chain_sync.list_count();
        assert!(
            sync_only_lists > 2,
            "tip activity should require multiple extend lists, got {sync_only_lists}"
        );

        let chain = CountingChainSource::new(utxos);
        let synced = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w, &chain, &m, &pay_to, 25_000, 5, "", opts,
        )
        .unwrap();
        assert_eq!(
            chain.list_count(),
            sync_only_lists,
            "extend product path must not add select list (sync-only={sync_only_lists})"
        );
        assert!(synced.sync.extended_receive_by >= 1);
        assert_eq!(synced.prepared.payment_sats, 25_000);
    }

    /// from_utxos prepares without a ChainSource (API takes none).
    #[test]
    fn select_from_utxos_does_not_call_chain() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('f'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let prep =
            select_and_prepare_bip84_spend_from_utxos(&w, &utxos, &m, &pay_to, 25_000, 5, "", 5)
                .unwrap();
        assert_eq!(prep.payment_sats, 25_000);
        assert!(prep.fee_sats > 0);
        assert_eq!(prep.input_count, 1);
        assert!(!prep.raw_hex().is_empty());

        // Empty slice → same empty error as list path (AfterSync-compatible cause).
        let err = select_and_prepare_bip84_spend_from_utxos(&w, &[], &m, &pay_to, 25_000, 5, "", 5)
            .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no utxo") || msg.contains("fund"),
            "empty utxos must not invent spend, got: {err}"
        );

        // Zero fee rate rejected without depending on UTXO content.
        let zerr =
            select_and_prepare_bip84_spend_from_utxos(&w, &utxos, &m, &pay_to, 25_000, 0, "", 5)
                .unwrap_err();
        assert!(
            zerr.to_string().to_ascii_lowercase().contains("fee"),
            "got: {zerr}"
        );
    }

    /// Product UTXO list must not list again after `sync_with_gap_extend` —
    /// snapshot is authoritative (same honesty as select-from-snapshot spend).
    #[test]
    fn list_bip84_utxos_with_gap_sync_no_extra_list() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('u'), 0),
            amount_sats: 80_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 50,
        };

        let mut w_sync = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let chain_sync = CountingChainSource::new(utxos.clone());
        let baseline = w_sync
            .sync_with_gap_extend(&m, "", &chain_sync, opts)
            .unwrap();
        let sync_only_lists = chain_sync.list_count();
        assert!(
            sync_only_lists >= 2,
            "quiet sync is terminal no-grow list + final snapshot list, got {sync_only_lists}"
        );
        assert_eq!(baseline.utxos.len(), 1);
        assert_eq!(baseline.balance.confirmed_sats, 80_000);

        let chain = CountingChainSource::new(utxos);
        let snap = list_bip84_utxos_with_gap_sync(&mut w, &chain, &m, "", opts).unwrap();
        assert_eq!(
            chain.list_count(),
            sync_only_lists,
            "product list helper must not re-list after sync (sync-only={sync_only_lists}, product={})",
            chain.list_count()
        );
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.balance.confirmed_sats, 80_000);
        assert_eq!(snap.utxos[0].amount_sats, 80_000);
    }

    /// Deep tip UTXO found after extend on product list helper.
    #[test]
    fn list_bip84_utxos_with_gap_sync_finds_deep_utxo() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep = derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap();
        let utxos = vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('v'), 0),
                amount_sats: 1_000,
                address: tip,
                confirmations: 3,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('w'), 0),
                amount_sats: 90_000,
                address: deep.clone(),
                confirmations: 3,
                is_change: false,
            },
        ];
        let opts = GapExtendOptions {
            lookahead: 1,
            extend_step: 2,
            max_gap: 20,
        };
        let chain = MockChainSource::with_utxos(utxos);
        let snap = list_bip84_utxos_with_gap_sync(&mut w, &chain, &m, "", opts).unwrap();
        assert!(
            snap.extended_receive_by >= 1,
            "tip activity should extend receive window"
        );
        assert!(
            snap.utxos
                .iter()
                .any(|u| u.address == deep && u.amount_sats == 90_000),
            "deep UTXO must appear in snapshot after extend: {:?}",
            snap.utxos
        );
        assert_eq!(snap.balance.total_sats(), 91_000);
    }

    /// Empty chain → successful empty snapshot (observational list; no invent).
    #[test]
    fn list_bip84_utxos_with_gap_sync_empty_chain_not_invented() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let chain = MockChainSource::with_utxos(vec![]);
        let snap =
            list_bip84_utxos_with_gap_sync(&mut w, &chain, &m, "", GapExtendOptions::default())
                .unwrap();
        assert!(snap.utxos.is_empty(), "empty chain must not invent UTXOs");
        assert_eq!(snap.balance.confirmed_sats, 0);
        assert_eq!(snap.balance.unconfirmed_sats, 0);
        assert_eq!(snap.balance.total_sats(), 0);
        assert!(!snap.hit_max_gap || snap.extended_receive_by == 0);
    }

    /// Wrong passphrase fail-closed on product list (same as spend Sync arm).
    #[test]
    fn list_bip84_utxos_with_gap_sync_wrong_passphrase_fail_closed() {
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = "correct-list-pass";
        let mut w =
            DescriptorWallet::from_mnemonic_with_passphrase(&m, pass, Network::Bitcoin, 3).unwrap();
        let tip = w.receive_addresses()[2].clone();
        let deep =
            derive_bip84_receive_address_with_passphrase(&m, pass, Network::Bitcoin, 3).unwrap();
        let chain = MockChainSource::with_utxos(vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('x'), 0),
                amount_sats: 50_000,
                address: tip,
                confirmations: 3,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('y'), 0),
                amount_sats: 50_000,
                address: deep,
                confirmations: 3,
                is_change: false,
            },
        ]);
        let before = w.receive_gap();
        let err = list_bip84_utxos_with_gap_sync(
            &mut w,
            &chain,
            &m,
            "wrong-passphrase",
            GapExtendOptions {
                lookahead: 1,
                extend_step: 2,
                max_gap: 20,
            },
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("passphrase")
                || msg.contains("re-derive")
                || msg.contains("mnemonic")
                || msg.contains("gap extend"),
            "expected material mismatch wording, got: {err}"
        );
        assert_eq!(
            w.receive_gap(),
            before,
            "wrong passphrase must not grow the window"
        );
    }

    /// Product gap-sync rejects fee rate 0 **before** sync (Sync arm; no lists).
    #[test]
    fn gap_sync_spend_rejects_zero_fee_rate_before_sync() {
        let m = import_mnemonic(VECTOR).unwrap();
        let mut w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let gap_before = w.receive_gap();
        let chain = CountingChainSource::new(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('0'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }]);
        let err = select_and_prepare_bip84_spend_with_gap_sync(
            &mut w,
            &chain,
            &m,
            &pay_to,
            25_000,
            0,
            "",
            GapExtendOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, GapSyncSpendFailure::Sync(WalletError::Onchain(_))),
            "fee 0 must be Sync-stage (pre-sync), got: {err:?}"
        );
        assert!(!err.is_after_sync());
        assert!(err.sync_snapshot().is_none());
        assert!(
            err.notice_lines().is_empty(),
            "Sync fee-0 carries no gap notices"
        );
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("fee"), "expected fee-rate wording, got: {err}");
        assert_eq!(
            chain.list_count(),
            0,
            "fee 0 must not run gap-sync list rounds"
        );
        assert_eq!(
            w.receive_gap(),
            gap_before,
            "fee 0 must not mutate wallet gap"
        );
    }

    /// Fixed-window list helper still lists once then selects (DRY via from_utxos).
    #[test]
    fn select_and_prepare_lists_once_then_from_utxos() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = CountingChainSource::new(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('1'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }]);
        let prep =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, "", 5).unwrap();
        assert_eq!(
            chain.list_count(),
            1,
            "fixed-window path lists exactly once"
        );
        assert_eq!(prep.payment_sats, 25_000);
    }

    #[test]
    fn selection_with_rbf_fee_same_inputs_higher_fee() {
        let sel = CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('a'), 0),
                amount_sats: 100_000,
                address: "a".into(),
                confirmations: 6,
                is_change: false,
            }],
            total_input_sats: 100_000,
            change_sats: 74_295,
            target_sats: 25_000,
            fee_sats: 705, // 141 vb * 5
        };
        let bumped = selection_with_rbf_fee(&sel, 1_410).unwrap();
        assert_eq!(bumped.selected.len(), 1);
        assert_eq!(bumped.target_sats, 25_000);
        assert_eq!(bumped.fee_sats, 1_410);
        assert_eq!(bumped.change_sats, 100_000 - 25_000 - 1_410);
        assert_eq!(bumped.total_input_sats, 100_000);

        // Not strictly greater → error.
        let err = selection_with_rbf_fee(&sel, 705).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("greater"));
        let err = selection_with_rbf_fee(&sel, 100).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("greater"));

        // Insufficient for huge fee.
        let err = selection_with_rbf_fee(&sel, 80_000).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient"),
            "{err}"
        );
    }

    #[test]
    fn selection_with_rbf_fee_folds_dust_change() {
        // Payment 9_000, fee bump leaves 200 sats change (< dust 294).
        let sel = CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('b'), 0),
                amount_sats: 10_000,
                address: "a".into(),
                confirmations: 1,
                is_change: false,
            }],
            total_input_sats: 10_000,
            change_sats: 500,
            target_sats: 9_000,
            fee_sats: 500,
        };
        // new_fee = 800 → change = 200 → fold into fee → fee 1000, change 0.
        let bumped = selection_with_rbf_fee(&sel, 800).unwrap();
        assert_eq!(bumped.change_sats, 0);
        assert_eq!(bumped.fee_sats, 1_000);
        assert!(bumped.fee_sats > sel.fee_sats);
    }

    #[test]
    fn prepare_rbf_replacement_from_selection_signs() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let original = CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('c'), 0),
                amount_sats: 100_000,
                address: recv,
                confirmations: 6,
                is_change: false,
            }],
            total_input_sats: 100_000,
            change_sats: 74_295,
            target_sats: 25_000,
            fee_sats: 705,
        };
        let params = SpendParams {
            payment_address: pay_to,
            change_address: Some(change),
            network: Network::Bitcoin,
        };
        let prep =
            prepare_rbf_replacement_from_selection(&original, &params, 1_410, &m, "", 5).unwrap();
        assert_eq!(prep.payment_sats, 25_000);
        assert_eq!(prep.fee_sats, 1_410);
        assert!(prep.fee_sats > original.fee_sats);
        assert!(!prep.raw_hex().is_empty());
        assert_eq!(prep.txid_hex().len(), 64);
        assert_eq!(prep.input_count, 1);
        assert_eq!(prep.selected_inputs.len(), 1);
        assert_eq!(prep.selected_inputs[0].outpoint.txid, valid_txid('c'));
    }

    #[test]
    fn prepare_rbf_replacement_same_inputs_bumps_absolute_fee() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('d'), 0),
            amount_sats: 100_000,
            address: recv.clone(),
            confirmations: 6,
            is_change: false,
        }]);
        let orig =
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, "", 5).unwrap();
        let orig_fee = orig.fee_sats;
        let orig_vb = orig.weight_vbytes();
        assert!(!orig.selected_inputs.is_empty());

        let rbf = prepare_rbf_replacement(
            &w,
            &m,
            &orig.selected_inputs,
            &pay_to,
            25_000,
            orig_fee,
            orig_vb,
            15,
            "",
            5,
        )
        .unwrap();
        assert_eq!(rbf.prepared.payment_sats, 25_000);
        assert!(rbf.prepared.fee_sats > orig_fee);
        assert!(rbf.prepared.fee_sats >= rbf.plan.recommended_fee_sats);
        validate_rbf_replacement_fee(
            orig_fee,
            rbf.prepared.fee_sats,
            rbf.prepared.weight_vbytes(),
            rbf.plan.incremental_relay_sat_vb,
            rbf.plan.min_replacement_fee_sats,
        )
        .unwrap();
        // Same outpoints as original (true BIP-125 conflict set).
        assert_eq!(
            rbf.prepared.selected_inputs.len(),
            orig.selected_inputs.len()
        );
        assert_eq!(
            rbf.prepared.selected_inputs[0].outpoint,
            orig.selected_inputs[0].outpoint
        );
        assert_ne!(rbf.prepared.txid_hex(), orig.txid_hex());
    }

    #[test]
    fn prepare_rbf_replacement_rejects_empty_inputs_and_bad_args() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let err =
            prepare_rbf_replacement(&w, &m, &[], &pay_to, 25_000, 700, 140, 10, "", 5).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("input") || msg.contains("original"), "{err}");

        let utxo = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('e'), 0),
            amount_sats: 100_000,
            address: w.primary_receive_address().unwrap().to_owned(),
            confirmations: 6,
            is_change: false,
        };
        let err = prepare_rbf_replacement(&w, &m, &[utxo.clone()], &pay_to, 0, 700, 140, 10, "", 5)
            .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("amount"));

        let err =
            prepare_rbf_replacement(&w, &m, &[utxo.clone()], &pay_to, 25_000, 700, 0, 10, "", 5)
                .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("vbytes"));

        let err = prepare_rbf_replacement(&w, &m, &[utxo], &pay_to, 25_000, 700, 140, 0, "", 5)
            .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("fee rate"));
    }

    #[test]
    fn validate_rbf_replacement_fee_rejects_floor_rate_underpay() {
        // Counterexample from review: original_fee=1000, vb=141 → recommended 1141,
        // floor rate 8 → estimated 1128 underpays BIP-125 bandwidth (+141).
        let plan = plan_rbf_fee_bump(1000, 141, 5, 1).unwrap();
        assert_eq!(plan.recommended_fee_sats, 1141);
        assert_eq!(plan.recommended_fee_rate_sat_vb, 8); // floor
        let underpay = 8 * 141; // 1128
        assert!(underpay < plan.min_replacement_fee_sats);
        let err =
            validate_rbf_replacement_fee(1000, underpay, 141, 1, plan.min_replacement_fee_sats)
                .unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("bip-125")
                || err.to_string().to_ascii_lowercase().contains("floor"),
            "{err}"
        );
        validate_rbf_replacement_fee(
            1000,
            plan.recommended_fee_sats,
            141,
            1,
            plan.min_replacement_fee_sats,
        )
        .unwrap();

        // original_fee=999, vb=200 → delta must be ≥ 200, not 1.
        let plan2 = plan_rbf_fee_bump(999, 200, 5, 1).unwrap();
        assert!(plan2.min_replacement_fee_sats >= 999 + 200);
        assert!(
            validate_rbf_replacement_fee(999, 1000, 200, 1, plan2.min_replacement_fee_sats)
                .is_err()
        );
    }

    #[test]
    fn prepare_rbf_meets_bip125_when_floor_rate_would_underpay() {
        // Same inputs + absolute plan fee path must not underpay like floor-rate re-select.
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let inputs = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('a'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        // original_fee=1000, vb=141, target 5 → plan wants 1141 absolute.
        let rbf =
            prepare_rbf_replacement(&w, &m, &inputs, &pay_to, 25_000, 1000, 141, 5, "", 5).unwrap();
        assert!(
            rbf.prepared.fee_sats >= rbf.plan.recommended_fee_sats,
            "fee {} < recommended {}",
            rbf.prepared.fee_sats,
            rbf.plan.recommended_fee_sats
        );
        assert!(rbf.prepared.fee_sats >= 1141);
        assert_eq!(
            rbf.prepared.selected_inputs[0].outpoint.txid,
            valid_txid('a')
        );
    }

    #[test]
    fn prepare_rbf_multi_input_keeps_exact_original_outpoints() {
        // Documents product invariant: replacement must conflict with stuck tx
        // (same outpoints), not pick alternate confirmed coins.
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv0 = w.receive_addresses()[0].clone();
        let recv1 = w.receive_addresses()[1].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();
        let inputs = vec![
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('2'), 0),
                amount_sats: 40_000,
                address: recv0,
                confirmations: 6,
                is_change: false,
            },
            WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('3'), 1),
                amount_sats: 40_000,
                address: recv1,
                confirmations: 6,
                is_change: false,
            },
        ];
        let rbf =
            prepare_rbf_replacement(&w, &m, &inputs, &pay_to, 30_000, 800, 200, 12, "", 5).unwrap();
        assert_eq!(rbf.prepared.selected_inputs.len(), 2);
        let mut got: Vec<_> = rbf
            .prepared
            .selected_inputs
            .iter()
            .map(|u| (u.outpoint.txid.clone(), u.outpoint.vout))
            .collect();
        got.sort();
        let mut want = vec![(valid_txid('2'), 0u32), (valid_txid('3'), 1u32)];
        want.sort();
        assert_eq!(got, want);
        assert!(rbf.prepared.fee_sats > 800);
        assert!(rbf.prepared.fee_sats >= rbf.plan.recommended_fee_sats);
    }

    #[test]
    fn prepare_rbf_insufficient_funds_when_bump_exceeds_value() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        // Payment leaves almost no room for fee bump.
        let inputs = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('4'), 0),
            amount_sats: 10_500,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let err = prepare_rbf_replacement(&w, &m, &inputs, &pay_to, 10_000, 400, 141, 50, "", 5)
            .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("insufficient") || msg.contains("fee"), "{err}");
    }

    #[test]
    fn prepare_rbf_broadcast_never_claimed_without_broadcaster() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let inputs = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('f'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let rbf =
            prepare_rbf_replacement(&w, &m, &inputs, &pay_to, 25_000, 500, 100, 20, "", 5).unwrap();
        let hex = rbf.prepared.raw_hex();
        let mut mock = crate::explorer::MockTxBroadcaster::new();
        mock.push_ok(rbf.prepared.txid_hex());
        let res = broadcast_raw_tx(&mut mock, &hex).unwrap();
        assert_eq!(res.txid, rbf.prepared.txid_hex());
        mock.push_err("policy reject");
        let err = broadcast_raw_tx(&mut mock, &hex).unwrap_err();
        assert!(err.to_string().contains("policy"));
    }

    #[test]
    fn coin_selection_from_rbf_inputs_rejects_duplicates_and_shortfall() {
        let u = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('5'), 0),
            amount_sats: 50_000,
            address: "bc1q".into(),
            confirmations: 1,
            is_change: false,
        };
        let err = coin_selection_from_rbf_inputs(&[u.clone(), u.clone()], 10_000, 500).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("duplicate"));

        let err = coin_selection_from_rbf_inputs(&[u], 49_000, 2_000).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient")
        );
    }

    #[test]
    fn coin_selection_for_cpfp_parent_plus_extra_and_rejects() {
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('6'), 0),
            amount_sats: 20_000,
            address: "bc1qparent".into(),
            confirmations: 0,
            is_change: true,
        };
        let extra = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('7'), 1),
            amount_sats: 30_000,
            address: "bc1qextra".into(),
            confirmations: 6,
            is_change: false,
        };
        let sel =
            coin_selection_for_cpfp(&[parent.clone()], &[extra.clone()], 40_000, 5_000).unwrap();
        assert_eq!(sel.selected.len(), 2);
        assert_eq!(sel.total_input_sats, 50_000);
        assert_eq!(sel.target_sats, 40_000);
        assert_eq!(sel.fee_sats, 5_000);
        assert_eq!(sel.change_sats, 5_000);

        // Empty parent.
        let err = coin_selection_for_cpfp(&[], &[extra.clone()], 10_000, 1_000).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("parent"));

        // Zero fee / zero payment.
        let err = coin_selection_for_cpfp(&[parent.clone()], &[], 10_000, 0).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("fee"));
        let err = coin_selection_for_cpfp(&[parent.clone()], &[], 0, 1_000).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("amount"));

        // Duplicate parent/extra.
        let err =
            coin_selection_for_cpfp(&[parent.clone()], &[parent.clone()], 1_000, 500).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("duplicate"));

        // Shortfall.
        let err = coin_selection_for_cpfp(&[parent], &[], 19_000, 2_000).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient")
        );
    }

    #[test]
    fn coin_selection_for_cpfp_folds_dust_change() {
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('8'), 0),
            amount_sats: 10_000,
            address: "bc1q".into(),
            confirmations: 0,
            is_change: true,
        };
        // payment 9_000 + fee 800 = 9_800 → change 200 < dust → fold.
        let sel = coin_selection_for_cpfp(&[parent], &[], 9_000, 800).unwrap();
        assert_eq!(sel.change_sats, 0);
        assert_eq!(sel.fee_sats, 1_000);
    }

    #[test]
    fn validate_cpfp_child_fee_package_and_rejects_zero() {
        // parent 200 fee / 200 vb underpays; child must cover package at 10 sat/vB.
        let child_vb = estimate_cpfp_child_vbytes(1);
        let plan = plan_cpfp_child_fee(200, 200, child_vb, 10).unwrap();
        validate_cpfp_child_fee(
            200,
            200,
            plan.min_child_fee_sats,
            child_vb,
            10,
            plan.min_child_fee_sats,
        )
        .unwrap();
        // Underpay package.
        let under = plan.min_child_fee_sats.saturating_sub(1);
        if under > 0 {
            let err =
                validate_cpfp_child_fee(200, 200, under, child_vb, 10, plan.min_child_fee_sats)
                    .unwrap_err();
            assert!(
                err.to_string().to_ascii_lowercase().contains("cpfp")
                    || err.to_string().to_ascii_lowercase().contains("floor"),
                "{err}"
            );
        }
        assert!(
            validate_cpfp_child_fee(200, 200, 0, child_vb, 10, 0)
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase()
                .contains("fee")
        );
        assert!(
            validate_cpfp_child_fee(200, 0, 100, child_vb, 10, 0)
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase()
                .contains("parent")
        );
        assert!(
            validate_cpfp_child_fee(200, 200, 100, 0, 10, 0)
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase()
                .contains("child")
        );
        assert!(
            validate_cpfp_child_fee(200, 200, 100, child_vb, 0, 0)
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase()
                .contains("target")
                || validate_cpfp_child_fee(200, 200, 100, child_vb, 0, 0)
                    .unwrap_err()
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("fee rate")
        );
    }

    #[test]
    fn prepare_cpfp_child_signs_and_meets_package_rate() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        // Large parent change output; underpaying parent package needs high child fee.
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('c'), 1),
            amount_sats: 80_000,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let parent_fee = 200u64;
        let parent_vb = 200u64;
        let target = 10u64;
        let cpfp = prepare_cpfp_child(
            &w,
            &m,
            &[parent.clone()],
            &[],
            &pay_to,
            50_000,
            parent_fee,
            parent_vb,
            target,
            "",
            5,
        )
        .unwrap();
        assert_eq!(cpfp.prepared.payment_sats, 50_000);
        assert!(cpfp.prepared.fee_sats >= cpfp.plan.min_child_fee_sats);
        assert!(cpfp.prepared.fee_sats > 0);
        validate_cpfp_child_fee(
            parent_fee,
            parent_vb,
            cpfp.prepared.fee_sats,
            cpfp.prepared.weight_vbytes(),
            target,
            cpfp.plan.min_child_fee_sats,
        )
        .unwrap();
        assert_eq!(
            cpfp.prepared.selected_inputs[0].outpoint.txid,
            valid_txid('c')
        );
        assert_eq!(cpfp.prepared.selected_inputs[0].outpoint.vout, 1);
        assert!(!cpfp.prepared.raw_hex().is_empty());
        assert_eq!(cpfp.prepared.txid_hex().len(), 64);
        // Product honesty: package fee includes parent; child is not a replacement.
        assert_eq!(cpfp.package_fee_sats(), parent_fee + cpfp.prepared.fee_sats);
        // Child is a new tx (different inputs than a parent replacement would use).
        assert_eq!(cpfp.prepared.input_count, 1);
    }

    #[test]
    fn prepare_cpfp_child_with_extra_input_when_parent_alone_short() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv0 = w.receive_addresses()[0].clone();
        let recv1 = w.receive_addresses()[1].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();
        // Small parent output; high package target needs extra confirmed input.
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('9'), 0),
            amount_sats: 5_000,
            address: recv0,
            confirmations: 0,
            is_change: true,
        };
        let extra = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('a'), 0),
            amount_sats: 50_000,
            address: recv1,
            confirmations: 6,
            is_change: false,
        };
        // Without extra, small parent cannot fund payment+fee.
        let err = prepare_cpfp_child(
            &w,
            &m,
            &[parent.clone()],
            &[],
            &pay_to,
            4_000,
            100,
            200,
            50,
            "",
            5,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient"),
            "{err}"
        );
        let cpfp = prepare_cpfp_child(
            &w,
            &m,
            &[parent.clone()],
            &[extra],
            &pay_to,
            30_000,
            100,
            200,
            20,
            "",
            5,
        )
        .unwrap();
        assert_eq!(cpfp.prepared.selected_inputs.len(), 2);
        assert!(
            cpfp.prepared
                .selected_inputs
                .iter()
                .any(|u| u.outpoint.txid == valid_txid('9'))
        );
        assert!(cpfp.prepared.fee_sats >= cpfp.plan.min_child_fee_sats);
        validate_cpfp_child_fee(
            100,
            200,
            cpfp.prepared.fee_sats,
            cpfp.prepared.weight_vbytes(),
            20,
            cpfp.plan.min_child_fee_sats,
        )
        .unwrap();
    }

    #[test]
    fn prepare_cpfp_child_rejects_empty_parent_and_bad_args() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('b'), 0),
            amount_sats: 80_000,
            address: w.primary_receive_address().unwrap().to_owned(),
            confirmations: 0,
            is_change: true,
        };
        let err =
            prepare_cpfp_child(&w, &m, &[], &[], &pay_to, 25_000, 200, 200, 10, "", 5).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("parent"));

        let err = prepare_cpfp_child(
            &w,
            &m,
            &[parent.clone()],
            &[],
            &pay_to,
            0,
            200,
            200,
            10,
            "",
            5,
        )
        .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("amount"));

        let err = prepare_cpfp_child(
            &w,
            &m,
            &[parent.clone()],
            &[],
            &pay_to,
            25_000,
            200,
            0,
            10,
            "",
            5,
        )
        .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("vbytes"));

        let err = prepare_cpfp_child(&w, &m, &[parent], &[], &pay_to, 25_000, 200, 200, 0, "", 5)
            .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("fee rate"));
    }

    #[test]
    fn prepare_cpfp_child_from_selection_signs() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('d'), 0),
            amount_sats: 100_000,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let sel = coin_selection_for_cpfp(&[parent], &[], 50_000, 2_000).unwrap();
        let params = SpendParams {
            payment_address: pay_to,
            change_address: Some(change),
            network: Network::Bitcoin,
        };
        let prep = prepare_cpfp_child_from_selection(&sel, &params, 2_000, &m, "", 5).unwrap();
        assert_eq!(prep.payment_sats, 50_000);
        assert_eq!(prep.fee_sats, 2_000);
        assert!(!prep.raw_hex().is_empty());
        assert_eq!(prep.input_count, 1);

        let err = prepare_cpfp_child_from_selection(&sel, &params, 0, &m, "", 5).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("fee"));
    }

    #[test]
    fn prepare_cpfp_child_from_selection_rejects_empty_and_insufficient() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let params = SpendParams {
            payment_address: pay_to,
            change_address: None,
            network: Network::Bitcoin,
        };
        let empty = CoinSelection {
            selected: vec![],
            total_input_sats: 0,
            change_sats: 0,
            target_sats: 1_000,
            fee_sats: 100,
        };
        let err = prepare_cpfp_child_from_selection(&empty, &params, 500, &m, "", 5).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("no inputs")
                || err.to_string().to_ascii_lowercase().contains("selection"),
            "{err}"
        );

        let recv = w.primary_receive_address().unwrap().to_owned();
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('1'), 0),
            amount_sats: 10_000,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let sel = coin_selection_for_cpfp(&[parent], &[], 5_000, 1_000).unwrap();
        // Fee higher than residual → insufficient.
        let err = prepare_cpfp_child_from_selection(&sel, &params, 9_000, &m, "", 5).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("insufficient"),
            "{err}"
        );

        // Zero payment on selection.
        let mut zero_pay = sel.clone();
        zero_pay.target_sats = 0;
        let err =
            prepare_cpfp_child_from_selection(&zero_pay, &params, 500, &m, "", 5).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("amount"),
            "{err}"
        );
    }

    #[test]
    fn prepare_cpfp_child_one_out_replan_does_not_oscillate_underpay() {
        // Residual sized so 2-out plan fee leaves change=0, but dropping to 1-out
        // fee would reintroduce non-dust change. Must keep 2-out plan (not sign a
        // 2-out child against a 1-out fee plan).
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent_fee = 200u64;
        let parent_vb = 200u64;
        let target = 10u64;
        let two_out_vb = estimate_tx_vbytes(1, 2);
        let plan2 = plan_cpfp_child_fee(parent_fee, parent_vb, two_out_vb, target).unwrap();
        let f2 = plan2.min_child_fee_sats;
        let total = 50_000u64;
        let payment = total - f2; // exact fit at 2-out → change 0
        assert!(payment > 0);
        let one_out_vb = estimate_tx_vbytes(1, 1);
        let plan1 = plan_cpfp_child_fee(parent_fee, parent_vb, one_out_vb, target).unwrap();
        let f1 = plan1.min_child_fee_sats;
        assert!(f1 < f2, "1-out fee must be lower to exercise oscillation");
        let reintroduced = total - payment - f1;
        assert!(
            reintroduced >= DUST_P2WPKH_SATS,
            "1-out replan would reintroduce non-dust change {reintroduced}"
        );

        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('2'), 0),
            amount_sats: total,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let cpfp = prepare_cpfp_child(
            &w,
            &m,
            &[parent],
            &[],
            &pay_to,
            payment,
            parent_fee,
            parent_vb,
            target,
            "",
            5,
        )
        .unwrap();
        // Must meet package floor on actual weight (retry backstop if needed).
        validate_cpfp_child_fee(
            parent_fee,
            parent_vb,
            cpfp.prepared.fee_sats,
            cpfp.prepared.weight_vbytes(),
            target,
            cpfp.plan.min_child_fee_sats,
        )
        .unwrap();
        // Absolute fee at least the stable 2-out package floor (not underpaid 1-out fee).
        assert!(
            cpfp.prepared.fee_sats >= f2,
            "fee {} < 2-out floor {f2} (1-out would underpay package when change reappears)",
            cpfp.prepared.fee_sats
        );
        // Plan refreshed to actual signed weight.
        assert_eq!(cpfp.plan.child_vbytes, cpfp.prepared.weight_vbytes());
    }

    #[test]
    fn prepare_cpfp_child_plan_refreshed_to_actual_weight() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('3'), 0),
            amount_sats: 90_000,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let cpfp = prepare_cpfp_child(&w, &m, &[parent], &[], &pay_to, 40_000, 200, 200, 12, "", 5)
            .unwrap();
        assert_eq!(
            cpfp.plan.child_vbytes,
            cpfp.prepared.weight_vbytes(),
            "plan must reflect actual signed child weight, not pre-sign heuristic"
        );
        assert_eq!(
            cpfp.plan.package_vbytes,
            cpfp.parent_vbytes + cpfp.prepared.weight_vbytes()
        );
        // Package fee on plan uses at least the prepared child fee when dust fold raised it.
        assert!(cpfp.plan.package_fee_sats >= cpfp.parent_fee_sats + cpfp.plan.min_child_fee_sats);
        assert!(
            cpfp.plan.package_fee_sats >= cpfp.parent_fee_sats + cpfp.prepared.fee_sats
                || cpfp.prepared.fee_sats <= cpfp.plan.min_child_fee_sats
        );
        if cpfp.prepared.fee_sats > cpfp.plan.min_child_fee_sats {
            assert_eq!(
                cpfp.plan.package_fee_sats,
                cpfp.parent_fee_sats + cpfp.prepared.fee_sats
            );
        }
        validate_cpfp_child_fee(
            cpfp.parent_fee_sats,
            cpfp.parent_vbytes,
            cpfp.prepared.fee_sats,
            cpfp.prepared.weight_vbytes(),
            12,
            cpfp.plan.min_child_fee_sats,
        )
        .unwrap();
    }

    #[test]
    fn prepare_cpfp_child_retry_insufficient_mentions_extra_input_not_only_floor() {
        // Residual exactly covers the estimate-based child fee; if actual weight
        // needs a higher absolute fee, retry selection must surface insufficient
        // (extra-input / lower payment) rather than only "below package floor".
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent_fee = 0u64;
        let parent_vb = 1_000u64;
        let target = 10u64;
        // Use 1-in 1-out estimate floor; leave almost no headroom.
        let est_vb = estimate_tx_vbytes(1, 1);
        let plan = plan_cpfp_child_fee(parent_fee, parent_vb, est_vb, target).unwrap();
        let f = plan.min_child_fee_sats;
        let payment = 1_000u64;
        let total = payment + f; // exact; any fee bump on retry shortfalls
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('4'), 0),
            amount_sats: total,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        // If first prepare+validate succeeds (actual vb ≤ estimate), still OK — package met.
        // If actual vb > estimate, retry must fail with insufficient guidance.
        match prepare_cpfp_child(
            &w,
            &m,
            &[parent],
            &[],
            &pay_to,
            payment,
            parent_fee,
            parent_vb,
            target,
            "",
            5,
        ) {
            Ok(cpfp) => {
                validate_cpfp_child_fee(
                    parent_fee,
                    parent_vb,
                    cpfp.prepared.fee_sats,
                    cpfp.prepared.weight_vbytes(),
                    target,
                    cpfp.plan.min_child_fee_sats,
                )
                .unwrap();
                // Actual weight did not force a fee bump beyond residual.
                assert!(cpfp.prepared.fee_sats >= f);
            }
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                assert!(
                    msg.contains("insufficient")
                        || msg.contains("extra-input")
                        || msg.contains("extra input"),
                    "retry shortfall must mention insufficient/extra-input, got: {e}"
                );
                // Should not be a bare package-floor-only message that tempts raising fee-rate alone.
                if msg.contains("package floor") || msg.contains("below package") {
                    assert!(
                        msg.contains("insufficient"),
                        "package floor error without insufficient context: {e}"
                    );
                }
            }
        }
    }

    #[test]
    fn prepare_cpfp_broadcast_never_claimed_without_broadcaster() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 3).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('e'), 0),
            amount_sats: 80_000,
            address: recv,
            confirmations: 0,
            is_change: true,
        };
        let cpfp = prepare_cpfp_child(&w, &m, &[parent], &[], &pay_to, 40_000, 200, 200, 15, "", 5)
            .unwrap();
        let hex = cpfp.prepared.raw_hex();
        let mut mock = crate::explorer::MockTxBroadcaster::new();
        mock.push_ok(cpfp.prepared.txid_hex());
        let res = broadcast_raw_tx(&mut mock, &hex).unwrap();
        assert_eq!(res.txid, cpfp.prepared.txid_hex());
        mock.push_err("policy reject");
        let err = broadcast_raw_tx(&mut mock, &hex).unwrap_err();
        assert!(err.to_string().contains("policy"));
    }

    #[test]
    fn extract_and_broadcast_accepts_finalized_and_rejects_unfinalized() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 80_000, 30_000, 400);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to.clone(),
                change_address: Some(change.clone()),
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        // Unfinalized: extract_and_broadcast must fail closed without calling broadcaster.
        let mut mock = crate::explorer::MockTxBroadcaster::new();
        mock.push_ok("should-not-be-used");
        let err = extract_and_broadcast(built.psbt.clone(), &mut mock).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("final_script_witness")
                || err.to_string().to_ascii_lowercase().contains("finalize"),
            "{err}"
        );
        assert!(
            mock.submitted.is_empty(),
            "unfinalized must not POST: {:?}",
            mock.submitted
        );

        // Finalize pipeline then extract_and_broadcast must accept via mock.
        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(outcome.is_complete());
        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_broadcast_ready(), "{fin:?}");
        let expected_txid =
            transaction_txid_hex(&extract_finalized_tx(built.psbt.clone()).unwrap());
        let mut mock = crate::explorer::MockTxBroadcaster::new();
        mock.push_ok(expected_txid.clone());
        let res = extract_and_broadcast(built.psbt, &mut mock).unwrap();
        assert_eq!(res.txid, expected_txid);
        assert_eq!(mock.submitted.len(), 1);
        assert!(!mock.submitted[0].is_empty());
    }

    #[test]
    fn extract_rejects_unfinalized_psbt() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("final_script_witness")
                || err.to_string().to_ascii_lowercase().contains("finalize"),
            "{err}"
        );
    }

    #[test]
    fn build_unsigned_psbt_rejects_network_mismatch_payment() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Mainnet UTXO + payment, but SpendParams claims Testnet.
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Testnet,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("network") || msg.contains("mismatch"), "{err}");
    }

    #[test]
    fn build_unsigned_psbt_rejects_network_mismatch_utxo_address() {
        let m = import_mnemonic(VECTOR).unwrap();
        // Testnet UTXO while network is mainnet; payment is valid mainnet.
        let testnet_recv = derive_bip84_receive_address(&m, Network::Testnet, 0).unwrap();
        let mainnet_pay = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let sel = selection_one_utxo(&testnet_recv, 10_000, 9_000, 1_000);
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: mainnet_pay,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("network") || msg.contains("mismatch"), "{err}");
    }

    #[test]
    fn build_unsigned_psbt_rejects_network_mismatch_change() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let testnet_change = derive_bip84_receive_address(&m, Network::Testnet, 0).unwrap();
        let sel = selection_one_utxo(&recv, 100_000, 40_000, 500);
        assert!(sel.change_sats > DUST_P2WPKH_SATS);
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(testnet_change),
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("network") || msg.contains("mismatch"), "{err}");
    }

    #[test]
    fn build_unsigned_psbt_rejects_dust_change() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        // Hand-built selection with sub-dust change (fee-aware select would fold).
        let dust = DUST_P2WPKH_SATS - 1;
        let sel = CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('d'), 0),
                amount_sats: 10_000,
                address: recv,
                confirmations: 3,
                is_change: false,
            }],
            total_input_sats: 10_000,
            change_sats: dust,
            target_sats: 9_000,
            fee_sats: 10_000 - 9_000 - dust,
        };
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(change),
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("dust") || msg.contains("threshold"), "{err}");
    }

    #[test]
    fn build_unsigned_psbt_rejects_duplicate_outpoints() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let op = OutPointRef::new(valid_txid('e'), 0);
        let sel = CoinSelection {
            selected: vec![
                WalletUtxo {
                    outpoint: op.clone(),
                    amount_sats: 5_000,
                    address: recv.clone(),
                    confirmations: 3,
                    is_change: false,
                },
                WalletUtxo {
                    outpoint: op,
                    amount_sats: 5_000,
                    address: recv,
                    confirmations: 3,
                    is_change: false,
                },
            ],
            total_input_sats: 10_000,
            change_sats: 0,
            target_sats: 9_000,
            fee_sats: 1_000,
        };
        let err = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        assert!(
            err.to_string().to_ascii_lowercase().contains("duplicate"),
            "{err}"
        );
    }

    #[test]
    fn finalize_p2wpkh_rejects_pubkey_script_mismatch() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Sign correctly first, then swap witness_utxo to a different P2WPKH script
        // so finalize must reject the pubkey/script mismatch.
        sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert_eq!(built.psbt.inputs[0].partial_sigs.len(), 1);
        let other_spk = parse_network_address(
            &derive_bip84_receive_address(&m, Network::Bitcoin, 3).unwrap(),
            Network::Bitcoin,
        )
        .unwrap()
        .script_pubkey();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = other_spk;
        }
        let err = finalize_p2wpkh_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash160") || msg.contains("match") || msg.contains("p2wpkh"),
            "{err}"
        );
    }

    #[test]
    fn finalize_p2wpkh_treats_empty_witness_as_missing() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Pre-stuff empty final witness — finalize must not count it as done.
        built.psbt.inputs[0].final_script_witness = Some(Witness::default());
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(
            !fin.is_complete(),
            "empty witness is not finalized: {fin:?}"
        );
        assert_eq!(fin.finalized_inputs(), 0);
        // Extract must refuse empty / missing witnesses (never success claim).
        let err = extract_finalized_tx(built.psbt.clone()).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("final_script_witness")
                || msg.contains("empty")
                || msg.contains("not broadcast"),
            "{err}"
        );
        // After sign, finalize should replace empty with real witness.
        sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        // Empty may have been cleared; re-stuff empty after sign to force the path.
        built.psbt.inputs[0].final_script_witness = Some(Witness::default());
        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        assert!(
            built.psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .is_some_and(|w| !w.is_empty())
        );
        assert!(psbt_is_broadcast_ready(&built.psbt));
    }

    /// Multi-sig shaped input (2 partial_sigs): never invent P2WPKH witness / complete.
    #[test]
    fn finalize_multisig_partial_sigs_is_partial_not_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[1u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[2u8; 32]).expect("sk2");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let msg = Message::from_digest_slice(&[9u8; 32]).expect("msg");
        let sig1 = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk1),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        let sig2 = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk2),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        built.psbt.inputs[0].partial_sigs.insert(pk1, sig1);
        built.psbt.inputs[0].partial_sigs.insert(pk2, sig2);
        assert_eq!(built.psbt.inputs[0].partial_sigs.len(), 2);

        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 0);
                assert_eq!(*residual_inputs, 1);
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("multi") || d.contains("partial_sig"), "{detail}");
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        // Must not invent a final witness for multi-sig residual.
        assert!(
            built.psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .map(|w| w.is_empty())
                .unwrap_or(true),
            "multi-sig residual must not claim final witness"
        );
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("final_script_witness")
                || err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("not broadcast"),
            "{err}"
        );
    }

    /// Non-P2WPKH (P2WSH) script residual: finalize Partial, never extract success.
    #[test]
    fn finalize_non_p2wpkh_p2wsh_is_partial_not_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        // Replace witness_utxo script with P2WSH (non-P2WPKH residual).
        let redeem = ScriptBuf::from_hex("51").expect("OP_TRUE");
        let p2wsh = redeem.to_p2wsh();
        assert!(p2wsh.is_p2wsh());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2wsh;
        }
        // Inject a single partial_sig so finalize reaches the script-type check
        // (unsigned residual would also be Partial; this asserts non-P2WPKH path).
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[3u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let msg = Message::from_digest_slice(&[8u8; 32]).expect("msg");
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        built.psbt.inputs[0].partial_sigs.insert(pk, sig);

        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 0);
                assert_eq!(*residual_inputs, 1);
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("non-p2wpkh") || d.contains("p2wpkh"), "{detail}");
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            built.psbt.inputs[0].final_script_witness.is_none(),
            "non-P2WPKH must not set final_script_witness"
        );
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("final_script_witness") || msg.contains("not broadcast"),
            "{err}"
        );
    }

    /// Partial sign must never claim extract / prepare / broadcast-ready success.
    #[test]
    fn partial_sign_never_claims_extract_or_prepare_success() {
        let m = import_mnemonic(VECTOR).unwrap();
        let foreign = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let sel = selection_one_utxo(foreign, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to.clone(),
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(!outcome.is_complete() && !outcome.is_broadcast_ready());
        match &outcome {
            SignOutcome::Partial { detail, .. } => {
                assert!(
                    detail.to_ascii_lowercase().contains("not broadcast-ready"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }

        // Finalize of unsigned inputs is Partial (not Complete).
        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 0);
        assert!(!psbt_is_broadcast_ready(&built.psbt));

        let err = extract_finalized_tx(built.psbt.clone()).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("final_script_witness")
                || err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("not broadcast"),
            "{err}"
        );

        let mut mock = crate::explorer::MockTxBroadcaster::new();
        mock.push_ok("should-not-be-used");
        let err = extract_and_broadcast(built.psbt, &mut mock).unwrap_err();
        assert!(mock.submitted.is_empty(), "partial must not broadcast");
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("final_script_witness")
                || err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("not broadcast")
                || err.to_string().to_ascii_lowercase().contains("finalize"),
            "{err}"
        );

        // Product prepare path refuses partial (honest residual).
        let err = prepare_bip84_p2wpkh_spend(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("incomplete") || msg.contains("not broadcast"),
            "{err}"
        );
        assert!(!msg.contains("broadcast accepted") && !msg.contains("txid accepted"));
    }

    /// Empty final_script_witness alone is never broadcast-ready for extract.
    #[test]
    fn extract_rejects_empty_final_script_witness() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        built.psbt.inputs[0].final_script_witness = Some(Witness::default());
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("empty") || msg.contains("final_script_witness"),
            "{err}"
        );
    }

    /// Empty final_script_sig alone is never broadcast-ready / Complete.
    #[test]
    fn empty_final_script_sig_never_complete() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        built.psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
        assert!(!input_is_finalized(&built.psbt.inputs[0]));
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(
            !fin.is_complete(),
            "empty script_sig is not complete: {fin:?}"
        );
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("empty")
                || msg.contains("final_script")
                || msg.contains("not broadcast")
                || msg.contains("missing"),
            "{err}"
        );
    }

    /// Already-present non-empty final_script_witness is preserved → Complete.
    #[test]
    fn finalize_preserves_preexisting_final_witness() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // External coordinator already finalized — no partial_sigs required.
        let pre = Witness::from_slice(&[&[0u8; 71][..], &[0u8; 33][..]]);
        built.psbt.inputs[0].final_script_witness = Some(pre.clone());
        assert!(input_is_finalized(&built.psbt.inputs[0]));
        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        assert_eq!(
            built.psbt.inputs[0].final_script_witness.as_ref(),
            Some(&pre),
            "must preserve existing final witness without rewrite"
        );
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].witness.is_empty());
    }

    /// Already-present non-empty final_script_sig is preserved → Complete.
    #[test]
    fn finalize_preserves_preexisting_final_script_sig() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        let pre = bitcoin::script::Builder::new()
            .push_slice([1u8; 71])
            .push_slice([2u8; 33])
            .into_script();
        built.psbt.inputs[0].final_script_sig = Some(pre.clone());
        assert!(input_is_finalized(&built.psbt.inputs[0]));
        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        assert_eq!(built.psbt.inputs[0].final_script_sig.as_ref(), Some(&pre));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].script_sig.is_empty());
    }

    /// Single-key P2PKH with matching partial_sig → final_script_sig Complete.
    #[test]
    fn finalize_single_key_p2pkh_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let p2pkh = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        assert!(p2pkh.is_p2pkh());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2pkh;
        }
        let msg = Message::from_digest_slice(&[4u8; 32]).expect("msg");
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        built.psbt.inputs[0].partial_sigs.insert(pk, sig);

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert!(
            built.psbt.inputs[0]
                .final_script_sig
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "P2PKH must set final_script_sig"
        );
        assert!(psbt_is_broadcast_ready(&built.psbt));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].script_sig.is_empty());
    }

    /// Single-key P2SH-P2WPKH with redeem_script + matching partial_sig → Complete.
    #[test]
    fn finalize_p2sh_p2wpkh_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[11u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let wpkh = pk.wpubkey_hash().expect("compressed");
        let redeem = ScriptBuf::new_p2wpkh(&wpkh);
        let p2sh = redeem.to_p2sh();
        assert!(p2sh.is_p2sh());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2sh;
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        let msg = Message::from_digest_slice(&[5u8; 32]).expect("msg");
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        built.psbt.inputs[0].partial_sigs.insert(pk, sig);

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert!(
            built.psbt.inputs[0]
                .final_script_sig
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "nested P2WPKH needs final_script_sig (redeem push)"
        );
        assert!(
            built.psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .is_some_and(|w| w.len() == 2),
            "nested P2WPKH witness is sig + pubkey"
        );
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].script_sig.is_empty());
        assert_eq!(tx.input[0].witness.len(), 2);
    }

    /// Single-key bare CHECKSIG P2WSH with witness_script → Complete.
    #[test]
    fn finalize_single_checksig_p2wsh_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[13u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk push");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let p2wsh = wscript.to_p2wsh();
        assert!(p2wsh.is_p2wsh());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2wsh;
        }
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        let msg = Message::from_digest_slice(&[6u8; 32]).expect("msg");
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type: bitcoin::EcdsaSighashType::All,
        };
        built.psbt.inputs[0].partial_sigs.insert(pk, sig);

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        assert_eq!(wit.len(), 2, "sig + witnessScript");
        assert_eq!(wit.last().map(|b| b.to_vec()), Some(wscript.to_bytes()));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 2);
    }

    /// Helpers: build bare m-of-n CHECKMULTISIG witness_script from ordered pubkeys.
    fn bare_checkmultisig_script(threshold: u8, pubkeys: &[bitcoin::PublicKey]) -> ScriptBuf {
        assert!((1..=16).contains(&threshold));
        assert!(!pubkeys.is_empty() && pubkeys.len() <= 16);
        assert!((threshold as usize) <= pubkeys.len());
        let mut b = bitcoin::script::Builder::new();
        b = b.push_int(i64::from(threshold));
        for pk in pubkeys {
            let pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk push");
            b = b.push_slice(pb);
        }
        b = b.push_int(pubkeys.len() as i64);
        b.push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script()
    }

    fn ecdsa_sig(
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
        sk: &bitcoin::secp256k1::SecretKey,
        digest: [u8; 32],
    ) -> bitcoin::ecdsa::Signature {
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&digest).expect("msg");
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, sk),
            sighash_type: bitcoin::EcdsaSighashType::All,
        }
    }

    /// 1-of-2 CHECKMULTISIG with one matching partial_sig → Complete (BIP147 stack).
    #[test]
    fn finalize_checkmultisig_1of2_with_enough_sigs_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[21u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[22u8; 32]).expect("sk2");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let wscript = bare_checkmultisig_script(1, &[pk1, pk2]);
        let p2wsh = wscript.to_p2wsh();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2wsh;
        }
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        // Threshold 1: only pk2 sig (second key) is enough; order preserved.
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk2, ecdsa_sig(&secp, &sk2, [7u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        // dummy + 1 sig + witnessScript
        assert_eq!(wit.len(), 3, "BIP147 stack: OP_0, sig, script");
        assert!(wit.second_to_last().is_some());
        assert_eq!(wit.last().map(|b| b.to_vec()), Some(wscript.to_bytes()));
        // First element is empty BIP147 dummy.
        assert!(wit.to_vec()[0].is_empty(), "BIP147 dummy must be empty");
        assert!(psbt_is_broadcast_ready(&built.psbt));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 3);
    }

    /// 2-of-3 CHECKMULTISIG with exactly two matching ordered partial_sigs → Complete.
    #[test]
    fn finalize_checkmultisig_2of3_with_enough_sigs_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[51u8; 32]).expect("ska");
        let sk_b = SecretKey::from_slice(&[52u8; 32]).expect("skb");
        let sk_c = SecretKey::from_slice(&[53u8; 32]).expect("skc");
        let pk_a = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_a));
        let pk_b = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_b));
        let pk_c = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_c));
        let wscript = bare_checkmultisig_script(2, &[pk_a, pk_b, pk_c]);
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        // Sigs for A and C only (skip B) — still enough for 2-of-3; order A then C.
        let sig_a = ecdsa_sig(&secp, &sk_a, [8u8; 32]);
        let sig_c = ecdsa_sig(&secp, &sk_c, [8u8; 32]);
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_a, sig_a.clone());
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_c, sig_c.clone());

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        // dummy + 2 sigs + witnessScript
        assert_eq!(wit.len(), 4);
        let items = wit.to_vec();
        assert!(items[0].is_empty(), "BIP147 dummy");
        assert_eq!(items[1], sig_a.to_vec());
        assert_eq!(items[2], sig_c.to_vec());
        assert_eq!(items[3], wscript.to_bytes());
        extract_finalized_tx(built.psbt).unwrap();
    }

    /// 1-of-2 with zero matching partial_sigs (only foreign key) → Partial, no invent.
    #[test]
    fn finalize_checkmultisig_1of2_wrong_key_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[61u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[62u8; 32]).expect("sk2");
        let sk_wrong = SecretKey::from_slice(&[63u8; 32]).expect("sk_wrong");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let pk_wrong = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_wrong,
        ));
        let wscript = bare_checkmultisig_script(1, &[pk1, pk2]);
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript);
        // Only a foreign key — must not invent a sig for pk1/pk2.
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_wrong, ecdsa_sig(&secp, &sk_wrong, [9u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("checkmultisig") || d.contains("threshold") || d.contains("multi"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            !input_is_finalized(&built.psbt.inputs[0]),
            "must not invent multi-sig final_script_witness"
        );
        assert!(extract_finalized_tx(built.psbt).is_err());
    }

    /// 2-of-3 with only one matching partial_sig → Partial (insufficient threshold).
    #[test]
    fn finalize_checkmultisig_2of3_insufficient_sigs_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[71u8; 32]).expect("ska");
        let sk_b = SecretKey::from_slice(&[72u8; 32]).expect("skb");
        let sk_c = SecretKey::from_slice(&[73u8; 32]).expect("skc");
        let pk_a = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_a));
        let pk_b = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_b));
        let pk_c = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_c));
        let wscript = bare_checkmultisig_script(2, &[pk_a, pk_b, pk_c]);
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript);
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_b, ecdsa_sig(&secp, &sk_b, [10u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 0);
                assert_eq!(*residual_inputs, 1);
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("threshold") || d.contains("checkmultisig") || d.contains("1/2"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(!input_is_finalized(&built.psbt.inputs[0]));
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("final_script")
                || msg.contains("not broadcast")
                || msg.contains("missing"),
            "{err}"
        );
    }

    /// Nested P2SH-P2WSH bare 1-of-2 CHECKMULTISIG with enough sigs → Complete.
    #[test]
    fn finalize_p2sh_p2wsh_checkmultisig_1of2_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[81u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[82u8; 32]).expect("sk2");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let wscript = bare_checkmultisig_script(1, &[pk1, pk2]);
        let redeem = wscript.to_p2wsh();
        let p2sh = redeem.to_p2sh();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2sh;
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk1, ecdsa_sig(&secp, &sk1, [11u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert!(
            built.psbt.inputs[0]
                .final_script_sig
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "nested P2WSH needs final_script_sig (redeem push)"
        );
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        assert_eq!(wit.len(), 3, "dummy + sig + script");
        assert_eq!(wit.last().map(|b| b.to_vec()), Some(wscript.to_bytes()));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].script_sig.is_empty());
        assert_eq!(tx.input[0].witness.len(), 3);
    }

    /// Enough matching keys plus a foreign partial_sig → Complete; foreign ignored.
    #[test]
    fn finalize_checkmultisig_ignores_extra_unrelated_partial_sigs() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[101u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[102u8; 32]).expect("sk2");
        let sk_foreign = SecretKey::from_slice(&[103u8; 32]).expect("sk_foreign");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let pk_foreign = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &sk_foreign,
        ));
        let wscript = bare_checkmultisig_script(1, &[pk1, pk2]);
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        let sig1 = ecdsa_sig(&secp, &sk1, [13u8; 32]);
        let sig_foreign = ecdsa_sig(&secp, &sk_foreign, [13u8; 32]);
        // Matching threshold + unrelated key that must not appear in the stack.
        built.psbt.inputs[0].partial_sigs.insert(pk1, sig1.clone());
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_foreign, sig_foreign.clone());
        assert_eq!(built.psbt.inputs[0].partial_sigs.len(), 2);

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        // BIP147 dummy + one matching sig + script (foreign must not pad stack).
        assert_eq!(wit.len(), 3);
        let items = wit.to_vec();
        assert!(items[0].is_empty(), "BIP147 NULLDUMMY");
        assert_eq!(items[1], sig1.to_vec(), "only script-order matching sig");
        assert_ne!(
            items[1],
            sig_foreign.to_vec(),
            "foreign partial_sig must not be used in final stack"
        );
        assert_eq!(items[2], wscript.to_bytes());
        extract_finalized_tx(built.psbt).unwrap();
    }

    /// Nested P2SH-P2WSH 2-of-3 with only one matching sig → Partial (no invent).
    #[test]
    fn finalize_p2sh_p2wsh_checkmultisig_insufficient_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[111u8; 32]).expect("ska");
        let sk_b = SecretKey::from_slice(&[112u8; 32]).expect("skb");
        let sk_c = SecretKey::from_slice(&[113u8; 32]).expect("skc");
        let pk_a = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_a));
        let pk_b = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_b));
        let pk_c = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_c));
        let wscript = bare_checkmultisig_script(2, &[pk_a, pk_b, pk_c]);
        let redeem = wscript.to_p2wsh();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = redeem.to_p2sh();
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        built.psbt.inputs[0].witness_script = Some(wscript);
        // Only one of two required — must not invent the second.
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk_a, ecdsa_sig(&secp, &sk_a, [14u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 0);
                assert_eq!(*residual_inputs, 1);
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("threshold") || d.contains("checkmultisig") || d.contains("1/2"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            !input_is_finalized(&built.psbt.inputs[0]),
            "insufficient nested CHECKMULTISIG must not invent finals"
        );
        assert!(
            built.psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .map(|w| w.is_empty())
                .unwrap_or(true),
            "no empty or invented final_script_witness"
        );
        assert!(
            built.psbt.inputs[0]
                .final_script_sig
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true),
            "must not set redeem script_sig when residual"
        );
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("final_script")
                || msg.contains("not broadcast")
                || msg.contains("missing"),
            "{err}"
        );
    }

    /// Non-standard (not bare CHECKMULTISIG) script-path stays Partial — no invent.
    #[test]
    fn finalize_nonstandard_p2wsh_script_stays_partial() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[91u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        // Non-standard: OP_DUP then CHECKSIG — not bare CHECKSIG or CHECKMULTISIG.
        let pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk");
        let wscript = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .push_slice(pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript);
        built.psbt.inputs[0]
            .partial_sigs
            .insert(pk, ecdsa_sig(&secp, &sk, [12u8; 32]));

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("script-path") || d.contains("residual") || d.contains("not bare"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(!input_is_finalized(&built.psbt.inputs[0]));
        assert!(extract_finalized_tx(built.psbt).is_err());
    }

    /// Multi-sig with already-present final witness → Complete (preserve, no invent).
    #[test]
    fn finalize_multisig_with_preexisting_final_is_complete() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Multi-key partial_sigs alone would be residual; a real final wins.
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[31u8; 32]).expect("sk1");
        let sk2 = SecretKey::from_slice(&[32u8; 32]).expect("sk2");
        let pk1 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1));
        let pk2 = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2));
        let msg = Message::from_digest_slice(&[10u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk1,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk1),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );
        built.psbt.inputs[0].partial_sigs.insert(
            pk2,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk2),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );
        let pre = Witness::from_slice(&[&[][..], &[1u8; 71][..], &[2u8; 71][..], &[3u8; 71][..]]);
        built.psbt.inputs[0].final_script_witness = Some(pre);
        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(
            fin.is_complete(),
            "pre-final multi-sig must Complete: {fin:?}"
        );
        assert!(psbt_is_broadcast_ready(&built.psbt));
        extract_finalized_tx(built.psbt).unwrap();
    }

    /// Mixed inputs: one completeable P2WPKH + one incomplete multi-sig → Partial.
    #[test]
    fn finalize_mixed_completeable_and_multisig_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();
        let sel = CoinSelection {
            selected: vec![
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('1'), 0),
                    amount_sats: 10_000,
                    address: recv,
                    confirmations: 6,
                    is_change: false,
                },
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('2'), 1),
                    amount_sats: 10_000,
                    address: change,
                    confirmations: 6,
                    is_change: true,
                },
            ],
            total_input_sats: 20_000,
            change_sats: 0,
            target_sats: 19_000,
            fee_sats: 1_000,
        };
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Sign both BIP84 keys first, then overwrite input 1 into multi-sig residual.
        sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert_eq!(built.psbt.inputs[0].partial_sigs.len(), 1);
        assert_eq!(built.psbt.inputs[1].partial_sigs.len(), 1);

        let secp = Secp256k1::new();
        let sk_extra = SecretKey::from_slice(&[41u8; 32]).expect("sk");
        let pk_extra = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_extra,
        ));
        let msg = Message::from_digest_slice(&[11u8; 32]).expect("msg");
        built.psbt.inputs[1].partial_sigs.insert(
            pk_extra,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk_extra),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );
        assert_eq!(built.psbt.inputs[1].partial_sigs.len(), 2);

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 1, "input 0 P2WPKH should finalize");
                assert_eq!(*residual_inputs, 1, "input 1 multi-sig stays residual");
                assert!(detail.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(input_is_finalized(&built.psbt.inputs[0]));
        assert!(!input_is_finalized(&built.psbt.inputs[1]));
        assert!(!psbt_is_broadcast_ready(&built.psbt));
        assert!(extract_finalized_tx(built.psbt).is_err());
    }

    /// Product prepare still refuses Partial for broadcast claim after finalize expansion.
    #[test]
    fn prepare_still_refuses_partial_finalize() {
        let m = import_mnemonic(VECTOR).unwrap();
        let foreign = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let sel = selection_one_utxo(foreign, 10_000, 9_000, 1_000);
        let err = prepare_bip84_p2wpkh_spend(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("incomplete") || msg.contains("not broadcast"),
            "{err}"
        );
        assert!(!msg.contains("broadcast accepted"));
        // Copy must not claim finalize is P2WPKH-only after offline expansion.
        assert!(
            !msg.contains("incomplete p2wpkh finalize"),
            "prepare residual must use offline-finalize wording: {err}"
        );
    }

    /// Extract must not blame a finalized input that still has an empty companion field.
    #[test]
    fn extract_skips_finalized_input_with_empty_companion_field() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();
        let sel = CoinSelection {
            selected: vec![
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('1'), 0),
                    amount_sats: 10_000,
                    address: recv,
                    confirmations: 6,
                    is_change: false,
                },
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('2'), 1),
                    amount_sats: 10_000,
                    address: change,
                    confirmations: 6,
                    is_change: true,
                },
            ],
            total_input_sats: 20_000,
            change_sats: 0,
            target_sats: 19_000,
            fee_sats: 1_000,
        };
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Input 0: non-empty witness + empty companion script_sig (still finalized).
        built.psbt.inputs[0].final_script_witness =
            Some(Witness::from_slice(&[&[1u8; 71][..], &[2u8; 33][..]]));
        built.psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
        assert!(input_is_finalized(&built.psbt.inputs[0]));
        // Input 1: truly residual (no finals).
        assert!(!input_is_finalized(&built.psbt.inputs[1]));
        assert!(!psbt_is_broadcast_ready(&built.psbt));

        let err = extract_finalized_tx(built.psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("input 1"),
            "must report residual input 1, not finalized input 0: {err}"
        );
        assert!(
            !msg.contains("input 0"),
            "must not mis-blame finalized input 0 empty companion: {err}"
        );
        assert!(
            msg.contains("missing") || msg.contains("not broadcast") || msg.contains("final"),
            "{err}"
        );
    }

    /// Nested P2SH-P2WSH bare CHECKSIG → Complete with redeem push + witness.
    #[test]
    fn finalize_p2sh_p2wsh_single_checksig_is_complete() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[17u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk push");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let redeem = wscript.to_p2wsh();
        let p2sh = redeem.to_p2sh();
        assert!(p2sh.is_p2sh() && redeem.is_p2wsh());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = p2sh;
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        built.psbt.inputs[0].witness_script = Some(wscript.clone());
        let msg = Message::from_digest_slice(&[12u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert!(
            built.psbt.inputs[0]
                .final_script_sig
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "nested P2WSH needs final_script_sig (redeem push)"
        );
        let wit = built.psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final witness");
        assert_eq!(wit.len(), 2, "sig + witnessScript");
        assert_eq!(wit.last().map(|b| b.to_vec()), Some(wscript.to_bytes()));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert!(!tx.input[0].script_sig.is_empty());
        assert_eq!(tx.input[0].witness.len(), 2);
    }

    /// Nested P2SH-P2WSH without witness_script stays Partial.
    #[test]
    fn finalize_p2sh_p2wsh_missing_witness_script_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[18u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk push");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let redeem = wscript.to_p2wsh();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = redeem.to_p2sh();
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        // Deliberately omit witness_script.
        let msg = Message::from_digest_slice(&[13u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let fin = finalize_psbt(&mut built.psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("witness_script") || d.contains("p2sh-p2wsh"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(!input_is_finalized(&built.psbt.inputs[0]));
    }

    /// Nested P2SH-P2WSH: witness_script hash ≠ redeem → hard error (not Partial).
    #[test]
    fn finalize_p2sh_p2wsh_witness_script_hash_mismatch_is_hard_error() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[19u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk push");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let redeem = wscript.to_p2wsh();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = redeem.to_p2sh();
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        // Different bare CHECKSIG script so hash ≠ redeem.
        let sk_other = SecretKey::from_slice(&[20u8; 32]).expect("sk_other");
        let pk_other = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_other,
        ));
        let other_pb =
            bitcoin::script::PushBytesBuf::try_from(pk_other.to_bytes()).expect("other pk");
        let wrong_wscript = bitcoin::script::Builder::new()
            .push_slice(other_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        built.psbt.inputs[0].witness_script = Some(wrong_wscript);
        let msg = Message::from_digest_slice(&[14u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash") || msg.contains("match") || msg.contains("witness_script"),
            "{err}"
        );
    }

    /// Malformed PSBT: inputs.len() ≠ unsigned_tx.input.len() → Onchain, not panic.
    #[test]
    fn finalize_and_extract_reject_input_len_mismatch() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        // Extra PSBT input map entry without a matching unsigned_tx vin.
        built.psbt.inputs.push(bitcoin::psbt::Input::default());
        assert_ne!(built.psbt.inputs.len(), built.psbt.unsigned_tx.input.len());

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("length") || msg.contains("malformed") || msg.contains("match"),
            "{err}"
        );

        let err = extract_finalized_tx(built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("length") || msg.contains("malformed") || msg.contains("match"),
            "{err}"
        );
    }

    /// P2PKH pubkey HASH160 ≠ script → hard error.
    #[test]
    fn finalize_p2pkh_rejects_pubkey_script_mismatch() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[51u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let sk_other = SecretKey::from_slice(&[52u8; 32]).expect("sk_other");
        let pk_other = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_other,
        ));
        // UTXO locked to pk_other; partial_sig is for pk → mismatch.
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = ScriptBuf::new_p2pkh(&pk_other.pubkey_hash());
        }
        let msg = Message::from_digest_slice(&[15u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash160") || msg.contains("match") || msg.contains("p2pkh"),
            "{err}"
        );
    }

    /// P2SH redeem_script HASH160 ≠ scriptPubKey → hard error.
    #[test]
    fn finalize_p2sh_rejects_redeem_script_hash_mismatch() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[53u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let wpkh = pk.wpubkey_hash().expect("compressed");
        let redeem = ScriptBuf::new_p2wpkh(&wpkh);
        // Spk is a different P2SH (OP_TRUE redeem), not redeem.to_p2sh().
        let other_redeem = ScriptBuf::from_hex("51").expect("OP_TRUE");
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = other_redeem.to_p2sh();
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        let msg = Message::from_digest_slice(&[16u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash160") || msg.contains("redeem") || msg.contains("match"),
            "{err}"
        );
    }

    /// P2SH-P2WPKH: redeem matches spk but not partial_sig pubkey → hard error.
    #[test]
    fn finalize_p2sh_p2wpkh_rejects_pubkey_redeem_mismatch() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[54u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let sk_other = SecretKey::from_slice(&[55u8; 32]).expect("sk_other");
        let pk_other = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_other,
        ));
        let redeem = ScriptBuf::new_p2wpkh(&pk_other.wpubkey_hash().expect("compressed"));
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = redeem.to_p2sh();
        }
        built.psbt.inputs[0].redeem_script = Some(redeem);
        let msg = Message::from_digest_slice(&[17u8; 32]).expect("msg");
        // partial_sig for pk, redeem is for pk_other.
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash160") || msg.contains("redeem") || msg.contains("match"),
            "{err}"
        );
    }

    /// Native P2WSH: witness_script hash ≠ scriptPubKey → hard error.
    #[test]
    fn finalize_p2wsh_rejects_witness_script_hash_mismatch() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[56u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        // Spk from a different script.
        let other = ScriptBuf::from_hex("51").expect("OP_TRUE");
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = other.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript);
        let msg = Message::from_digest_slice(&[18u8; 32]).expect("msg");
        built.psbt.inputs[0].partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("hash") || msg.contains("match") || msg.contains("witness_script"),
            "{err}"
        );
    }

    /// Single-CHECKSIG P2WSH: partial_sig pubkey ≠ script pubkey → hard error.
    #[test]
    fn finalize_single_checksig_rejects_pubkey_mismatch() {
        use bitcoin::PublicKey;
        use bitcoin::ecdsa;
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[57u8; 32]).expect("sk");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        let sk_other = SecretKey::from_slice(&[58u8; 32]).expect("sk_other");
        let pk_other = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk_other,
        ));
        let pk_pb = bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).expect("pk");
        let wscript = bitcoin::script::Builder::new()
            .push_slice(pk_pb)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = wscript.to_p2wsh();
        }
        built.psbt.inputs[0].witness_script = Some(wscript);
        let msg = Message::from_digest_slice(&[19u8; 32]).expect("msg");
        // partial_sig for different key than witness_script.
        built.psbt.inputs[0].partial_sigs.insert(
            pk_other,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk_other),
                sighash_type: bitcoin::EcdsaSighashType::All,
            },
        );

        let err = finalize_psbt(&mut built.psbt).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("pubkey") || msg.contains("match") || msg.contains("checksig"),
            "{err}"
        );
    }

    #[test]
    fn sign_finalize_extract_multi_input_receive_and_change() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv = w.primary_receive_address().unwrap().to_owned();
        let change_addr = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 2).unwrap();
        let new_change = w.change_addresses()[1].clone();

        let sel = CoinSelection {
            selected: vec![
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('1'), 0),
                    amount_sats: 30_000,
                    address: recv,
                    confirmations: 6,
                    is_change: false,
                },
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('2'), 1),
                    amount_sats: 20_000,
                    address: change_addr,
                    confirmations: 3,
                    is_change: true,
                },
            ],
            total_input_sats: 50_000,
            change_sats: 19_500,
            target_sats: 30_000,
            fee_sats: 500,
        };

        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(new_change),
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        assert_eq!(built.input_count(), 2);

        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(outcome.is_complete(), "{outcome:?}");
        assert_eq!(outcome.signed_inputs(), 2);

        let fin = finalize_p2wpkh_psbt(&mut built.psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 2);
        assert!(psbt_is_broadcast_ready(&built.psbt));
        let tx = extract_finalized_tx(built.psbt).unwrap();
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 30_000);
        assert_eq!(tx.output[1].value.to_sat(), 19_500);
        assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
    }

    #[test]
    fn sign_psbt_mixed_partial_owned_and_foreign() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let foreign = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();

        let sel = CoinSelection {
            selected: vec![
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('3'), 0),
                    amount_sats: 40_000,
                    address: recv,
                    confirmations: 3,
                    is_change: false,
                },
                WalletUtxo {
                    outpoint: OutPointRef::new(valid_txid('4'), 0),
                    amount_sats: 20_000,
                    address: foreign.into(),
                    confirmations: 3,
                    is_change: false,
                },
            ],
            total_input_sats: 60_000,
            change_sats: 29_500,
            target_sats: 30_000,
            fee_sats: 500,
        };

        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(change),
                network: Network::Bitcoin,
            },
        )
        .unwrap();

        let outcome = sign_psbt_bip84_p2wpkh(&mut built.psbt, &m, "", Network::Bitcoin, 5).unwrap();
        assert!(!outcome.is_complete());
        match outcome {
            SignOutcome::Partial {
                signed_inputs,
                unsigned_inputs,
                ..
            } => {
                assert_eq!(signed_inputs, 1);
                assert_eq!(unsigned_inputs, 1);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn sign_finalize_extract_change_chain_only_utxo() {
        let m = import_mnemonic(VECTOR).unwrap();
        let w = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let change_utxo_addr = w.change_addresses()[0].clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let new_change = w.change_addresses()[1].clone();

        let sel = CoinSelection {
            selected: vec![WalletUtxo {
                outpoint: OutPointRef::new(valid_txid('5'), 0),
                amount_sats: 50_000,
                address: change_utxo_addr,
                confirmations: 6,
                is_change: true,
            }],
            total_input_sats: 50_000,
            change_sats: 29_750,
            target_sats: 20_000,
            fee_sats: 250,
        };

        let tx = build_sign_extract_bip84_p2wpkh(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: Some(new_change),
                network: Network::Bitcoin,
            },
            &m,
            "",
            5,
        )
        .unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 20_000);
        assert!(!tx.input[0].witness.is_empty());
    }

    #[test]
    fn fee_aware_select_then_build_psbt_balances() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let change = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 2)
            .unwrap()
            .change_addresses()[0]
            .clone();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();

        let utxos = vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('b'), 1),
            amount_sats: 100_000,
            address: recv,
            confirmations: 6,
            is_change: false,
        }];
        let sel =
            select_coins_with_fee(&utxos, 25_000, 10, CoinSelectStrategy::LargestFirst).unwrap();
        assert!(sel.fee_sats > 0);

        let built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: if sel.change_sats > 0 {
                    Some(change)
                } else {
                    None
                },
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        let tx = &built.psbt.unsigned_tx;
        let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(sel.total_input_sats - out_sum, sel.fee_sats);
        assert_eq!(tx.output[0].value.to_sat(), 25_000);
        if sel.change_sats > 0 {
            assert_eq!(tx.output.len(), 2);
            assert_eq!(tx.output[1].value.to_sat(), sel.change_sats);
        } else {
            assert_eq!(tx.output.len(), 1);
        }
    }

    #[test]
    fn built_psbt_debug_has_no_mnemonic() {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        let dbg = format!("{built:?}");
        assert!(!dbg.contains("leader"));
        assert!(!dbg.contains("monkey"));
        assert!(dbg.contains("BuiltPsbt"));
    }

    /// Empty vs non-empty BIP-39 passphrase changes addresses and product sign path.
    #[test]
    fn product_prepare_paths_honor_bip39_passphrase() {
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = "test-passphrase-not-for-prod";
        let w_pass =
            DescriptorWallet::from_mnemonic_with_passphrase(&m, pass, Network::Bitcoin, 5).unwrap();
        let w_empty = DescriptorWallet::from_mnemonic(&m, Network::Bitcoin, 5).unwrap();
        let recv_pass = w_pass.primary_receive_address().unwrap().to_owned();
        let recv_empty = w_empty.primary_receive_address().unwrap().to_owned();
        assert_ne!(
            recv_pass, recv_empty,
            "passphrase must change BIP84 receive addresses"
        );

        let pay_pass =
            derive_bip84_receive_address_with_passphrase(&m, pass, Network::Bitcoin, 1).unwrap();
        let chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('e'), 0),
            amount_sats: 100_000,
            address: recv_pass.clone(),
            confirmations: 6,
            is_change: false,
        }]);

        // Matching wallet + passphrase signs.
        let prep =
            select_and_prepare_bip84_spend(&w_pass, &chain, &m, &pay_pass, 25_000, 5, pass, 5)
                .unwrap();
        assert_eq!(prep.payment_sats, 25_000);
        assert!(!prep.raw_hex().is_empty());
        assert_eq!(prep.input_count, 1);

        // Wrong passphrase cannot map script → key (sign incomplete / lookup miss).
        let wrong = select_and_prepare_bip84_spend(
            &w_pass,
            &chain,
            &m,
            &pay_pass,
            25_000,
            5,
            "wrong-pass",
            5,
        );
        assert!(
            wrong.is_err(),
            "wrong passphrase must not produce a signed spend"
        );

        // Empty-passphrase product path against empty-passphrase wallet still works.
        let chain_empty = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('f'), 0),
            amount_sats: 100_000,
            address: recv_empty,
            confirmations: 6,
            is_change: false,
        }]);
        let pay_empty = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let prep_empty = select_and_prepare_bip84_spend(
            &w_empty,
            &chain_empty,
            &m,
            &pay_empty,
            25_000,
            5,
            "",
            5,
        )
        .unwrap();
        assert_eq!(prep_empty.payment_sats, 25_000);

        // RBF product path with passphrase.
        let rbf = prepare_rbf_replacement(
            &w_pass,
            &m,
            &prep.selected_inputs,
            &pay_pass,
            25_000,
            prep.fee_sats,
            prep.weight_vbytes(),
            15,
            pass,
            5,
        )
        .unwrap();
        assert!(rbf.prepared.fee_sats > prep.fee_sats);
        assert_eq!(rbf.prepared.payment_sats, 25_000);

        // CPFP product path with passphrase (parent = large unconfirmed output).
        let parent = WalletUtxo {
            outpoint: OutPointRef::new(valid_txid('d'), 0),
            amount_sats: 80_000,
            address: recv_pass,
            confirmations: 0,
            is_change: true,
        };
        let cpfp = prepare_cpfp_child(
            &w_pass,
            &m,
            &[parent],
            &[],
            &pay_pass,
            40_000,
            200,
            200,
            12,
            pass,
            5,
        )
        .unwrap();
        assert_eq!(cpfp.prepared.payment_sats, 40_000);
        assert!(cpfp.prepared.fee_sats > 0);
    }

    #[test]
    fn from_mnemonic_env_network_with_passphrase_matches_explicit() {
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = "env-passphrase-test";
        let a =
            DescriptorWallet::from_mnemonic_with_passphrase(&m, pass, Network::Bitcoin, 3).unwrap();
        let b = DescriptorWallet::from_mnemonic_env_network_with_passphrase(&m, pass, "mainnet", 3)
            .unwrap();
        assert_eq!(a.primary_receive_address(), b.primary_receive_address());
        assert_eq!(a.change_addresses(), b.change_addresses());
        let empty = DescriptorWallet::from_mnemonic_env_network(&m, "mainnet", 3).unwrap();
        assert_ne!(a.primary_receive_address(), empty.primary_receive_address());
    }

    // --- Taproot key-path + bare script-path finalize (honest; never invents) ---

    /// Build a P2TR prevout on a single-input PSBT (replaces BIP84 witness_utxo).
    fn p2tr_psbt_with_internal(
        internal: bitcoin::secp256k1::XOnlyPublicKey,
        merkle: Option<bitcoin::taproot::TapNodeHash>,
    ) -> (bitcoin::psbt::Psbt, ScriptBuf) {
        let m = import_mnemonic(VECTOR).unwrap();
        let recv = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let pay_to = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        let sel = selection_one_utxo(&recv, 10_000, 9_000, 1_000);
        let mut built = build_unsigned_psbt(
            &sel,
            &SpendParams {
                payment_address: pay_to,
                change_address: None,
                network: Network::Bitcoin,
            },
        )
        .unwrap();
        let secp = Secp256k1::new();
        let spk = ScriptBuf::new_p2tr(&secp, internal, merkle);
        assert!(spk.is_p2tr());
        if let Some(utxo) = built.psbt.inputs[0].witness_utxo.as_mut() {
            utxo.script_pubkey = spk.clone();
        }
        built.psbt.inputs[0].tap_internal_key = Some(internal);
        built.psbt.inputs[0].tap_merkle_root = merkle;
        (built.psbt, spk)
    }

    fn sample_tap_key_sig(sk_bytes: [u8; 32], msg_bytes: [u8; 32]) -> bitcoin::taproot::Signature {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&sk_bytes).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest_slice(&msg_bytes).expect("msg");
        bitcoin::taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&msg, &keypair),
            sighash_type: bitcoin::TapSighashType::Default,
        }
    }

    /// Bare `<x-only> OP_CHECKSIG` leaf + control block via TaprootBuilder.
    ///
    /// Returns (psbt with P2TR prevout + internal/merkle, leaf, control_block,
    /// spend_xonly used in the leaf).
    fn p2tr_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(
            single_tapscript_checksig_xonly(&leaf).is_some(),
            "test leaf must be bare x-only CHECKSIG"
        );

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        // Ensure spk matches TaprootBuilder output (same internal + merkle).
        assert_eq!(
            spk,
            ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            "builder output key must match new_p2tr(internal, merkle)"
        );
        assert!(
            control_block.verify_taproot_commitment(
                &secp,
                p2tr_output_key(&spk).expect("output key"),
                &leaf
            ),
            "test control block must verify"
        );
        (psbt, leaf, control_block, spend_xonly)
    }

    /// P2TR with present `tap_key_sig` → Complete key-path witness (no invent).
    #[test]
    fn finalize_taproot_key_path_with_tap_key_sig_is_complete() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[41u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        let sig = sample_tap_key_sig([41u8; 32], [7u8; 32]);
        psbt.inputs[0].tap_key_sig = Some(sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("key-path final witness");
        assert_eq!(wit.len(), 1, "key-path witness is a single Schnorr element");
        assert_eq!(
            wit.to_vec()[0],
            Witness::p2tr_key_spend(&sig).to_vec()[0],
            "must use p2tr_key_spend assembly from present tap_key_sig"
        );
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    /// P2TR without `tap_key_sig` → Partial; never invents a Schnorr sig.
    #[test]
    fn finalize_taproot_missing_tap_key_sig_is_partial() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[42u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial {
                finalized_inputs,
                residual_inputs,
                detail,
            } => {
                assert_eq!(*finalized_inputs, 0);
                assert_eq!(*residual_inputs, 1);
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("taproot") && d.contains("tap_key_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent Taproot key-path witness"
        );
        assert!(!psbt_is_broadcast_ready(&psbt));
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// P2TR with only ECDSA `partial_sigs` (no tap_key_sig) → Partial, no invent.
    #[test]
    fn finalize_taproot_ecdsa_partial_sigs_only_is_partial() {
        use bitcoin::PublicKey;
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[43u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        psbt.inputs[0]
            .partial_sigs
            .insert(pk, ecdsa_sig(&secp, &sk, [9u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("taproot"), "{detail}");
                assert!(d.contains("ecdsa") && d.contains("partial_sig"), "{detail}");
                assert!(
                    d.contains("insufficient") || d.contains("tap_key_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Non-bare Taproot script-path maps without `tap_key_sig` stay Partial (no invent).
    #[test]
    fn finalize_taproot_script_path_partial_maps_is_partial() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::LeafVersion;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[44u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, parity) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);

        // Empty leaf is not bare x-only CHECKSIG — residual honesty (no invent).
        let leaf = ScriptBuf::new();
        let cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: parity,
            internal_key: xonly,
            merkle_branch: Default::default(),
        };
        psbt.inputs[0]
            .tap_scripts
            .insert(cb, (leaf, LeafVersion::TapScript));
        let leaf_hash =
            bitcoin::taproot::TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        psbt.inputs[0].tap_script_sigs.insert(
            (xonly, leaf_hash),
            sample_tap_key_sig([44u8; 32], [3u8; 32]),
        );

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("script-path") || d.contains("taproot"),
                    "{detail}"
                );
                assert!(
                    d.contains("bare") || d.contains("checksig") || d.contains("not assembled"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent Taproot script-path witness stack"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Bare x-only CHECKSIG leaf + present control block + matching tap_script_sig → Complete.
    #[test]
    fn finalize_taproot_script_path_bare_checksig_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (mut psbt, leaf, control_block, spend_xonly) =
            p2tr_script_path_psbt([50u8; 32], [51u8; 32]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig = sample_tap_key_sig([51u8; 32], [11u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((spend_xonly, leaf_hash), sig);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("script-path final witness");
        assert_eq!(
            wit.len(),
            3,
            "script-path witness is <sig> <script> <control block>"
        );
        let items = wit.to_vec();
        assert_eq!(
            items[0],
            sig.to_vec(),
            "sig element from present tap_script_sig"
        );
        assert_eq!(
            items[1],
            leaf.as_bytes(),
            "leaf script from present tap_scripts"
        );
        assert_eq!(
            items[2],
            control_block.serialize(),
            "control block from present tap_scripts key (never invented)"
        );
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 3);
    }

    /// Bare CHECKSIG leaf present but missing matching tap_script_sig → Partial (no invent).
    #[test]
    fn finalize_taproot_script_path_missing_sig_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let (mut psbt, leaf, control_block, _spend_xonly) =
            p2tr_script_path_psbt([52u8; 32], [53u8; 32]);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // No tap_script_sigs entry.
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("tap_script_sig") || d.contains("missing"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Control block that fails commitment verify → hard error (tamper).
    #[test]
    fn finalize_taproot_script_path_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (mut psbt, leaf, _good_cb, spend_xonly) = p2tr_script_path_psbt([54u8; 32], [55u8; 32]);
        // Build a control block for a different internal key (does not commit).
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[56u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0].tap_script_sigs.insert(
            (spend_xonly, leaf_hash),
            sample_tap_key_sig([55u8; 32], [12u8; 32]),
        );

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "tamper path must not set final witness"
        );
    }

    /// tap_script_sigs without tap_scripts → Partial (no invent control block).
    #[test]
    fn finalize_taproot_script_path_sigs_without_scripts_is_partial() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[57u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_script_sigs.insert(
            (xonly, leaf_hash),
            sample_tap_key_sig([57u8; 32], [13u8; 32]),
        );
        assert!(psbt.inputs[0].tap_scripts.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("script-path") || d.contains("tap_scripts"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent control block / leaf from sigs alone"
        );
    }

    /// Multi-leaf: first completeable entry in ControlBlock BTreeMap order wins
    /// (not insertion order / last-wins). Skips incomplete earlier entries.
    #[test]
    fn finalize_taproot_script_path_first_completeable_btree_order_wins() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[60u8; 32]).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_a_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[61u8; 32]).expect("ska"));
        let (spend_a, _) = spend_a_kp.x_only_public_key();
        let spend_b_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[62u8; 32]).expect("skb"));
        let (spend_b, _) = spend_b_kp.x_only_public_key();

        let leaf_a = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let leaf_b = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        // Two leaves at depth 1 (binary tree under root).
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, leaf_a.clone())
            .expect("leaf a")
            .add_leaf(1, leaf_b.clone())
            .expect("leaf b")
            .finalize(&secp, internal_xonly)
            .expect("tree");
        let cb_a = spend_info
            .control_block(&(leaf_a.clone(), LeafVersion::TapScript))
            .expect("cb a");
        let cb_b = spend_info
            .control_block(&(leaf_b.clone(), LeafVersion::TapScript))
            .expect("cb b");
        assert_ne!(cb_a, cb_b, "distinct control blocks for two leaves");

        let (mut psbt, spk) = p2tr_psbt_with_internal(internal_xonly, spend_info.merkle_root());
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));

        let sig_a = sample_tap_key_sig([61u8; 32], [21u8; 32]);
        let sig_b = sample_tap_key_sig([62u8; 32], [22u8; 32]);
        let hash_a = TapLeafHash::from_script(&leaf_a, LeafVersion::TapScript);
        let hash_b = TapLeafHash::from_script(&leaf_b, LeafVersion::TapScript);

        // Insert B then A so insertion order ≠ map order; map uses ControlBlock Ord.
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_b.clone(), (leaf_b.clone(), LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_a.clone(), (leaf_a.clone(), LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((spend_a, hash_a), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((spend_b, hash_b), sig_b);

        // Expected winner = first key in BTreeMap / ControlBlock Ord order.
        let first_cb = psbt.inputs[0]
            .tap_scripts
            .keys()
            .next()
            .expect("two entries")
            .clone();
        let (expected_leaf, expected_sig, expected_cb_ser) = if first_cb == cb_a {
            (leaf_a.clone(), sig_a, cb_a.serialize())
        } else {
            assert_eq!(first_cb, cb_b, "first key must be one of the two CBs");
            (leaf_b.clone(), sig_b, cb_b.serialize())
        };

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("script-path final");
        let items = wit.to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0],
            expected_sig.to_vec(),
            "witness sig must match first completeable BTreeMap entry"
        );
        assert_eq!(
            items[1],
            expected_leaf.as_bytes(),
            "witness leaf must match first completeable BTreeMap entry"
        );
        assert_eq!(
            items[2], expected_cb_ser,
            "witness control block must match first completeable BTreeMap entry (not last-wins)"
        );
    }

    /// Incomplete (non-bare) earlier map entry is skipped; later bare completeable wins.
    #[test]
    fn finalize_taproot_script_path_skips_incomplete_then_completes_later() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (mut psbt, leaf, good_cb, spend_xonly) = p2tr_script_path_psbt([63u8; 32], [64u8; 32]);
        let secp = Secp256k1::new();
        // Non-bare empty leaf with a CB that sorts before the good one when possible.
        let junk_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).expect("jk"));
        let (junk_internal, junk_parity) = junk_kp.x_only_public_key();
        let junk_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: junk_parity,
            internal_key: junk_internal,
            merkle_branch: Default::default(),
        };
        // Insert both; junk is incomplete (empty leaf), good is completeable.
        psbt.inputs[0]
            .tap_scripts
            .insert(junk_cb.clone(), (ScriptBuf::new(), LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(good_cb.clone(), (leaf.clone(), LeafVersion::TapScript));
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig = sample_tap_key_sig([64u8; 32], [23u8; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((spend_xonly, leaf_hash), sig);

        // Precondition: junk is incomplete; good is completeable regardless of order.
        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "must skip non-bare and assemble completeable leaf: {fin:?}"
        );
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items[1], leaf.as_bytes(), "must use bare completeable leaf");
        assert_eq!(
            items[2],
            good_cb.serialize(),
            "must use good control block, not junk"
        );
        // Residual reason for skipped junk must not block completion.
        let _ = junk_cb;
    }

    /// leaf_version mismatch on map value vs control block → Partial (no assemble / hard-error).
    #[test]
    fn finalize_taproot_script_path_leaf_version_mismatch_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (mut psbt, leaf, control_block, spend_xonly) =
            p2tr_script_path_psbt([65u8; 32], [66u8; 32]);
        // Control block is TapScript; map value claims a different leaf version.
        let mismatched_ver = LeafVersion::from_consensus(0xc2).expect("future leaf version 0xc2");
        assert_ne!(
            mismatched_ver, control_block.leaf_version,
            "precondition: versions differ"
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, control_block.leaf_version);
        // Sig key uses control-block leaf version hash (would match if versions agreed).
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block.clone(), (leaf.clone(), mismatched_ver));
        psbt.inputs[0].tap_script_sigs.insert(
            (spend_xonly, leaf_hash),
            sample_tap_key_sig([66u8; 32], [24u8; 32]),
        );

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("leaf_version") || d.contains("mismatch"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "leaf_version mismatch must not assemble or hard-error"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Completeable-but-invalid control block hard-errors the whole input even if a
    /// later map entry would verify (intentional: do not silently skip tamper).
    #[test]
    fn finalize_taproot_script_path_bad_cb_hard_errors_before_later_good() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (mut psbt, good_leaf, good_cb, spend_xonly) =
            p2tr_script_path_psbt([67u8; 32], [68u8; 32]);
        let secp = Secp256k1::new();
        // Bare leaf + matching sig, but CB does not commit to prevout (tamper).
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[69u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        // Same bare leaf template so both entries are "completeable until verify".
        let leaf_hash = TapLeafHash::from_script(&good_leaf, LeafVersion::TapScript);
        let sig = sample_tap_key_sig([68u8; 32], [25u8; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((spend_xonly, leaf_hash), sig);

        // Ensure bad_cb is first in BTreeMap order so we hit verify-fail before good.
        // If good sorts first by accident, flip construction until bad is first.
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb.clone(), (good_leaf.clone(), LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(good_cb.clone(), (good_leaf.clone(), LeafVersion::TapScript));
        let first = psbt.inputs[0]
            .tap_scripts
            .keys()
            .next()
            .expect("two entries")
            .clone();
        if first != bad_cb {
            // Rebuild map so bad is forced first: use a CB that is strictly less
            // than good under Ord (all-zero-ish valid key with Even parity default).
            psbt.inputs[0].tap_scripts.clear();
            // Pick the smaller of bad_cb and a synthetic smaller bad if needed.
            // ControlBlock Ord: leaf_version, parity, internal_key, merkle_branch.
            // Force Even parity + minimal internal that still fails verify.
            let tiny_kp =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).expect("tiny"));
            let (tiny_x, _) = tiny_kp.x_only_public_key();
            let forced_bad = bitcoin::taproot::ControlBlock {
                leaf_version: LeafVersion::TapScript,
                output_key_parity: bitcoin::secp256k1::Parity::Even,
                internal_key: tiny_x,
                merkle_branch: Default::default(),
            };
            // Prefer forced_bad if it sorts before good_cb; else keep original bad_cb
            // only when it already sorts first (handled above).
            let use_bad = if forced_bad < good_cb {
                forced_bad
            } else if bad_cb < good_cb {
                bad_cb.clone()
            } else {
                // Last resort: make good_cb the second by cloning bad with Even + tiny
                // and assert ordering.
                forced_bad
            };
            psbt.inputs[0]
                .tap_scripts
                .insert(use_bad.clone(), (good_leaf.clone(), LeafVersion::TapScript));
            psbt.inputs[0]
                .tap_scripts
                .insert(good_cb.clone(), (good_leaf.clone(), LeafVersion::TapScript));
            let first2 = psbt.inputs[0].tap_scripts.keys().next().unwrap();
            assert!(
                first2 != &good_cb,
                "precondition failed: need a bad completeable CB first in map order \
                 (first={first2:?}, good={good_cb:?})"
            );
            // Bad entry must fail verify (completeable until commitment check).
            assert!(
                !first2.verify_taproot_commitment(
                    &secp,
                    p2tr_output_key(&psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey)
                        .unwrap(),
                    &good_leaf
                ),
                "first CB must be the failing/tamper entry"
            );
        } else {
            assert!(
                !bad_cb.verify_taproot_commitment(
                    &secp,
                    p2tr_output_key(&psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey)
                        .unwrap(),
                    &good_leaf
                ),
                "precondition: bad CB fails verify"
            );
        }

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "must hard-error on first completeable-but-invalid CB, not fall through: {err}"
        );
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not assemble later good path after tamper CB"
        );
    }

    /// Multi-leaf residual joins unique incompleteness reasons (not first-only).
    #[test]
    fn finalize_taproot_script_path_multi_leaf_residual_joins_reasons() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::LeafVersion;

        let (mut psbt, bare_leaf, bare_cb, _spend) = p2tr_script_path_psbt([70u8; 32], [71u8; 32]);
        let secp = Secp256k1::new();
        let junk_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).expect("jk"));
        let (junk_x, junk_parity) = junk_kp.x_only_public_key();
        let junk_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: junk_parity,
            internal_key: junk_x,
            merkle_branch: Default::default(),
        };
        // Non-bare leaf (empty) + bare leaf without matching sig → both residual reasons.
        psbt.inputs[0]
            .tap_scripts
            .insert(junk_cb, (ScriptBuf::new(), LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(bare_cb, (bare_leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                // Joined unique reasons: non-bare + missing sig.
                assert!(
                    d.contains("bare") || d.contains("checksig") || d.contains("complex"),
                    "should mention non-bare leaf: {detail}"
                );
                assert!(
                    d.contains("tap_script_sig") || d.contains("missing"),
                    "should mention missing sig: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Wrong `tap_internal_key` vs P2TR scriptPubKey → hard error (tamper).
    #[test]
    fn finalize_taproot_internal_key_mismatch_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[45u8; 32]).expect("sk_a");
        let sk_b = SecretKey::from_slice(&[46u8; 32]).expect("sk_b");
        let kp_a = Keypair::from_secret_key(&secp, &sk_a);
        let kp_b = Keypair::from_secret_key(&secp, &sk_b);
        let (x_a, _) = kp_a.x_only_public_key();
        let (x_b, _) = kp_b.x_only_public_key();
        // Build PSBT whose prevout is P2TR(A), then claim internal key B.
        let (mut psbt, spk_a) = p2tr_psbt_with_internal(x_a, None);
        assert_eq!(
            psbt.inputs[0]
                .witness_utxo
                .as_ref()
                .map(|u| &u.script_pubkey),
            Some(&spk_a)
        );
        psbt.inputs[0].tap_internal_key = Some(x_b);
        psbt.inputs[0].tap_key_sig = Some(sample_tap_key_sig([45u8; 32], [1u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("tap_internal_key") || msg.contains("p2tr") || msg.contains("match"),
            "{err}"
        );
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "tamper path must not set final witness"
        );
    }

    /// Correct internal key but wrong `tap_merkle_root` → hard error (same tamper check).
    #[test]
    fn finalize_taproot_wrong_merkle_root_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapNodeHash};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[47u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        // Prevout is key-path-only P2TR (merkle = None).
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        // Claim a non-empty merkle root that does not reproduce that spk.
        let wrong_merkle = TapNodeHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        psbt.inputs[0].tap_merkle_root = Some(wrong_merkle);
        psbt.inputs[0].tap_key_sig = Some(sample_tap_key_sig([47u8; 32], [2u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("merkle")
                || msg.contains("tap_internal_key")
                || msg.contains("p2tr")
                || msg.contains("match"),
            "{err}"
        );
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "wrong merkle must not set final witness"
        );
    }

    /// No `tap_internal_key` + present `tap_key_sig` → Complete (tamper check skipped).
    #[test]
    fn finalize_taproot_key_path_without_internal_key_is_complete() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[48u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        // Optional fields absent — finalize must not require them for key-path.
        psbt.inputs[0].tap_internal_key = None;
        psbt.inputs[0].tap_merkle_root = None;
        let sig = sample_tap_key_sig([48u8; 32], [4u8; 32]);
        psbt.inputs[0].tap_key_sig = Some(sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        assert_eq!(fin.finalized_inputs(), 1);
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("key-path final witness without internal key");
        assert_eq!(wit.len(), 1);
        assert_eq!(wit.to_vec()[0], Witness::p2tr_key_spend(&sig).to_vec()[0]);
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    /// Both `tap_key_sig` and script-path maps → prefer key-path Complete (no invent).
    #[test]
    fn finalize_taproot_prefers_key_path_when_both_sig_and_script_maps() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::LeafVersion;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[49u8; 32]).expect("sk");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, parity) = keypair.x_only_public_key();
        let (mut psbt, _) = p2tr_psbt_with_internal(xonly, None);
        let sig = sample_tap_key_sig([49u8; 32], [5u8; 32]);
        psbt.inputs[0].tap_key_sig = Some(sig);

        // Dual material: script-path maps present alongside key-path sig.
        let leaf = ScriptBuf::new();
        let cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: parity,
            internal_key: xonly,
            merkle_branch: Default::default(),
        };
        psbt.inputs[0]
            .tap_scripts
            .insert(cb, (leaf, LeafVersion::TapScript));
        let leaf_hash =
            bitcoin::taproot::TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        psbt.inputs[0].tap_script_sigs.insert(
            (xonly, leaf_hash),
            sample_tap_key_sig([49u8; 32], [6u8; 32]),
        );

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "key-path must win over script-path maps: {fin:?}"
        );
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("key-path final");
        assert_eq!(
            wit.len(),
            1,
            "must assemble key-path only (single element), not script-path stack"
        );
        assert_eq!(wit.to_vec()[0], Witness::p2tr_key_spend(&sig).to_vec()[0]);
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    // --- Taproot multi_a (CHECKSIGADD k-of-n) script-path finalize ---

    /// Build bare multi_a leaf `<pk1> CHECKSIG <pk2> CHECKSIGADD … <k> NUMEQUAL`
    /// under a single-leaf Taproot tree. Returns (psbt, leaf, control_block, keys).
    fn p2tr_multi_a_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sks: &[[u8; 32]],
        threshold: u8,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        assert!(spend_sks.len() >= 2, "multi_a needs n ≥ 2");
        assert!(
            threshold >= 1 && (threshold as usize) <= spend_sks.len(),
            "k in 1..=n"
        );

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let mut keys = Vec::with_capacity(spend_sks.len());
        for sk_bytes in spend_sks {
            let kp =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(sk_bytes).expect("ssk"));
            let (xonly, _) = kp.x_only_public_key();
            keys.push(xonly);
        }

        let mut builder = bitcoin::script::Builder::new()
            .push_x_only_key(&keys[0])
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
        for pk in keys.iter().skip(1) {
            builder = builder
                .push_x_only_key(pk)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD);
        }
        let leaf = builder
            .push_int(i64::from(threshold))
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        let parsed = bare_tapscript_checksigadd_multi_template(&leaf)
            .expect("test leaf must parse as multi_a");
        assert_eq!(parsed.0, threshold as usize);
        assert_eq!(parsed.1, keys);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, keys)
    }

    /// 2-of-2 multi_a with both tap_script_sigs present → Complete.
    #[test]
    fn finalize_taproot_multi_a_2of2_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[80u8; 32], [81u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([79u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [30u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [31u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("multi_a final witness");
        // <sig_key1> <sig_key0> is wrong — reverse key order: sig last key first.
        // Witness: <sig1> <sig0> <script> <control block>
        assert_eq!(wit.len(), 4, "2 sigs + script + control block");
        let items = wit.to_vec();
        assert_eq!(items[0], sig1.to_vec(), "first stack item = last key sig");
        assert_eq!(items[1], sig0.to_vec(), "second stack item = first key sig");
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    /// 2-of-3 multi_a with first two keys signed → Complete (empty for key3).
    #[test]
    fn finalize_taproot_multi_a_2of3_with_first_two_sigs_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[82u8; 32], [83u8; 32], [84u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([78u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [32u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [33u8; 32]);
        // Only keys 0 and 1 — threshold met in script order; key 2 empty.
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // Reverse order: key2 empty, key1 sig, key0 sig, then script, cb.
        assert_eq!(items.len(), 5);
        assert!(
            items[0].is_empty(),
            "unused last key must be empty BIP-342 placeholder"
        );
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// 2-of-3 with only keys 2 and 3 signed (skip first) → Complete with empty for key1.
    #[test]
    fn finalize_taproot_multi_a_2of3_skip_first_key_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[85u8; 32], [86u8; 32], [87u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([77u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig1 = sample_tap_key_sig(sks[1], [34u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [35u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // Reverse: key2 sig, key1 sig, key0 empty.
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], sig2.to_vec());
        assert_eq!(items[1], sig1.to_vec());
        assert!(
            items[2].is_empty(),
            "unsigned first key → empty placeholder"
        );
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
    }

    /// 2-of-3 with all three sigs present → use first 2 in script order; empty last.
    /// (NUMEQUAL requires exact k; cannot include all three non-empty.)
    #[test]
    fn finalize_taproot_multi_a_2of3_extra_sigs_uses_first_k_only() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[88u8; 32], [89u8; 32], [90u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([76u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [36u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [37u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [38u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // First k=2 in script order: keys 0,1 used; key 2 empty even though sig present.
        assert_eq!(items.len(), 5);
        assert!(
            items[0].is_empty(),
            "third key must be empty so NUMEQUAL sees exactly k=2"
        );
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        // Must not include sig2 in the witness (would make count 3 ≠ 2).
        assert_ne!(items[0], sig2.to_vec());
    }

    /// multi_a with insufficient tap_script_sigs → Partial (no invent).
    #[test]
    fn finalize_taproot_multi_a_insufficient_sigs_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[91u8; 32], [92u8; 32], [93u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([75u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        // Only one sig when k=2.
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [39u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("insufficient")
                        || d.contains("multi_a")
                        || d.contains("threshold")
                        || d.contains("tap_script_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent missing multi_a signatures"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// multi_a leaf + bad control block → hard error (tamper), same as bare CHECKSIG.
    #[test]
    fn finalize_taproot_multi_a_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[94u8; 32], [95u8; 32]];
        let (mut psbt, leaf, _good_cb, keys) = p2tr_multi_a_script_path_psbt([74u8; 32], &sks, 2);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[96u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [40u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sample_tap_key_sig(sks[1], [41u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// 1-of-2 multi_a: only second key signed → Complete with empty first-key slot.
    #[test]
    fn finalize_taproot_multi_a_1of2_second_key_only_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[100u8; 32], [101u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([99u8; 32], &sks, 1);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig1 = sample_tap_key_sig(sks[1], [42u8; 32]);
        // Only key1 signed — exercises CHECKSIG-with-empty on first key + k=1.
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // Reverse: key1 sig, key0 empty, script, cb.
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig1.to_vec());
        assert!(
            items[1].is_empty(),
            "unsigned first key must be empty BIP-342 placeholder (CHECKSIG-with-empty)"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// 3-of-3 multi_a: all three keys signed → Complete, no empty slots.
    #[test]
    fn finalize_taproot_multi_a_3of3_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[102u8; 32], [103u8; 32], [104u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([98u8; 32], &sks, 3);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [43u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [44u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [45u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // Reverse: sig2, sig1, sig0, script, cb — no empties for n-of-n.
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], sig2.to_vec());
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert!(!items[0].is_empty() && !items[1].is_empty() && !items[2].is_empty());
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// Multi-leaf: incomplete multi_a skipped; later completeable bare CHECKSIG wins.
    #[test]
    fn finalize_taproot_multi_leaf_incomplete_multi_a_then_bare_checksig() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[105u8; 32]).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let bare_sk = [106u8; 32];
        let bare_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&bare_sk).expect("bsk"));
        let (bare_xonly, _) = bare_kp.x_only_public_key();
        let multi_sks = [[107u8; 32], [108u8; 32]];
        let multi_kp0 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&multi_sks[0]).expect("m0"));
        let multi_kp1 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&multi_sks[1]).expect("m1"));
        let (multi_k0, _) = multi_kp0.x_only_public_key();
        let (multi_k1, _) = multi_kp1.x_only_public_key();

        let bare_leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&bare_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let multi_leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&multi_k0)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&multi_k1)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_checksigadd_multi_template(&multi_leaf).is_some());
        assert!(single_tapscript_checksig_xonly(&bare_leaf).is_some());

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, multi_leaf.clone())
            .expect("multi leaf")
            .add_leaf(1, bare_leaf.clone())
            .expect("bare leaf")
            .finalize(&secp, internal_xonly)
            .expect("tree");
        let cb_multi = spend_info
            .control_block(&(multi_leaf.clone(), LeafVersion::TapScript))
            .expect("cb multi");
        let cb_bare = spend_info
            .control_block(&(bare_leaf.clone(), LeafVersion::TapScript))
            .expect("cb bare");

        let (mut psbt, spk) = p2tr_psbt_with_internal(internal_xonly, spend_info.merkle_root());
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));

        // Incomplete multi_a (no sigs) + completeable bare CHECKSIG.
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_multi.clone(), (multi_leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_bare.clone(), (bare_leaf.clone(), LeafVersion::TapScript));
        let bare_hash = TapLeafHash::from_script(&bare_leaf, LeafVersion::TapScript);
        let bare_sig = sample_tap_key_sig(bare_sk, [46u8; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((bare_xonly, bare_hash), bare_sig);
        // multi_a has zero tap_script_sigs — insufficient.

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "must skip incomplete multi_a and assemble bare CHECKSIG: {fin:?}"
        );
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items.len(), 3, "bare CHECKSIG is <sig> <script> <cb>");
        assert_eq!(items[0], bare_sig.to_vec());
        assert_eq!(items[1], bare_leaf.as_bytes());
        assert_eq!(items[2], cb_bare.serialize());
        let _ = cb_multi; // incomplete path skipped, not used
    }

    /// Key-path preferred when complete multi_a script-path material is also present.
    #[test]
    fn finalize_taproot_prefers_key_path_over_complete_multi_a() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[109u8; 32], [110u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_multi_a_script_path_psbt([111u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [47u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [48u8; 32]);
        // Fully completeable multi_a maps…
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        // …plus key-path sig — key-path must win (single-element witness).
        let key_sig = sample_tap_key_sig([111u8; 32], [49u8; 32]);
        psbt.inputs[0].tap_key_sig = Some(key_sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "key-path must win over complete multi_a: {fin:?}"
        );
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("key-path final");
        assert_eq!(
            wit.len(),
            1,
            "must assemble key-path only (single element), not multi_a stack"
        );
        assert_eq!(
            wit.to_vec()[0],
            Witness::p2tr_key_spend(&key_sig).to_vec()[0]
        );
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    /// Template parser rejects non-multi_a leaves (bare CHECKSIG, empty, junk, edges).
    #[test]
    fn bare_tapscript_checksigadd_multi_template_rejects_non_multi() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[97u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[112u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(
            bare_tapscript_checksigadd_multi_template(&bare).is_none(),
            "single-key CHECKSIG is not multi_a"
        );
        assert!(single_tapscript_checksig_xonly(&bare).is_some());

        assert!(bare_tapscript_checksigadd_multi_template(&ScriptBuf::new()).is_none());

        // CHECKSIG without CHECKSIGADD then NUMEQUAL is not multi_a.
        let one_key_numequal = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_checksigadd_multi_template(&one_key_numequal).is_none());

        // k > n: 2 keys + OP_3 NUMEQUAL.
        let k_gt_n = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(3)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(
            bare_tapscript_checksigadd_multi_template(&k_gt_n).is_none(),
            "k > n must be rejected"
        );

        // Starts with CHECKSIGADD (no leading CHECKSIG).
        let starts_checksigadd = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(
            bare_tapscript_checksigadd_multi_template(&starts_checksigadd).is_none(),
            "must require leading CHECKSIG"
        );

        // Trailing opcode after NUMEQUAL.
        let trailing = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(
            bare_tapscript_checksigadd_multi_template(&trailing).is_none(),
            "trailing ops after NUMEQUAL must be rejected"
        );

        // k encoded as pushbytes (OP_PUSHBYTES_1 0x02) instead of OP_2.
        let pushbytes_k = {
            let base = bitcoin::script::Builder::new()
                .push_x_only_key(&xonly)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .push_x_only_key(&xonly2)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
                .into_script();
            // Append raw OP_PUSHBYTES_1 + 0x02 + OP_NUMEQUAL (non OP_n encoding of k).
            let mut raw = base.into_bytes();
            raw.push(0x01); // OP_PUSHBYTES_1
            raw.push(0x02); // value 2
            raw.push(bitcoin::opcodes::all::OP_NUMEQUAL.to_u8());
            ScriptBuf::from_bytes(raw)
        };
        assert!(
            bare_tapscript_checksigadd_multi_template(&pushbytes_k).is_none(),
            "k must be OP_1..=OP_16, not pushbytes numeric"
        );
    }

    // --- Taproot and_v (CHECKSIGVERIFY chain) + or_i (IF/ELSE) script-path ---

    /// Build bare and_v leaf `(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG` under a
    /// single-leaf Taproot tree. Returns (psbt, leaf, control_block, keys).
    fn p2tr_and_v_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sks: &[[u8; 32]],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        assert!(spend_sks.len() >= 2, "and_v needs n ≥ 2");

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let mut keys = Vec::with_capacity(spend_sks.len());
        for sk_bytes in spend_sks {
            let kp =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(sk_bytes).expect("ssk"));
            let (xonly, _) = kp.x_only_public_key();
            keys.push(xonly);
        }

        // (<pk> CHECKSIGVERIFY)* for all but last, then last <pk> CHECKSIG.
        let mut builder = bitcoin::script::Builder::new();
        for pk in keys.iter().take(keys.len() - 1) {
            builder = builder
                .push_x_only_key(pk)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY);
        }
        let leaf = builder
            .push_x_only_key(keys.last().expect("n≥2"))
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let parsed = bare_tapscript_and_v_checksigverify_template(&leaf)
            .expect("test leaf must parse as and_v");
        assert_eq!(parsed, keys);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, keys)
    }

    /// Build bare or_i leaf `IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF`.
    fn p2tr_or_i_script_path_psbt(
        internal_sk: [u8; 32],
        sk_a: [u8; 32],
        sk_b: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let kp_a = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_a).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_b).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b) =
            bare_tapscript_or_i_checksig_template(&leaf).expect("test leaf must parse as or_i");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, pk_a, pk_b)
    }

    /// and_v 2-of-2 with both tap_script_sigs present → Complete.
    #[test]
    fn finalize_taproot_and_v_2of2_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[120u8; 32], [121u8; 32]];
        let (mut psbt, leaf, control_block, keys) = p2tr_and_v_script_path_psbt([119u8; 32], &sks);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [50u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [51u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let wit = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("and_v final witness");
        // Reverse key order: <sig1> <sig0> <script> <control block>
        assert_eq!(wit.len(), 4, "2 sigs + script + control block");
        let items = wit.to_vec();
        assert_eq!(items[0], sig1.to_vec(), "first stack item = last key sig");
        assert_eq!(items[1], sig0.to_vec(), "second stack item = first key sig");
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    /// and_v 3-of-3 with all three sigs → Complete.
    #[test]
    fn finalize_taproot_and_v_3of3_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[122u8; 32], [123u8; 32], [124u8; 32]];
        let (mut psbt, leaf, control_block, keys) = p2tr_and_v_script_path_psbt([118u8; 32], &sks);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [52u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [53u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [54u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        // Reverse: sig2, sig1, sig0, script, cb — no empties (CHECKSIGVERIFY rejects empty).
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], sig2.to_vec());
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert!(!items[0].is_empty() && !items[1].is_empty() && !items[2].is_empty());
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// and_v with only one of two required sigs → Partial (no invent / no empty placeholders).
    #[test]
    fn finalize_taproot_and_v_insufficient_sigs_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[125u8; 32], [126u8; 32]];
        let (mut psbt, leaf, control_block, keys) = p2tr_and_v_script_path_psbt([117u8; 32], &sks);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Only first key signed — second missing; never invent / never empty-slot.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [55u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("and_v")
                        || d.contains("checksigverify")
                        || d.contains("insufficient")
                        || d.contains("tap_script_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent missing and_v signatures or empty CSV placeholders"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_v leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_and_v_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[127u8; 32], [128u8; 32]];
        let (mut psbt, leaf, _good_cb, keys) = p2tr_and_v_script_path_psbt([116u8; 32], &sks);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[129u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [56u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sample_tap_key_sig(sks[1], [57u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parser rejects non-and_v leaves.
    #[test]
    fn bare_tapscript_and_v_template_rejects_non_and_v() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[130u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[131u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        // Single-key CHECKSIG is not and_v (n ≥ 2 required).
        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_checksigverify_template(&bare).is_none());
        assert!(single_tapscript_checksig_xonly(&bare).is_some());

        // multi_a is not and_v.
        let multi = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_and_v_checksigverify_template(&multi).is_none());
        assert!(bare_tapscript_checksigadd_multi_template(&multi).is_some());

        // Only CHECKSIGVERIFY without trailing CHECKSIG.
        let only_csv = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .into_script();
        assert!(bare_tapscript_and_v_checksigverify_template(&only_csv).is_none());

        // Trailing op after CHECKSIG.
        let trailing = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_and_v_checksigverify_template(&trailing).is_none());

        assert!(bare_tapscript_and_v_checksigverify_template(&ScriptBuf::new()).is_none());
    }

    /// or_i IF branch (A) with matching sig → Complete; witness <sigA> <0x01> <script> <cb>.
    #[test]
    fn finalize_taproot_or_i_if_branch_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [132u8; 32];
        let sk_b = [133u8; 32];
        let (mut psbt, leaf, control_block, pk_a, _pk_b) =
            p2tr_or_i_script_path_psbt([134u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [58u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_i final")
            .to_vec();
        // <sigA> <0x01> <script> <control block>
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_a.to_vec());
        assert_eq!(items[1], vec![1u8], "IF branch selector must be 0x01");
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// or_i ELSE branch (B only) → Complete; witness <sigB> <empty> <script> <cb>.
    #[test]
    fn finalize_taproot_or_i_else_branch_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [135u8; 32];
        let sk_b = [136u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, pk_b) =
            p2tr_or_i_script_path_psbt([137u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_b = sample_tap_key_sig(sk_b, [59u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        // Only B signed — take ELSE branch.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_i final")
            .to_vec();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_b.to_vec());
        assert!(
            items[1].is_empty(),
            "ELSE branch selector must be empty (OP_IF false)"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// or_i both branches signed → prefer IF/A (deterministic).
    #[test]
    fn finalize_taproot_or_i_both_sigs_prefers_if_branch() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [138u8; 32];
        let sk_b = [139u8; 32];
        let (mut psbt, leaf, control_block, pk_a, pk_b) =
            p2tr_or_i_script_path_psbt([140u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [60u8; 32]);
        let sig_b = sample_tap_key_sig(sk_b, [61u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_i final")
            .to_vec();
        assert_eq!(
            items[0],
            sig_a.to_vec(),
            "must prefer IF/A when both present"
        );
        assert_eq!(items[1], vec![1u8]);
        assert_ne!(items[0], sig_b.to_vec());
    }

    /// or_i with neither branch signed → Partial (no invent branch selector alone).
    #[test]
    fn finalize_taproot_or_i_missing_both_sigs_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let (mut psbt, leaf, control_block, _pk_a, _pk_b) =
            p2tr_or_i_script_path_psbt([141u8; 32], [142u8; 32], [143u8; 32]);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("or_i")
                        || d.contains("if")
                        || d.contains("else")
                        || d.contains("missing")
                        || d.contains("tap_script_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent or_i branch selector or signatures"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// or_i leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_or_i_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [144u8; 32];
        let sk_b = [145u8; 32];
        let (mut psbt, leaf, _good_cb, pk_a, _pk_b) =
            p2tr_or_i_script_path_psbt([146u8; 32], sk_a, sk_b);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[147u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [62u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parser rejects non-or_i leaves.
    #[test]
    fn bare_tapscript_or_i_template_rejects_non_or_i() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[148u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[149u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_or_i_checksig_template(&bare).is_none());

        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_or_i_checksig_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&and_v).is_some());

        // Missing ENDIF.
        let no_endif = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_or_i_checksig_template(&no_endif).is_none());

        // Nested / extra ops after ENDIF.
        let trailing = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_or_i_checksig_template(&trailing).is_none());

        assert!(bare_tapscript_or_i_checksig_template(&ScriptBuf::new()).is_none());
    }

    // --- Taproot or_d (IFDUP NOTIF) + and_n (NOTIF 0 ELSE) script-path ---

    /// Build bare or_d leaf `<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF`.
    fn p2tr_or_d_script_path_psbt(
        internal_sk: [u8; 32],
        sk_a: [u8; 32],
        sk_b: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let kp_a = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_a).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_b).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_IFDUP)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b) =
            bare_tapscript_or_d_checksig_template(&leaf).expect("test leaf must parse as or_d");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, pk_a, pk_b)
    }

    /// Build bare and_n leaf `<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF`.
    fn p2tr_and_n_script_path_psbt(
        internal_sk: [u8; 32],
        sk_a: [u8; 32],
        sk_b: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let kp_a = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_a).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_b).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0) // OP_0 / empty push
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b) =
            bare_tapscript_and_n_checksig_template(&leaf).expect("test leaf must parse as and_n");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, pk_a, pk_b)
    }

    /// or_d A branch with matching sig → Complete; witness <sigA> <script> <cb>.
    #[test]
    fn finalize_taproot_or_d_a_branch_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [150u8; 32];
        let sk_b = [151u8; 32];
        let (mut psbt, leaf, control_block, pk_a, _pk_b) =
            p2tr_or_d_script_path_psbt([152u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [63u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_d final")
            .to_vec();
        // <sigA> <script> <control block> — no branch selector (IFDUP path).
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig_a.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// or_d B-only → Complete; witness <sigB> <empty> <script> <cb> (BIP-342 dissat of A).
    #[test]
    fn finalize_taproot_or_d_b_branch_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [153u8; 32];
        let sk_b = [154u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, pk_b) =
            p2tr_or_d_script_path_psbt([155u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_b = sample_tap_key_sig(sk_b, [64u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_d final")
            .to_vec();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_b.to_vec());
        assert!(
            items[1].is_empty(),
            "A dissatisfaction must be empty BIP-342 placeholder, not invented sig"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// or_d both sigs → prefer A (single-element stack, not B+empty).
    #[test]
    fn finalize_taproot_or_d_both_sigs_prefers_a() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [156u8; 32];
        let sk_b = [157u8; 32];
        let (mut psbt, leaf, control_block, pk_a, pk_b) =
            p2tr_or_d_script_path_psbt([158u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [65u8; 32]);
        let sig_b = sample_tap_key_sig(sk_b, [66u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("or_d final")
            .to_vec();
        assert_eq!(items.len(), 3, "A path is single sig + script + cb");
        assert_eq!(items[0], sig_a.to_vec(), "must prefer A when both present");
        assert_ne!(items[0], sig_b.to_vec());
    }

    /// or_d with neither branch signed → Partial (no invent).
    #[test]
    fn finalize_taproot_or_d_missing_both_sigs_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let (mut psbt, leaf, control_block, _pk_a, _pk_b) =
            p2tr_or_d_script_path_psbt([159u8; 32], [160u8; 32], [161u8; 32]);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("or_d")
                        || d.contains("missing")
                        || d.contains("tap_script_sig")
                        || d.contains("branch"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent or_d branch dissatisfaction or signatures"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// or_d leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_or_d_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [162u8; 32];
        let sk_b = [163u8; 32];
        let (mut psbt, leaf, _good_cb, pk_a, _pk_b) =
            p2tr_or_d_script_path_psbt([164u8; 32], sk_a, sk_b);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[165u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [67u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parser rejects non-or_d leaves (incl. bare or_c / or_i).
    #[test]
    fn bare_tapscript_or_d_template_rejects_non_or_d() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[166u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[167u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_or_d_checksig_template(&bare).is_none());

        // Bare or_c (no IFDUP) is NOT or_d — and is not a valid top-level CLEANSTACK leaf.
        let or_c = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(
            bare_tapscript_or_d_checksig_template(&or_c).is_none(),
            "or_c without IFDUP must not parse as or_d"
        );

        // or_i is IF-first, not CHECKSIG-first.
        let or_i = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_or_d_checksig_template(&or_i).is_none());
        assert!(bare_tapscript_or_i_checksig_template(&or_i).is_some());

        // and_n has ELSE 0 branch, not IFDUP.
        let and_n = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_or_d_checksig_template(&and_n).is_none());
        assert!(bare_tapscript_and_n_checksig_template(&and_n).is_some());

        assert!(bare_tapscript_or_d_checksig_template(&ScriptBuf::new()).is_none());
    }

    /// Pure parse: bare or_c template returns `(pk_a, pk_b)`; rejects siblings.
    #[test]
    fn bare_tapscript_or_c_template_parses_and_rejects_siblings() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp_a =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[186u8; 32]).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[187u8; 32]).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();

        // Positive: bare or_c = CHECKSIG NOTIF CHECKSIG ENDIF (no IFDUP).
        let or_c = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b) =
            bare_tapscript_or_c_checksig_template(&or_c).expect("or_c leaf must parse");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);
        // Cross-check: detector is exclusive vs assemblable siblings.
        assert!(bare_tapscript_or_d_checksig_template(&or_c).is_none());
        assert!(bare_tapscript_and_n_checksig_template(&or_c).is_none());
        assert!(bare_tapscript_or_i_checksig_template(&or_c).is_none());
        assert!(bare_tapscript_andor_checksig_template(&or_c).is_none());

        // or_d (IFDUP) is not or_c.
        let or_d = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_IFDUP)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_or_c_checksig_template(&or_d).is_none());
        assert!(bare_tapscript_or_d_checksig_template(&or_d).is_some());

        // and_n (NOTIF 0 ELSE …) is not or_c.
        let and_n = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_or_c_checksig_template(&and_n).is_none());
        assert!(bare_tapscript_and_n_checksig_template(&and_n).is_some());

        // or_i (IF … ELSE … ENDIF) is not or_c.
        let or_i = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_or_c_checksig_template(&or_i).is_none());
        assert!(bare_tapscript_or_i_checksig_template(&or_i).is_some());

        // Single-key CHECKSIG / empty / trailing garbage.
        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_or_c_checksig_template(&bare).is_none());
        assert!(bare_tapscript_or_c_checksig_template(&ScriptBuf::new()).is_none());
        let trailing = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_or_c_checksig_template(&trailing).is_none());
    }

    /// End-to-end: bare or_c leaf with verifying CB + present sigs stays Partial
    /// (not assembled as or_d/and_n; no final witness; extract fails).
    #[test]
    fn finalize_taproot_bare_or_c_with_present_material_stays_partial() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let sk_a = [183u8; 32];
        let sk_b = [184u8; 32];
        let internal_sk = [185u8; 32];
        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let kp_a = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_a).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_b).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();

        // Bare or_c: CHECKSIG NOTIF CHECKSIG ENDIF (no IFDUP) — CLEANSTACK-invalid
        // as top-level; must not match or_d / and_n / or_i assemblers.
        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b) =
            bare_tapscript_or_c_checksig_template(&leaf).expect("or_c must parse as or_c");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);
        assert!(
            bare_tapscript_or_d_checksig_template(&leaf).is_none(),
            "or_c must not parse as or_d"
        );
        assert!(
            bare_tapscript_and_n_checksig_template(&leaf).is_none(),
            "or_c must not parse as and_n"
        );
        assert!(
            bare_tapscript_andor_checksig_template(&leaf).is_none(),
            "or_c must not parse as andor (no ELSE branch)"
        );
        assert!(
            bare_tapscript_or_i_checksig_template(&leaf).is_none(),
            "or_c must not parse as or_i"
        );
        assert!(single_tapscript_checksig_xonly(&leaf).is_none());

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block");
        let (mut psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));

        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Present material for both keys — still must not assemble bare or_c.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [74u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sample_tap_key_sig(sk_b, [75u8; 32]));
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                // Named residual: must mention or_c + CLEANSTACK (honest polish).
                assert!(
                    d.contains("or_c"),
                    "bare or_c residual must name or_c: {detail}"
                );
                assert!(
                    d.contains("cleanstack"),
                    "bare or_c residual must mention CLEANSTACK: {detail}"
                );
                assert!(
                    d.contains("not assembled") || d.contains("not assemble"),
                    "must not claim assembly: {detail}"
                );
                assert!(
                    !d.contains("missing a") && !d.contains("missing b"),
                    "or_c must not be mis-attributed as incomplete and_n: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial for bare or_c, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not assemble final witness for bare or_c leaf"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_n with both sigs → Complete; witness <sigB> <sigA> <script> <cb>.
    #[test]
    fn finalize_taproot_and_n_both_sigs_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [168u8; 32];
        let sk_b = [169u8; 32];
        let (mut psbt, leaf, control_block, pk_a, pk_b) =
            p2tr_and_n_script_path_psbt([170u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [68u8; 32]);
        let sig_b = sample_tap_key_sig(sk_b, [69u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("and_n final")
            .to_vec();
        // <sigB> <sigA> <script> <control block> — A is top-of-stack first.
        assert_eq!(items.len(), 4);
        assert_eq!(
            items[0],
            sig_b.to_vec(),
            "first stack item = B (executed second)"
        );
        assert_eq!(
            items[1],
            sig_a.to_vec(),
            "second stack item = A (executed first)"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    /// and_n missing A only → Partial (never invent B-only / empty A).
    #[test]
    fn finalize_taproot_and_n_missing_a_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [171u8; 32];
        let sk_b = [172u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, pk_b) =
            p2tr_and_n_script_path_psbt([173u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Only B — and_n short-circuits when A is false; never assemble B-only.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sample_tap_key_sig(sk_b, [70u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(d.contains("and_n"), "{detail}");
                assert!(
                    d.contains("missing a"),
                    "residual must name missing A distinctly: {detail}"
                );
                assert!(
                    !d.contains("missing b"),
                    "must not claim missing B when only A is absent: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent empty A dissatisfaction for partial and_n"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_n missing B only → Partial.
    #[test]
    fn finalize_taproot_and_n_missing_b_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [174u8; 32];
        let sk_b = [175u8; 32];
        let (mut psbt, leaf, control_block, pk_a, _pk_b) =
            p2tr_and_n_script_path_psbt([176u8; 32], sk_a, sk_b);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [71u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(d.contains("and_n"), "{detail}");
                assert!(
                    d.contains("missing b"),
                    "residual must name missing B distinctly: {detail}"
                );
                assert!(
                    !d.contains("missing a"),
                    "must not claim missing A when only B is absent: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_n leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_and_n_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [177u8; 32];
        let sk_b = [178u8; 32];
        let (mut psbt, leaf, _good_cb, pk_a, pk_b) =
            p2tr_and_n_script_path_psbt([179u8; 32], sk_a, sk_b);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[180u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [72u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sample_tap_key_sig(sk_b, [73u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parser rejects non-and_n leaves.
    #[test]
    fn bare_tapscript_and_n_template_rejects_non_and_n() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[181u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[182u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_n_checksig_template(&bare).is_none());

        // and_v uses CHECKSIGVERIFY chain, not NOTIF 0.
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_n_checksig_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&and_v).is_some());

        // or_d has IFDUP, not ELSE 0.
        let or_d = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_IFDUP)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_and_n_checksig_template(&or_d).is_none());
        assert!(bare_tapscript_or_d_checksig_template(&or_d).is_some());

        // Missing ELSE / wrong constant.
        let no_else = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_and_n_checksig_template(&no_else).is_none());

        // OP_1 instead of OP_0 in NOTIF branch.
        let wrong_const = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_and_n_checksig_template(&wrong_const).is_none());

        // andor has a third key in the NOTIF branch, not OP_0.
        let kp3 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[186u8; 32]).expect("sk3"));
        let (xonly3, _) = kp3.x_only_public_key();
        let andor = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly3)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(
            bare_tapscript_and_n_checksig_template(&andor).is_none(),
            "andor must not parse as and_n"
        );
        assert!(bare_tapscript_andor_checksig_template(&andor).is_some());

        assert!(bare_tapscript_and_n_checksig_template(&ScriptBuf::new()).is_none());
    }

    // --- Taproot andor (NOTIF C ELSE B) script-path ---

    /// Build bare andor leaf
    /// `<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF`.
    fn p2tr_andor_script_path_psbt(
        internal_sk: [u8; 32],
        sk_a: [u8; 32],
        sk_b: [u8; 32],
        sk_c: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
        bitcoin::secp256k1::XOnlyPublicKey,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let kp_a = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_a).expect("ska"));
        let (pk_a, _) = kp_a.x_only_public_key();
        let kp_b = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_b).expect("skb"));
        let (pk_b, _) = kp_b.x_only_public_key();
        let kp_c = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_c).expect("skc"));
        let (pk_c, _) = kp_c.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_a)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&pk_c)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&pk_b)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        let (parsed_a, parsed_b, parsed_c) =
            bare_tapscript_andor_checksig_template(&leaf).expect("test leaf must parse as andor");
        assert_eq!(parsed_a, pk_a);
        assert_eq!(parsed_b, pk_b);
        assert_eq!(parsed_c, pk_c);
        // Must not be mis-parsed as and_n (OP_0) or or_d (IFDUP).
        assert!(bare_tapscript_and_n_checksig_template(&leaf).is_none());
        assert!(bare_tapscript_or_d_checksig_template(&leaf).is_none());

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, pk_a, pk_b, pk_c)
    }

    /// andor AB path (A+B) → Complete; witness <sigB> <sigA> <script> <cb>.
    #[test]
    fn finalize_taproot_andor_ab_path_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [187u8; 32];
        let sk_b = [188u8; 32];
        let sk_c = [189u8; 32];
        let (mut psbt, leaf, control_block, pk_a, pk_b, _pk_c) =
            p2tr_andor_script_path_psbt([190u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [76u8; 32]);
        let sig_b = sample_tap_key_sig(sk_b, [77u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("andor final")
            .to_vec();
        // <sigB> <sigA> <script> <control block>
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_b.to_vec(), "first stack item = B");
        assert_eq!(
            items[1],
            sig_a.to_vec(),
            "second stack item = A (top first)"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    /// andor C-only → Complete; witness <sigC> <empty> <script> <cb>.
    #[test]
    fn finalize_taproot_andor_c_path_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [191u8; 32];
        let sk_b = [192u8; 32];
        let sk_c = [193u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, _pk_b, pk_c) =
            p2tr_andor_script_path_psbt([194u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_c = sample_tap_key_sig(sk_c, [78u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_c, leaf_hash), sig_c);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("andor final")
            .to_vec();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_c.to_vec());
        assert!(
            items[1].is_empty(),
            "A dissatisfaction must be empty BIP-342 placeholder, not invented sig"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(extract_finalized_tx(psbt).is_ok());
    }

    /// andor all three sigs → prefer AB (not C+empty).
    #[test]
    fn finalize_taproot_andor_all_sigs_prefers_ab() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [195u8; 32];
        let sk_b = [196u8; 32];
        let sk_c = [197u8; 32];
        let (mut psbt, leaf, control_block, pk_a, pk_b, pk_c) =
            p2tr_andor_script_path_psbt([198u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [79u8; 32]);
        let sig_b = sample_tap_key_sig(sk_b, [80u8; 32]);
        let sig_c = sample_tap_key_sig(sk_c, [81u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_c, leaf_hash), sig_c);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("andor final")
            .to_vec();
        assert_eq!(items.len(), 4, "AB path is two sigs + script + cb");
        assert_eq!(items[0], sig_b.to_vec(), "must prefer AB when all present");
        assert_eq!(items[1], sig_a.to_vec());
        assert_ne!(items[0], sig_c.to_vec());
        assert!(!items[1].is_empty(), "AB path must not use empty A dissat");
    }

    /// andor A+C without B → take C path (AB incomplete; never invent B).
    #[test]
    fn finalize_taproot_andor_a_and_c_without_b_takes_c() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [199u8; 32];
        let sk_b = [200u8; 32];
        let sk_c = [201u8; 32];
        let (mut psbt, leaf, control_block, pk_a, _pk_b, pk_c) =
            p2tr_andor_script_path_psbt([202u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_a = sample_tap_key_sig(sk_a, [82u8; 32]);
        let sig_c = sample_tap_key_sig(sk_c, [83u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        // A present but B missing — AB incomplete; C completeable.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sig_a);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_c, leaf_hash), sig_c);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("andor final")
            .to_vec();
        assert_eq!(items[0], sig_c.to_vec(), "must take C when AB incomplete");
        assert!(items[1].is_empty(), "C path uses empty A dissat, not sigA");
        assert_ne!(
            items[0],
            sig_a.to_vec(),
            "must not invent AB with missing B using only A"
        );
    }

    /// andor B+C without A → take C path (AB incomplete; never invent A or AB).
    #[test]
    fn finalize_taproot_andor_b_and_c_without_a_takes_c() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [223u8; 32];
        let sk_b = [224u8; 32];
        let sk_c = [225u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, pk_b, pk_c) =
            p2tr_andor_script_path_psbt([226u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig_b = sample_tap_key_sig(sk_b, [88u8; 32]);
        let sig_c = sample_tap_key_sig(sk_c, [89u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        // B present but A missing — AB incomplete; C completeable.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sig_b);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_c, leaf_hash), sig_c);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("andor final")
            .to_vec();
        // C path: <sigC> <empty> <script> <cb> — never invent A or assemble AB.
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig_c.to_vec(), "must take C when AB incomplete");
        assert!(
            items[1].is_empty(),
            "C path uses empty A dissat, not invented sigA"
        );
        assert_ne!(
            items[0],
            sig_b.to_vec(),
            "must not invent AB with missing A using only B"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
    }

    /// andor A-only (missing B and C) → Partial (never invent B or empty+C).
    #[test]
    fn finalize_taproot_andor_missing_b_and_c_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [203u8; 32];
        let sk_b = [204u8; 32];
        let sk_c = [205u8; 32];
        let (mut psbt, leaf, control_block, pk_a, _pk_b, _pk_c) =
            p2tr_andor_script_path_psbt([206u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [84u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(d.contains("andor"), "{detail}");
                assert!(
                    d.contains("missing b"),
                    "residual must name missing B for AB: {detail}"
                );
                assert!(
                    d.contains("missing c"),
                    "residual must name missing C alt: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent B or empty A + invented C for partial andor"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// andor B-only (missing A and C) → Partial.
    #[test]
    fn finalize_taproot_andor_missing_a_and_c_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [207u8; 32];
        let sk_b = [208u8; 32];
        let sk_c = [209u8; 32];
        let (mut psbt, leaf, control_block, _pk_a, pk_b, _pk_c) =
            p2tr_andor_script_path_psbt([210u8; 32], sk_a, sk_b, sk_c);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sample_tap_key_sig(sk_b, [85u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(d.contains("andor"), "{detail}");
                assert!(
                    d.contains("missing a"),
                    "residual must name missing A for AB: {detail}"
                );
                assert!(
                    d.contains("missing c"),
                    "residual must name missing C alt: {detail}"
                );
                assert!(
                    !d.contains("missing b for"),
                    "must not claim missing B when only A/C absent: {detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// andor with no sigs → Partial.
    #[test]
    fn finalize_taproot_andor_missing_all_sigs_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let (mut psbt, leaf, control_block, _pk_a, _pk_b, _pk_c) =
            p2tr_andor_script_path_psbt([211u8; 32], [212u8; 32], [213u8; 32], [214u8; 32]);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("andor") || d.contains("missing") || d.contains("tap_script_sig"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent andor paths without present sigs"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// andor leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_andor_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sk_a = [215u8; 32];
        let sk_b = [216u8; 32];
        let sk_c = [217u8; 32];
        let (mut psbt, leaf, _good_cb, pk_a, pk_b, _pk_c) =
            p2tr_andor_script_path_psbt([218u8; 32], sk_a, sk_b, sk_c);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[219u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_a, leaf_hash), sample_tap_key_sig(sk_a, [86u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_b, leaf_hash), sample_tap_key_sig(sk_b, [87u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parser rejects non-andor leaves (and_n / multi_a / and_v / or_d / or_c / or_i).
    #[test]
    fn bare_tapscript_andor_template_rejects_non_andor() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[220u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[221u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();
        let kp3 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[222u8; 32]).expect("sk3"));
        let (xonly3, _) = kp3.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&bare).is_none());

        // and_n has OP_0, not a third key.
        let and_n = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&and_n).is_none());
        assert!(bare_tapscript_and_n_checksig_template(&and_n).is_some());

        // multi_a is CHECKSIGADD / NUMEQUAL, not NOTIF/ELSE.
        let multi_a = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&multi_a).is_none());
        assert!(bare_tapscript_checksigadd_multi_template(&multi_a).is_some());

        // and_v is CHECKSIGVERIFY chain, not NOTIF/ELSE.
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&and_v).is_some());

        // or_d has IFDUP.
        let or_d = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_IFDUP)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&or_d).is_none());

        // Bare or_c (no ELSE) is not andor.
        let or_c = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&or_c).is_none());

        // or_i is IF-first.
        let or_i = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&or_i).is_none());

        // Trailing op after ENDIF.
        let trailing = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly3)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_andor_checksig_template(&trailing).is_none());

        assert!(bare_tapscript_andor_checksig_template(&ScriptBuf::new()).is_none());
    }

    // --- Taproot thresh (SWAP CHECKSIG ADD + k EQUAL) script-path ---

    /// Build bare thresh leaf
    /// `<pk1> CHECKSIG (SWAP <pki> CHECKSIG ADD)+ <k> EQUAL`.
    fn p2tr_thresh_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sks: &[[u8; 32]],
        threshold: u8,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        assert!(spend_sks.len() >= 2, "thresh needs n ≥ 2");
        assert!(
            threshold >= 1 && (threshold as usize) <= spend_sks.len(),
            "k must be in 1..=n"
        );

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let mut keys = Vec::with_capacity(spend_sks.len());
        for sk in spend_sks {
            let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(sk).expect("sk"));
            let (xonly, _) = kp.x_only_public_key();
            keys.push(xonly);
        }

        let mut b = bitcoin::script::Builder::new()
            .push_x_only_key(&keys[0])
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
        for pk in &keys[1..] {
            b = b
                .push_opcode(bitcoin::opcodes::all::OP_SWAP)
                .push_x_only_key(pk)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .push_opcode(bitcoin::opcodes::all::OP_ADD);
        }
        let leaf = b
            .push_int(i64::from(threshold))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();

        let (parsed_k, parsed_pks) =
            bare_tapscript_thresh_checksig_template(&leaf).expect("test leaf must parse as thresh");
        assert_eq!(parsed_k, threshold as usize);
        assert_eq!(parsed_pks, keys);
        // Must not be mis-parsed as multi_a (CHECKSIGADD / NUMEQUAL).
        assert!(bare_tapscript_checksigadd_multi_template(&leaf).is_none());

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, keys)
    }

    /// 2-of-2 thresh with both tap_script_sigs → Complete; reverse-key witness.
    #[test]
    fn finalize_taproot_thresh_2of2_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[40u8; 32], [41u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([42u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [10u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [11u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        assert!(psbt.inputs[0].tap_key_sig.is_none());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final witness")
            .to_vec();
        // reverse key order: sig1, sig0, script, control block
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig1.to_vec(), "last key first");
        assert_eq!(items[1], sig0.to_vec(), "first key second");
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let tx = extract_finalized_tx(psbt).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    /// 2-of-3 thresh with first two keys signed → Complete (empty for key3).
    #[test]
    fn finalize_taproot_thresh_2of3_with_first_two_sigs_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[43u8; 32], [44u8; 32], [45u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([46u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [12u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [13u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        // Only keys 0 and 1 — threshold met in script order; key 2 empty.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final")
            .to_vec();
        // reverse: key2 empty, key1 sig, key0 sig, script, cb
        assert_eq!(items.len(), 5);
        assert!(
            items[0].is_empty(),
            "unused last key must be empty BIP-342 placeholder"
        );
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
    }

    /// 2-of-3 thresh skip first key (keys 1+2) → Complete with empty first slot.
    #[test]
    fn finalize_taproot_thresh_2of3_skip_first_key_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[47u8; 32], [48u8; 32], [49u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([50u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig1 = sample_tap_key_sig(sks[1], [14u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [15u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final")
            .to_vec();
        // reverse: key2 sig, key1 sig, key0 empty
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], sig2.to_vec());
        assert_eq!(items[1], sig1.to_vec());
        assert!(
            items[2].is_empty(),
            "unsigned first key → empty placeholder"
        );
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
    }

    /// 2-of-3 with all three sigs → use first k only; last key empty placeholder.
    #[test]
    fn finalize_taproot_thresh_2of3_extra_sigs_uses_first_k_only() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[51u8; 32], [52u8; 32], [53u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([54u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [16u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [17u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [18u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final")
            .to_vec();
        // first k in script order = keys 0,1; key 2 gets empty even though sig present
        assert_eq!(items.len(), 5);
        assert!(
            items[0].is_empty(),
            "past-threshold key3 must be empty placeholder (not use extra sig)"
        );
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert_ne!(items[0], sig2.to_vec());
    }

    /// 1-of-2 thresh: only second key signed → Complete with empty first slot.
    #[test]
    fn finalize_taproot_thresh_1of2_second_key_only_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[55u8; 32], [56u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([57u8; 32], &sks, 1);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig1 = sample_tap_key_sig(sks[1], [19u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final")
            .to_vec();
        // reverse: key1 sig, key0 empty
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], sig1.to_vec());
        assert!(
            items[1].is_empty(),
            "unsigned first key must be empty BIP-342 placeholder"
        );
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
    }

    /// 3-of-3 thresh: all three keys signed → Complete, no empty slots.
    #[test]
    fn finalize_taproot_thresh_3of3_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[58u8; 32], [59u8; 32], [60u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([61u8; 32], &sks, 3);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sig0 = sample_tap_key_sig(sks[0], [20u8; 32]);
        let sig1 = sample_tap_key_sig(sks[1], [21u8; 32]);
        let sig2 = sample_tap_key_sig(sks[2], [22u8; 32]);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sig0);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sig1);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[2], leaf_hash), sig2);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("thresh final")
            .to_vec();
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], sig2.to_vec());
        assert_eq!(items[1], sig1.to_vec());
        assert_eq!(items[2], sig0.to_vec());
        assert!(!items[0].is_empty() && !items[1].is_empty() && !items[2].is_empty());
        assert_eq!(items[3], leaf.as_bytes());
        assert_eq!(items[4], control_block.serialize());
    }

    /// thresh with insufficient tap_script_sigs → Partial (no invent).
    #[test]
    fn finalize_taproot_thresh_insufficient_sigs_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[62u8; 32], [63u8; 32], [64u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([65u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Only one of two required.
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [23u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("thresh") || d.contains("threshold") || d.contains("insufficient"),
                    "{detail}"
                );
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent missing thresh signatures"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// thresh with no sigs → Partial.
    #[test]
    fn finalize_taproot_thresh_missing_all_sigs_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let sks = [[66u8; 32], [67u8; 32]];
        let (mut psbt, leaf, control_block, _keys) =
            p2tr_thresh_script_path_psbt([68u8; 32], &sks, 2);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(
                    d.contains("thresh") || d.contains("threshold") || d.contains("insufficient"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// thresh leaf + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_thresh_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[69u8; 32], [70u8; 32]];
        let (mut psbt, leaf, _good_cb, keys) = p2tr_thresh_script_path_psbt([71u8; 32], &sks, 2);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[72u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [24u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sample_tap_key_sig(sks[1], [25u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Multi-leaf: incomplete thresh skipped; later completeable bare CHECKSIG wins.
    #[test]
    fn finalize_taproot_multi_leaf_incomplete_thresh_then_bare_checksig() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[73u8; 32]).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let sk_bare = [74u8; 32];
        let sk_t0 = [75u8; 32];
        let sk_t1 = [76u8; 32];
        let kp_bare =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_bare).expect("skb"));
        let (pk_bare, _) = kp_bare.x_only_public_key();
        let kp_t0 = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_t0).expect("sk0"));
        let (pk_t0, _) = kp_t0.x_only_public_key();
        let kp_t1 = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_t1).expect("sk1"));
        let (pk_t1, _) = kp_t1.x_only_public_key();

        let thresh_leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_t0)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_SWAP)
            .push_x_only_key(&pk_t1)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&thresh_leaf).is_some());

        let bare_leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_bare)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, thresh_leaf.clone())
            .expect("thresh leaf")
            .add_leaf(1, bare_leaf.clone())
            .expect("bare leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let cb_thresh = spend_info
            .control_block(&(thresh_leaf.clone(), LeafVersion::TapScript))
            .expect("cb thresh");
        let cb_bare = spend_info
            .control_block(&(bare_leaf.clone(), LeafVersion::TapScript))
            .expect("cb bare");
        let (mut psbt, _spk) = p2tr_psbt_with_internal(internal_xonly, merkle);

        // Incomplete thresh (no sigs) + completeable bare CHECKSIG.
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_thresh, (thresh_leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_bare.clone(), (bare_leaf.clone(), LeafVersion::TapScript));
        let bare_hash = TapLeafHash::from_script(&bare_leaf, LeafVersion::TapScript);
        let sig_bare = sample_tap_key_sig(sk_bare, [26u8; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_bare, bare_hash), sig_bare);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "must skip incomplete thresh and assemble bare CHECKSIG: {fin:?}"
        );
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("bare final")
            .to_vec();
        assert_eq!(items[0], sig_bare.to_vec());
        assert_eq!(items[1], bare_leaf.as_bytes());
        assert_eq!(items[2], cb_bare.serialize());
    }

    /// Key-path preferred when complete thresh script-path material is also present.
    #[test]
    fn finalize_taproot_prefers_key_path_over_complete_thresh() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let sks = [[77u8; 32], [78u8; 32]];
        let (mut psbt, leaf, control_block, keys) =
            p2tr_thresh_script_path_psbt([79u8; 32], &sks, 2);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[0], leaf_hash), sample_tap_key_sig(sks[0], [27u8; 32]));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((keys[1], leaf_hash), sample_tap_key_sig(sks[1], [28u8; 32]));
        let key_sig = sample_tap_key_sig([80u8; 32], [29u8; 32]);
        psbt.inputs[0].tap_key_sig = Some(key_sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("key-path final")
            .to_vec();
        // Key-path: single sig element only.
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], key_sig.to_vec());
    }

    /// Template parser rejects multi_a / and_v / or_* / andor / bare / no-SWAP.
    #[test]
    fn bare_tapscript_thresh_template_rejects_non_thresh() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[81u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[82u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();
        let kp3 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[83u8; 32]).expect("sk3"));
        let (xonly3, _) = kp3.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&bare).is_none());

        // multi_a: CHECKSIGADD / NUMEQUAL — not SWAP/ADD/EQUAL.
        let multi_a = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&multi_a).is_none());
        assert!(bare_tapscript_checksigadd_multi_template(&multi_a).is_some());

        // Broken thresh without SWAP (would not type-check in miniscript).
        let no_swap = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&no_swap).is_none());

        // multi_a-shaped with EQUAL instead of NUMEQUAL still not thresh (no SWAP).
        let multi_a_equal = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&multi_a_equal).is_none());

        // and_v
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&and_v).is_none());

        // or_i
        let or_i = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&or_i).is_none());

        // or_d
        let or_d = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_IFDUP)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&or_d).is_none());

        // and_n
        let and_n = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&and_n).is_none());

        // andor
        let andor = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_NOTIF)
            .push_x_only_key(&xonly3)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&andor).is_none());

        // NUMEQUAL instead of EQUAL (would be wrong for thresh).
        let numequal = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_SWAP)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(2)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&numequal).is_none());

        // Trailing op.
        let trailing = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_SWAP)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&trailing).is_none());

        // k > n
        let k_gt_n = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_SWAP)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(3)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_thresh_checksig_template(&k_gt_n).is_none());

        assert!(bare_tapscript_thresh_checksig_template(&ScriptBuf::new()).is_none());
    }

    // --- Taproot bare hash / and_v(v:pk, hash) script-path finalize ---

    /// Build bare miniscript hash leaf under a single-leaf Taproot tree.
    fn p2tr_hash_script_path_psbt(
        internal_sk: [u8; 32],
        kind: TapscriptHashKind,
        digest: &[u8],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let hash_op = match kind {
            TapscriptHashKind::Sha256 => bitcoin::opcodes::all::OP_SHA256,
            TapscriptHashKind::Hash256 => bitcoin::opcodes::all::OP_HASH256,
            TapscriptHashKind::Ripemd160 => bitcoin::opcodes::all::OP_RIPEMD160,
            TapscriptHashKind::Hash160 => bitcoin::opcodes::all::OP_HASH160,
        };
        let leaf = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(hash_op)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest).expect("digest pushable"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let parsed = bare_tapscript_hash_preimage_template(&leaf).expect("test leaf is bare hash");
        assert_eq!(parsed.0, kind);
        assert_eq!(parsed.1, digest);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block)
    }

    /// Build and_v(v:pk, hash) leaf under a single-leaf Taproot tree.
    fn p2tr_and_v_pk_hash_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
        kind: TapscriptHashKind,
        digest: &[u8],
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let hash_op = match kind {
            TapscriptHashKind::Sha256 => bitcoin::opcodes::all::OP_SHA256,
            TapscriptHashKind::Hash256 => bitcoin::opcodes::all::OP_HASH256,
            TapscriptHashKind::Ripemd160 => bitcoin::opcodes::all::OP_RIPEMD160,
            TapscriptHashKind::Hash160 => bitcoin::opcodes::all::OP_HASH160,
        };
        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(hash_op)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest).expect("digest pushable"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let parsed =
            bare_tapscript_and_v_pk_hash_template(&leaf).expect("test leaf is and_v(v:pk, hash)");
        assert_eq!(parsed.0, spend_xonly);
        assert_eq!(parsed.1, kind);
        assert_eq!(parsed.2, digest);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, spend_xonly)
    }

    fn sample_sha256_preimage_and_digest(seed: u8) -> ([u8; 32], [u8; 32]) {
        use bitcoin::hashes::{Hash, sha256};
        let mut preimage = [0u8; 32];
        preimage.fill(seed);
        preimage[0] = seed.wrapping_add(1);
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        (preimage, digest)
    }

    fn sample_hash160_preimage_and_digest(seed: u8) -> ([u8; 32], [u8; 20]) {
        use bitcoin::hashes::{Hash, hash160};
        let mut preimage = [0u8; 32];
        preimage.fill(seed);
        preimage[0] = seed.wrapping_add(2);
        let digest = hash160::Hash::hash(&preimage).to_byte_array();
        (preimage, digest)
    }

    /// bare sha256 with matching PSBT preimage → Complete.
    #[test]
    fn finalize_taproot_bare_sha256_with_preimage_is_complete() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::LeafVersion;

        let (preimage, digest) = sample_sha256_preimage_and_digest(90);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([91u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("hash final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], preimage.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        assert!(psbt_is_broadcast_ready(&psbt));
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// bare hash160 with matching PSBT preimage → Complete (SIZE still 32).
    #[test]
    fn finalize_taproot_bare_hash160_with_preimage_is_complete() {
        use bitcoin::hashes::{Hash, hash160};
        use bitcoin::taproot::LeafVersion;

        let (preimage, digest) = sample_hash160_preimage_and_digest(92);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([93u8; 32], TapscriptHashKind::Hash160, &digest);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .hash160_preimages
            .insert(hash160::Hash::from_byte_array(digest), preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("hash160 final")
            .to_vec();
        assert_eq!(items[0], preimage.to_vec());
        assert_eq!(items[0].len(), 32, "miniscript preimage is always 32 bytes");
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
    }

    /// bare hash256 with matching PSBT preimage → Complete.
    #[test]
    fn finalize_taproot_bare_hash256_with_preimage_is_complete() {
        use bitcoin::hashes::{Hash, sha256d};
        use bitcoin::taproot::LeafVersion;

        let mut preimage = [0u8; 32];
        preimage.fill(94);
        let digest = sha256d::Hash::hash(&preimage).to_byte_array();
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([95u8; 32], TapscriptHashKind::Hash256, &digest);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .hash256_preimages
            .insert(sha256d::Hash::from_byte_array(digest), preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("hash256 final")
            .to_vec();
        assert_eq!(items[0], preimage.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
    }

    /// bare ripemd160 with matching PSBT preimage → Complete.
    #[test]
    fn finalize_taproot_bare_ripemd160_with_preimage_is_complete() {
        use bitcoin::hashes::{Hash, ripemd160};
        use bitcoin::taproot::LeafVersion;

        let mut preimage = [0u8; 32];
        preimage.fill(96);
        let digest = ripemd160::Hash::hash(&preimage).to_byte_array();
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([97u8; 32], TapscriptHashKind::Ripemd160, &digest);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0]
            .ripemd160_preimages
            .insert(ripemd160::Hash::from_byte_array(digest), preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("ripemd160 final")
            .to_vec();
        assert_eq!(items[0], preimage.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
    }

    /// bare hash without preimage → Partial (never invent).
    #[test]
    fn finalize_taproot_bare_hash_missing_preimage_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let (_preimage, digest) = sample_sha256_preimage_and_digest(98);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([99u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].sha256_preimages.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("script-path"), "{detail}");
                assert!(d.contains("preimage") || d.contains("hash"), "{detail}");
                assert!(d.contains("not broadcast-ready"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(
            psbt.inputs[0].final_script_witness.is_none(),
            "must not invent missing preimage"
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Wrong-map preimage (e.g. hash160 map for sha256 leaf) → Partial.
    #[test]
    fn finalize_taproot_bare_hash_wrong_map_is_partial() {
        use bitcoin::hashes::{Hash, hash160};
        use bitcoin::taproot::LeafVersion;

        let (preimage, digest) = sample_sha256_preimage_and_digest(100);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([101u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Preimage lives only in the wrong map — sha256 leaf must not use it.
        let wrong_key = hash160::Hash::hash(&preimage);
        psbt.inputs[0]
            .hash160_preimages
            .insert(wrong_key, preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Preimage present under wrong digest key that doesn't match leaf → not found → Partial.
    #[test]
    fn finalize_taproot_bare_hash_unrelated_preimage_key_is_partial() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::LeafVersion;

        let (_preimage, digest) = sample_sha256_preimage_and_digest(102);
        let (other_pre, _) = sample_sha256_preimage_and_digest(103);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([104u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Different hash key (honestly keyed to other_pre) — leaf digest not covered.
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::hash(&other_pre), other_pre.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                assert!(
                    detail.to_ascii_lowercase().contains("preimage")
                        || detail.to_ascii_lowercase().contains("hash"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Corrupt map: key is leaf digest but value does not hash to it → hard error.
    #[test]
    fn finalize_taproot_bare_hash_corrupt_preimage_is_hard_error() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::LeafVersion;

        let (_preimage, digest) = sample_sha256_preimage_and_digest(105);
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([106u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // Map key claims digest, but value is garbage that does not hash to it.
        let garbage = vec![7u8; 32];
        assert_ne!(sha256::Hash::hash(&garbage).to_byte_array(), digest);
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), garbage);

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("preimage")
                || msg.contains("hash")
                || msg.contains("tamper")
                || msg.contains("corrupt"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Non-32-byte preimage under correct key → hard error (miniscript SIZE).
    #[test]
    fn finalize_taproot_bare_hash_wrong_length_preimage_is_hard_error() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::LeafVersion;

        // Craft a digest for a non-32 preimage, then put that short value in the map.
        // (BIP-174 allows arbitrary preimage lengths; miniscript SIZE rejects ≠32.)
        let short = b"too-short-preimage-not-32".to_vec();
        assert_ne!(short.len(), 32);
        let digest = sha256::Hash::hash(&short).to_byte_array();
        let (mut psbt, leaf, control_block) =
            p2tr_hash_script_path_psbt([107u8; 32], TapscriptHashKind::Sha256, &digest);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), short);

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("32") || msg.contains("length") || msg.contains("preimage"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// bare hash + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_bare_hash_bad_control_block_is_hard_error() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::LeafVersion;

        let (preimage, digest) = sample_sha256_preimage_and_digest(108);
        let (mut psbt, leaf, _good_cb) =
            p2tr_hash_script_path_psbt([109u8; 32], TapscriptHashKind::Sha256, &digest);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[110u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), preimage.to_vec());

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// and_v(v:pk, sha256) with both sig + preimage → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_sha256_is_complete() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [111u8; 32];
        let (preimage, digest) = sample_sha256_preimage_and_digest(112);
        let (mut psbt, leaf, control_block, pk) = p2tr_and_v_pk_hash_script_path_psbt(
            [113u8; 32],
            spend_sk,
            TapscriptHashKind::Sha256,
            &digest,
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [114u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), preimage.to_vec());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("and_v pk+hash final")
            .to_vec();
        // <preimage> <sig> <script> <cb>
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], preimage.to_vec());
        assert_eq!(items[1], sig.to_vec());
        assert_eq!(items[2], leaf.as_bytes());
        assert_eq!(items[3], control_block.serialize());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// and_v(v:pk, hash) missing sig → Partial (preimage alone insufficient).
    #[test]
    fn finalize_taproot_and_v_pk_hash_missing_sig_is_partial() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::taproot::LeafVersion;

        let (preimage, digest) = sample_sha256_preimage_and_digest(115);
        let (mut psbt, leaf, control_block, _pk) = p2tr_and_v_pk_hash_script_path_psbt(
            [116u8; 32],
            [117u8; 32],
            TapscriptHashKind::Sha256,
            &digest,
        );
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), preimage.to_vec());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("and_v") || d.contains("missing") || d.contains("tap_script"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_v(v:pk, hash) missing preimage → Partial (sig alone insufficient).
    #[test]
    fn finalize_taproot_and_v_pk_hash_missing_preimage_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [118u8; 32];
        let (_preimage, digest) = sample_sha256_preimage_and_digest(119);
        let (mut psbt, leaf, control_block, pk) = p2tr_and_v_pk_hash_script_path_psbt(
            [120u8; 32],
            spend_sk,
            TapscriptHashKind::Sha256,
            &digest,
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [121u8; 32]));
        assert!(psbt.inputs[0].sha256_preimages.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("preimage") || d.contains("hash"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_v(v:pk, hash) + bad control block → hard error.
    #[test]
    fn finalize_taproot_and_v_pk_hash_bad_control_block_is_hard_error() {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [122u8; 32];
        let (preimage, digest) = sample_sha256_preimage_and_digest(123);
        let (mut psbt, leaf, _good_cb, pk) = p2tr_and_v_pk_hash_script_path_psbt(
            [124u8; 32],
            spend_sk,
            TapscriptHashKind::Sha256,
            &digest,
        );
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[125u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [126u8; 32]));
        psbt.inputs[0]
            .sha256_preimages
            .insert(sha256::Hash::from_byte_array(digest), preimage.to_vec());

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Multi-leaf: incomplete hash skipped; later completeable bare CHECKSIG wins.
    #[test]
    fn finalize_taproot_multi_leaf_incomplete_hash_then_bare_checksig() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[127u8; 32]).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let sk_bare = [128u8; 32];
        let kp_bare =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk_bare).expect("skb"));
        let (pk_bare, _) = kp_bare.x_only_public_key();

        let (_pre, digest) = sample_sha256_preimage_and_digest(129);
        let hash_leaf = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest.as_slice()).expect("digest"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&hash_leaf).is_some());

        let bare_leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&pk_bare)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, hash_leaf.clone())
            .expect("hash leaf")
            .add_leaf(1, bare_leaf.clone())
            .expect("bare leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let cb_hash = spend_info
            .control_block(&(hash_leaf.clone(), LeafVersion::TapScript))
            .expect("cb hash");
        let cb_bare = spend_info
            .control_block(&(bare_leaf.clone(), LeafVersion::TapScript))
            .expect("cb bare");
        let (mut psbt, _spk) = p2tr_psbt_with_internal(internal_xonly, merkle);

        // Incomplete hash (no preimage) + completeable bare CHECKSIG.
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_hash, (hash_leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_scripts
            .insert(cb_bare.clone(), (bare_leaf.clone(), LeafVersion::TapScript));
        let bare_hash = TapLeafHash::from_script(&bare_leaf, LeafVersion::TapScript);
        let sig_bare = sample_tap_key_sig(sk_bare, [130u8; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk_bare, bare_hash), sig_bare);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "must skip incomplete hash and assemble bare CHECKSIG: {fin:?}"
        );
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("bare final")
            .to_vec();
        assert_eq!(items[0], sig_bare.to_vec());
        assert_eq!(items[1], bare_leaf.as_bytes());
        assert_eq!(items[2], cb_bare.serialize());
    }

    /// Template parsers reject sibling scripts (no false positives).
    #[test]
    fn bare_tapscript_hash_templates_reject_non_hash() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[131u8; 32]).expect("sk"));
        let (xonly, _) = kp.x_only_public_key();
        let kp2 =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[132u8; 32]).expect("sk2"));
        let (xonly2, _) = kp2.x_only_public_key();

        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&bare).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&bare).is_none());

        // and_v CHECKSIGVERIFY chain (two pks) is not hash.
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&and_v).is_some());

        // SIZE without EQUALVERIFY / wrong size push.
        let bad_size = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(20)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(&[0u8; 32])
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&bad_size).is_none());

        // SHA256 without SIZE prefix (non-miniscript).
        let no_size = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(&[0u8; 32])
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&no_size).is_none());

        // or_i not hash.
        let or_i = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_IF)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ELSE)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&or_i).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&or_i).is_none());

        // Bare hash is not and_v(v:pk, hash).
        let (_p, digest) = sample_sha256_preimage_and_digest(133);
        let bare_hash = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest.as_slice()).expect("d"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&bare_hash).is_some());
        assert!(bare_tapscript_and_v_pk_hash_template(&bare_hash).is_none());

        // and_v(v:pk, hash) is not bare hash / not and_v checksig chain.
        let and_v_pk_hash = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest.as_slice()).expect("d2"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_and_v_pk_hash_template(&and_v_pk_hash).is_some());
        assert!(bare_tapscript_hash_preimage_template(&and_v_pk_hash).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&and_v_pk_hash).is_none());

        // Trailing op rejects.
        let trailing = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(digest.as_slice()).expect("d3"))
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .into_script();
        assert!(bare_tapscript_hash_preimage_template(&trailing).is_none());

        assert!(bare_tapscript_hash_preimage_template(&ScriptBuf::new()).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&ScriptBuf::new()).is_none());
    }

    // --- Taproot older / CSV script-path finalize ---

    /// Build `and_v(v:pk, older(n))` leaf under a single-leaf Taproot tree.
    fn p2tr_and_v_pk_older_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
        older_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(i64::from(older_n))
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        let parsed =
            bare_tapscript_and_v_pk_older_template(&leaf).expect("test leaf is and_v(v:pk, older)");
        assert_eq!(parsed.0, spend_xonly);
        assert_eq!(parsed.1, older_n);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, spend_xonly)
    }

    /// Build `and_v(v:older(n), pk)` leaf under a single-leaf Taproot tree.
    fn p2tr_and_v_older_pk_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
        older_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_int(i64::from(older_n))
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let parsed =
            bare_tapscript_and_v_older_pk_template(&leaf).expect("test leaf is and_v(v:older, pk)");
        assert_eq!(parsed.0, older_n);
        assert_eq!(parsed.1, spend_xonly);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        (psbt, leaf, control_block, spend_xonly)
    }

    /// Build bare `older(n)` leaf under a single-leaf Taproot tree.
    fn p2tr_bare_older_script_path_psbt(
        internal_sk: [u8; 32],
        older_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_int(i64::from(older_n))
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        assert_eq!(
            bare_tapscript_older_template(&leaf).expect("test leaf is bare older"),
            older_n
        );

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        (psbt, leaf, control_block)
    }

    /// and_v(v:pk, older) with matching sig + satisfying nSequence → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_older_with_sequence_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [120u8; 32];
        let older_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([121u8; 32], spend_sk, older_n);
        // Present nSequence that satisfies older(9) — never invented by finalize.
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(9);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [122u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("older final")
            .to_vec();
        // <sigA> <script> <cb>
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        // Sequence must be unchanged (never invented / mutated).
        assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence::from_height(9));
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// Larger older(n) via push_int (not OP_1..16) with sequence ≥ n → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_older_large_n_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [123u8; 32];
        let older_n = 144u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([124u8; 32], spend_sk, older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(200);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [125u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// and_v(v:older, pk) with matching sig + satisfying nSequence → Complete.
    #[test]
    fn finalize_taproot_and_v_older_pk_with_sequence_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [126u8; 32];
        let older_n = 16u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_older_pk_script_path_psbt([127u8; 32], spend_sk, older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(16);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [128u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// bare older(n) with satisfying nSequence → Complete (empty script inputs).
    #[test]
    fn finalize_taproot_bare_older_with_sequence_is_complete() {
        use bitcoin::taproot::LeafVersion;

        let older_n = 10u32;
        let (mut psbt, leaf, control_block) =
            p2tr_bare_older_script_path_psbt([129u8; 32], older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(10);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("bare older final")
            .to_vec();
        // Empty script inputs: <script> <cb> only.
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], leaf.as_bytes());
        assert_eq!(items[1], control_block.serialize());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// and_v(v:pk, older) missing sig → Partial (never invent sig; sequence alone insufficient).
    #[test]
    fn finalize_taproot_and_v_pk_older_missing_sig_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let older_n = 9u32;
        let (mut psbt, leaf, control_block, _pk) =
            p2tr_and_v_pk_older_script_path_psbt([130u8; 32], [131u8; 32], older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(9);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("missing") || d.contains("tap_script_sig") || d.contains("older"),
                    "{detail}"
                );
                // Must not mis-attribute as sequence failure when sig is the gap.
                assert!(!d.contains("nsequence does not satisfy"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_v(v:pk, older) with sig but RBF-disabled-relative sequence → Partial
    /// (never invents nSequence).
    #[test]
    fn finalize_taproot_and_v_pk_older_disabled_sequence_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [132u8; 32];
        let older_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([133u8; 32], spend_sk, older_n);
        // Default ENABLE_RBF_NO_LOCKTIME has relative locktime disable flag set.
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [134u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("nsequence") || d.contains("csv") || d.contains("older"),
                    "{detail}"
                );
                assert!(
                    d.contains("not satisfy") || d.contains("relative"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not mutate sequence to make CSV pass.
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// Sequence height below required older(n) → Partial.
    #[test]
    fn finalize_taproot_and_v_pk_older_sequence_below_required_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [135u8; 32];
        let older_n = 100u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([136u8; 32], spend_sk, older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(50); // < 100
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [137u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(d.contains("nsequence") || d.contains("csv"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::from_height(50)
        );
    }

    /// Height vs time type mismatch → Partial (sequence present but wrong type).
    #[test]
    fn finalize_taproot_and_v_pk_older_type_mismatch_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [138u8; 32];
        // Height-based older(9).
        let older_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([139u8; 32], spend_sk, older_n);
        // Time-based sequence — type mismatch with height older.
        let time_seq = Sequence::from_512_second_intervals(9);
        psbt.unsigned_tx.input[0].sequence = time_seq;
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [140u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("nsequence") || d.contains("csv") || d.contains("older"),
                    "{detail}"
                );
                assert!(
                    d.contains("not satisfy") || d.contains("relative"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not invent/mutate nSequence to a height-based value.
        assert_eq!(psbt.unsigned_tx.input[0].sequence, time_seq);
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// and_v(v:older, pk) missing sig → Partial (sig-before-sequence residual naming).
    #[test]
    fn finalize_taproot_and_v_older_pk_missing_sig_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let older_n = 16u32;
        let (mut psbt, leaf, control_block, _pk) =
            p2tr_and_v_older_pk_script_path_psbt([150u8; 32], [151u8; 32], older_n);
        // Satisfying nSequence alone is insufficient — must not invent sig.
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(16);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("missing") || d.contains("tap_script_sig") || d.contains("older"),
                    "{detail}"
                );
                // Must not mis-attribute as sequence failure when sig is the gap.
                assert!(!d.contains("nsequence does not satisfy"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::from_height(16)
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// bare older with RBF-disabled-relative sequence → Partial (never invents nSequence).
    #[test]
    fn finalize_taproot_bare_older_disabled_sequence_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let older_n = 10u32;
        let (mut psbt, leaf, control_block) =
            p2tr_bare_older_script_path_psbt([152u8; 32], older_n);
        // Default ENABLE_RBF_NO_LOCKTIME has relative locktime disable flag set.
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete() && !fin.is_broadcast_ready(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("nsequence") || d.contains("csv") || d.contains("older"),
                    "{detail}"
                );
                assert!(
                    d.contains("not satisfy") || d.contains("relative"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not mutate sequence to make CSV pass.
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        assert!(extract_finalized_tx(psbt).is_err());
    }

    /// tx version < 2 → Partial (BIP-112 requires version ≥ 2 for relative CSV).
    #[test]
    fn finalize_taproot_and_v_pk_older_tx_version_one_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [141u8; 32];
        let older_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_older_script_path_psbt([142u8; 32], spend_sk, older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(9);
        psbt.unsigned_tx.version = transaction::Version::ONE;
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [143u8; 32]));

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(!fin.is_complete(), "{fin:?}");
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_ascii_lowercase();
                assert!(
                    d.contains("nsequence") || d.contains("csv") || d.contains("older"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not bump version to make CSV pass.
        assert_eq!(psbt.unsigned_tx.version, transaction::Version::ONE);
    }

    /// and_v(v:pk, older) + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_and_v_pk_older_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [144u8; 32];
        let older_n = 9u32;
        let (mut psbt, leaf, _good_cb, pk) =
            p2tr_and_v_pk_older_script_path_psbt([145u8; 32], spend_sk, older_n);
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(9);
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[146u8; 32]).expect("wsk"));
        let (wrong_internal, wrong_parity) = wrong_kp.x_only_public_key();
        let bad_cb = bitcoin::taproot::ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: wrong_parity,
            internal_key: wrong_internal,
            merkle_branch: Default::default(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, leaf_hash), sample_tap_key_sig(spend_sk, [147u8; 32]));

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("control block")
                || msg.contains("verify")
                || msg.contains("tamper")
                || msg.contains("commit"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template parsers reject sibling false positives (and_v chain, hash, or_d, bare CHECKSIG).
    #[test]
    fn bare_tapscript_older_templates_reject_siblings() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[148u8; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();
        let kp2 = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[149u8; 32]).unwrap());
        let (xonly2, _) = kp2.x_only_public_key();

        // Bare CHECKSIG is not older.
        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_pk_older_template(&bare).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&bare).is_none());
        assert!(bare_tapscript_older_template(&bare).is_none());

        // and_v dual CHECKSIGVERIFY chain is not older.
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly2)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_pk_older_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&and_v).is_none());
        assert!(bare_tapscript_older_template(&and_v).is_none());

        // and_v(v:pk, hash) is not older.
        let digest = [0xabu8; 32];
        let pk_hash = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_SHA256)
            .push_slice(
                <&bitcoin::script::PushBytes>::try_from(digest.as_slice())
                    .expect("digest pushable"),
            )
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        assert!(bare_tapscript_and_v_pk_older_template(&pk_hash).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&pk_hash).is_none());
        assert!(bare_tapscript_older_template(&pk_hash).is_none());

        // and_v(v:pk, older) must not parse as bare older or and_v(v:older, pk).
        let pk_older = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        assert!(bare_tapscript_and_v_pk_older_template(&pk_older).is_some());
        assert!(bare_tapscript_and_v_older_pk_template(&pk_older).is_none());
        assert!(bare_tapscript_older_template(&pk_older).is_none());
        // Sibling and_v chain / hash templates must not claim it either.
        assert!(bare_tapscript_and_v_checksigverify_template(&pk_older).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&pk_older).is_none());

        // and_v(v:older, pk) must not parse as bare older or and_v(v:pk, older).
        let older_pk = bitcoin::script::Builder::new()
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_older_pk_template(&older_pk).is_some());
        assert!(bare_tapscript_and_v_pk_older_template(&older_pk).is_none());
        assert!(bare_tapscript_older_template(&older_pk).is_none());

        // bare older is not and_v forms.
        let bare_older = bitcoin::script::Builder::new()
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        assert!(bare_tapscript_older_template(&bare_older).is_some());
        assert!(bare_tapscript_and_v_pk_older_template(&bare_older).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&bare_older).is_none());
        // older is not after (CSV ≠ CLTV).
        assert!(bare_tapscript_after_template(&bare_older).is_none());
        assert!(bare_tapscript_and_v_pk_after_template(&bare_older).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&bare_older).is_none());

        // older(0) invalid.
        let older_zero = bitcoin::script::Builder::new()
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        assert!(bare_tapscript_older_template(&older_zero).is_none());

        // Trailing op rejects.
        let trailing = bitcoin::script::Builder::new()
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .into_script();
        assert!(bare_tapscript_older_template(&trailing).is_none());

        assert!(bare_tapscript_older_template(&ScriptBuf::new()).is_none());
        assert!(bare_tapscript_and_v_pk_older_template(&ScriptBuf::new()).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&ScriptBuf::new()).is_none());
    }

    /// sequence_satisfies_csv_older pure unit edges.
    #[test]
    fn sequence_satisfies_csv_older_edges() {
        let v2 = transaction::Version::TWO;
        let v1 = transaction::Version::ONE;
        assert!(sequence_satisfies_csv_older(
            v2,
            Sequence::from_height(9),
            9
        ));
        assert!(sequence_satisfies_csv_older(
            v2,
            Sequence::from_height(10),
            9
        ));
        assert!(!sequence_satisfies_csv_older(
            v2,
            Sequence::from_height(8),
            9
        ));
        assert!(!sequence_satisfies_csv_older(
            v2,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            9
        ));
        assert!(!sequence_satisfies_csv_older(
            v1,
            Sequence::from_height(9),
            9
        ));
        // Time-based older + matching sequence.
        let time_n = Sequence::from_512_second_intervals(70).to_consensus_u32();
        assert!(sequence_satisfies_csv_older(
            v2,
            Sequence::from_512_second_intervals(70),
            time_n
        ));
        assert!(!sequence_satisfies_csv_older(
            v2,
            Sequence::from_height(70),
            time_n
        ));
    }

    // --- Taproot after / CLTV script-path finalize ---

    /// Build `and_v(v:pk, after(n))` leaf under a single-leaf Taproot tree.
    fn p2tr_and_v_pk_after_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
        after_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(i64::from(after_n))
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        let parsed =
            bare_tapscript_and_v_pk_after_template(&leaf).expect("test leaf is and_v(v:pk, after)");
        assert_eq!(parsed.0, spend_xonly);
        assert_eq!(parsed.1, after_n);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        assert!(control_block.verify_taproot_commitment(
            &secp,
            p2tr_output_key(&spk).expect("output key"),
            &leaf
        ));
        (psbt, leaf, control_block, spend_xonly)
    }

    /// Build `and_v(v:after(n), pk)` leaf under a single-leaf Taproot tree.
    fn p2tr_and_v_after_pk_script_path_psbt(
        internal_sk: [u8; 32],
        spend_sk: [u8; 32],
        after_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::secp256k1::XOnlyPublicKey,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let spend_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&spend_sk).expect("ssk"));
        let (spend_xonly, _) = spend_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_int(i64::from(after_n))
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .push_x_only_key(&spend_xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let parsed =
            bare_tapscript_and_v_after_pk_template(&leaf).expect("test leaf is and_v(v:after, pk)");
        assert_eq!(parsed.0, after_n);
        assert_eq!(parsed.1, spend_xonly);

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        (psbt, leaf, control_block, spend_xonly)
    }

    /// Build bare `after(n)` leaf under a single-leaf Taproot tree.
    fn p2tr_bare_after_script_path_psbt(
        internal_sk: [u8; 32],
        after_n: u32,
    ) -> (
        bitcoin::psbt::Psbt,
        ScriptBuf,
        bitcoin::taproot::ControlBlock,
    ) {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let internal_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&internal_sk).expect("isk"));
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let leaf = bitcoin::script::Builder::new()
            .push_int(i64::from(after_n))
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert_eq!(
            bare_tapscript_after_template(&leaf).expect("test leaf is bare after"),
            after_n
        );

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, internal_xonly)
            .expect("finalize tree");
        let merkle = spend_info.merkle_root();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for leaf");
        let (psbt, spk) = p2tr_psbt_with_internal(internal_xonly, merkle);
        assert_eq!(spk, ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
        (psbt, leaf, control_block)
    }

    /// and_v(v:pk, after) with matching sig + satisfying nLockTime → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_after_with_locktime_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [160u8; 32];
        let after_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([161u8; 32], spend_sk, after_n);
        // Present nLockTime that satisfies after(9) — never invented by finalize.
        psbt.unsigned_tx.lock_time = LockTime::from_height(9).expect("height 9");
        // Default ENABLE_RBF_NO_LOCKTIME enables absolute locktime (≠ Sequence::MAX).
        assert!(
            psbt.unsigned_tx.input[0]
                .sequence
                .enables_absolute_lock_time()
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [162u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete() && fin.is_broadcast_ready(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("after final")
            .to_vec();
        // <sigA> <script> <cb>
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        // Locktime + sequence must be unchanged (never invented / mutated).
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(9).expect("height 9")
        );
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// CLTV has no BIP-112-style version ≥ 2 gate — after still Completes on v1.
    ///
    /// Regression: accidental `if tx_version.0 < 2` on the CLTV helper would
    /// not be caught by other complete paths (helpers default to Version::TWO).
    /// Contrast older/CSV which requires v2 (`finalize_taproot_and_v_pk_older_tx_version_one_is_partial`).
    #[test]
    fn finalize_taproot_and_v_pk_after_tx_version_one_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [192u8; 32];
        let after_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([193u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(9).expect("height 9");
        // Explicit v1 — BIP-65 CLTV does not require version ≥ 2 (unlike CSV).
        psbt.unsigned_tx.version = transaction::Version::ONE;
        // Non-final sequence still required for absolute locktime.
        assert!(
            psbt.unsigned_tx.input[0]
                .sequence
                .enables_absolute_lock_time()
        );
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [194u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(
            fin.is_complete() && fin.is_broadcast_ready(),
            "CLTV must not require tx version ≥ 2; got {fin:?}"
        );
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("after v1 final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        // Must not bump version or mutate locktime/sequence.
        assert_eq!(psbt.unsigned_tx.version, transaction::Version::ONE);
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(9).expect("height 9")
        );
        assert_eq!(
            psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// Larger after(n) via push_int (not OP_1..16) with locktime ≥ n → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_after_large_n_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [163u8; 32];
        let after_n = 500_000u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([164u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(500_100).expect("height");
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [165u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// and_v(v:after, pk) with matching sig + satisfying nLockTime → Complete.
    #[test]
    fn finalize_taproot_and_v_after_pk_with_locktime_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [166u8; 32];
        let after_n = 16u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_after_pk_script_path_psbt([167u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(16).expect("height 16");
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [168u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("final")
            .to_vec();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], sig.to_vec());
        assert_eq!(items[1], leaf.as_bytes());
        assert_eq!(items[2], control_block.serialize());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// bare after(n) with satisfying nLockTime → Complete (empty script inputs).
    #[test]
    fn finalize_taproot_bare_after_with_locktime_is_complete() {
        use bitcoin::taproot::LeafVersion;

        let after_n = 10u32;
        let (mut psbt, leaf, control_block) =
            p2tr_bare_after_script_path_psbt([169u8; 32], after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(10).expect("height 10");
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        let items = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("bare after final")
            .to_vec();
        // <script> <cb> only (empty script-input stack)
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], leaf.as_bytes());
        assert_eq!(items[1], control_block.serialize());
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// Time-based after(n) with matching time nLockTime → Complete.
    #[test]
    fn finalize_taproot_and_v_pk_after_time_based_is_complete() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [170u8; 32];
        // UNIX timestamp (above LOCK_TIME_THRESHOLD = 500_000_000).
        let after_n = 1_653_195_600u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([171u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_time(after_n).expect("time");
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf.clone(), LeafVersion::TapScript),
        );
        let sig = sample_tap_key_sig(spend_sk, [172u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        assert!(fin.is_complete(), "{fin:?}");
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_time(after_n).expect("time")
        );
        let _tx = extract_finalized_tx(psbt).unwrap();
    }

    /// and_v(v:pk, after) missing sig → Partial (never invent sig; locktime alone insufficient).
    #[test]
    fn finalize_taproot_and_v_pk_after_missing_sig_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let after_n = 9u32;
        let (mut psbt, leaf, control_block, _pk) =
            p2tr_and_v_pk_after_script_path_psbt([173u8; 32], [174u8; 32], after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(9).expect("height 9");
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        // No tap_script_sigs.

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("missing") || d.contains("tap_script_sig") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(9).expect("height 9")
        );
    }

    /// and_v(v:pk, after) with sig but final nSequence (MAX) → Partial
    /// (never invents nSequence; BIP-65 requires non-final sequence).
    #[test]
    fn finalize_taproot_and_v_pk_after_final_sequence_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [175u8; 32];
        let after_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([176u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(9).expect("height 9");
        // Sequence::MAX disables absolute nLockTime for this input.
        psbt.unsigned_tx.input[0].sequence = Sequence::MAX;
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        let sig = sample_tap_key_sig(spend_sk, [177u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("nlocktime") || d.contains("cltv") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not mutate sequence to make CLTV pass.
        assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence::MAX);
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(9).expect("height 9")
        );
    }

    /// nLockTime height below required after(n) → Partial.
    #[test]
    fn finalize_taproot_and_v_pk_after_locktime_below_required_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [178u8; 32];
        let after_n = 100u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([179u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(50).expect("height 50");
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        let sig = sample_tap_key_sig(spend_sk, [180u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("nlocktime") || d.contains("cltv") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(50).expect("height 50")
        );
    }

    /// Height-based after + time-based nLockTime → Partial (type mismatch).
    #[test]
    fn finalize_taproot_and_v_pk_after_type_mismatch_is_partial() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let spend_sk = [181u8; 32];
        // Height-based after(9).
        let after_n = 9u32;
        let (mut psbt, leaf, control_block, pk) =
            p2tr_and_v_pk_after_script_path_psbt([182u8; 32], spend_sk, after_n);
        // Time-based locktime — type mismatch with height after.
        psbt.unsigned_tx.lock_time = LockTime::from_time(1_653_195_600).expect("time");
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));
        let sig = sample_tap_key_sig(spend_sk, [183u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("nlocktime") || d.contains("cltv") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not invent/mutate nLockTime to a height-based value.
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_time(1_653_195_600).expect("time")
        );
    }

    /// and_v(v:after, pk) missing sig → Partial.
    #[test]
    fn finalize_taproot_and_v_after_pk_missing_sig_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let after_n = 16u32;
        let (mut psbt, leaf, control_block, _pk) =
            p2tr_and_v_after_pk_script_path_psbt([184u8; 32], [185u8; 32], after_n);
        // Satisfying nLockTime alone is insufficient — must not invent sig.
        psbt.unsigned_tx.lock_time = LockTime::from_height(16).expect("height 16");
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("missing") || d.contains("tap_script_sig") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(
            psbt.unsigned_tx.lock_time,
            LockTime::from_height(16).expect("height 16")
        );
    }

    /// bare after with nLockTime ZERO (below required) → Partial (never invents nLockTime).
    #[test]
    fn finalize_taproot_bare_after_zero_locktime_is_partial() {
        use bitcoin::taproot::LeafVersion;

        let after_n = 10u32;
        let (mut psbt, leaf, control_block) =
            p2tr_bare_after_script_path_psbt([186u8; 32], after_n);
        // Default lock_time is ZERO — does not satisfy after(10).
        assert_eq!(psbt.unsigned_tx.lock_time, LockTime::ZERO);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf, LeafVersion::TapScript));

        let fin = finalize_psbt(&mut psbt).unwrap();
        match &fin {
            FinalizeOutcome::Partial { detail, .. } => {
                let d = detail.to_lowercase();
                assert!(
                    d.contains("nlocktime") || d.contains("cltv") || d.contains("after"),
                    "{detail}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(psbt.inputs[0].final_script_witness.is_none());
        // Must not mutate locktime to make CLTV pass.
        assert_eq!(psbt.unsigned_tx.lock_time, LockTime::ZERO);
    }

    /// and_v(v:pk, after) + bad control block → hard error (tamper).
    #[test]
    fn finalize_taproot_and_v_pk_after_bad_control_block_is_hard_error() {
        use bitcoin::secp256k1::{Keypair, SecretKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

        let spend_sk = [187u8; 32];
        let after_n = 9u32;
        let (mut psbt, leaf, _good_cb, pk) =
            p2tr_and_v_pk_after_script_path_psbt([188u8; 32], spend_sk, after_n);
        psbt.unsigned_tx.lock_time = LockTime::from_height(9).expect("height 9");

        // Build a control block for a different internal key (tamper).
        let secp = Secp256k1::new();
        let wrong_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[189u8; 32]).expect("sk"));
        let (wrong_internal, _) = wrong_kp.x_only_public_key();
        let wrong_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("add leaf")
            .finalize(&secp, wrong_internal)
            .expect("finalize");
        let bad_cb = wrong_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("cb");

        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf, LeafVersion::TapScript));
        let sig = sample_tap_key_sig(spend_sk, [190u8; 32]);
        psbt.inputs[0].tap_script_sigs.insert((pk, leaf_hash), sig);

        let err = finalize_psbt(&mut psbt).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("control block") || msg.contains("tamper") || msg.contains("verify"),
            "{err}"
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    /// Template sibling rejects for after/CLTV parsers.
    #[test]
    fn bare_tapscript_after_templates_reject_siblings() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[191u8; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();

        // Bare CHECKSIG is not after.
        let bare = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_pk_after_template(&bare).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&bare).is_none());
        assert!(bare_tapscript_after_template(&bare).is_none());

        // and_v dual CHECKSIGVERIFY chain is not after.
        let and_v = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_pk_after_template(&and_v).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&and_v).is_none());
        assert!(bare_tapscript_after_template(&and_v).is_none());

        // and_v(v:pk, older) is not after (CSV ≠ CLTV).
        let pk_older = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .into_script();
        assert!(bare_tapscript_and_v_pk_older_template(&pk_older).is_some());
        assert!(bare_tapscript_and_v_pk_after_template(&pk_older).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&pk_older).is_none());
        assert!(bare_tapscript_after_template(&pk_older).is_none());

        // and_v(v:pk, after) must not parse as bare after / and_v(v:after, pk) / older.
        let pk_after = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(9)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_and_v_pk_after_template(&pk_after).is_some());
        assert!(bare_tapscript_and_v_after_pk_template(&pk_after).is_none());
        assert!(bare_tapscript_after_template(&pk_after).is_none());
        assert!(bare_tapscript_and_v_pk_older_template(&pk_after).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&pk_after).is_none());
        assert!(bare_tapscript_older_template(&pk_after).is_none());
        assert!(bare_tapscript_and_v_checksigverify_template(&pk_after).is_none());
        assert!(bare_tapscript_and_v_pk_hash_template(&pk_after).is_none());

        // and_v(v:after, pk) must not parse as bare after or and_v(v:pk, after).
        let after_pk = bitcoin::script::Builder::new()
            .push_int(16)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_after_pk_template(&after_pk).is_some());
        assert!(bare_tapscript_and_v_pk_after_template(&after_pk).is_none());
        assert!(bare_tapscript_after_template(&after_pk).is_none());
        assert!(bare_tapscript_and_v_older_pk_template(&after_pk).is_none());

        // bare after is not and_v forms / not older.
        let bare_after = bitcoin::script::Builder::new()
            .push_int(10)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_after_template(&bare_after).is_some());
        assert!(bare_tapscript_and_v_pk_after_template(&bare_after).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&bare_after).is_none());
        assert!(bare_tapscript_older_template(&bare_after).is_none());

        // after(0) invalid.
        let after_zero = bitcoin::script::Builder::new()
            .push_int(0)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_after_template(&after_zero).is_none());

        // Miniscript AbsLockTime max 0x7FFF_FFFF accepted; above-max / high-bit rejected.
        let after_max_ok = bitcoin::script::Builder::new()
            .push_int(i64::from(0x7FFF_FFFFu32))
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert_eq!(
            bare_tapscript_after_template(&after_max_ok),
            Some(0x7FFF_FFFF)
        );
        // 0x8000_0000 = miniscript max + 1 (also the CScriptNum high-bit / signed boundary).
        let after_above_max = bitcoin::script::Builder::new()
            .push_int(i64::from(0x7FFF_FFFFu32) + 1)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_after_template(&after_above_max).is_none());
        assert!(bare_tapscript_and_v_pk_after_template(&after_above_max).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&after_above_max).is_none());
        // Negative scriptnum (high-bit as signed) rejected.
        let after_neg = bitcoin::script::Builder::new()
            .push_int(-1)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_after_template(&after_neg).is_none());
        assert!(bare_tapscript_and_v_pk_after_template(&after_neg).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&after_neg).is_none());
        // High-bit value also rejects when wrapped in and_v forms.
        let pk_after_high = bitcoin::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(i64::from(0x7FFF_FFFFu32) + 1)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .into_script();
        assert!(bare_tapscript_and_v_pk_after_template(&pk_after_high).is_none());
        let after_pk_high = bitcoin::script::Builder::new()
            .push_int(i64::from(0x7FFF_FFFFu32) + 1)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(bare_tapscript_and_v_after_pk_template(&after_pk_high).is_none());

        // Trailing opcode after CLTV.
        let trailing = bitcoin::script::Builder::new()
            .push_int(10)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .into_script();
        assert!(bare_tapscript_after_template(&trailing).is_none());

        assert!(bare_tapscript_after_template(&ScriptBuf::new()).is_none());
        assert!(bare_tapscript_and_v_pk_after_template(&ScriptBuf::new()).is_none());
        assert!(bare_tapscript_and_v_after_pk_template(&ScriptBuf::new()).is_none());
    }

    /// locktime_satisfies_cltv_after pure unit edges.
    #[test]
    fn locktime_satisfies_cltv_after_edges() {
        let en = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let max = Sequence::MAX;
        assert!(locktime_satisfies_cltv_after(
            LockTime::from_height(9).unwrap(),
            en,
            9
        ));
        assert!(locktime_satisfies_cltv_after(
            LockTime::from_height(10).unwrap(),
            en,
            9
        ));
        assert!(!locktime_satisfies_cltv_after(
            LockTime::from_height(8).unwrap(),
            en,
            9
        ));
        assert!(!locktime_satisfies_cltv_after(LockTime::ZERO, en, 9));
        // Final sequence disables absolute locktime.
        assert!(!locktime_satisfies_cltv_after(
            LockTime::from_height(9).unwrap(),
            max,
            9
        ));
        // Time-based after + matching time locktime.
        let t = 1_653_195_600u32;
        assert!(locktime_satisfies_cltv_after(
            LockTime::from_time(t).unwrap(),
            en,
            t
        ));
        // Type mismatch: height locktime vs time after.
        assert!(!locktime_satisfies_cltv_after(
            LockTime::from_height(100).unwrap(),
            en,
            t
        ));
        // Type mismatch: time locktime vs height after.
        assert!(!locktime_satisfies_cltv_after(
            LockTime::from_time(t).unwrap(),
            en,
            9
        ));
    }

    /// Live mempool.space address UTXO probe via [`MempoolChainSource`].
    /// Offline CI must not run this (ignored + feature-gated).
    #[test]
    #[ignore = "network: live mempool.space address UTXO"]
    #[cfg(feature = "explorer-http")]
    fn live_mempool_chain_source_address_utxo() {
        // Well-known genesis coinbase address still has historical UTXOs on mainnet
        // explorers; use a high-traffic address that reliably has UTXOs, or accept empty.
        // Satoshi's address may be empty on some mirrors — prefer empty-ok shape check.
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned();
        let chain =
            MempoolChainSource::with_defaults(crate::address_ux::BitcoinNetwork::Mainnet).unwrap();
        let utxos = chain
            .list_unspent_for_addresses(&[addr.clone()])
            .expect("list_unspent against mempool.space");
        // May be empty if fully spent on a given mirror; when present, shape must be valid.
        for u in &utxos {
            assert_eq!(u.address, addr);
            assert!(!u.outpoint.txid.is_empty());
            assert!(u.amount_sats > 0);
        }
        // Tip-backed list should not invent absurd conf counts when empty either.
        let _ = utxos;
    }
}
