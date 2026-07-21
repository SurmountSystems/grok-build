//! BIP84 spend preparation, gap-sync product paths, RBF and CPFP prepare.

use std::collections::HashSet;

use bitcoin::Transaction;

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;

use super::broadcast::{extract_finalized_tx, transaction_to_raw_hex, transaction_txid_hex};
use super::chain_source::ChainSource;
use super::coin_select::{CoinSelectStrategy, CoinSelection, select_coins_with_fee};
use super::fee::{
    CpfpFeePlan, DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB, DUST_P2WPKH_SATS, RbfFeePlan,
    effective_fee_rate_sat_vb, estimate_tx_vbytes, plan_cpfp_child_fee, plan_rbf_fee_bump,
    rbf_min_fee_increase_sats,
};
use super::gap::{GapExtendOptions, WalletSyncSnapshot};
use super::psbt_build::{SpendParams, build_unsigned_psbt};
use super::sign_bip84::{SignOutcome, sign_psbt_bip84_p2wpkh};
use super::types::WalletUtxo;
use super::wallet::DescriptorWallet;
use super::{FinalizeOutcome, finalize_p2wpkh_psbt, psbt_is_broadcast_ready};

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
