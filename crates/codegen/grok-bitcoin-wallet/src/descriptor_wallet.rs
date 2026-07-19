//! Descriptor-shaped BIP84 wallet surface: list UTXOs + coin selection + PSBT.
//!
//! Full `bdk_wallet` electrum/esplora sync remains residual. This module
//! provides:
//! - BIP84 external/internal descriptor **strings** (wpkh account xpub)
//! - injectable [`ChainSource`] (mock for tests; live mempool UTXO behind
//!   `explorer-http`)
//! - [`list_unspent`], balance, and fee-aware [`select_coins`] APIs
//! - unsigned PSBT build from [`CoinSelection`] ([`build_unsigned_psbt`])
//! - BIP84 P2WPKH sign + finalize for inputs resolvable in a derivation gap
//! - extract + raw-hex helpers; network broadcast via [`crate::explorer::TxBroadcaster`]
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

/// Outcome of P2WPKH finalize (honest about multi-sig / non-P2WPKH residual).
///
/// Only single-key P2WPKH inputs with a matching partial signature become
/// `final_script_witness`. Multi-sig, script-path, and non-P2WPKH scripts are
/// left residual and surface as [`FinalizeOutcome::Partial`] — **not**
/// broadcast-ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// Every input has a non-empty `final_script_witness`.
    Complete { finalized_inputs: usize },
    /// Some inputs finalized; others could not (unsigned, multi-sig, non-P2WPKH).
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

/// True when every PSBT input has a **non-empty** `final_script_witness`.
///
/// Empty witnesses and missing witnesses are **not** complete. Never use this
/// alone to claim multi-sig success — only single-key P2WPKH finalize fills
/// witnesses in this crate.
pub fn psbt_is_broadcast_ready(psbt: &Psbt) -> bool {
    !psbt.inputs.is_empty()
        && psbt.inputs.iter().all(|i| {
            i.final_script_witness
                .as_ref()
                .is_some_and(|w| !w.is_empty())
        })
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
    let min_relay_child = child_vbytes.saturating_mul(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB).max(1);
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
/// Production will wrap mempool.space or electrum; tests inject [`MockChainSource`].
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

/// BIP84 account descriptors + derived receive address window.
///
/// Does **not** perform live electrum/esplora sync. Callers pass a [`ChainSource`].
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
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        let gap = receive_gap.max(1);
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
    pub fn from_mnemonic_env_network(
        mnemonic: &MnemonicSecret,
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
                     use mainnet, signet, testnet, or regtest"
                ))
            })?
        };
        Self::from_mnemonic(mnemonic, network, receive_gap)
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

/// Convert ECDSA `partial_sigs` on P2WPKH inputs into `final_script_witness`.
///
/// # Honesty
///
/// - Only single-key **P2WPKH** with exactly one matching partial signature is
///   finalized.
/// - Multi-sig (`partial_sigs.len() != 1`), non-P2WPKH scripts, missing
///   `witness_utxo`, and unsigned inputs are left residual and yield
///   [`FinalizeOutcome::Partial`] (not broadcast-ready) — never a complete
///   success claim.
/// - Empty pre-existing `final_script_witness` values are treated as missing
///   (aligned with [`extract_finalized_tx`] / [`psbt_is_broadcast_ready`]).
/// - Pubkey HASH160 mismatch against a P2WPKH `witness_utxo` is a hard error
///   (corrupt / tampered PSBT), not a silent skip.
///
/// Product paths must require [`FinalizeOutcome::is_complete`] before extract
/// or broadcast.
pub fn finalize_p2wpkh_psbt(psbt: &mut Psbt) -> Result<FinalizeOutcome> {
    let total = psbt.inputs.len();
    if total == 0 {
        return Err(WalletError::Onchain(
            "PSBT has no inputs to finalize".into(),
        ));
    }
    let mut finalized = 0usize;
    let mut residual_reasons: Vec<String> = Vec::new();

    for (idx, input) in psbt.inputs.iter_mut().enumerate() {
        if let Some(w) = input.final_script_witness.as_ref() {
            if w.is_empty() {
                // Match extract: empty is not finalized; clear so partial_sigs
                // can still produce a real witness below.
                input.final_script_witness = None;
            } else {
                finalized += 1;
                continue;
            }
        }
        if input.partial_sigs.is_empty() {
            residual_reasons.push(format!(
                "input {idx}: no partial_sigs (unsigned residual; not broadcast-ready)"
            ));
            continue;
        }
        if input.partial_sigs.len() != 1 {
            // Multi-sig / multi-key: never invent a P2WPKH witness.
            residual_reasons.push(format!(
                "input {idx}: multi-sig / multi-key residual ({} partial_sigs; only single-key \
                 P2WPKH finalize supported; not broadcast-ready)",
                input.partial_sigs.len()
            ));
            continue;
        }
        let Some(utxo) = input.witness_utxo.as_ref() else {
            residual_reasons.push(format!(
                "input {idx}: missing witness_utxo (not broadcast-ready)"
            ));
            continue;
        };
        if !utxo.script_pubkey.is_p2wpkh() {
            // P2WSH / multi-sig / script-path / legacy — honest residual.
            residual_reasons.push(format!(
                "input {idx}: non-P2WPKH script residual (only single-key P2WPKH finalize; \
                 not broadcast-ready)"
            ));
            continue;
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
        let expected_spk = ScriptBuf::new_p2wpkh(&wpkh);
        if utxo.script_pubkey != expected_spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: partial_sig pubkey HASH160 does not match witness_utxo P2WPKH script"
            )));
        }
        let witness = Witness::from_slice(&[sig.to_vec(), pk.to_bytes()]);
        input.final_script_witness = Some(witness);
        finalized += 1;
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

/// Extract a transaction when **every** input has a **non-empty**
/// `final_script_witness`.
///
/// Empty witnesses are rejected (never treated as complete). Multi-sig /
/// non-P2WPKH residual PSBTs fail here if finalize left them partial.
///
/// Uses fee-rate-unchecked extract so dust-folded / test fees are not rejected.
/// **Does not broadcast.** Submit via [`broadcast_raw_tx`] / [`TxBroadcaster`].
pub fn extract_finalized_tx(psbt: Psbt) -> Result<Transaction> {
    if psbt.inputs.is_empty() {
        return Err(WalletError::Onchain("cannot extract empty PSBT".into()));
    }
    if !psbt_is_broadcast_ready(&psbt) {
        for (idx, input) in psbt.inputs.iter().enumerate() {
            match &input.final_script_witness {
                Some(w) if !w.is_empty() => {}
                Some(w) if w.is_empty() => {
                    return Err(WalletError::Onchain(format!(
                        "input {idx} has empty final_script_witness (not complete; \
                         multi-sig / non-P2WPKH residual or unsigned)"
                    )));
                }
                _ => {
                    return Err(WalletError::Onchain(format!(
                        "input {idx} missing final_script_witness; finalize P2WPKH before extract \
                         (partial / multi-sig / non-P2WPKH is not broadcast-ready)"
                    )));
                }
            }
        }
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
            "incomplete P2WPKH finalize (not broadcast-ready): {}",
            match &fin {
                FinalizeOutcome::Partial { detail, .. } => detail.clone(),
                FinalizeOutcome::Complete { .. } => unreachable!(),
            }
        )));
    }
    if !psbt_is_broadcast_ready(&built.psbt) {
        return Err(WalletError::Onchain(
            "PSBT not broadcast-ready after finalize (empty or missing witnesses)".into(),
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
    })
}

/// Fee-aware select + BIP84 prepare for a payment from wallet UTXOs.
///
/// `fee_rate_sat_vb` of 0 is rejected (product paths must pass a positive rate).
/// Change goes to the wallet's first change address when needed.
pub fn select_and_prepare_bip84_spend(
    wallet: &DescriptorWallet,
    chain: &dyn ChainSource,
    mnemonic: &MnemonicSecret,
    payment_address: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    address_gap: u32,
) -> Result<PreparedSpend> {
    if fee_rate_sat_vb == 0 {
        return Err(WalletError::Onchain(
            "fee rate must be > 0 sat/vB for product spend".into(),
        ));
    }
    let utxos = wallet.list_unspent(chain)?;
    if utxos.is_empty() {
        return Err(WalletError::Onchain(
            "no UTXOs found for wallet address gap (fund the receive address first)".into(),
        ));
    }
    let selection = select_coins_with_fee(
        &utxos,
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
    prepare_bip84_p2wpkh_spend(&selection, &params, mnemonic, "", address_gap.max(1))
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
    use crate::onchain::derive_bip84_receive_address;

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
        assert_eq!(plan.incremental_relay_sat_vb, DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB);
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
        let prep = select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, 5).unwrap();
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
        let prep = select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 5, 5).unwrap();
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
            select_and_prepare_bip84_spend(&w, &chain, &m, &pay_to, 25_000, 0, 5).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("fee rate") && (msg.contains("> 0") || msg.contains("must be")),
            "expected fee-rate rejection, got: {err}"
        );
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
