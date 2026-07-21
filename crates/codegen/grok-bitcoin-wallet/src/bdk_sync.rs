//! Feature-gated **`bdk_wallet`** BIP84 auto-sync (spent-tx history + keychain).
//!
//! Enabled only with Cargo feature **`bdk`** (not default CI). Default product
//! UTXO discovery remains gap-limit [`crate::descriptor_wallet::ChainSource`]
//! sync — this module is the real BDK engine path.
//!
//! ## What this lands
//!
//! - In-memory [`bdk_wallet::Wallet`] from BIP84 receive/change descriptors
//! - [`BdkBip84Wallet::apply_update`] / [`BdkUpdateSource`] for full transaction
//!   graph updates (spent outputs drop out of `list_unspent`)
//! - Conversion to product [`WalletUtxo`] / [`WalletBalance`] /
//!   [`WalletSyncSnapshot`] for existing spend-from-snapshot helpers
//! - Offline unit tests (mock updates; no live network)
//! - **Transport full_scan adapters** (no `bdk_esplora` / `bdk_electrum` graph):
//!   - [`EsploraBdkUpdateSource`] over injectable [`crate::esplora::EsploraTransport`]
//!     (`GET /address/{addr}/txs` + `/tx/{txid}/hex` + tip)
//!   - [`ElectrumBdkUpdateSource`] over injectable [`crate::electrum::ElectrumTransport`]
//!     (`scripthash.get_history` + `transaction.get` + headers)
//!   - Live HTTP/TCP constructors behind features `esplora` / `electrum` (not default CI)
//!
//! ## Product prefer-BDK (shell wire)
//!
//! - Env [`crate::chain_select::UTXO_SYNC_ENV`] = `bdk` (default `gap`)
//! - [`open_product_bdk_update_source`] maps product chain config → live
//!   Esplora/Electrum full_scan sources (mempool fails closed)
//! - Shell `complete_routstr_{utxos,spend}_with_mnemonic` prefer this when
//!   feature `bdk` is compiled; without feature → structured residual
//!
//! Live network is never forced in unit tests; only mock transports run offline.
//!
//! Seed material: never stored on the BDK wallet for list/balance; construction
//! takes [`MnemonicSecret`] ephemerally to build public descriptors only
//! (watch-only). Signing stays on the existing BIP84 product path.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::transaction::Version as TxVersion;
use bdk_wallet::bitcoin::{
    Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
};
use bdk_wallet::chain::{BlockId, ChainPosition, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Update, Wallet};

use crate::chain_select::{
    ChainSourceKind, ProductChainSourceConfig, bdk_utxo_sync_mempool_unsupported_error,
    validated_electrum_endpoint_from_config, validated_esplora_url_from_config,
};
use crate::descriptor_wallet::{
    DescriptorWallet, GapSyncedPreparedSpend, MAX_ADDRESS_GAP, OutPointRef, WalletBalance,
    WalletSyncSnapshot, WalletUtxo, balance_from_utxos, select_and_prepare_bip84_spend_from_utxos,
};
use crate::electrum::{
    ElectrumTransport, electrum_script_hash_from_script, parse_electrum_get_history_entries,
    parse_electrum_headers_subscribe_height, parse_electrum_transaction_get_hex,
};
use crate::error::{Result, WalletError};
use crate::esplora::{
    ESPLORA_MAX_TX_PAGES, ESPLORA_TXS_PAGE_SIZE, EsploraTransport, EsploraTxHistoryEntry,
    esplora_address_txs_chain_path, esplora_address_txs_path, esplora_tip_height_path,
    esplora_tx_hex_path, parse_esplora_address_txs_entries,
};
use crate::mnemonic::MnemonicSecret;
use crate::watcher::parse_tip_height;

/// Confirmation observation from chain-source history (not tip-anchored).
///
/// Transport full_scan uses this so 0-conf / mempool txs stay unconfirmed for
/// product `confirmed_only` coin select, while confirmed txs keep real height
/// for confirmation depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BdkTxObservation {
    /// Confirmed in a block at `height` (`> 0`).
    Confirmed { height: u32 },
    /// Mempool / unconfirmed (Electrum height ≤ 0; Esplora `status.confirmed=false`).
    Unconfirmed,
}

/// Full transaction plus confirmation observation for transport Update build.
#[derive(Debug, Clone)]
pub struct ScannedTx {
    pub tx: Transaction,
    pub observation: BdkTxObservation,
}

/// Capability flag when built with feature `bdk`.
pub const BDK_SYNC_AVAILABLE: bool = true;

/// Product cap on BIP84 sign/construction gap after BDK sync.
///
/// Equal to [`MAX_ADDRESS_GAP`]: a buggy/hostile [`BdkUpdateSource`] cannot force
/// unbounded `bip84_script_lookup` derivation. Snapshot UTXOs whose derivation
/// index is ≥ this cap fail honestly (no silent drop).
pub const BDK_PRODUCT_SIGN_GAP_CAP: u32 = MAX_ADDRESS_GAP;

/// Default BIP44-style stop-gap for Esplora/Electrum BDK full_scan (consecutive
/// empty scripts before a keychain scan ends).
pub const BDK_FULL_SCAN_DEFAULT_STOP_GAP: u32 = 20;

/// Hard max derivation index scanned by transport full_scan (inclusive bound is
/// exclusive: indices `0..BDK_FULL_SCAN_MAX_INDEX`).
///
/// Equal to [`BDK_PRODUCT_SIGN_GAP_CAP`] so a hostile chain cannot force O(huge)
/// peek/history probes beyond product sign capacity.
pub const BDK_FULL_SCAN_MAX_INDEX: u32 = BDK_PRODUCT_SIGN_GAP_CAP;

/// In-memory BIP84 BDK wallet for spent-aware UTXO discovery.
///
/// Watch-only: constructed from public account descriptors. Never retains
/// BIP-39 / passphrase. Not the default product path (gap-limit is).
pub struct BdkBip84Wallet {
    inner: Wallet,
    /// Descriptor strings used at construction (for honesty / accessors).
    /// Not printed in [`Debug`] (xpubs are privacy-sensitive).
    receive_descriptor: String,
    change_descriptor: String,
}

impl std::fmt::Debug for BdkBip84Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact full descriptor strings (account xpubs + origin). Not BIP-39,
        // but still privacy-sensitive if logs are shared.
        f.debug_struct("BdkBip84Wallet")
            .field("network", &self.inner.network())
            .field("receive_descriptor", &"[descriptor redacted]")
            .field("change_descriptor", &"[descriptor redacted]")
            .field(
                "external_index",
                &self.inner.derivation_index(KeychainKind::External),
            )
            .field(
                "internal_index",
                &self.inner.derivation_index(KeychainKind::Internal),
            )
            .finish()
    }
}

impl BdkBip84Wallet {
    /// Build a watch-only BDK wallet from already-built BIP84 descriptors.
    ///
    /// Descriptors must be `wpkh([origin]xpub/0/*)` / `wpkh([origin]xpub/1/*)`
    /// style (as produced by [`DescriptorWallet`]).
    pub fn from_descriptors(
        receive_descriptor: impl Into<String>,
        change_descriptor: impl Into<String>,
        network: Network,
    ) -> Result<Self> {
        let receive_descriptor = receive_descriptor.into();
        let change_descriptor = change_descriptor.into();
        let inner = Wallet::create(receive_descriptor.clone(), change_descriptor.clone())
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| WalletError::Onchain(format!("bdk_wallet create failed: {e}")))?;
        Ok(Self {
            inner,
            receive_descriptor,
            change_descriptor,
        })
    }

    /// Build from BIP-39 via product [`DescriptorWallet`] descriptor strings.
    ///
    /// `passphrase` must match funding material. Never logged or retained.
    /// Mnemonic is used only to derive public descriptors (watch-only BDK).
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        let dw = DescriptorWallet::from_mnemonic_with_passphrase(
            mnemonic,
            passphrase,
            network,
            receive_gap,
        )?;
        Self::from_descriptor_wallet(&dw)
    }

    /// Same with empty BIP-39 passphrase.
    pub fn from_mnemonic(
        mnemonic: &MnemonicSecret,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(mnemonic, "", network, receive_gap)
    }

    /// Lift descriptors from an existing product [`DescriptorWallet`].
    pub fn from_descriptor_wallet(dw: &DescriptorWallet) -> Result<Self> {
        Self::from_descriptors(
            dw.receive_descriptor.clone(),
            dw.change_descriptor.clone(),
            dw.network(),
        )
    }

    pub fn network(&self) -> Network {
        self.inner.network()
    }

    pub fn receive_descriptor(&self) -> &str {
        &self.receive_descriptor
    }

    pub fn change_descriptor(&self) -> &str {
        &self.change_descriptor
    }

    /// Borrow the inner BDK wallet (advanced / tests).
    pub fn inner(&self) -> &Wallet {
        &self.inner
    }

    /// Mutable borrow of the inner BDK wallet.
    pub fn inner_mut(&mut self) -> &mut Wallet {
        &mut self.inner
    }

    /// Apply a BDK [`Update`] (full txs + anchors + last_active_indices).
    ///
    /// This is the core auto-sync step: spent outputs disappear from
    /// [`Self::list_wallet_utxos`] after the spending tx is applied.
    pub fn apply_update(&mut self, update: Update) -> Result<()> {
        self.inner
            .apply_update(update)
            .map_err(|e| WalletError::Onchain(format!("bdk_wallet apply_update failed: {e}")))
    }

    /// Apply an update from an injectable source (offline mock or live client).
    pub fn sync_with_source(&mut self, source: &dyn BdkUpdateSource) -> Result<WalletSyncSnapshot> {
        let before_ext = self.revealed_external_count();
        let before_int = self.revealed_internal_count();
        let update = source.full_scan_update(self)?;
        self.apply_update(update)?;
        let after_ext = self.revealed_external_count();
        let after_int = self.revealed_internal_count();
        self.snapshot(
            after_ext.saturating_sub(before_ext),
            after_int.saturating_sub(before_int),
        )
    }

    /// List unspent outputs as product [`WalletUtxo`]s (never invents coins).
    pub fn list_wallet_utxos(&self) -> Result<Vec<WalletUtxo>> {
        let tip_height = self.inner.latest_checkpoint().height();
        let network = self.inner.network();
        let mut out = Vec::new();
        for local in self.inner.list_unspent() {
            out.push(local_output_to_wallet_utxo(&local, tip_height, network)?);
        }
        Ok(out)
    }

    /// Confirmed + unconfirmed balances from the BDK graph (via product UTXOs).
    pub fn balance(&self) -> Result<WalletBalance> {
        let utxos = self.list_wallet_utxos()?;
        balance_from_utxos(&utxos)
    }

    /// Snapshot compatible with gap-sync product helpers (honest meta fields).
    ///
    /// `extended_*_by` are caller-supplied deltas (e.g. from
    /// [`Self::sync_with_source`]). `hit_max_gap` is always `false` here —
    /// BDK uses chain-source `last_active_indices` / stop-gap, not
    /// [`crate::descriptor_wallet::MAX_ADDRESS_GAP`].
    pub fn snapshot(
        &self,
        extended_receive_by: u32,
        extended_change_by: u32,
    ) -> Result<WalletSyncSnapshot> {
        let utxos = self.list_wallet_utxos()?;
        let balance = balance_from_utxos(&utxos)?;
        let highest_used_receive = utxos
            .iter()
            .filter(|u| !u.is_change)
            .filter_map(|u| address_index_from_utxo(self, u, KeychainKind::External))
            .max();
        let highest_used_change = utxos
            .iter()
            .filter(|u| u.is_change)
            .filter_map(|u| address_index_from_utxo(self, u, KeychainKind::Internal))
            .max();
        Ok(WalletSyncSnapshot {
            utxos,
            balance,
            receive_gap: self.revealed_external_count().max(1),
            change_gap: self.revealed_internal_count().max(1),
            highest_used_receive,
            highest_used_change,
            extended_receive_by,
            extended_change_by,
            hit_max_gap: false,
        })
    }

    /// Current revealed external (receive) index window length.
    pub fn revealed_external_count(&self) -> u32 {
        // next_derivation_index is one past the last revealed; 0 when none.
        self.inner.next_derivation_index(KeychainKind::External)
    }

    /// Current revealed internal (change) index window length.
    pub fn revealed_internal_count(&self) -> u32 {
        self.inner.next_derivation_index(KeychainKind::Internal)
    }

    /// Peek a receive address at `index` without revealing (BDK peek).
    pub fn peek_receive_address(&self, index: u32) -> String {
        self.inner
            .peek_address(KeychainKind::External, index)
            .address
            .to_string()
    }

    /// Peek a change address at `index` without revealing.
    pub fn peek_change_address(&self, index: u32) -> String {
        self.inner
            .peek_address(KeychainKind::Internal, index)
            .address
            .to_string()
    }

    /// Script pubkey for receive index `index`.
    pub fn receive_script_pubkey(&self, index: u32) -> ScriptBuf {
        self.inner
            .peek_address(KeychainKind::External, index)
            .address
            .script_pubkey()
    }

    /// Script pubkey for change index `index`.
    pub fn change_script_pubkey(&self, index: u32) -> ScriptBuf {
        self.inner
            .peek_address(KeychainKind::Internal, index)
            .address
            .script_pubkey()
    }
}

/// Injectable producer of BDK [`Update`]s (offline mock or live client).
///
/// Transport adapters: [`EsploraBdkUpdateSource`], [`ElectrumBdkUpdateSource`].
/// Offline fixtures: [`MockBdkUpdateSource`], [`FailingBdkUpdateSource`].
/// Default product CI stays on gap-limit ChainSource (feature `bdk` off).
pub trait BdkUpdateSource {
    /// Produce a full-scan style update for `wallet` (may inspect peek SPKs).
    fn full_scan_update(&self, wallet: &BdkBip84Wallet) -> Result<Update>;
}

/// Offline fixture: pre-built BDK [`Update`] (or empty).
#[derive(Debug, Clone, Default)]
pub struct MockBdkUpdateSource {
    update: Update,
}

impl MockBdkUpdateSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_update(update: Update) -> Self {
        Self { update }
    }
}

impl BdkUpdateSource for MockBdkUpdateSource {
    fn full_scan_update(&self, _wallet: &BdkBip84Wallet) -> Result<Update> {
        Ok(self.update.clone())
    }
}

/// Offline fixture: always fails `full_scan_update` (error-path honesty).
#[derive(Debug, Clone)]
pub struct FailingBdkUpdateSource {
    message: String,
}

impl FailingBdkUpdateSource {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl BdkUpdateSource for FailingBdkUpdateSource {
    fn full_scan_update(&self, _wallet: &BdkBip84Wallet) -> Result<Update> {
        Err(WalletError::Onchain(self.message.clone()))
    }
}

/// Esplora REST full_scan → BDK [`Update`] over an injectable transport.
///
/// **Offline:** [`crate::esplora::MockEsploraTransport`] (+ optional
/// `default_empty_address_txs`). **Live HTTP:** feature `esplora` +
/// [`crate::esplora::HttpEsploraTransport`] via
/// [`EsploraBdkUpdateSource::with_http_base_url`] (never runs in default tests).
///
/// Scan: for each keychain, probe `GET /address/{addr}/txs` and paginate
/// confirmed history via `/txs/chain/{last_txid}` until a short page (Esplora
/// page size 25; hard cap [`crate::esplora::ESPLORA_MAX_TX_PAGES`]) until
/// `stop_gap` consecutive empty scripts (capped at [`BDK_FULL_SCAN_MAX_INDEX`]).
/// Fetch each unique `GET /tx/{txid}/hex`, tip via `/blocks/tip/height`, then
/// [`chain_update_from_scanned_txs`] (per-tx confirmation height / unconfirmed
/// `seen_ats` — not tip-anchored placeholder). Transport/`Err` → Sync failure
/// (never empty Success). Does **not** depend on `bdk_esplora`.
pub struct EsploraBdkUpdateSource<T: EsploraTransport> {
    transport: RefCell<T>,
    stop_gap: u32,
}

impl<T: EsploraTransport> std::fmt::Debug for EsploraBdkUpdateSource<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsploraBdkUpdateSource")
            .field("stop_gap", &self.stop_gap)
            .field("transport", &"EsploraTransport")
            .finish()
    }
}

impl<T: EsploraTransport> EsploraBdkUpdateSource<T> {
    /// Full_scan with BIP44-style stop-gap ([`BDK_FULL_SCAN_DEFAULT_STOP_GAP`]).
    pub fn new(transport: T) -> Self {
        Self::with_stop_gap(transport, BDK_FULL_SCAN_DEFAULT_STOP_GAP)
    }

    /// Full_scan with explicit stop-gap (`0` is rejected at scan time).
    pub fn with_stop_gap(transport: T, stop_gap: u32) -> Self {
        Self {
            transport: RefCell::new(transport),
            stop_gap,
        }
    }

    pub fn stop_gap(&self) -> u32 {
        self.stop_gap
    }

    pub fn transport(&self) -> std::cell::Ref<'_, T> {
        self.transport.borrow()
    }

    pub fn transport_mut(&self) -> std::cell::RefMut<'_, T> {
        self.transport.borrow_mut()
    }
}

#[cfg(feature = "esplora")]
impl EsploraBdkUpdateSource<crate::esplora::HttpEsploraTransport> {
    /// Live HTTP Esplora full_scan (feature `esplora`). Not used by default CI.
    pub fn with_http_base_url(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self::new(
            crate::esplora::HttpEsploraTransport::with_defaults(base_url)?,
        ))
    }
}

impl<T: EsploraTransport> BdkUpdateSource for EsploraBdkUpdateSource<T> {
    fn full_scan_update(&self, wallet: &BdkBip84Wallet) -> Result<Update> {
        let stop_gap = normalize_stop_gap(self.stop_gap)?;
        let mut transport = self.transport.borrow_mut();
        let tip_body = transport.get_text(esplora_tip_height_path()).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Esplora full_scan tip height transport error: {e}"
            ))
        })?;
        let tip_height = parse_tip_height(&tip_body).ok_or_else(|| {
            WalletError::Onchain(format!(
                "bdk Esplora full_scan tip height unparseable: {:?}",
                tip_body.chars().take(40).collect::<String>()
            ))
        })?;
        let tip_u32 = tip_height_to_u32(tip_height)?;

        let mut txs_by_id: BTreeMap<String, ScannedTx> = BTreeMap::new();
        let last_ext = scan_keychain_esplora(
            &mut *transport,
            wallet,
            KeychainKind::External,
            stop_gap,
            &mut txs_by_id,
        )?;
        let last_int = scan_keychain_esplora(
            &mut *transport,
            wallet,
            KeychainKind::Internal,
            stop_gap,
            &mut txs_by_id,
        )?;

        let txs: Vec<ScannedTx> = txs_by_id.into_values().collect();
        chain_update_from_scanned_txs(wallet.network(), tip_u32, txs, last_ext, last_int)
    }
}

/// Electrum JSON-RPC full_scan → BDK [`Update`] over an injectable transport.
///
/// **Offline:** [`crate::electrum::MockElectrumTransport`] (+ optional
/// `default_empty_history`). **Live TCP/TLS:** feature `electrum` +
/// [`ElectrumBdkUpdateSource::with_tcp_addr`] /
/// [`ElectrumBdkUpdateSource::with_tls_addr`].
///
/// Scan: `blockchain.scripthash.get_history` per peeked SPK until stop-gap
/// empties; `blockchain.transaction.get` for each unique txid; tip via
/// `blockchain.headers.subscribe`. Builds [`chain_update_from_scanned_txs`]
/// with Electrum history heights (`>0` confirmed, `≤0` unconfirmed).
/// Transport/`Err` → Sync failure. Does **not** depend on `bdk_electrum`.
pub struct ElectrumBdkUpdateSource<T: ElectrumTransport> {
    transport: RefCell<T>,
    stop_gap: u32,
}

impl<T: ElectrumTransport> std::fmt::Debug for ElectrumBdkUpdateSource<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumBdkUpdateSource")
            .field("stop_gap", &self.stop_gap)
            .field("transport", &"ElectrumTransport")
            .finish()
    }
}

impl<T: ElectrumTransport> ElectrumBdkUpdateSource<T> {
    pub fn new(transport: T) -> Self {
        Self::with_stop_gap(transport, BDK_FULL_SCAN_DEFAULT_STOP_GAP)
    }

    pub fn with_stop_gap(transport: T, stop_gap: u32) -> Self {
        Self {
            transport: RefCell::new(transport),
            stop_gap,
        }
    }

    pub fn stop_gap(&self) -> u32 {
        self.stop_gap
    }

    pub fn transport(&self) -> std::cell::Ref<'_, T> {
        self.transport.borrow()
    }

    pub fn transport_mut(&self) -> std::cell::RefMut<'_, T> {
        self.transport.borrow_mut()
    }
}

#[cfg(feature = "electrum")]
impl ElectrumBdkUpdateSource<crate::electrum::TcpElectrumTransport> {
    /// Live plaintext TCP Electrum full_scan (feature `electrum`). Not default CI.
    pub fn with_tcp_addr(addr: impl Into<String>) -> Self {
        Self::new(crate::electrum::TcpElectrumTransport::new(addr))
    }
}

#[cfg(feature = "electrum")]
impl ElectrumBdkUpdateSource<crate::electrum::TlsElectrumTransport> {
    /// Live TLS Electrum full_scan (feature `electrum`). Not default CI.
    pub fn with_tls_addr(addr: impl Into<String>) -> Self {
        Self::new(crate::electrum::TlsElectrumTransport::new(addr))
    }
}

impl<T: ElectrumTransport> BdkUpdateSource for ElectrumBdkUpdateSource<T> {
    fn full_scan_update(&self, wallet: &BdkBip84Wallet) -> Result<Update> {
        let stop_gap = normalize_stop_gap(self.stop_gap)?;
        let mut transport = self.transport.borrow_mut();
        let tip_val = transport
            .call("blockchain.headers.subscribe", &[])
            .map_err(|e| {
                WalletError::Onchain(format!(
                    "bdk Electrum full_scan headers.subscribe transport error: {e}"
                ))
            })?;
        let tip_height = parse_electrum_headers_subscribe_height(&tip_val).ok_or_else(|| {
            WalletError::Onchain(format!(
                "bdk Electrum full_scan tip height unparseable: {tip_val}"
            ))
        })?;
        let tip_u32 = tip_height_to_u32(tip_height)?;

        let mut txs_by_id: BTreeMap<String, ScannedTx> = BTreeMap::new();
        let last_ext = scan_keychain_electrum(
            &mut *transport,
            wallet,
            KeychainKind::External,
            stop_gap,
            &mut txs_by_id,
        )?;
        let last_int = scan_keychain_electrum(
            &mut *transport,
            wallet,
            KeychainKind::Internal,
            stop_gap,
            &mut txs_by_id,
        )?;

        let txs: Vec<ScannedTx> = txs_by_id.into_values().collect();
        chain_update_from_scanned_txs(wallet.network(), tip_u32, txs, last_ext, last_int)
    }
}

fn normalize_stop_gap(stop_gap: u32) -> Result<u32> {
    if stop_gap == 0 {
        return Err(WalletError::Onchain(
            "bdk full_scan stop_gap must be > 0".into(),
        ));
    }
    Ok(stop_gap.min(BDK_FULL_SCAN_MAX_INDEX))
}

fn tip_height_to_u32(tip: u64) -> Result<u32> {
    if tip == 0 {
        return Err(WalletError::Onchain(
            "bdk full_scan tip_height must be > 0 (genesis reserved)".into(),
        ));
    }
    u32::try_from(tip)
        .map_err(|_| WalletError::Onchain(format!("bdk full_scan tip_height {tip} exceeds u32")))
}

fn peek_spk(wallet: &BdkBip84Wallet, keychain: KeychainKind, index: u32) -> ScriptBuf {
    match keychain {
        KeychainKind::External => wallet.receive_script_pubkey(index),
        KeychainKind::Internal => wallet.change_script_pubkey(index),
    }
}

fn peek_address(wallet: &BdkBip84Wallet, keychain: KeychainKind, index: u32) -> String {
    match keychain {
        KeychainKind::External => wallet.peek_receive_address(index),
        KeychainKind::Internal => wallet.peek_change_address(index),
    }
}

fn scan_keychain_esplora<T: EsploraTransport>(
    transport: &mut T,
    wallet: &BdkBip84Wallet,
    keychain: KeychainKind,
    stop_gap: u32,
    txs_by_id: &mut BTreeMap<String, ScannedTx>,
) -> Result<Option<u32>> {
    let mut empty_run = 0u32;
    let mut last_active: Option<u32> = None;
    let mut index = 0u32;
    while empty_run < stop_gap && index < BDK_FULL_SCAN_MAX_INDEX {
        let addr = peek_address(wallet, keychain, index);
        let entries = fetch_esplora_address_history_paginated(transport, &addr, index)?;
        if entries.is_empty() {
            empty_run = empty_run.saturating_add(1);
        } else {
            empty_run = 0;
            last_active = Some(index);
            fetch_esplora_txs(transport, &entries, txs_by_id)?;
        }
        index = index.saturating_add(1);
    }
    Ok(last_active)
}

/// Fetch full Esplora address history: first page + `/txs/chain/{last}` pages.
///
/// Stops when a page has fewer than [`ESPLORA_TXS_PAGE_SIZE`] items. Hitting
/// [`ESPLORA_MAX_TX_PAGES`] with a full last page is a hard error (no silent
/// truncate).
fn fetch_esplora_address_history_paginated<T: EsploraTransport>(
    transport: &mut T,
    addr: &str,
    index: u32,
) -> Result<Vec<EsploraTxHistoryEntry>> {
    let mut all = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut last_txid: Option<String> = None;
    let mut pages = 0usize;

    loop {
        pages = pages.saturating_add(1);
        if pages > ESPLORA_MAX_TX_PAGES {
            return Err(WalletError::Onchain(format!(
                "bdk Esplora full_scan address history exceeded {ESPLORA_MAX_TX_PAGES} pages \
                 at index {index} (refusing silent truncate)"
            )));
        }
        let path = match &last_txid {
            None => esplora_address_txs_path(addr).map_err(|e| {
                WalletError::Onchain(format!("bdk Esplora full_scan address path: {e}"))
            })?,
            Some(cursor) => esplora_address_txs_chain_path(addr, cursor).map_err(|e| {
                WalletError::Onchain(format!("bdk Esplora full_scan chain path: {e}"))
            })?,
        };
        let body = transport.get_text(&path).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Esplora full_scan address txs transport error (index {index}): {e}"
            ))
        })?;
        let page = parse_esplora_address_txs_entries(&body).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Esplora full_scan address txs parse (index {index}): {e}"
            ))
        })?;
        let page_len = page.len();
        for e in page {
            if seen.insert(e.txid.clone()) {
                last_txid = Some(e.txid.clone());
                all.push(e);
            } else {
                // Duplicate cursor / loop guard: still advance last_txid so we
                // do not re-request the same page forever.
                last_txid = Some(e.txid.clone());
            }
        }
        if page_len < ESPLORA_TXS_PAGE_SIZE {
            break;
        }
        // Full page requires a cursor for the next chain request.
        if last_txid.is_none() {
            return Err(WalletError::Onchain(format!(
                "bdk Esplora full_scan full page without txids at index {index}"
            )));
        }
    }
    Ok(all)
}

fn observation_from_esplora_height(block_height: Option<u32>) -> BdkTxObservation {
    match block_height {
        Some(height) if height > 0 => BdkTxObservation::Confirmed { height },
        _ => BdkTxObservation::Unconfirmed,
    }
}

fn merge_observation(a: BdkTxObservation, b: BdkTxObservation) -> BdkTxObservation {
    match (a, b) {
        (
            BdkTxObservation::Confirmed { height: h1 },
            BdkTxObservation::Confirmed { height: h2 },
        ) => BdkTxObservation::Confirmed { height: h1.min(h2) },
        (c @ BdkTxObservation::Confirmed { .. }, _)
        | (_, c @ BdkTxObservation::Confirmed { .. }) => c,
        _ => BdkTxObservation::Unconfirmed,
    }
}

fn fetch_esplora_txs<T: EsploraTransport>(
    transport: &mut T,
    entries: &[EsploraTxHistoryEntry],
    txs_by_id: &mut BTreeMap<String, ScannedTx>,
) -> Result<()> {
    for entry in entries {
        let observation = observation_from_esplora_height(entry.block_height);
        if let Some(existing) = txs_by_id.get_mut(&entry.txid) {
            existing.observation = merge_observation(existing.observation, observation);
            continue;
        }
        let path = esplora_tx_hex_path(&entry.txid)
            .map_err(|e| WalletError::Onchain(format!("bdk Esplora full_scan tx hex path: {e}")))?;
        let hex_body = transport.get_text(&path).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Esplora full_scan tx hex transport error ({}): {e}",
                entry.txid
            ))
        })?;
        let tx = deserialize_tx_hex(&hex_body)?;
        let computed = tx.compute_txid().to_string();
        if computed != entry.txid {
            return Err(WalletError::Onchain(format!(
                "bdk Esplora full_scan tx hex txid mismatch: expected {}, got {computed}",
                entry.txid
            )));
        }
        txs_by_id.insert(entry.txid.clone(), ScannedTx { tx, observation });
    }
    Ok(())
}

fn scan_keychain_electrum<T: ElectrumTransport>(
    transport: &mut T,
    wallet: &BdkBip84Wallet,
    keychain: KeychainKind,
    stop_gap: u32,
    txs_by_id: &mut BTreeMap<String, ScannedTx>,
) -> Result<Option<u32>> {
    use serde_json::Value;

    let mut empty_run = 0u32;
    let mut last_active: Option<u32> = None;
    let mut index = 0u32;
    while empty_run < stop_gap && index < BDK_FULL_SCAN_MAX_INDEX {
        let spk = peek_spk(wallet, keychain, index);
        let sh = electrum_script_hash_from_script(&spk);
        let hist = transport
            .call(
                "blockchain.scripthash.get_history",
                &[Value::String(sh.clone())],
            )
            .map_err(|e| {
                WalletError::Onchain(format!(
                    "bdk Electrum full_scan get_history transport error (index {index}): {e}"
                ))
            })?;
        let entries = parse_electrum_get_history_entries(&hist).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Electrum full_scan get_history parse (index {index}): {e}"
            ))
        })?;
        if entries.is_empty() {
            empty_run = empty_run.saturating_add(1);
        } else {
            empty_run = 0;
            last_active = Some(index);
            fetch_electrum_txs(transport, &entries, txs_by_id)?;
        }
        index = index.saturating_add(1);
    }
    Ok(last_active)
}

fn observation_from_electrum_height(height: i64) -> BdkTxObservation {
    if height > 0 {
        match u32::try_from(height) {
            Ok(h) => BdkTxObservation::Confirmed { height: h },
            Err(_) => BdkTxObservation::Unconfirmed,
        }
    } else {
        BdkTxObservation::Unconfirmed
    }
}

fn fetch_electrum_txs<T: ElectrumTransport>(
    transport: &mut T,
    entries: &[crate::electrum::ElectrumHistoryEntry],
    txs_by_id: &mut BTreeMap<String, ScannedTx>,
) -> Result<()> {
    use serde_json::Value;

    for entry in entries {
        let observation = observation_from_electrum_height(entry.height);
        if let Some(existing) = txs_by_id.get_mut(&entry.txid) {
            existing.observation = merge_observation(existing.observation, observation);
            continue;
        }
        let result = transport
            .call(
                "blockchain.transaction.get",
                &[Value::String(entry.txid.clone()), Value::Bool(false)],
            )
            .map_err(|e| {
                WalletError::Onchain(format!(
                    "bdk Electrum full_scan transaction.get transport error ({}): {e}",
                    entry.txid
                ))
            })?;
        let hex_body = parse_electrum_transaction_get_hex(&result).map_err(|e| {
            WalletError::Onchain(format!(
                "bdk Electrum full_scan transaction.get parse ({}): {e}",
                entry.txid
            ))
        })?;
        let tx = deserialize_tx_hex(&hex_body)?;
        let computed = tx.compute_txid().to_string();
        if computed != entry.txid {
            return Err(WalletError::Onchain(format!(
                "bdk Electrum full_scan tx hex txid mismatch: expected {}, got {computed}",
                entry.txid
            )));
        }
        txs_by_id.insert(entry.txid.clone(), ScannedTx { tx, observation });
    }
    Ok(())
}

fn deserialize_tx_hex(hex_body: &str) -> Result<Transaction> {
    let trimmed = hex_body.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Onchain(
            "bdk full_scan tx hex body is empty".into(),
        ));
    }
    deserialize_hex::<Transaction>(trimmed)
        .map_err(|e| WalletError::Onchain(format!("bdk full_scan tx hex deserialize failed: {e}")))
}

/// Encode a transaction as consensus hex (fixtures / tests).
pub fn serialize_tx_hex(tx: &Transaction) -> String {
    bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx)
}

/// Failure of product [`select_and_prepare_bip84_spend_with_bdk_sync`].
///
/// **Do not** use [`crate::descriptor_wallet::GapSyncSpendFailure`] for BDK
/// spend: its `notice_lines` hard-code gap-limit copy and would mislabel a BDK
/// path. This type wires [`bdk_sync_notice_lines`] instead.
///
/// Dual-arm:
/// - [`Self::Sync`]: failed before a usable snapshot (fee 0, source error, …).
/// - [`Self::AfterSync`]: sync succeeded; select/prepare failed afterward.
pub enum BdkSyncSpendFailure {
    /// Sync stage failed; no post-sync snapshot.
    Sync(WalletError),
    /// Sync produced a snapshot; select/prepare failed afterward.
    AfterSync {
        sync: WalletSyncSnapshot,
        cause: WalletError,
    },
}

impl BdkSyncSpendFailure {
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

    /// Honest BDK sync notice lines (empty for [`Self::Sync`]).
    ///
    /// Uses [`bdk_sync_notice_lines`] — never gap-limit copy, never invents
    /// balance/UTXO counts.
    pub fn notice_lines(&self) -> Vec<String> {
        match self {
            Self::Sync(_) => Vec::new(),
            Self::AfterSync { sync, .. } => bdk_sync_notice_lines(sync),
        }
    }

    /// Cause message, then any BDK notice lines (multi-line UX).
    pub fn display_lines(&self) -> Vec<String> {
        let mut lines = vec![self.cause().to_string()];
        lines.extend(self.notice_lines());
        lines
    }

    /// `true` when select/prepare failed after a successful BDK sync.
    pub fn is_after_sync(&self) -> bool {
        matches!(self, Self::AfterSync { .. })
    }

    /// Consume into the underlying [`WalletError`], **dropping** any AfterSync
    /// snapshot (and therefore BDK notices). Prefer [`Self::notice_lines`] /
    /// [`Self::display_lines`] for product UX.
    pub fn into_cause(self) -> WalletError {
        match self {
            Self::Sync(e) | Self::AfterSync { cause: e, .. } => e,
        }
    }
}

impl std::fmt::Display for BdkSyncSpendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cause())
    }
}

impl std::fmt::Debug for BdkSyncSpendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(e) => f.debug_tuple("Sync").field(e).finish(),
            Self::AfterSync { sync, cause } => f
                .debug_struct("AfterSync")
                .field("receive_gap", &sync.receive_gap)
                .field("change_gap", &sync.change_gap)
                .field("utxo_count", &sync.utxos.len())
                .field("cause", cause)
                .finish(),
        }
    }
}

/// Open a product [`BdkUpdateSource`] from the same chain-source config as
/// gap-limit spend (`GROK_BITCOIN_CHAIN_SOURCE` + URL/addr env).
///
/// Feature honesty (never hangs on missing feature):
/// - `mempool` → [`bdk_utxo_sync_mempool_unsupported_error`] (no full_scan map)
/// - `esplora` without feature `esplora` → structured error
/// - `electrum` without feature `electrum` → structured error
/// - `esplora`/`electrum` with matching feature → live HTTP/TCP/TLS adapter
///
/// Re-validates Esplora URL / Electrum endpoint shape so hand-built configs
/// cannot bypass offline gates. Does **not** invent UTXOs or claim Success.
pub fn open_product_bdk_update_source(
    config: &ProductChainSourceConfig,
) -> Result<Box<dyn BdkUpdateSource>> {
    match config.kind {
        ChainSourceKind::Mempool => Err(bdk_utxo_sync_mempool_unsupported_error()),
        ChainSourceKind::Esplora => {
            let url = validated_esplora_url_from_config(config)?;
            open_esplora_bdk_update_source(url)
        }
        ChainSourceKind::Electrum => {
            let (addr, tls) = validated_electrum_endpoint_from_config(config)?;
            open_electrum_bdk_update_source(&addr, tls)
        }
    }
}

fn open_esplora_bdk_update_source(base_url: &str) -> Result<Box<dyn BdkUpdateSource>> {
    #[cfg(feature = "esplora")]
    {
        Ok(Box::new(EsploraBdkUpdateSource::with_http_base_url(
            base_url,
        )?))
    }
    #[cfg(not(feature = "esplora"))]
    {
        let _ = base_url;
        Err(WalletError::Onchain(
            "bdk utxo sync with chain source 'esplora' requires feature `esplora` \
             (not compiled into this build; rebuild with --features bdk,esplora, set \
             GROK_BITCOIN_ESPLORA_URL, or use GROK_BITCOIN_UTXO_SYNC=gap for \
             default gap-limit ChainSource)"
                .into(),
        ))
    }
}

fn open_electrum_bdk_update_source(addr: &str, tls: bool) -> Result<Box<dyn BdkUpdateSource>> {
    #[cfg(feature = "electrum")]
    {
        if tls {
            Ok(Box::new(ElectrumBdkUpdateSource::with_tls_addr(addr)))
        } else {
            Ok(Box::new(ElectrumBdkUpdateSource::with_tcp_addr(addr)))
        }
    }
    #[cfg(not(feature = "electrum"))]
    {
        let _ = (addr, tls);
        Err(WalletError::Onchain(
            "bdk utxo sync with chain source 'electrum' requires feature `electrum` \
             (not compiled into this build; rebuild with --features bdk,electrum, set \
             GROK_BITCOIN_ELECTRUM_ADDR [and optional GROK_BITCOIN_ELECTRUM_TLS=1 or \
             ssl://host:port for TLS], or use GROK_BITCOIN_UTXO_SYNC=gap for \
             default gap-limit ChainSource)"
                .into(),
        ))
    }
}

/// Product UTXO list / balance via BDK apply_update (spent-aware).
///
/// Applies `source.full_scan_update`, then returns a
/// [`WalletSyncSnapshot`]. Snapshot `utxos` / `balance` are authoritative —
/// do not re-list. Never invents coins. Wrong descriptors fail at wallet
/// construction (caller). Source errors propagate as [`WalletError`] (never
/// empty Success).
///
/// **Not** the default product path; enable feature `bdk` and pass a real or
/// mock [`BdkUpdateSource`].
pub fn list_bip84_utxos_with_bdk_sync(
    wallet: &mut BdkBip84Wallet,
    source: &dyn BdkUpdateSource,
) -> Result<WalletSyncSnapshot> {
    wallet.sync_with_source(source)
}

/// Product spend: BDK sync → select/prepare from snapshot UTXOs (no re-list).
///
/// Uses existing BIP84 P2WPKH sign/finalize (`select_and_prepare_bip84_spend_from_utxos`)
/// with a lightweight [`DescriptorWallet`] rebuilt from the same mnemonic for
/// change address + sign gap. Sync failures → [`BdkSyncSpendFailure::Sync`];
/// select/prepare failures after sync → [`BdkSyncSpendFailure::AfterSync`].
///
/// **Notices:** use [`BdkSyncSpendFailure::notice_lines`] / [`display_lines`](BdkSyncSpendFailure::display_lines)
/// (BDK copy via [`bdk_sync_notice_lines`]). Do **not** cast to
/// [`crate::descriptor_wallet::GapSyncSpendFailure`] — its notices mislabel
/// BDK as gap-limit.
///
/// **Sign gap:** clamped to [`BDK_PRODUCT_SIGN_GAP_CAP`] (`MAX_ADDRESS_GAP`).
/// Snapshot UTXOs beyond that cap fail honestly (no silent drop).
///
/// Gap-limit path remains the default product baseline when feature `bdk` is
/// off or when callers prefer [`crate::descriptor_wallet::select_and_prepare_bip84_spend_with_gap_sync`].
#[allow(clippy::too_many_arguments)]
pub fn select_and_prepare_bip84_spend_with_bdk_sync(
    bdk: &mut BdkBip84Wallet,
    source: &dyn BdkUpdateSource,
    mnemonic: &MnemonicSecret,
    payment_address: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    passphrase: &str,
) -> std::result::Result<GapSyncedPreparedSpend, BdkSyncSpendFailure> {
    if fee_rate_sat_vb == 0 {
        return Err(BdkSyncSpendFailure::Sync(WalletError::Onchain(
            "fee rate must be > 0 sat/vB for product spend".into(),
        )));
    }
    let sync = bdk
        .sync_with_source(source)
        .map_err(BdkSyncSpendFailure::Sync)?;
    // Product DescriptorWallet for change + sign scan. Cap derivation work so a
    // hostile/buggy BdkUpdateSource cannot force O(huge) key scans.
    let raw_gap = bdk
        .revealed_external_count()
        .max(bdk.revealed_internal_count())
        .max(sync.receive_gap)
        .max(sync.change_gap)
        .max(1);
    let address_gap = raw_gap.min(BDK_PRODUCT_SIGN_GAP_CAP);
    if let Err(cause) = assert_snapshot_utxos_within_sign_gap(bdk, &sync.utxos, address_gap) {
        return Err(BdkSyncSpendFailure::AfterSync { sync, cause });
    }
    let product_wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        passphrase,
        bdk.network(),
        address_gap,
    )
    .map_err(BdkSyncSpendFailure::Sync)?;
    match select_and_prepare_bip84_spend_from_utxos(
        &product_wallet,
        &sync.utxos,
        mnemonic,
        payment_address,
        amount_sats,
        fee_rate_sat_vb,
        passphrase,
        address_gap,
    ) {
        Ok(prepared) => Ok(GapSyncedPreparedSpend { prepared, sync }),
        Err(cause) => Err(BdkSyncSpendFailure::AfterSync { sync, cause }),
    }
}

/// Fail closed when a snapshot UTXO sits at derivation index ≥ `sign_gap`.
///
/// Prevents silently dropping deep coins after clamping sign/construction gap
/// to [`BDK_PRODUCT_SIGN_GAP_CAP`].
fn assert_snapshot_utxos_within_sign_gap(
    bdk: &BdkBip84Wallet,
    utxos: &[WalletUtxo],
    sign_gap: u32,
) -> Result<()> {
    for u in utxos {
        let keychain = if u.is_change {
            KeychainKind::Internal
        } else {
            KeychainKind::External
        };
        match address_index_from_utxo(bdk, u, keychain) {
            Some(i) if i < sign_gap => {}
            Some(i) => {
                return Err(WalletError::Onchain(format!(
                    "bdk UTXO at derivation index {i} exceeds product sign gap cap {sign_gap} \
                     (BDK_PRODUCT_SIGN_GAP_CAP / MAX_ADDRESS_GAP); refusing silent drop — \
                     raise cap only with an explicit product decision"
                )));
            }
            None => {
                return Err(WalletError::Onchain(format!(
                    "bdk snapshot UTXO address could not be mapped to a derivation index \
                     within sign gap {sign_gap} (chain={keychain:?}, addr={})",
                    u.address
                )));
            }
        }
    }
    Ok(())
}

/// Build a confirmed-chain [`Update`] from full transactions (offline helper).
///
/// - `tip_height` becomes the chain tip (genesis at 0 + tip).
/// - All txs are anchored at `tip_height` (confirmed) — **fixture convenience**
///   for spent-presence / index tests. Prefer
///   [`chain_update_from_scanned_txs`] for transport full_scan (real heights /
///   unconfirmed `seen_ats`).
/// - `last_active_external` / `last_active_internal` advance BDK keychain
///   reveal (script scan depth) — this is what recovers deep indices without
///   our `MAX_ADDRESS_GAP` UTXO-list loop.
///
/// Used by tests and any offline fixture path that intentionally tip-anchors.
pub fn chain_update_from_transactions(
    network: Network,
    tip_height: u32,
    txs: Vec<Transaction>,
    last_active_external: Option<u32>,
    last_active_internal: Option<u32>,
) -> Result<Update> {
    let scanned: Vec<ScannedTx> = txs
        .into_iter()
        .map(|tx| ScannedTx {
            tx,
            observation: BdkTxObservation::Confirmed { height: tip_height },
        })
        .collect();
    chain_update_from_scanned_txs(
        network,
        tip_height,
        scanned,
        last_active_external,
        last_active_internal,
    )
}

/// Build a BDK [`Update`] from scanned txs with **per-tx** confirmation status.
///
/// - Confirmed (`BdkTxObservation::Confirmed { height }`): anchor at that
///   height (included in local checkpoint); confirmation depth =
///   `tip_height - height + 1`.
/// - Unconfirmed: `seen_ats` only (no tip anchor) so product
///   `confirmations == 0` / `confirmed_only` stays honest.
/// - `height > tip_height` → hard error (never invents future confirmation).
/// - Intermediate checkpoint heights use deterministic synthetic block hashes
///   (height-derived); enough for confirmation math without merkle proofs.
///
/// Transport full_scan paths use this. Offline tip-anchored fixtures may still
/// use [`chain_update_from_transactions`].
pub fn chain_update_from_scanned_txs(
    network: Network,
    tip_height: u32,
    txs: Vec<ScannedTx>,
    last_active_external: Option<u32>,
    last_active_internal: Option<u32>,
) -> Result<Update> {
    if tip_height == 0 {
        return Err(WalletError::Onchain(
            "bdk chain update tip_height must be > 0 (genesis reserved for height 0)".into(),
        ));
    }

    let genesis_hash = BlockHash::from_slice(network.chain_hash().as_bytes())
        .map_err(|e| WalletError::Onchain(format!("bdk genesis blockhash from network: {e}")))?;

    // Collect confirmation heights that must appear in the local chain.
    let mut height_set = std::collections::BTreeSet::new();
    height_set.insert(0u32);
    height_set.insert(tip_height);
    for s in &txs {
        if let BdkTxObservation::Confirmed { height } = s.observation {
            if height == 0 {
                return Err(WalletError::Onchain(
                    "bdk chain update confirmed height must be > 0".into(),
                ));
            }
            if height > tip_height {
                return Err(WalletError::Onchain(format!(
                    "bdk chain update confirmed height {height} exceeds tip {tip_height}"
                )));
            }
            height_set.insert(height);
        }
    }

    let block_ids: Vec<BlockId> = height_set
        .into_iter()
        .map(|height| BlockId {
            height,
            hash: if height == 0 {
                genesis_hash
            } else {
                synthetic_block_hash(height)
            },
        })
        .collect();
    let chain = CheckPoint::from_block_ids(block_ids).map_err(|_| {
        WalletError::Onchain("bdk CheckPoint::from_block_ids failed (ordering?)".into())
    })?;

    let mut last_active = std::collections::BTreeMap::new();
    if let Some(i) = last_active_external {
        last_active.insert(KeychainKind::External, i);
    }
    if let Some(i) = last_active_internal {
        last_active.insert(KeychainKind::Internal, i);
    }

    // Deterministic seen_at for unconfirmed (offline-stable; not wall-clock).
    const UNCONFIRMED_SEEN_AT: u64 = 1;

    let mut tx_update = TxUpdate::default();
    for scanned in txs {
        let txid = scanned.tx.compute_txid();
        tx_update.txs.push(Arc::new(scanned.tx));
        match scanned.observation {
            BdkTxObservation::Confirmed { height } => {
                let anchor = ConfirmationBlockTime {
                    block_id: BlockId {
                        height,
                        hash: if height == 0 {
                            genesis_hash
                        } else {
                            synthetic_block_hash(height)
                        },
                    },
                    confirmation_time: 1,
                };
                tx_update.anchors.insert((anchor, txid));
            }
            BdkTxObservation::Unconfirmed => {
                tx_update.seen_ats.insert((txid, UNCONFIRMED_SEEN_AT));
            }
        }
    }

    #[allow(clippy::field_reassign_with_default)]
    {
        let mut update = Update::default();
        update.chain = Some(chain);
        update.last_active_indices = last_active;
        update.tx_update = tx_update;
        Ok(update)
    }
}

/// Deterministic non-genesis block hash from height (offline / transport path).
///
/// Not a real chain hash — only needs uniqueness per height for CheckPoint +
/// ConfirmationBlockTime identity. Height 0 must use network genesis instead.
fn synthetic_block_hash(height: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&height.to_le_bytes());
    // Tag so synthetic hashes never collide with all-zeros tip of older fixtures.
    bytes[4] = 0xbd;
    bytes[5] = 0x6b;
    BlockHash::from_byte_array(bytes)
}

/// Minimal unsigned coinbase-like funding tx paying `script_pubkey`.
pub fn funding_tx_to_script(
    script_pubkey: ScriptBuf,
    amount_sats: u64,
    locktime: u32,
) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey,
        }],
    }
}

/// Spend `prev` fully (minus optional residual not modeled) to `script_pubkey`.
///
/// Offline fixture only — not a fee-aware builder. Sets one input and one output.
pub fn spend_tx_from_outpoint(
    prev: OutPoint,
    script_pubkey: ScriptBuf,
    amount_sats: u64,
    locktime: u32,
) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![TxIn {
            previous_output: prev,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey,
        }],
    }
}

/// Notice lines for BDK sync snapshots (product UX; never invents balances).
pub fn bdk_sync_notice_lines(snap: &WalletSyncSnapshot) -> Vec<String> {
    let mut lines = vec![
        "bdk_wallet auto-sync (spent-tx history + keychain index); not gap-limit ChainSource."
            .to_owned(),
    ];
    if snap.extended_receive_by > 0 || snap.extended_change_by > 0 {
        lines.push(format!(
            "BDK keychain advanced during sync (receive +{}, change +{}; \
             windows receive={}, change={}).",
            snap.extended_receive_by, snap.extended_change_by, snap.receive_gap, snap.change_gap
        ));
    }
    lines
}

fn local_output_to_wallet_utxo(
    local: &bdk_wallet::LocalOutput,
    tip_height: u32,
    network: Network,
) -> Result<WalletUtxo> {
    let address = Address::from_script(&local.txout.script_pubkey, network).map_err(|e| {
        WalletError::Onchain(format!(
            "bdk utxo script is not a standard address for {network:?}: {e}"
        ))
    })?;
    let confirmations = match &local.chain_position {
        ChainPosition::Confirmed { anchor, .. } => {
            let bh = anchor.block_id.height;
            tip_height.saturating_sub(bh).saturating_add(1)
        }
        ChainPosition::Unconfirmed { .. } => 0,
    };
    Ok(WalletUtxo {
        outpoint: OutPointRef::new(local.outpoint.txid.to_string(), local.outpoint.vout),
        amount_sats: local.txout.value.to_sat(),
        address: address.to_string(),
        confirmations,
        is_change: local.keychain == KeychainKind::Internal,
    })
}

fn address_index_from_utxo(
    wallet: &BdkBip84Wallet,
    utxo: &WalletUtxo,
    keychain: KeychainKind,
) -> Option<u32> {
    // Match by address string against peeked indices up to revealed window.
    let limit = match keychain {
        KeychainKind::External => wallet.revealed_external_count().max(1),
        KeychainKind::Internal => wallet.revealed_internal_count().max(1),
    };
    // Also scan a little past highest known for safety (last_active may lag peek).
    let scan_to = limit.saturating_add(8);
    for i in 0..scan_to {
        let addr = match keychain {
            KeychainKind::External => wallet.peek_receive_address(i),
            KeychainKind::Internal => wallet.peek_change_address(i),
        };
        if addr == utxo.address {
            return Some(i);
        }
    }
    None
}

/// Re-export commonly needed BDK types for fixtures / advanced callers.
pub mod types {
    pub use bdk_wallet::bitcoin::{
        Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    pub use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
    pub use bdk_wallet::{KeychainKind, Update, Wallet};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::import_mnemonic;

    /// BIP-39 test mnemonic (public vector; not a funded wallet).
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> BdkBip84Wallet {
        let m = import_mnemonic(PHRASE).unwrap();
        BdkBip84Wallet::from_mnemonic(&m, Network::Regtest, 20).unwrap()
    }

    #[test]
    fn bdk_capability_flag_true() {
        assert!(BDK_SYNC_AVAILABLE);
        assert_eq!(BDK_PRODUCT_SIGN_GAP_CAP, MAX_ADDRESS_GAP);
    }

    #[test]
    fn create_watch_only_empty() {
        let w = test_wallet();
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
        assert_eq!(w.balance().unwrap().total_sats(), 0);
        assert!(w.receive_descriptor().starts_with("wpkh("));
        assert!(w.change_descriptor().starts_with("wpkh("));
    }

    #[test]
    fn debug_redacts_descriptor_xpubs() {
        let w = test_wallet();
        let dbg = format!("{w:?}");
        assert!(dbg.contains("[descriptor redacted]"));
        assert!(
            !dbg.contains("tpub"),
            "Debug must not leak account xpub: {dbg}"
        );
        assert!(
            !dbg.contains("xpub") && !dbg.contains("tpub"),
            "Debug must not leak account xpub: {dbg}"
        );
        // Accessors still return full strings for product use.
        assert!(w.receive_descriptor().contains("tpub") || w.receive_descriptor().contains("xpub"));
    }

    #[test]
    fn spent_tx_history_drops_spent_utxo() {
        let mut w = test_wallet();
        let spk0 = w.receive_script_pubkey(0);
        let spk5 = w.receive_script_pubkey(5);
        let foreign = Address::from_script(
            &ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x11; 20]).unwrap(),
            ),
            Network::Regtest,
        )
        .unwrap();

        let fund0 = funding_tx_to_script(spk0, 50_000, 0);
        let fund5 = funding_tx_to_script(spk5, 30_000, 1);
        let spend0 = spend_tx_from_outpoint(
            OutPoint {
                txid: fund0.compute_txid(),
                vout: 0,
            },
            foreign.script_pubkey(),
            49_000,
            2,
        );

        let update = chain_update_from_transactions(
            Network::Regtest,
            100,
            vec![fund0, fund5, spend0],
            Some(5),
            None,
        )
        .unwrap();

        let source = MockBdkUpdateSource::with_update(update);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();

        assert_eq!(
            snap.utxos.len(),
            1,
            "spent fund0 must leave only fund5; got {:?}",
            snap.utxos
        );
        assert_eq!(snap.utxos[0].amount_sats, 30_000);
        assert_eq!(snap.highest_used_receive, Some(5));
        assert_eq!(snap.balance.confirmed_sats, 30_000);
        assert!(snap.receive_gap > 5);
        assert!(!snap.utxos[0].is_change);
        assert!(snap.utxos[0].confirmations >= 1);

        let notices = bdk_sync_notice_lines(&snap);
        assert!(notices[0].contains("bdk_wallet"));
        assert!(!notices[0].contains("Gap-limit"));
    }

    #[test]
    fn deep_index_recovered_via_last_active() {
        let mut w = test_wallet();
        let spk = w.receive_script_pubkey(42);
        let fund = funding_tx_to_script(spk, 12_345, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 50, vec![fund], Some(42), None)
                .unwrap();
        w.apply_update(update).unwrap();
        let utxos = w.list_wallet_utxos().unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount_sats, 12_345);
        assert_eq!(w.revealed_external_count(), 43); // next after 42
    }

    #[test]
    fn change_chain_marked_is_change() {
        let mut w = test_wallet();
        let spk = w.change_script_pubkey(1);
        let fund = funding_tx_to_script(spk, 8_000, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 10, vec![fund], None, Some(1))
                .unwrap();
        w.apply_update(update).unwrap();
        let utxos = w.list_wallet_utxos().unwrap();
        assert_eq!(utxos.len(), 1);
        assert!(utxos[0].is_change);
        assert_eq!(utxos[0].amount_sats, 8_000);
    }

    #[test]
    fn snapshot_compatible_with_product_balance() {
        let mut w = test_wallet();
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 100_000, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 5, vec![fund], Some(0), None).unwrap();
        w.apply_update(update).unwrap();
        let snap = w.snapshot(0, 0).unwrap();
        assert_eq!(snap.balance.total_sats(), 100_000);
        assert_eq!(snap.utxos.len(), 1);
        // Outpoint hex is 64 chars
        assert_eq!(snap.utxos[0].outpoint.txid.len(), 64);
    }

    #[test]
    fn descriptors_match_descriptor_wallet() {
        let m = import_mnemonic(PHRASE).unwrap();
        let dw = DescriptorWallet::from_mnemonic(&m, Network::Regtest, 5).unwrap();
        let bdk = BdkBip84Wallet::from_descriptor_wallet(&dw).unwrap();
        assert_eq!(bdk.receive_descriptor(), dw.receive_descriptor);
        assert_eq!(bdk.change_descriptor(), dw.change_descriptor);
        // Index 0 address must match product BIP84 derivation.
        assert_eq!(bdk.peek_receive_address(0), dw.receive_addresses()[0]);
    }

    #[test]
    fn zero_fee_spend_fails_sync_arm() {
        let mut w = test_wallet();
        let source = MockBdkUpdateSource::new();
        let m = import_mnemonic(PHRASE).unwrap();
        let err = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w,
            &source,
            &m,
            "bcrt1qexample",
            1000,
            0,
            "",
        )
        .unwrap_err();
        assert!(!err.is_after_sync());
        assert!(err.cause().to_string().contains("fee rate"));
        assert!(err.notice_lines().is_empty());
    }

    #[test]
    fn failing_update_source_propagates_to_list_and_spend_sync() {
        let mut w = test_wallet();
        let source = FailingBdkUpdateSource::new("mock full_scan transport refused");
        let list_err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            list_err
                .to_string()
                .contains("mock full_scan transport refused"),
            "{list_err}"
        );
        // Never invent empty Success on source failure.
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);

        let m = import_mnemonic(PHRASE).unwrap();
        let pay_to = w.peek_receive_address(1);
        let spend_err = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w, &source, &m, &pay_to, 1_000, 5, "",
        )
        .unwrap_err();
        assert!(!spend_err.is_after_sync());
        assert!(spend_err.cause().to_string().contains("mock full_scan"));
        assert!(spend_err.sync_snapshot().is_none());
        assert!(spend_err.notice_lines().is_empty());
    }

    #[test]
    fn spend_happy_path_prepare_from_bdk_snapshot() {
        let m = import_mnemonic(PHRASE).unwrap();
        let mut w = BdkBip84Wallet::from_mnemonic(&m, Network::Regtest, 20).unwrap();
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 100_000, 0);
        let fund_txid = fund.compute_txid().to_string();
        let update =
            chain_update_from_transactions(Network::Regtest, 10, vec![fund], Some(1), None)
                .unwrap();
        let source = MockBdkUpdateSource::with_update(update);
        let pay_to = w.peek_receive_address(1);

        let synced = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w, &source, &m, &pay_to, 25_000, 5, "",
        )
        .expect("funded BDK prepare must succeed");

        assert_eq!(synced.prepared.payment_sats, 25_000);
        assert!(synced.prepared.fee_sats > 0);
        assert!(!synced.prepared.raw_hex().is_empty());
        assert_eq!(synced.prepared.input_count, 1);
        assert_eq!(synced.prepared.selected_inputs.len(), 1);
        assert_eq!(synced.prepared.selected_inputs[0].outpoint.txid, fund_txid);
        assert_eq!(synced.prepared.selected_inputs[0].outpoint.vout, 0);
        assert_eq!(synced.sync.utxos.len(), 1);
        assert_eq!(synced.sync.utxos[0].amount_sats, 100_000);
        // Signed tx has a real txid (64 hex).
        assert_eq!(synced.prepared.txid_hex().len(), 64);
    }

    #[test]
    fn spend_after_sync_insufficient_funds_uses_bdk_notices_not_gap_copy() {
        let m = import_mnemonic(PHRASE).unwrap();
        let mut w = BdkBip84Wallet::from_mnemonic(&m, Network::Regtest, 20).unwrap();
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 5_000, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 10, vec![fund], Some(0), None)
                .unwrap();
        let source = MockBdkUpdateSource::with_update(update);
        let pay_to = w.peek_receive_address(1);

        let err = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w, &source, &m, &pay_to, 4_000, 50, "",
        )
        .unwrap_err();
        assert!(err.is_after_sync());
        let notices = err.notice_lines();
        assert!(
            notices.iter().any(|l| l.contains("bdk_wallet")),
            "AfterSync notices must use BDK copy, got {notices:?}"
        );
        assert!(
            notices
                .iter()
                .all(|l| !l.contains("Gap-limit ChainSource") && !l.contains("not full bdk")),
            "must not mislabel BDK as gap-limit: {notices:?}"
        );
        let display = err.display_lines().join("\n");
        assert!(!display.contains("not full bdk_wallet auto-sync"));
    }

    #[test]
    fn spend_refuses_utxo_beyond_sign_gap_cap() {
        // Hostile source: last_active past BDK_PRODUCT_SIGN_GAP_CAP with a deep UTXO.
        let m = import_mnemonic(PHRASE).unwrap();
        let mut w = BdkBip84Wallet::from_mnemonic(&m, Network::Regtest, 20).unwrap();
        let deep = BDK_PRODUCT_SIGN_GAP_CAP; // index == cap is out of range (need index < cap)
        let fund = funding_tx_to_script(w.receive_script_pubkey(deep), 50_000, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 20, vec![fund], Some(deep), None)
                .unwrap();
        let source = MockBdkUpdateSource::with_update(update);
        let pay_to = w.peek_receive_address(0);

        let err = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w, &source, &m, &pay_to, 10_000, 5, "",
        )
        .unwrap_err();
        assert!(err.is_after_sync());
        let msg = err.cause().to_string();
        assert!(
            msg.contains("exceeds product sign gap cap") || msg.contains("sign gap"),
            "expected sign-gap honesty, got: {msg}"
        );
        // Coins remain on the BDK wallet (not silently dropped from graph).
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 1);
    }

    #[test]
    fn empty_mock_source_snapshot_zero() {
        let mut w = test_wallet();
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &MockBdkUpdateSource::new()).unwrap();
        assert!(snap.utxos.is_empty());
        assert_eq!(snap.balance.total_sats(), 0);
    }

    #[test]
    fn tip_height_zero_rejected() {
        let err =
            chain_update_from_transactions(Network::Regtest, 0, vec![], None, None).unwrap_err();
        assert!(err.to_string().contains("tip_height"));
    }

    /// Esplora transport path: spent-tx drop via real full_scan fixtures.
    #[test]
    fn esplora_transport_full_scan_spent_tx_drop() {
        use crate::esplora::MockEsploraTransport;
        use serde_json::json;

        let mut w = test_wallet();
        let spk0 = w.receive_script_pubkey(0);
        let spk5 = w.receive_script_pubkey(5);
        let addr0 = w.peek_receive_address(0);
        let addr5 = w.peek_receive_address(5);
        let foreign = Address::from_script(
            &ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x11; 20]).unwrap(),
            ),
            Network::Regtest,
        )
        .unwrap();

        let fund0 = funding_tx_to_script(spk0, 50_000, 0);
        let fund5 = funding_tx_to_script(spk5, 30_000, 1);
        let spend0 = spend_tx_from_outpoint(
            OutPoint {
                txid: fund0.compute_txid(),
                vout: 0,
            },
            foreign.script_pubkey(),
            49_000,
            2,
        );
        let fund0_id = fund0.compute_txid().to_string();
        let fund5_id = fund5.compute_txid().to_string();
        let spend0_id = spend0.compute_txid().to_string();

        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        // Address 0: fund + spend history.
        mock.insert_fixture(
            &format!("/address/{addr0}/txs"),
            json!([
                {"txid": fund0_id, "status": {"confirmed": true, "block_height": 90}},
                {"txid": spend0_id, "status": {"confirmed": true, "block_height": 95}}
            ])
            .to_string(),
        );
        mock.insert_fixture(
            &format!("/address/{addr5}/txs"),
            json!([{"txid": fund5_id, "status": {"confirmed": true, "block_height": 91}}])
                .to_string(),
        );
        mock.insert_fixture(&format!("/tx/{fund0_id}/hex"), serialize_tx_hex(&fund0));
        mock.insert_fixture(&format!("/tx/{fund5_id}/hex"), serialize_tx_hex(&fund5));
        mock.insert_fixture(&format!("/tx/{spend0_id}/hex"), serialize_tx_hex(&spend0));

        // stop_gap must exceed empty run between index 0 and 5 (4 empties).
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 6);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();

        assert_eq!(
            snap.utxos.len(),
            1,
            "spent fund0 must leave only fund5; got {:?}",
            snap.utxos
        );
        assert_eq!(snap.utxos[0].amount_sats, 30_000);
        assert_eq!(snap.highest_used_receive, Some(5));
        assert_eq!(snap.balance.confirmed_sats, 30_000);
        // Transport was exercised (tip + txs + hex), not only MockBdkUpdateSource.
        let calls = &source.transport().calls;
        assert!(
            calls.iter().any(|p| p == "/blocks/tip/height"),
            "expected tip probe: {calls:?}"
        );
        assert!(
            calls.iter().any(|p| p.ends_with("/txs")),
            "expected address txs: {calls:?}"
        );
        assert!(
            calls.iter().any(|p| p.ends_with("/hex")),
            "expected tx hex: {calls:?}"
        );
    }

    #[test]
    fn esplora_transport_deep_index_and_empty_wallet() {
        use crate::esplora::MockEsploraTransport;
        use serde_json::json;

        let mut w = test_wallet();
        // Index 15 is within default BIP44 stop-gap (20) from 0 with no intermediate activity.
        let deep = 15u32;
        let addr = w.peek_receive_address(deep);
        let fund = funding_tx_to_script(w.receive_script_pubkey(deep), 12_345, 0);
        let fund_id = fund.compute_txid().to_string();

        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "50");
        mock.insert_fixture(
            &format!("/address/{addr}/txs"),
            json!([{"txid": fund_id}]).to_string(),
        );
        mock.insert_fixture(&format!("/tx/{fund_id}/hex"), serialize_tx_hex(&fund));

        let source = EsploraBdkUpdateSource::new(mock);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.utxos[0].amount_sats, 12_345);
        assert_eq!(w.revealed_external_count(), deep + 1);

        // Empty wallet: only tip + empty look-ahead → zero UTXOs, not invented.
        let mut w2 = test_wallet();
        let mut mock2 = MockEsploraTransport::new().with_default_empty_address_txs();
        mock2.insert_fixture("/blocks/tip/height", "10");
        let source2 = EsploraBdkUpdateSource::with_stop_gap(mock2, 2);
        let empty = list_bip84_utxos_with_bdk_sync(&mut w2, &source2).unwrap();
        assert!(empty.utxos.is_empty());
        assert_eq!(empty.balance.total_sats(), 0);
    }

    #[test]
    fn esplora_transport_error_is_sync_failure_not_empty_success() {
        use crate::esplora::MockEsploraTransport;

        let mut w = test_wallet();
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.fail_path("/blocks/tip/height", "simulated tip 503");
        let source = EsploraBdkUpdateSource::new(mock);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("tip") || err.to_string().contains("503"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);

        let m = import_mnemonic(PHRASE).unwrap();
        let pay_to = w.peek_receive_address(1);
        let spend_err = select_and_prepare_bip84_spend_with_bdk_sync(
            &mut w, &source, &m, &pay_to, 1_000, 5, "",
        )
        .unwrap_err();
        assert!(!spend_err.is_after_sync());
        assert!(spend_err.sync_snapshot().is_none());
    }

    #[test]
    fn electrum_transport_full_scan_spent_tx_drop() {
        use crate::electrum::{MockElectrumTransport, electrum_script_hash_from_script};
        use serde_json::json;

        let mut w = test_wallet();
        let spk0 = w.receive_script_pubkey(0);
        let spk5 = w.receive_script_pubkey(5);
        let foreign = Address::from_script(
            &ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x22; 20]).unwrap(),
            ),
            Network::Regtest,
        )
        .unwrap();

        let fund0 = funding_tx_to_script(spk0.clone(), 50_000, 0);
        let fund5 = funding_tx_to_script(spk5.clone(), 30_000, 1);
        let spend0 = spend_tx_from_outpoint(
            OutPoint {
                txid: fund0.compute_txid(),
                vout: 0,
            },
            foreign.script_pubkey(),
            49_000,
            2,
        );
        let fund0_id = fund0.compute_txid().to_string();
        let fund5_id = fund5.compute_txid().to_string();
        let spend0_id = spend0.compute_txid().to_string();
        let sh0 = electrum_script_hash_from_script(&spk0);
        let sh5 = electrum_script_hash_from_script(&spk5);

        let mut mock = MockElectrumTransport::new()
            .with_tip_height(100)
            .with_default_empty_history();
        mock.insert_history(
            &sh0,
            json!([
                {"tx_hash": fund0_id, "height": 90},
                {"tx_hash": spend0_id, "height": 95}
            ]),
        );
        mock.insert_history(&sh5, json!([{"tx_hash": fund5_id, "height": 91}]));
        mock.insert_transaction(&fund0_id, serialize_tx_hex(&fund0));
        mock.insert_transaction(&fund5_id, serialize_tx_hex(&fund5));
        mock.insert_transaction(&spend0_id, serialize_tx_hex(&spend0));

        // stop_gap must exceed empty run between index 0 and 5.
        let source = ElectrumBdkUpdateSource::with_stop_gap(mock, 6);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.utxos[0].amount_sats, 30_000);
        assert_eq!(snap.highest_used_receive, Some(5));

        let calls = &source.transport().calls;
        assert!(
            calls
                .iter()
                .any(|(m, _)| m == "blockchain.headers.subscribe"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(m, _)| m == "blockchain.scripthash.get_history"),
            "{calls:?}"
        );
        assert!(
            calls.iter().any(|(m, _)| m == "blockchain.transaction.get"),
            "{calls:?}"
        );
    }

    #[test]
    fn electrum_transport_error_is_sync_failure() {
        use crate::electrum::MockElectrumTransport;

        let mut w = test_wallet();
        let mut mock = MockElectrumTransport::new().with_default_empty_history();
        mock.fail_headers = true;
        let source = ElectrumBdkUpdateSource::new(mock);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("headers") || err.to_string().contains("subscribe"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
    }

    #[test]
    fn stop_gap_zero_rejected() {
        use crate::esplora::MockEsploraTransport;

        let mut w = test_wallet();
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "10");
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 0);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(err.to_string().contains("stop_gap"), "{err}");
    }

    #[test]
    fn esplora_mid_scan_history_error_is_sync_failure() {
        use crate::esplora::MockEsploraTransport;

        let mut w = test_wallet();
        let addr0 = w.peek_receive_address(0);
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        mock.fail_path(
            &format!("/address/{addr0}/txs"),
            "simulated address txs 503",
        );
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 2);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("address txs") || err.to_string().contains("503"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
    }

    #[test]
    fn esplora_mid_scan_tx_hex_error_is_sync_failure() {
        use crate::esplora::MockEsploraTransport;
        use serde_json::json;

        let mut w = test_wallet();
        let addr0 = w.peek_receive_address(0);
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 10_000, 0);
        let fund_id = fund.compute_txid().to_string();
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        mock.insert_fixture(
            &format!("/address/{addr0}/txs"),
            json!([{"txid": fund_id, "status": {"confirmed": true, "block_height": 90}}])
                .to_string(),
        );
        mock.fail_path(&format!("/tx/{fund_id}/hex"), "simulated tx hex 404");
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 2);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("tx hex") || err.to_string().contains("404"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
    }

    #[test]
    fn electrum_mid_scan_history_error_is_sync_failure() {
        use crate::electrum::{MockElectrumTransport, electrum_script_hash_from_script};

        let mut w = test_wallet();
        let sh0 = electrum_script_hash_from_script(&w.receive_script_pubkey(0));
        let mut mock = MockElectrumTransport::new()
            .with_tip_height(100)
            .with_default_empty_history();
        mock.fail_get_history(&sh0, "simulated get_history 503");
        let source = ElectrumBdkUpdateSource::with_stop_gap(mock, 2);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("get_history") || err.to_string().contains("503"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
    }

    #[test]
    fn electrum_mid_scan_tx_get_error_is_sync_failure() {
        use crate::electrum::{MockElectrumTransport, electrum_script_hash_from_script};
        use serde_json::json;

        let mut w = test_wallet();
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 10_000, 0);
        let fund_id = fund.compute_txid().to_string();
        let sh0 = electrum_script_hash_from_script(&w.receive_script_pubkey(0));
        let mut mock = MockElectrumTransport::new()
            .with_tip_height(100)
            .with_default_empty_history();
        mock.insert_history(&sh0, json!([{"tx_hash": fund_id, "height": 90}]));
        // No insert_transaction → transaction.get hard-errors.
        let source = ElectrumBdkUpdateSource::with_stop_gap(mock, 2);
        let err = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap_err();
        assert!(
            err.to_string().contains("transaction.get") || err.to_string().contains("fixture"),
            "{err}"
        );
        assert_eq!(w.list_wallet_utxos().unwrap().len(), 0);
    }

    #[test]
    fn transport_update_uses_history_height_not_tip_anchor() {
        use crate::esplora::MockEsploraTransport;
        use serde_json::json;

        let mut w = test_wallet();
        let addr0 = w.peek_receive_address(0);
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 25_000, 0);
        let fund_id = fund.compute_txid().to_string();
        // Confirmed at 90, tip 100 → confirmations = 11.
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        mock.insert_fixture(
            &format!("/address/{addr0}/txs"),
            json!([{"txid": fund_id, "status": {"confirmed": true, "block_height": 90}}])
                .to_string(),
        );
        mock.insert_fixture(&format!("/tx/{fund_id}/hex"), serialize_tx_hex(&fund));
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 2);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(
            snap.utxos[0].confirmations, 11,
            "must use history height 90 vs tip 100, not tip-anchor conf=1"
        );
    }

    #[test]
    fn transport_unconfirmed_stays_zero_confirmations() {
        use crate::esplora::MockEsploraTransport;
        use serde_json::json;

        let mut w = test_wallet();
        let addr0 = w.peek_receive_address(0);
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 15_000, 0);
        let fund_id = fund.compute_txid().to_string();
        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        mock.insert_fixture(
            &format!("/address/{addr0}/txs"),
            json!([{"txid": fund_id, "status": {"confirmed": false}}]).to_string(),
        );
        mock.insert_fixture(&format!("/tx/{fund_id}/hex"), serialize_tx_hex(&fund));
        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 2);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(
            snap.utxos[0].confirmations, 0,
            "mempool must not become tip-anchored confirmed"
        );
        assert_eq!(snap.balance.confirmed_sats, 0);
        assert_eq!(snap.balance.unconfirmed_sats, 15_000);
    }

    #[test]
    fn esplora_paginates_chain_history_beyond_first_page() {
        use crate::esplora::{
            ESPLORA_TXS_PAGE_SIZE, MockEsploraTransport, esplora_address_txs_chain_path,
        };
        use serde_json::json;

        let mut w = test_wallet();
        let addr0 = w.peek_receive_address(0);
        // Page 1: ESPLORA_TXS_PAGE_SIZE newest dummy txids + no real wallet coin.
        // Page 2 (chain): the real funding tx at older height.
        // Pagination must fetch page 2 so the funding UTXO is not missed.
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 40_000, 0);
        let fund_id = fund.compute_txid().to_string();

        let mut page1 = Vec::new();
        let mut dummy_hex: BTreeMap<String, String> = BTreeMap::new();
        for i in 0..ESPLORA_TXS_PAGE_SIZE {
            // Distinct locktimes so each dummy funding tx has a unique txid.
            let dummy = funding_tx_to_script(
                ScriptBuf::new_p2wpkh(
                    &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0xab; 20]).unwrap(),
                ),
                1,
                i as u32,
            );
            let id = dummy.compute_txid().to_string();
            dummy_hex.insert(id.clone(), serialize_tx_hex(&dummy));
            page1.push(json!({
                "txid": id,
                "status": {"confirmed": true, "block_height": 95}
            }));
        }
        let last_of_page1 = page1
            .last()
            .and_then(|v| v.get("txid"))
            .and_then(|t| t.as_str())
            .unwrap()
            .to_owned();

        let mut mock = MockEsploraTransport::new().with_default_empty_address_txs();
        mock.insert_fixture("/blocks/tip/height", "100");
        mock.insert_fixture(
            &format!("/address/{addr0}/txs"),
            serde_json::Value::Array(page1).to_string(),
        );
        let chain_path = esplora_address_txs_chain_path(&addr0, &last_of_page1).unwrap();
        mock.insert_fixture(
            &chain_path,
            json!([{
                "txid": fund_id,
                "status": {"confirmed": true, "block_height": 80}
            }])
            .to_string(),
        );
        for (id, hex) in dummy_hex {
            mock.insert_fixture(&format!("/tx/{id}/hex"), hex);
        }
        mock.insert_fixture(&format!("/tx/{fund_id}/hex"), serialize_tx_hex(&fund));

        let source = EsploraBdkUpdateSource::with_stop_gap(mock, 2);
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        // Foreign dummy outputs are ignored; only our SPK's fund UTXO remains.
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.utxos[0].amount_sats, 40_000);
        assert_eq!(snap.utxos[0].confirmations, 21); // tip 100, height 80
        let calls = &source.transport().calls;
        assert!(
            calls.iter().any(|p| p.contains("/txs/chain/")),
            "expected chain pagination call: {calls:?}"
        );
    }

    #[test]
    fn scanned_tx_future_height_rejected() {
        let fund = funding_tx_to_script(
            ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0xcd; 20]).unwrap(),
            ),
            1_000,
            0,
        );
        let err = chain_update_from_scanned_txs(
            Network::Regtest,
            10,
            vec![ScannedTx {
                tx: fund,
                observation: BdkTxObservation::Confirmed { height: 50 },
            }],
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds tip"), "{err}");
    }

    /// Product open: mempool never maps to BDK full_scan (offline residual).
    #[test]
    fn open_product_bdk_update_source_mempool_fail_closed() {
        use crate::chain_select::ProductChainSourceConfig;
        // Match (not unwrap_err): `Box<dyn BdkUpdateSource>` is not Debug.
        let err = match open_product_bdk_update_source(&ProductChainSourceConfig::mempool()) {
            Ok(_) => panic!("mempool must not open a BDK full_scan source"),
            Err(e) => e.to_string(),
        };
        let lower = err.to_ascii_lowercase();
        assert!(lower.contains("mempool"), "err={err}");
        assert!(
            lower.contains("bdk") || lower.contains("full_scan"),
            "err={err}"
        );
        assert!(
            lower.contains("gap") || lower.contains("esplora") || lower.contains("electrum"),
            "err={err}"
        );
        assert!(!lower.contains("crypto"));
    }

    /// Product open: esplora without feature → structured residual (or Ok box when
    /// live feature on — still no network call until full_scan).
    #[test]
    fn open_product_bdk_update_source_esplora_feature_honesty() {
        use crate::chain_select::{ChainSourceKind, ProductChainSourceConfig};
        let cfg = ProductChainSourceConfig {
            kind: ChainSourceKind::Esplora,
            esplora_url: Some("https://blockstream.info/api".into()),
            electrum_addr: None,
            electrum_tls: false,
        };
        let result = open_product_bdk_update_source(&cfg);
        #[cfg(not(feature = "esplora"))]
        {
            let err = match result {
                Ok(_) => panic!("expected feature-missing error"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("feature `esplora`"), "err={err}");
            assert!(
                err.contains("not compiled") || err.contains("bdk"),
                "err={err}"
            );
        }
        #[cfg(feature = "esplora")]
        {
            assert!(
                result.is_ok(),
                "live Esplora BDK source constructs without I/O"
            );
        }
    }

    /// Product open: electrum without feature → structured residual.
    #[test]
    fn open_product_bdk_update_source_electrum_feature_honesty() {
        use crate::chain_select::{ChainSourceKind, ProductChainSourceConfig};
        let cfg = ProductChainSourceConfig {
            kind: ChainSourceKind::Electrum,
            esplora_url: None,
            electrum_addr: Some("127.0.0.1:50001".into()),
            electrum_tls: false,
        };
        let result = open_product_bdk_update_source(&cfg);
        #[cfg(not(feature = "electrum"))]
        {
            let err = match result {
                Ok(_) => panic!("expected feature-missing error"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("feature `electrum`"), "err={err}");
            assert!(
                err.contains("not compiled") || err.contains("bdk"),
                "err={err}"
            );
        }
        #[cfg(feature = "electrum")]
        {
            assert!(
                result.is_ok(),
                "live Electrum BDK source constructs without I/O"
            );
        }
    }

    /// Offline product path: mock source via list helper still spent-aware.
    #[test]
    fn product_prefer_bdk_list_with_mock_source() {
        let mut w = test_wallet();
        let fund = funding_tx_to_script(w.receive_script_pubkey(0), 12_000, 0);
        let update =
            chain_update_from_transactions(Network::Regtest, 50, vec![fund], Some(0), None)
                .unwrap();
        let source = MockBdkUpdateSource::with_update(update);
        // Same entry as shell prefer-BDK after open_product_* (inject mock offline).
        let snap = list_bip84_utxos_with_bdk_sync(&mut w, &source).unwrap();
        assert_eq!(snap.utxos.len(), 1);
        assert_eq!(snap.utxos[0].amount_sats, 12_000);
        let notices = bdk_sync_notice_lines(&snap);
        let j = notices.join("\n").to_ascii_lowercase();
        assert!(j.contains("bdk"), "notices={notices:?}");
        // BDK notice contrasts "not gap-limit"; reject gap-only residual phrasing.
        assert!(
            !j.contains("gap-limit chainsource sync only") && !j.contains("not full bdk_wallet"),
            "must not use gap residual copy: {notices:?}"
        );
        assert!(!j.contains("crypto"));
    }
}
