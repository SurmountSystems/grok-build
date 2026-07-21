//! Unsigned PSBT construction from coin selection.

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, transaction,
};

use crate::error::{Result, WalletError};
use crate::explorer::is_valid_txid_hex;

use super::coin_select::CoinSelection;
use super::fee::DUST_P2WPKH_SATS;
use super::types::OutPointRef;

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

/// Parse a 64-hex [`OutPointRef`] into a bitcoin [`OutPoint`].
pub(super) fn outpoint_from_ref(op: &OutPointRef) -> Result<OutPoint> {
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
pub(super) fn parse_network_address(addr: &str, network: Network) -> Result<Address> {
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
