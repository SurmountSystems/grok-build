//! Extract finalized transactions and broadcast via [`crate::explorer::TxBroadcaster`].

use bitcoin::Transaction;
use bitcoin::psbt::Psbt;

use crate::error::{Result, WalletError};

use super::{input_is_finalized, psbt_is_broadcast_ready};

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
