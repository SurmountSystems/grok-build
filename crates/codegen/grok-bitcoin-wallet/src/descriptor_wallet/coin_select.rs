//! Coin selection strategies and fee-aware selection.

use crate::error::{Result, WalletError};

use super::fee::{DUST_P2WPKH_SATS, estimate_fee_sats};
use super::types::{WalletBalance, WalletUtxo};

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
