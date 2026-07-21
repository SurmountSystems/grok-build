//! Core wallet value types (outpoints, UTXOs, balances).

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
