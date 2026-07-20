//! Bitcoin wallet foundations for Grok OSS (Surmount).
//!
//! **Real money.** Read `SECURITY.md` and `docs/bitcoin-routstr/` before
//! extending this crate. Seed material must never use plaintext JSON stores.
//!
//! User-facing language: Bitcoin, Lightning, Cashu (Chaumian eCash). Never
//! "crypto".
//!
//! ## Modules
//!
//! - [`mnemonic`]: BIP-39 generate / import / validate
//! - [`seed_vault`]: OS keyring + password AEAD storage (never CredentialsStore)
//! - [`nip06`]: Nostr key derivation (feature `nip06`)
//! - [`address_ux`]: QR + copy + BIP21 + mempool.space helpers
//! - [`onchain`]: BIP84 receive address from mnemonic (feature `onchain-address`)
//! - [`descriptor_wallet`]: BIP84 descriptors + list_unspent + gap-limit
//!   `sync_utxos` / `sync_with_gap_extend` (bounded; not full bdk auto-sync) +
//!   product `list_bip84_utxos_with_gap_sync` (snapshot-authoritative UTXO list /
//!   balance — no extra list) + product `select_and_prepare_bip84_spend_with_gap_sync`
//!   (select-from-snapshot after sync — no extra list; `GapSyncSpendFailure`
//!   AfterSync carries hit-max notices on select/prepare Err) +
//!   `select_and_prepare_bip84_spend_from_utxos` + fee-aware select_coins;
//!   mock + optional mempool `ChainSource` (`explorer-http`); unsigned PSBT
//!   build + BIP84 P2WPKH sign/finalize/extract; RBF/CPFP fee planners;
//!   RBF replacement + CPFP child prepare; broadcast via [`explorer::TxBroadcaster`]
//! - [`esplora`]: Esplora REST `ChainSource` + `TxBroadcaster` (`POST /tx`; mock always;
//!   live HTTP behind feature `esplora`)
//! - [`electrum`]: Electrum JSON-RPC `ChainSource` + `TxBroadcaster`
//!   (`blockchain.transaction.broadcast`; mock always; live plaintext TCP + TLS
//!   behind feature `electrum`; rustls + WebPKI roots; no skip-verify)
//! - [`chain_select`]: product env/config selector for live `ChainSource` + `TxBroadcaster`
//!   (default mempool; UTXO + push aligned; `GROK_BITCOIN_CHAIN_SOURCE` + feature-honest open)
//! - [`lightning`]: capability trait + BOLT12 honesty flag + `default_lightning_backend`
//! - [`cashu`]: Cashu token newtype + funding wizard + `default_cashu_backend` seams
//! - [`explorer`]: rate-limited mempool.space client + fee estimates + TxBroadcaster
//!   (+ optional HTTP)
//! - [`watcher`]: address/tx poll → FundingWizard confirmations
//! - [`funding_cli`]: backup gate + unlock; spend/RBF/CPFP/utxos CLI copy; topup/refund via
//!   default backends (CLI/TUI)
//! - [`routstr_invoice`]: pure Routstr Lightning invoice parse/display (HTTP in shell)

#![forbid(unsafe_code)]

pub mod address_ux;
pub mod cashu;
#[cfg(feature = "onchain-address")]
pub mod chain_select;
#[cfg(feature = "onchain-address")]
pub mod descriptor_wallet;
#[cfg(feature = "onchain-address")]
pub mod electrum;
pub mod error;
#[cfg(feature = "onchain-address")]
pub mod esplora;
pub mod explorer;
pub mod funding_cli;
pub mod lightning;
pub mod mnemonic;
pub mod routstr_invoice;
#[cfg(feature = "nip06")]
pub mod nip06;
#[cfg(feature = "onchain-address")]
pub mod onchain;
pub mod seed_vault;
pub mod watcher;

/// Crate version (for diagnostics).
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short pointer for logs and `grok --version` style diagnostics.
pub fn security_doc_hint() -> &'static str {
    "see crates/codegen/grok-bitcoin-wallet/SECURITY.md and docs/bitcoin-routstr/"
}

/// BOLT12 offer routing is **not** implemented in this crate yet.
/// Never claim BOLT12 support in UI while this is `false`.
pub const BOLT12_SUPPORTED: bool = false;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_metadata_present() {
        assert!(!super::CRATE_VERSION.is_empty());
        assert!(super::security_doc_hint().contains("bitcoin-routstr"));
    }

    #[test]
    fn bolt12_not_claimed() {
        // Keep the const false until LDK offer path lands (const assert).
        const {
            assert!(!super::BOLT12_SUPPORTED);
        }
    }
}
