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
//! - [`lightning`]: capability trait + BOLT12 honesty flag
//! - [`cashu`]: Cashu token newtype + funding wizard state machine
//! - [`explorer`]: rate-limited mempool.space client (+ optional HTTP feature)
//! - [`watcher`]: address/tx poll → FundingWizard confirmations
//! - [`funding_cli`]: backup gate + unlock session before ShowAddress (CLI)

#![forbid(unsafe_code)]

pub mod address_ux;
pub mod cashu;
pub mod error;
pub mod explorer;
pub mod funding_cli;
pub mod lightning;
pub mod mnemonic;
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
